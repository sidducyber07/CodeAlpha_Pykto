"""
Real-time packet capture engine for Pykto.

Runs live capture in a background thread using either Python's built-in raw
`socket` module or `scapy`, delivering parsed `PacketRecord` items to the UI
via a thread-safe `queue.Queue` so the GUI never freezes.
"""

import importlib.util
import os
import platform
import queue
import socket
import threading
from typing import Callable, Optional

from packet_parser import (
    PacketRecord,
    parse_raw_ethernet_frame,
    parse_raw_ipv4_packet,
    parse_scapy_packet,
)


def is_scapy_available() -> bool:
    """Return True if scapy is installed without importing all of scapy.all yet."""
    return importlib.util.find_spec("scapy") is not None


def has_capture_privileges() -> bool:
    """Best-effort check for root/admin privileges needed by raw sockets."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def list_interfaces() -> list[str]:
    """Return available network interface names (e.g., lo, eth0, wlan0)."""
    names: list[str] = []
    # Python 3.3+ exposes OS interface names directly via socket.if_nameindex().
    if hasattr(socket, "if_nameindex"):
        try:
            names = [name for _, name in socket.if_nameindex()]
        except OSError:
            names = []
    # Fallback to scapy's interface list if socket.if_nameindex is unavailable.
    if not names and is_scapy_available():
        try:
            from scapy.interfaces import get_if_list
            names = list(get_if_list())
        except Exception:
            names = []
    # Keep order stable and deduplicated.
    seen: set[str] = set()
    unique: list[str] = []
    for name in names:
        if name and name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


class CaptureEngine:
    """
    Background packet capture controller with Start / Stop / Reset support.

    Capture runs off the main Tkinter thread and communicates solely via
    `packet_queue` and `on_error` so the UI remains smooth during traffic bursts.
    """

    def __init__(
        self,
        packet_queue: "queue.Queue[PacketRecord]",
        on_error: Optional[Callable[[str, bool], None]] = None,
    ) -> None:
        self._queue = packet_queue
        self._on_error = on_error
        self._stop_event = threading.Event()   # Signals background loop to exit cleanly
        self._thread: Optional[threading.Thread] = None
        self._scapy_sniffer = None
        self._lock = threading.Lock()          # Protects shared counter/running state
        self._counter = 0
        self._active_engine = ""
        self._running = False

    @property
    def is_running(self) -> bool:
        """Return True while a capture session is active."""
        with self._lock:
            return self._running

    @property
    def active_engine(self) -> str:
        """Return the engine currently in use ('socket' or 'scapy')."""
        with self._lock:
            return self._active_engine

    def reset_counter(self) -> None:
        """Reset sequential packet numbering back to 0 (next packet will be #1)."""
        with self._lock:
            self._counter = 0

    def _next_index(self) -> int:
        """Thread-safely increment and return the next packet sequence number."""
        with self._lock:
            self._counter += 1
            return self._counter

    def _emit_error(self, message: str, is_permission: bool = False) -> None:
        """Mark capture stopped and notify the UI error handler."""
        with self._lock:
            self._running = False
        if self._on_error:
            self._on_error(message, is_permission)

    def _enqueue(self, record: Optional[PacketRecord]) -> None:
        """
        Push a parsed packet onto the UI queue without blocking the capture thread.

        If a sudden flood fills the 5,000-slot queue faster than the UI polls,
        drop the oldest queued packet so memory stays bounded.
        """
        if record is None:
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(record)
            except queue.Full:
                pass

    def start(self, interface: Optional[str] = None, engine_mode: str = "auto") -> str:
        """
        Start capturing packets in the background.

        engine_mode: 'auto', 'socket', or 'scapy'
        Returns the resolved engine name ('socket' or 'scapy'), or raises on error.
        """
        if self.is_running:
            return self.active_engine

        self._stop_event.clear()
        resolved = self._resolve_engine(engine_mode)

        if resolved == "scapy":
            self._start_scapy(interface)
        else:
            self._start_raw_socket(interface)

        with self._lock:
            self._active_engine = resolved
            self._running = True
        return resolved

    def stop(self) -> None:
        """Stop capturing packets cleanly and wait briefly for the worker thread."""
        self._stop_event.set()
        with self._lock:
            sniffer = self._scapy_sniffer
            self._scapy_sniffer = None
            thread = self._thread
            self._thread = None
            self._running = False

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

        if thread is not None and thread.is_alive():
            thread.join(timeout=1.0)

    def _resolve_engine(self, mode: str) -> str:
        """Choose between raw `socket` and `scapy` based on user selection and OS."""
        mode = mode.lower().strip()
        if mode == "scapy":
            if not is_scapy_available():
                raise RuntimeError("Scapy is not installed in this Python environment.")
            return "scapy"
        if mode == "socket":
            return "socket"
        # 'auto': prefer fast built-in AF_PACKET on Linux, otherwise scapy if available.
        if hasattr(socket, "AF_PACKET"):
            return "socket"
        if is_scapy_available():
            return "scapy"
        return "socket"

    def _start_raw_socket(self, interface: Optional[str]) -> None:
        """Open a raw socket and launch the background receiver thread."""
        system = platform.system()
        if hasattr(socket, "AF_PACKET"):
            # ETH_P_ALL (0x0003) captures all Ethernet frame types at Layer 2 on Linux.
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if interface:
                sock.bind((interface, 0))
            # Short timeout lets the loop check `_stop_event` promptly when Stop is clicked.
            sock.settimeout(0.25)
            parser = parse_raw_ethernet_frame
        elif system == "Windows":
            # Windows raw sockets capture IPv4 packets at Layer 3 using SIO_RCVALL.
            host = socket.gethostbyname(socket.gethostname())
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            sock.settimeout(0.25)
            parser = parse_raw_ipv4_packet
        else:
            sock_close_msg = (
                f"Raw AF_PACKET sockets are not supported on {system}. "
                "Select the 'Scapy' engine instead."
            )
            raise RuntimeError(sock_close_msg)

        thread = threading.Thread(
            target=self._raw_socket_loop,
            args=(sock, parser, system == "Windows"),
            daemon=True,
            name="PyktoSocketCapture",
        )
        with self._lock:
            self._thread = thread
        thread.start()

    def _raw_socket_loop(self, sock: socket.socket, parser, is_windows: bool) -> None:
        """Continuously read raw frames from the socket until Stop is requested."""
        try:
            while not self._stop_event.is_set():
                try:
                    raw_data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    # Expected every 0.25s when idle so we can re-check `_stop_event`.
                    continue
                except OSError as exc:
                    if not self._stop_event.is_set():
                        self._emit_error(f"Capture socket error: {exc}", False)
                    break

                record = parser(raw_data, self._next_index())
                self._enqueue(record)
        finally:
            if is_windows:
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            try:
                sock.close()
            except Exception:
                pass

    def _start_scapy(self, interface: Optional[str]) -> None:
        """Launch Scapy's AsyncSniffer and verify its capture socket opens cleanly."""
        from scapy.sendrecv import AsyncSniffer

        ready_event = threading.Event()

        def _handle(pkt) -> None:
            if self._stop_event.is_set():
                return
            try:
                record = parse_scapy_packet(pkt, self._next_index())
                self._enqueue(record)
            except Exception:
                pass

        sniffer = AsyncSniffer(
            iface=interface or None,
            prn=_handle,
            store=False,  # Do not keep all packets in Scapy's internal list.
            started_callback=ready_event.set,
        )
        sniffer.start()

        # AsyncSniffer opens its socket inside a worker thread; wait briefly so
        # PermissionError or interface errors surface immediately on Start.
        for _ in range(40):
            if ready_event.is_set():
                break
            if sniffer.exception is not None:
                raise sniffer.exception
            if sniffer.thread is not None and not sniffer.thread.is_alive():
                break
            ready_event.wait(0.05)

        if sniffer.exception is not None:
            raise sniffer.exception

        with self._lock:
            self._scapy_sniffer = sniffer
