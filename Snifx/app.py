#!/usr/bin/env python3
"""
Pykto — Real-Time Basic Network Sniffer UI

A standalone Python desktop application (Tkinter) that captures live network
packets using Python's built-in `socket` or `scapy`, displays bounded
real-time traffic summaries and packet rows (never flooding thousands of
printed lines), and lets you inspect headers and payloads on click.
"""

from collections import deque
import os
from pathlib import Path
import platform
import queue
import shutil
import subprocess
import sys
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

# Ensure sibling modules inside Snifx/ are importable regardless of working directory.
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from capture_engine import (  # noqa: E402
    CaptureEngine,
    has_capture_privileges,
    is_scapy_available,
    list_interfaces,
)
from env_bootstrap import ensure_environment  # noqa: E402
from packet_parser import PacketRecord, format_payload_hexdump  # noqa: E402


# Keep memory and UI row count bounded even under heavy network traffic.
MAX_BUFFER_PACKETS = 1000   # In-memory ring buffer used when re-applying filters
MAX_VISIBLE_ROWS = 300      # Maximum rows kept in the live Treeview table
POLL_INTERVAL_MS = 100      # Main-thread queue drain interval (10 updates/sec)


def format_bytes(num_bytes: int) -> str:
    """Format a raw byte count into human-readable B / KB / MB / GB."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024.0 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


class SnifxApp:
    """Main desktop GUI controller for the Pykto network sniffer."""

    COLORS = {
        "bg": "#0f172a",
        "panel": "#1e293b",
        "panel_alt": "#162033",
        "border": "#334155",
        "text": "#e2e8f0",
        "muted": "#94a3b8",
        "accent": "#38bdf8",
        "green": "#22c55e",
        "green_dark": "#16a34a",
        "red": "#ef4444",
        "red_dark": "#dc2626",
        "amber": "#f59e0b",
        "purple": "#a855f7",
        "tcp": "#93c5fd",
        "udp": "#5eead4",
        "icmp": "#fcd34d",
        "other": "#d8b4fe",
        "select": "#1d4ed8",
    }

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Pykto")
        self.root.geometry("1120x720")
        self.root.minsize(920, 600)
        self.root.configure(bg=self.COLORS["bg"])

        # Thread-safe queue connecting the background capture thread to the GUI thread.
        self.packet_queue: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=5000)
        self.engine = CaptureEngine(self.packet_queue, on_error=self._on_engine_error)

        # Bounded ring buffer + lookup maps for the currently visible Treeview rows.
        self.buffer: deque[PacketRecord] = deque(maxlen=MAX_BUFFER_PACKETS)
        self.row_records: dict[str, PacketRecord] = {}
        self.visible_iids: deque[str] = deque()
        # Monotonic UI row ID prevents duplicate Treeview IDs across Reset clicks.
        self._ui_seq = 0

        # Live traffic counters (updated continuously as packets arrive).
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self._rate_packets = 0
        self._rate_bytes = 0
        self._last_rate_ts = time.monotonic()

        # Tkinter control variables bound to dropdowns, radio buttons, and checkboxes.
        self.interface_var = tk.StringVar(value="All Interfaces")
        self.engine_var = tk.StringVar(value="Auto")
        self.proto_filter_var = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar()
        self.hide_loopback_var = tk.BooleanVar(value=False)
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.status_text_var = tk.StringVar(value="Ready. Click Start to capture live traffic.")
        self.buffer_info_var = tk.StringVar(value=f"Showing 0 / {MAX_VISIBLE_ROWS} max rows")

        self._configure_styles()
        self._build_ui()
        self._populate_interfaces()
        self._update_button_states(running=False)

        # Re-filter the visible table whenever the user types in the search box.
        self.search_var.trace_add("write", lambda *_: self._rebuild_table())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # Start the periodic UI refresh timer.
        self.root.after(POLL_INTERVAL_MS, self._poll_loop)

    def _configure_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        c = self.COLORS
        style.configure("TFrame", background=c["bg"])
        style.configure("Panel.TFrame", background=c["panel"])
        style.configure(
            "TLabel",
            background=c["bg"],
            foreground=c["text"],
            font=("TkDefaultFont", 10),
        )
        style.configure(
            "Panel.TLabel",
            background=c["panel"],
            foreground=c["text"],
            font=("TkDefaultFont", 10),
        )
        style.configure(
            "Muted.TLabel",
            background=c["panel"],
            foreground=c["muted"],
            font=("TkDefaultFont", 9),
        )
        style.configure(
            "TCombobox",
            fieldbackground=c["panel_alt"],
            background=c["panel"],
            foreground=c["text"],
            arrowcolor=c["text"],
            borderwidth=1,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", c["panel_alt"])],
            selectbackground=[("readonly", c["panel_alt"])],
            selectforeground=[("readonly", c["text"])],
        )
        style.configure(
            "Treeview",
            background=c["panel_alt"],
            fieldbackground=c["panel_alt"],
            foreground=c["text"],
            rowheight=24,
            borderwidth=0,
            font=("TkFixedFont", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=c["panel"],
            foreground=c["accent"],
            borderwidth=1,
            relief="flat",
            font=("TkDefaultFont", 9, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", c["select"])],
            foreground=[("selected", "#ffffff")],
        )
        style.map("Treeview.Heading", background=[("active", c["border"])])
        style.configure(
            "TPanedwindow",
            background=c["border"],
        )

    def _build_ui(self) -> None:
        c = self.COLORS

        # ── Top Toolbar ────────────────────────────────────────────────
        toolbar = tk.Frame(self.root, bg=c["panel"], padx=14, pady=10, highlightbackground=c["border"], highlightthickness=1)
        toolbar.pack(fill="x", padx=10, pady=(10, 6))

        left_hdr = tk.Frame(toolbar, bg=c["panel"])
        left_hdr.pack(side="left")

        tk.Label(
            left_hdr,
            text="PYKTO",
            bg=c["panel"],
            fg=c["accent"],
            font=("TkDefaultFont", 14, "bold"),
        ).pack(side="left")
        tk.Label(
            left_hdr,
            text="  Real-Time Network Sniffer",
            bg=c["panel"],
            fg=c["muted"],
            font=("TkDefaultFont", 10),
        ).pack(side="left", padx=(2, 12))

        self.status_badge = tk.Label(
            left_hdr,
            text="● IDLE",
            bg="#334155",
            fg=c["text"],
            padx=10,
            pady=3,
            font=("TkDefaultFont", 9, "bold"),
        )
        self.status_badge.pack(side="left")

        right_ctrl = tk.Frame(toolbar, bg=c["panel"])
        right_ctrl.pack(side="right")

        tk.Label(right_ctrl, text="Interface:", bg=c["panel"], fg=c["muted"], font=("TkDefaultFont", 9)).pack(side="left", padx=(0, 4))
        self.iface_combo = ttk.Combobox(right_ctrl, textvariable=self.interface_var, state="readonly", width=16)
        self.iface_combo.pack(side="left", padx=(0, 10))

        tk.Label(right_ctrl, text="Engine:", bg=c["panel"], fg=c["muted"], font=("TkDefaultFont", 9)).pack(side="left", padx=(0, 4))
        engines = ["Auto", "Socket"]
        if is_scapy_available():
            engines.append("Scapy")
        self.engine_combo = ttk.Combobox(right_ctrl, textvariable=self.engine_var, values=engines, state="readonly", width=8)
        self.engine_combo.pack(side="left", padx=(0, 14))

        self.start_btn = tk.Button(
            right_ctrl,
            text="▶  Start",
            command=self.start_capture,
            bg=c["green_dark"],
            fg="#ffffff",
            activebackground=c["green"],
            activeforeground="#ffffff",
            disabledforeground="#94a3b8",
            relief="flat",
            padx=14,
            pady=5,
            cursor="hand2",
            font=("TkDefaultFont", 9, "bold"),
        )
        self.start_btn.pack(side="left", padx=3)

        self.stop_btn = tk.Button(
            right_ctrl,
            text="■  Stop",
            command=self.stop_capture,
            bg=c["red_dark"],
            fg="#ffffff",
            activebackground=c["red"],
            activeforeground="#ffffff",
            disabledforeground="#94a3b8",
            relief="flat",
            padx=14,
            pady=5,
            cursor="hand2",
            font=("TkDefaultFont", 9, "bold"),
        )
        self.stop_btn.pack(side="left", padx=3)

        self.reset_btn = tk.Button(
            right_ctrl,
            text="↺  Reset",
            command=self.reset_capture,
            bg="#334155",
            fg=c["text"],
            activebackground="#475569",
            activeforeground="#ffffff",
            relief="flat",
            padx=14,
            pady=5,
            cursor="hand2",
            font=("TkDefaultFont", 9, "bold"),
        )
        self.reset_btn.pack(side="left", padx=(3, 0))

        # ── Real-Time Stats Cards ──────────────────────────────────────
        stats_frame = tk.Frame(self.root, bg=c["bg"])
        stats_frame.pack(fill="x", padx=10, pady=(0, 6))

        self.stat_labels: dict[str, tk.Label] = {}
        cards = [
            ("total", "CAPTURED", "0", c["text"]),
            ("TCP", "TCP", "0", c["tcp"]),
            ("UDP", "UDP", "0", c["udp"]),
            ("ICMP", "ICMP", "0", c["icmp"]),
            ("OTHER", "OTHER / ARP", "0", c["other"]),
            ("volume", "DATA / RATE", "0 B  (0 pkt/s)", c["accent"]),
        ]
        for idx, (key, title, initial, color) in enumerate(cards):
            card = tk.Frame(
                stats_frame,
                bg=c["panel"],
                padx=12,
                pady=7,
                highlightbackground=c["border"],
                highlightthickness=1,
            )
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 4, 0))
            stats_frame.columnconfigure(idx, weight=1)

            tk.Label(card, text=title, bg=c["panel"], fg=c["muted"], font=("TkDefaultFont", 8, "bold")).pack(anchor="w")
            val_lbl = tk.Label(card, text=initial, bg=c["panel"], fg=color, font=("TkDefaultFont", 12, "bold"))
            val_lbl.pack(anchor="w", pady=(2, 0))
            self.stat_labels[key] = val_lbl

        # ── Filter Bar ─────────────────────────────────────────────────
        filter_bar = tk.Frame(self.root, bg=c["panel"], padx=12, pady=6, highlightbackground=c["border"], highlightthickness=1)
        filter_bar.pack(fill="x", padx=10, pady=(0, 6))

        tk.Label(filter_bar, text="Protocol:", bg=c["panel"], fg=c["muted"], font=("TkDefaultFont", 9)).pack(side="left", padx=(0, 6))
        for proto in ("ALL", "TCP", "UDP", "ICMP", "OTHER"):
            rb = tk.Radiobutton(
                filter_bar,
                text=proto,
                variable=self.proto_filter_var,
                value=proto,
                command=self._rebuild_table,
                bg=c["panel"],
                fg=c["text"],
                selectcolor=c["panel_alt"],
                activebackground=c["panel"],
                activeforeground=c["accent"],
                highlightthickness=0,
                font=("TkDefaultFont", 9),
            )
            rb.pack(side="left", padx=2)

        tk.Label(filter_bar, text="   Filter IP / Port / Info:", bg=c["panel"], fg=c["muted"], font=("TkDefaultFont", 9)).pack(side="left", padx=(10, 6))
        search_entry = tk.Entry(
            filter_bar,
            textvariable=self.search_var,
            bg=c["panel_alt"],
            fg=c["text"],
            insertbackground=c["text"],
            relief="flat",
            highlightbackground=c["border"],
            highlightthickness=1,
            width=24,
            font=("TkDefaultFont", 9),
        )
        search_entry.pack(side="left", ipady=3)

        tk.Checkbutton(
            filter_bar,
            text="Hide Loopback",
            variable=self.hide_loopback_var,
            command=self._rebuild_table,
            bg=c["panel"],
            fg=c["text"],
            selectcolor=c["panel_alt"],
            activebackground=c["panel"],
            activeforeground=c["text"],
            highlightthickness=0,
            font=("TkDefaultFont", 9),
        ).pack(side="left", padx=(12, 6))

        tk.Checkbutton(
            filter_bar,
            text="Auto-scroll",
            variable=self.autoscroll_var,
            bg=c["panel"],
            fg=c["text"],
            selectcolor=c["panel_alt"],
            activebackground=c["panel"],
            activeforeground=c["text"],
            highlightthickness=0,
            font=("TkDefaultFont", 9),
        ).pack(side="left", padx=4)

        tk.Label(
            filter_bar,
            textvariable=self.buffer_info_var,
            bg=c["panel"],
            fg=c["muted"],
            font=("TkDefaultFont", 9),
        ).pack(side="right")

        # ── Main Split View: Live Table + Packet Inspector ─────────────
        paned = ttk.PanedWindow(self.root, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        # Top: Bounded Live Packet Table
        table_container = tk.Frame(paned, bg=c["panel"], highlightbackground=c["border"], highlightthickness=1)
        columns = ("no", "time", "proto", "src", "dst", "len", "info")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        headings = [
            ("no", "#", 65, "e"),
            ("time", "Time", 105, "center"),
            ("proto", "Protocol", 80, "center"),
            ("src", "Source IP : Port", 205, "w"),
            ("dst", "Destination IP : Port", 205, "w"),
            ("len", "Bytes", 70, "e"),
            ("info", "Summary / Info", 350, "w"),
        ]
        for col, title, width, anchor in headings:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=50, anchor=anchor, stretch=(col == "info"))

        self.tree.tag_configure("TCP", foreground=c["tcp"])
        self.tree.tag_configure("UDP", foreground=c["udp"])
        self.tree.tag_configure("ICMP", foreground=c["icmp"])
        self.tree.tag_configure("OTHER", foreground=c["other"])

        y_scroll = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=y_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        y_scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_packet_selected)

        paned.add(table_container, weight=3)

        # Bottom: Selected Packet Inspector (Headers + Hex/ASCII Payload)
        inspector = tk.Frame(paned, bg=c["panel"], padx=8, pady=8, highlightbackground=c["border"], highlightthickness=1)
        inspector.columnconfigure(0, weight=1)
        inspector.columnconfigure(1, weight=1)
        inspector.rowconfigure(1, weight=1)

        tk.Label(
            inspector,
            text="PACKET DETAILS",
            bg=c["panel"],
            fg=c["accent"],
            font=("TkDefaultFont", 9, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=(0, 6), pady=(0, 4))

        tk.Label(
            inspector,
            text="PAYLOAD PREVIEW (HEX & ASCII)",
            bg=c["panel"],
            fg=c["accent"],
            font=("TkDefaultFont", 9, "bold"),
        ).grid(row=0, column=1, sticky="w", padx=(6, 0), pady=(0, 4))

        self.details_text = tk.Text(
            inspector,
            height=9,
            bg=c["panel_alt"],
            fg=c["text"],
            relief="flat",
            highlightbackground=c["border"],
            highlightthickness=1,
            wrap="word",
            font=("TkFixedFont", 9),
            padx=8,
            pady=6,
            state="disabled",
        )
        self.details_text.grid(row=1, column=0, sticky="nsew", padx=(0, 6))

        self.payload_text = tk.Text(
            inspector,
            height=9,
            bg=c["panel_alt"],
            fg=c["text"],
            relief="flat",
            highlightbackground=c["border"],
            highlightthickness=1,
            wrap="none",
            font=("TkFixedFont", 9),
            padx=8,
            pady=6,
            state="disabled",
        )
        self.payload_text.grid(row=1, column=1, sticky="nsew", padx=(6, 0))

        paned.add(inspector, weight=2)

        self._set_inspector_text(
            "Select any captured packet row above to inspect Ethernet, IP, and TCP/UDP/ICMP headers.",
            "Payload bytes (hex + ASCII) will appear here when you select a packet.",
        )

        # ── Bottom Status Bar ──────────────────────────────────────────
        status_bar = tk.Frame(self.root, bg=c["panel"], padx=12, pady=5, highlightbackground=c["border"], highlightthickness=1)
        status_bar.pack(fill="x", padx=10, pady=(0, 10))

        tk.Label(
            status_bar,
            textvariable=self.status_text_var,
            bg=c["panel"],
            fg=c["muted"],
            font=("TkDefaultFont", 9),
        ).pack(side="left")

        priv_text = "Privileges: Admin/Root" if has_capture_privileges() else "Privileges: Standard User (raw capture may require root/CAP_NET_RAW)"
        tk.Label(
            status_bar,
            text=priv_text,
            bg=c["panel"],
            fg=c["green"] if has_capture_privileges() else c["amber"],
            font=("TkDefaultFont", 9),
        ).pack(side="right")

    def _populate_interfaces(self) -> None:
        """Discover OS network interfaces and populate the Interface dropdown."""
        ifaces = list_interfaces()
        values = ["All Interfaces"] + ifaces
        self.iface_combo["values"] = values
        self.interface_var.set("All Interfaces")

    def _set_badge(self, label: str, bg_color: str, fg_color: str = "#ffffff") -> None:
        """Update the colored status pill next to the PYKTO header."""
        self.status_badge.configure(text=label, bg=bg_color, fg=fg_color)

    def _update_button_states(self, running: bool) -> None:
        """Enable/disable Start, Stop, and dropdowns based on capture state."""
        c = self.COLORS
        if running:
            self.start_btn.configure(state="disabled", bg="#1e293b")
            self.stop_btn.configure(state="normal", bg=c["red_dark"])
            self.iface_combo.configure(state="disabled")
            self.engine_combo.configure(state="disabled")
        else:
            self.start_btn.configure(state="normal", bg=c["green_dark"])
            self.stop_btn.configure(state="disabled", bg="#1e293b")
            self.iface_combo.configure(state="readonly")
            self.engine_combo.configure(state="readonly")

    def start_capture(self) -> None:
        """Start real-time packet capture on the selected interface and engine."""
        if self.engine.is_running:
            return

        selected_iface = self.interface_var.get()
        iface = None if selected_iface == "All Interfaces" else selected_iface
        engine_mode = self.engine_var.get().lower()

        try:
            used_engine = self.engine.start(interface=iface, engine_mode=engine_mode)
        except PermissionError as exc:
            # Raw sockets require root or CAP_NET_RAW; guide the user cleanly.
            self._set_badge("● PERMISSION NEEDED", self.COLORS["red_dark"])
            self.status_text_var.set(f"Permission denied starting capture: {exc}")
            self._show_permission_help()
            return
        except Exception as exc:
            self._set_badge("● ERROR", self.COLORS["red_dark"])
            self.status_text_var.set(f"Failed to start capture: {exc}")
            messagebox.showerror("Capture Error", str(exc))
            return

        self._last_rate_ts = time.monotonic()
        self._rate_packets = 0
        self._rate_bytes = 0
        self._update_button_states(running=True)
        self._set_badge("● CAPTURING", self.COLORS["green_dark"])
        self.status_text_var.set(
            f"Capturing live on [{selected_iface}] using {used_engine} engine."
        )

    def stop_capture(self) -> None:
        """Stop live capture cleanly while keeping captured rows and stats visible."""
        if not self.engine.is_running:
            return
        self.engine.stop()
        self._update_button_states(running=False)
        self._set_badge("● STOPPED", "#b45309")
        self.status_text_var.set(f"Capture stopped. {self.total_packets:,} packets captured.")

    def reset_capture(self) -> None:
        """Clear queued packets, table rows, inspector panes, and all counters."""
        # Drain any packets still waiting in the thread-safe queue before resetting.
        while True:
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break

        self.engine.reset_counter()
        self.buffer.clear()
        self.row_records.clear()
        self.visible_iids.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self._rate_packets = 0
        self._rate_bytes = 0
        self._last_rate_ts = time.monotonic()

        self._refresh_stats_display(pkt_rate=0.0)
        self.buffer_info_var.set(f"Showing 0 / {MAX_VISIBLE_ROWS} max rows")
        self._set_inspector_text(
            "Capture reset. Select a packet row once traffic arrives.",
            "(no packet selected)",
        )
        if not self.engine.is_running:
            self._set_badge("● IDLE", "#334155")
            self.status_text_var.set("Reset complete. Click Start to capture live traffic.")
        else:
            self.status_text_var.set("Counters and view reset. Still capturing live...")

    def _on_engine_error(self, message: str, is_permission: bool) -> None:
        """Marshal background capture thread errors onto the main Tkinter thread."""
        self.root.after(0, lambda: self._handle_async_error(message, is_permission))

    def _handle_async_error(self, message: str, is_permission: bool) -> None:
        """Handle capture errors safely inside the UI thread."""
        self._update_button_states(running=False)
        self._set_badge("● ERROR", self.COLORS["red_dark"])
        self.status_text_var.set(message)
        if is_permission:
            self._show_permission_help()
        else:
            messagebox.showerror("Capture Error", message)

    def _show_permission_help(self) -> None:
        """Explain how to run with capture privileges (or relaunch via pkexec on Linux)."""
        python_exe = sys.executable
        script_path = Path(__file__).resolve()
        cmd = f"sudo -E {python_exe} {script_path}"
        msg = (
            "Live raw packet capture requires elevated network privileges on this OS.\n\n"
            "Run this app from a terminal with:\n"
            f"  {cmd}\n\n"
            "Or grant capture capabilities once to your Python binary:\n"
            f"  sudo setcap cap_net_raw,cap_net_admin=eip {Path(python_exe).resolve()}"
        )
        if platform.system() == "Linux" and shutil.which("pkexec") and os.environ.get("DISPLAY"):
            relaunch = messagebox.askyesno(
                "Capture Privileges Required",
                msg + "\n\nWould you like to relaunch now with admin privileges (pkexec)?",
            )
            if relaunch:
                self._relaunch_with_pkexec(python_exe, str(script_path))
                return
        else:
            messagebox.showwarning("Capture Privileges Required", msg)

    def _relaunch_with_pkexec(self, python_exe: str, script_path: str) -> None:
        """Relaunch Pykto via PolicyKit while preserving X11 display environment vars."""
        env_args = [f"DISPLAY={os.environ.get('DISPLAY', ':0')}"]
        if os.environ.get("XAUTHORITY"):
            env_args.append(f"XAUTHORITY={os.environ['XAUTHORITY']}")
        try:
            subprocess.Popen(["pkexec", "env", *env_args, python_exe, script_path])
            self._on_close()
        except Exception as exc:
            messagebox.showerror("Relaunch Failed", f"Could not relaunch with pkexec:\n{exc}")

    def _matches_filter(self, rec: PacketRecord) -> bool:
        """Return True if a packet satisfies the active Loopback, Protocol, and Search filters."""
        if self.hide_loopback_var.get() and rec.is_loopback:
            return False

        proto_filter = self.proto_filter_var.get()
        if proto_filter != "ALL" and rec.protocol != proto_filter:
            return False

        query = self.search_var.get().strip().lower()
        if query:
            haystack = (
                f"{rec.protocol} {rec.src_display} {rec.dst_display} {rec.info}"
            ).lower()
            if query not in haystack:
                return False
        return True

    def _insert_record_row(self, rec: PacketRecord) -> None:
        """Insert one packet row into the Treeview and prune oldest rows beyond MAX_VISIBLE_ROWS."""
        self._ui_seq += 1
        iid = f"r{self._ui_seq}"
        self.tree.insert(
            "",
            "end",
            iid=iid,
            values=(
                rec.index,
                rec.timestamp,
                rec.protocol,
                rec.src_display,
                rec.dst_display,
                rec.length,
                rec.info,
            ),
            tags=(rec.protocol,),
        )
        self.row_records[iid] = rec
        self.visible_iids.append(iid)

        # Keep the live table strictly bounded so it never bloats to thousands of rows.
        while len(self.visible_iids) > MAX_VISIBLE_ROWS:
            oldest = self.visible_iids.popleft()
            self.row_records.pop(oldest, None)
            if self.tree.exists(oldest):
                self.tree.delete(oldest)

    def _rebuild_table(self) -> None:
        """Re-render the visible table from the in-memory ring buffer when filters change."""
        self.row_records.clear()
        self.visible_iids.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        matching = [rec for rec in self.buffer if self._matches_filter(rec)]
        for rec in matching[-MAX_VISIBLE_ROWS:]:
            self._insert_record_row(rec)

        self._update_buffer_label()
        if self.autoscroll_var.get() and self.visible_iids:
            self.tree.see(self.visible_iids[-1])

    def _update_buffer_label(self) -> None:
        """Refresh the 'Showing X / 300 max rows' indicator."""
        shown = len(self.visible_iids)
        self.buffer_info_var.set(f"Showing {shown} / {MAX_VISIBLE_ROWS} max rows")

    def _refresh_stats_display(self, pkt_rate: Optional[float] = None) -> None:
        """Update the top summary stat cards with current packet and byte totals."""
        self.stat_labels["total"].configure(text=f"{self.total_packets:,}")
        for key in ("TCP", "UDP", "ICMP", "OTHER"):
            self.stat_labels[key].configure(text=f"{self.proto_counts[key]:,}")
        if pkt_rate is not None:
            self.stat_labels["volume"].configure(
                text=f"{format_bytes(self.total_bytes)}  ({pkt_rate:.1f} pkt/s)"
            )

    def _poll_loop(self) -> None:
        """
        Periodic UI timer (every 100 ms) that drains queued packets in batches.

        Batching up to 300 packets per tick keeps the GUI responsive under heavy
        traffic while updating counters, visible rows, and the 1-second packet rate.
        """
        batch: list[PacketRecord] = []
        for _ in range(300):
            try:
                batch.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break

        if batch:
            inserted = False
            for rec in batch:
                self.total_packets += 1
                self.total_bytes += rec.length
                self._rate_packets += 1
                self._rate_bytes += rec.length
                bucket = rec.protocol if rec.protocol in self.proto_counts else "OTHER"
                self.proto_counts[bucket] += 1

                self.buffer.append(rec)
                if self._matches_filter(rec):
                    self._insert_record_row(rec)
                    inserted = True

            if inserted:
                self._update_buffer_label()
                if self.autoscroll_var.get() and self.visible_iids:
                    self.tree.see(self.visible_iids[-1])

        now = time.monotonic()
        elapsed = now - self._last_rate_ts
        if elapsed >= 1.0:
            pkt_rate = self._rate_packets / elapsed
            self._rate_packets = 0
            self._rate_bytes = 0
            self._last_rate_ts = now
            self._refresh_stats_display(pkt_rate=pkt_rate)
        elif batch:
            self._refresh_stats_display(pkt_rate=None)

        self.root.after(POLL_INTERVAL_MS, self._poll_loop)

    def _on_packet_selected(self, _event=None) -> None:
        """Populate Packet Details and Hex/ASCII Payload when the user clicks a row."""
        selected = self.tree.selection()
        if not selected:
            return
        rec = self.row_records.get(selected[0])
        if rec is None:
            return
        details = "\n".join(rec.detail_lines)
        payload = format_payload_hexdump(rec.payload, max_bytes=512)
        self._set_inspector_text(details, payload)

    def _set_inspector_text(self, details: str, payload: str) -> None:
        """Safely replace text inside the read-only Packet Inspector widgets."""
        for widget, content in ((self.details_text, details), (self.payload_text, payload)):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", content)
            widget.configure(state="disabled")

    def _on_close(self) -> None:
        """Ensure background capture stops cleanly before closing the window."""
        self.engine.stop()
        self.root.destroy()


def main() -> None:
    """Application entry point: create the Tkinter root window and start the event loop."""
    root = tk.Tk()
    SnifxApp(root)
    root.mainloop()


if __name__ == "__main__":
    ensure_environment(Path(__file__))
    main()
