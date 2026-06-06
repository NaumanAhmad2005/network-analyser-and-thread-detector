#!/usr/bin/env python3
"""
main_controller.py — IS Lab Project: Unified TUI Dashboard Controller
======================================================================
Single-entry-point menu-driven controller for all project modules.
Uses the `rich` library for a polished, full-screen terminal UI.

Run:   python3 main_controller.py
"""

import os
import sys
import time
import json
import socket
import threading
import subprocess
import shutil
import textwrap
from datetime import datetime
from pathlib import Path
from collections import deque

# ── Rich imports ─────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich import box
except ImportError:
    print("[ERROR] 'rich' library not installed.")
    print("        Run:  pip3 install rich")
    sys.exit(1)

# ── Project paths ─────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
MOD_A      = BASE_DIR / "module_a_traffic"
MOD_B      = BASE_DIR / "module_b_detector"
POLICY     = MOD_B / "policy.json"
CERT_FILE  = MOD_A / "server.crt"
KEY_FILE   = MOD_A / "server.key"

console = Console()

# ── Global state ──────────────────────────────────────────────────────────────
_state = {
    "http_server":   None,   # subprocess.Popen or None
    "https_server":  None,
    "sniffer":       None,
    "last_scan":     [],     # list of finding dicts from last auditor run
    "log_lines":     deque(maxlen=200),  # rolling log
    "cert_ready":    CERT_FILE.exists() and KEY_FILE.exists(),
}

HTTP_PORT  = 8000
HTTPS_PORT = 8443


# =============================================================================
# Logging helpers
# =============================================================================

def log(msg: str, tag: str = "INFO", color: str = "white"):
    ts  = datetime.now().strftime("%H:%M:%S")
    line = f"[dim]{ts}[/dim]  [{color}][{tag}][/{color}]  {msg}"
    _state["log_lines"].append(line)
    # Also write to console directly when not inside a Live block
    # (callers inside Live blocks should not call console.print)


def _drain_proc_output(proc: subprocess.Popen, tag: str, color: str):
    """Background thread: read subprocess stdout/stderr and push to log."""
    for raw in proc.stdout:
        line = raw.rstrip()
        if line:
            log(line, tag, color)
    proc.wait()
    log(f"Process exited (code {proc.returncode})", tag, color)


# =============================================================================
# Visual components
# =============================================================================

BANNER = r"""
  ███╗   ██╗ ██╗ ████████╗ ██████╗  ███████╗
  ████╗  ██║ ██║ ╚══██╔══╝ ██╔══██╗ ██╔════╝
  ██╔██╗ ██║ ██║    ██║    ██║  ██║ ███████╗
  ██║╚██╗██║ ██║    ██║    ██║  ██║ ╚════██║
  ██║ ╚████║ ██║    ██║    ██████╔╝ ███████║
  ╚═╝  ╚═══╝ ╚═╝    ╚═╝    ╚═════╝  ╚══════╝
"""

SUBTITLE = "Network Inspection & Threat Detection System"


def render_banner() -> Panel:
    t = Text()
    t.append(BANNER, style="bold cyan")
    t.append(f"\n  {SUBTITLE}\n", style="bold white")
    t.append("  NITDS Final Project · Information Security · 4th Semester\n",
             style="dim white")
    return Panel(Align.center(t), border_style="cyan", box=box.DOUBLE, expand=False, width=100)


def render_status_bar() -> Table:
    """Small status table shown at the top of each screen."""
    g = Table.grid(expand=True, padding=(0, 2))
    g.add_column(justify="left")
    g.add_column(justify="center")
    g.add_column(justify="right")

    http_s  = "[green]● RUNNING[/green]" if _state["http_server"]  and _state["http_server"].poll()  is None else "[red]○ STOPPED[/red]"
    https_s = "[green]● RUNNING[/green]" if _state["https_server"] and _state["https_server"].poll() is None else "[red]○ STOPPED[/red]"
    sniff_s = "[green]● ACTIVE[/green]"  if _state["sniffer"]      and _state["sniffer"].poll()      is None else "[dim]○ IDLE[/dim]"
    cert_s  = "[green]✔ READY[/green]"   if _state["cert_ready"]   else "[yellow]✘ NOT GENERATED[/yellow]"

    g.add_row(
        f"HTTP :8000 {http_s}   HTTPS :8443 {https_s}",
        f"[bold cyan]Sniffer {sniff_s}[/bold cyan]",
        f"TLS Cert {cert_s}",
    )
    return g


def render_log_panel(n: int = 12) -> Panel:
    """Last n log lines in a scrolling panel."""
    lines = list(_state["log_lines"])[-n:]
    body  = "\n".join(lines) if lines else "[dim]No activity yet.[/dim]"
    return Panel(body, title="[bold]Activity Log[/bold]",
                 border_style="dim white", height=n + 2, expand=False, width=100)


# =============================================================================
# Main Menu
# =============================================================================

MENU_ITEMS = [
    ("1", "Module A — TC-01",   "Start Insecure HTTP Server  (port 8000)",   "red"),
    ("2", "Module A — TC-01",   "Stop  Insecure HTTP Server",                 "red"),
    ("3", "Module A — TC-02",   "Generate TLS Certificates (OpenSSL)",        "yellow"),
    ("4", "Module A — TC-02",   "Start Secure  HTTPS Server (port 8443)",    "green"),
    ("5", "Module A — TC-02",   "Stop  Secure  HTTPS Server",                 "green"),
    ("6", "Module A — Sniffer", "Run Sniffer — HTTP mode  (capture creds)",   "magenta"),
    ("7", "Module A — Sniffer", "Run Sniffer — HTTPS mode (verify TLS)",      "magenta"),
    ("8", "Module A — Sniffer", "Stop Sniffer",                                "magenta"),
    ("9", "Module B — TC-03",   "Run Network Auditor  (subnet scan)",         "cyan"),
    ("A", "Module B — TC-04",   "Run Demo: Flag Rogue Service (port 23)",     "bold red"),
    ("V", "View",               "Show Last Audit Results",                    "blue"),
    ("L", "Log",                "View Live Activity Log",                     "white"),
    ("Q", "Quit",               "Exit Dashboard",                             "dim"),
]


def draw_main_menu():
    """Render and return the main menu table."""
    table = Table(
        title="[bold cyan]MAIN MENU — Select an Option[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        expand=False,
        width=100,
    )
    table.add_column("Key",    width=5,  justify="center", style="bold yellow")
    table.add_column("Module", width=22, style="cyan")
    table.add_column("Action", width=45)

    for key, module, action, color in MENU_ITEMS:
        table.add_row(f"[{color}]{key}[/{color}]", f"[dim]{module}[/dim]", action)

    return table


# =============================================================================
# Module A actions
# =============================================================================

def start_http_server():
    """TC-01: Launch insecure HTTP server as a background process."""
    if _state["http_server"] and _state["http_server"].poll() is None:
        log("HTTP server is already running.", "WARN", "yellow")
        return

    script = str(MOD_A / "insecure_server.py")
    proc = subprocess.Popen(
        [sys.executable, "-u", script],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    _state["http_server"] = proc
    threading.Thread(target=_drain_proc_output, args=(proc, "HTTP", "red"),
                     daemon=True).start()
    log(f"Insecure HTTP server started (PID {proc.pid}) → http://localhost:{HTTP_PORT}", "HTTP", "red")
    log("Open browser at http://localhost:8000  OR run:  curl -d 'username=alice&password=secret123' http://localhost:8000/login", "HINT", "yellow")


def stop_http_server():
    proc = _state["http_server"]
    if proc and proc.poll() is None:
        proc.terminate()
        _state["http_server"] = None
        log("HTTP server stopped.", "HTTP", "red")
    else:
        log("HTTP server is not running.", "WARN", "yellow")


def generate_certs():
    """Run generate_certs.sh and capture output."""
    script = str(MOD_A / "generate_certs.sh")
    if not shutil.which("openssl"):
        log("openssl not found. Install: sudo apt-get install openssl", "ERROR", "red")
        return

    console.print("\n[bold yellow]  Generating TLS certificate via OpenSSL...[/bold yellow]\n")
    result = subprocess.run(
        ["bash", script],
        capture_output=True, text=True,
        cwd=str(MOD_A)
    )
    for line in (result.stdout + result.stderr).splitlines():
        log(line, "CERT", "yellow")

    _state["cert_ready"] = CERT_FILE.exists() and KEY_FILE.exists()
    if _state["cert_ready"]:
        log("✔ server.crt and server.key generated successfully!", "CERT", "green")
    else:
        log("✘ Certificate generation failed — check log above.", "ERROR", "red")


def start_https_server():
    """TC-02: Launch TLS-secured HTTPS server."""
    if not _state["cert_ready"]:
        log("TLS certificates not found! Run option [3] first.", "ERROR", "red")
        return

    if _state["https_server"] and _state["https_server"].poll() is None:
        log("HTTPS server is already running.", "WARN", "yellow")
        return

    script = str(MOD_A / "secure_server.py")
    proc = subprocess.Popen(
        [sys.executable, "-u", script],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    _state["https_server"] = proc
    threading.Thread(target=_drain_proc_output, args=(proc, "HTTPS", "green"),
                     daemon=True).start()
    log(f"Secure HTTPS server started (PID {proc.pid}) → https://localhost:{HTTPS_PORT}", "HTTPS", "green")
    log("Open browser at https://localhost:8443  (accept self-signed cert warning)  OR:", "HINT", "yellow")
    log("  curl -k -d 'username=alice&password=secret123' https://localhost:8443/login", "HINT", "yellow")


def stop_https_server():
    proc = _state["https_server"]
    if proc and proc.poll() is None:
        proc.terminate()
        _state["https_server"] = None
        log("HTTPS server stopped.", "HTTPS", "green")
    else:
        log("HTTPS server is not running.", "WARN", "yellow")


def _check_root_for_sniff() -> bool:
    if os.geteuid() != 0:
        log("Packet capture requires root. Relaunch:  sudo python3 main_controller.py", "WARN", "yellow")
        log("Attempting anyway — may fail on restricted systems...", "INFO", "dim")
    return True


def start_sniffer(mode: str):
    """Launch sniffer_agent.py in the specified mode (http/https)."""
    if _state["sniffer"] and _state["sniffer"].poll() is None:
        log("Sniffer is already active. Stop it first (option 8).", "WARN", "yellow")
        return

    _check_root_for_sniff()

    script = str(MOD_A / "sniffer_agent.py")
    iface  = "lo"   # loopback — safe for local demo

    # Build base command — no --count so sniffer runs until stopped manually
    py_cmd = [sys.executable, "-u", script, "--mode", mode, "--interface", iface]

    # Prepend sudo if we are not already root, so tshark can open the interface
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + py_cmd   # -n = non-interactive (no password prompt)
        log("Launching sniffer via 'sudo -n' (passwordless sudo required for tshark).", "SNIFF", "yellow")
    else:
        cmd = py_cmd

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    _state["sniffer"] = proc

    color = "magenta" if mode == "http" else "cyan"
    threading.Thread(target=_drain_proc_output, args=(proc, "SNIFF", color),
                     daemon=True).start()

    if mode == "http":
        log(f"Sniffer ACTIVE — HTTP mode on 'lo', port {HTTP_PORT}. Press [8] to stop.", "SNIFF", "magenta")
        log("Submit the login form at http://localhost:8000 to capture credentials.", "HINT", "yellow")
    else:
        log(f"Sniffer ACTIVE — HTTPS mode on 'lo', port {HTTPS_PORT}. Press [8] to stop.", "SNIFF", "cyan")
        log("Access https://localhost:8443 to trigger the TLS handshake.", "HINT", "yellow")


def stop_sniffer():
    proc = _state["sniffer"]
    if proc and proc.poll() is None:
        proc.terminate()
        _state["sniffer"] = None
        log("Sniffer stopped.", "SNIFF", "magenta")
    else:
        log("Sniffer is not running.", "WARN", "yellow")


# =============================================================================
# Module B actions
# =============================================================================

def run_auditor_interactive():
    """Prompt for subnet and run the network auditor with live output."""
    console.print(Panel(
        "[bold cyan]MODULE B — Network Auditor[/bold cyan]\n\n"
        "Enter the target subnet or IP to scan.\n\n"
        "[yellow]Examples:[/yellow]\n"
        "  127.0.0.1          ← localhost only (safe, no VM needed)\n"
        "  192.168.56.0/24    ← VirtualBox Host-Only network\n"
        "  192.168.56.101     ← Single target VM",
        border_style="cyan", title="[bold]Subnet Configuration[/bold]"
    ))

    subnet = Prompt.ask(
        "\n  [cyan]Target subnet or IP[/cyan]",
        default="127.0.0.1"
    )
    skip   = Prompt.ask(
        "  [cyan]Skip host-discovery ping scan?[/cyan] (yes for single IP / localhost)",
        choices=["yes", "no"], default="yes"
    )

    script = str(MOD_B / "network_auditor.py")
    cmd    = [sys.executable, script, "--subnet", subnet]
    if skip == "yes":
        cmd.append("--skip-discovery")

    log(f"Starting auditor scan on {subnet} ...", "AUDIT", "cyan")

    console.print(f"\n[bold cyan]  Running: {' '.join(cmd)}[/bold cyan]\n")
    console.print(Rule(style="cyan"))

    # Run synchronously so output streams live to the terminal
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=None,   # inherit — output goes directly to terminal
            stderr=None,
            text=True
        )
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        console.print("\n[yellow]  Scan interrupted by user.[/yellow]")

    log(f"Auditor scan on {subnet} finished.", "AUDIT", "cyan")
    _press_enter()


def run_rogue_demo():
    """TC-04 demo: start a netcat listener on port 23, run auditor, then clean up."""
    console.print(Panel(
        "[bold red]TC-04 — Rogue Service Demo[/bold red]\n\n"
        "This demo will:\n"
        "  1. Open a listener on [bold]port 23 (Telnet)[/bold] using netcat\n"
        "  2. Run the auditor against localhost\n"
        "  3. Show the CRITICAL risk flag\n"
        "  4. Kill the rogue listener\n\n"
        "[yellow]Requires:[/yellow] ncat/netcat installed  (sudo apt-get install ncat)",
        border_style="red", title="[bold red]Rogue Service Flag Demo[/bold red]"
    ))

    nc_bin = shutil.which("ncat") or shutil.which("nc") or shutil.which("netcat")
    if not nc_bin:
        log("ncat/nc not found. Install: sudo apt-get install ncat", "ERROR", "red")
        console.print("[red]  Install ncat first: sudo apt-get install ncat[/red]")
        _press_enter()
        return

    # Start rogue listener on port 23
    console.print("\n[bold red]  → Starting rogue Telnet listener on port 23...[/bold red]")
    rogue_proc = None
    try:
        # Build command: use sudo -n so it doesn't hang on a hidden password prompt
        cmd_prefix = ["sudo", "-n"] if os.geteuid() != 0 else []
        
        # We pipe a fake banner into nc so nmap's -sV version scan finishes instantly
        # rather than hanging for 90 seconds waiting for data.
        sh_cmd = f"echo 'Welcome to Rogue Telnet' | {nc_bin} -lvp 23"
        rogue_cmd = cmd_prefix + ["sh", "-c", sh_cmd]

        rogue_proc = subprocess.Popen(
            rogue_cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        log(f"Rogue listener started on port 23 (PID {rogue_proc.pid})", "ROGUE", "red")
        time.sleep(1)  # Let listener bind
    except Exception as e:
        log(f"Could not start rogue listener: {e}", "ERROR", "red")
        console.print(f"[red]  Failed to start rogue listener: {e}[/red]")
        _press_enter()
        return

    # Now run auditor against localhost
    console.print("\n[bold cyan]  → Running auditor to detect rogue service...[/bold cyan]\n")
    console.print(Rule(style="red"))

    script = str(MOD_B / "network_auditor.py")
    try:
        proc = subprocess.Popen(
            [sys.executable, script, "--subnet", "127.0.0.1", "--skip-discovery"],
            text=True
        )
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        # Kill the rogue listener
        if rogue_proc and rogue_proc.poll() is None:
            try:
                subprocess.run(["sudo", "kill", str(rogue_proc.pid)],
                               capture_output=True)
            except Exception:
                rogue_proc.terminate()
            log("Rogue listener on port 23 terminated.", "ROGUE", "red")
            console.print("\n[green]  ✔ Rogue listener cleaned up.[/green]")

    log("TC-04 demo complete.", "AUDIT", "cyan")
    _press_enter()


# =============================================================================
# Result viewer
# =============================================================================

def show_audit_results():
    """Display the last audit findings in a rich table."""
    console.clear()
    console.print(render_banner())

    log_lines = list(_state["log_lines"])
    audit_lines = [l for l in log_lines if "AUDIT" in l or "ROGUE" in l or "SAFE" in l]

    if not audit_lines:
        console.print(Panel(
            "[yellow]No audit results yet. Run option [9] or [A] first.[/yellow]",
            border_style="yellow", title="[bold]Last Audit Results[/bold]"
        ))
    else:
        # Parse policy for a quick reference table
        try:
            policy = json.loads(POLICY.read_text())
            rogue  = policy.get("rogue_ports", {})
            auth   = policy.get("authorized_ports", {})

            table = Table(
                title="[bold]Current Security Policy Reference[/bold]",
                box=box.ROUNDED, border_style="dim",
                show_header=True, header_style="bold cyan",
                expand=True
            )
            table.add_column("Port", width=7,  justify="center")
            table.add_column("Service", width=12)
            table.add_column("Status", width=12, justify="center")
            table.add_column("Risk",   width=10, justify="center")
            table.add_column("Notes",  ratio=1)

            for port, info in auth.items():
                table.add_row(port, info["service"],
                              "[green]AUTHORIZED[/green]", "[green]NONE[/green]",
                              info.get("note", ""))

            for port, info in rogue.items():
                risk_color = {"CRITICAL": "red", "HIGH": "dark_orange",
                              "MEDIUM": "yellow"}.get(info["risk"], "white")
                table.add_row(
                    port, info["service"],
                    "[red]ROGUE[/red]",
                    f"[{risk_color}]{info['risk']}[/{risk_color}]",
                    info.get("reason", "")
                )

            console.print(table)
        except Exception as e:
            console.print(f"[red]Could not load policy: {e}[/red]")

    console.print(render_log_panel(n=20))
    _press_enter()


def show_live_log():
    """Continuously refresh the activity log until the user presses Ctrl+C."""
    console.print("\n[dim]Press Ctrl+C to return to the main menu.[/dim]\n")
    try:
        with Live(refresh_per_second=4, console=console) as live:
            while True:
                live.update(render_log_panel(n=30))
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass




# =============================================================================
# Utility
# =============================================================================

def _press_enter():
    console.print("\n  [dim]Press Enter to return to the main menu...[/dim]")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


def _cleanup():
    """Gracefully kill any running subprocesses on exit."""
    for key in ("http_server", "https_server", "sniffer"):
        proc = _state[key]
        if proc and proc.poll() is None:
            proc.terminate()


def _check_tools():
    """Warn about missing system tools at startup."""
    tools = {"python3": "python3", "nmap": "nmap",
             "tshark": "tshark", "openssl": "openssl"}
    missing = [name for name, cmd in tools.items() if not shutil.which(cmd)]
    if missing:
        log(f"Missing tools: {', '.join(missing)} — some features may fail.", "WARN", "yellow")
    else:
        log("All required system tools detected (nmap, tshark, openssl).", "INIT", "green")


# =============================================================================
# Main loop
# =============================================================================

def main():
    _check_tools()
    log("NITDS Dashboard started.", "INIT", "cyan")

    DISPATCH = {
        "1": start_http_server,
        "2": stop_http_server,
        "3": generate_certs,
        "4": start_https_server,
        "5": stop_https_server,
        "6": lambda: start_sniffer("http"),
        "7": lambda: start_sniffer("https"),
        "8": stop_sniffer,
        "9": run_auditor_interactive,
        "a": run_rogue_demo,
        "v": show_audit_results,
        "l": show_live_log,
        "q": None,
    }

    while True:
        console.clear()
        console.print(Align.center(render_banner()))
        console.print(Align.center(Panel(render_status_bar(), border_style="dim", height=3, expand=False, width=100)))
        console.print()
        console.print(Align.center(draw_main_menu()))
        console.print()
        console.print(Align.center(render_log_panel(n=6)))
        console.print()

        try:
            choice = Prompt.ask(
                "  [bold cyan]Enter option[/bold cyan]",
                default="Q"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "q"

        if choice == "q":
            _cleanup()
            console.print("\n[bold cyan]  Goodbye! All processes terminated.[/bold cyan]\n")
            break

        action = DISPATCH.get(choice)
        if action is None:
            log(f"Unknown option '{choice}'.", "WARN", "yellow")
            time.sleep(0.5)
            continue

        # Actions that take over the full screen (run, demo) do their own clear.
        # For quick background actions, show a brief feedback pause.
        full_screen_actions = {run_auditor_interactive, run_rogue_demo,
                                show_audit_results, show_live_log}

        if action not in full_screen_actions:
            console.print()
            action()
            time.sleep(0.6)   # Let log lines accumulate before redraw
        else:
            console.clear()
            console.print(render_banner())
            action()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _cleanup()
        console.print("\n[bold cyan]  Exiting...[/bold cyan]\n")
