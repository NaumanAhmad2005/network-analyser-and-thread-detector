#!/usr/bin/env python3
"""
sniffer_agent.py — Module A: Automated Packet Sniffer & Credential Parser
==========================================================================
SECURITY CONCEPT: Lack of Confidentiality (HTTP) vs. Confidentiality (HTTPS)

This script demonstrates two modes:
  MODE 1 (HTTP / TC-01): Captures plaintext POST requests on Port 8000 and
          extracts username/password credentials directly from the TCP stream.
  MODE 2 (HTTPS / TC-02): Captures traffic on Port 8443 and shows that
          TLS handshake packets are present but payload bytes are unreadable.

The script uses two capture strategies:
  • PRIMARY:   pyshark (Python wrapper around tshark/Wireshark)
  • FALLBACK:  Raw subprocess call to tshark if pyshark is unavailable

IMPORTANT: Packet capture requires root or CAP_NET_RAW capability.
           Run with:  sudo python3 sniffer_agent.py
Test Cases: TC-01 (HTTP mode), TC-02 (HTTPS mode)
"""

import subprocess
import sys
import os
import re
import time
import argparse
import urllib.parse

# ---- ANSI colour codes for terminal output --------------------------------
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

HTTP_PORT  = 8000
HTTPS_PORT = 8443


# ===========================================================================
# Strategy A: pyshark-based capture (preferred — rich dissection)
# ===========================================================================

def sniff_http_pyshark(interface: str, packet_count: int):
    """
    Use pyshark to capture packets on the HTTP port and extract plaintext
    credentials from POST request bodies.

    pyshark gives access to Wireshark's full protocol dissector tree,
    so we can query fields like http.file_data and tcp.payload directly.
    """
    try:
        import pyshark
    except ImportError:
        return False   # Signal to caller: fall back to tshark

    print(f"\n  {CYAN}[pyshark] Starting HTTP capture on interface '{interface}' port {HTTP_PORT}...{RESET}")
    print(f"  {YELLOW}Submit the login form now (http://localhost:{HTTP_PORT}){RESET}\n")

    # BPF filter: capture only TCP traffic on the target port
    capture = pyshark.LiveCapture(
        interface=interface,
        bpf_filter=f"tcp port {HTTP_PORT}"
    )

    credentials_found = False
    captured = 0

    try:
        for pkt in capture.sniff_continuously(packet_count=packet_count):
            captured += 1
            # Check if this packet has HTTP layer data
            if hasattr(pkt, "http"):
                try:
                    # http.file_data contains the POST body as decoded ASCII
                    file_data = getattr(pkt.http, "file_data", None)
                    if file_data and "username=" in file_data:
                        params = urllib.parse.parse_qs(file_data)
                        username = params.get("username", ["?"])[0]
                        password = params.get("password", ["?"])[0]

                        print("  " + "=" * 56)
                        print(f"  {RED}{BOLD}[!!] PLAINTEXT CREDENTIALS EXTRACTED FROM WIRE{RESET}")
                        print(f"  {RED}  Packet #{captured}{RESET}")
                        print(f"  {RED}  Username : {BOLD}{username}{RESET}")
                        print(f"  {RED}  Password : {BOLD}{password}{RESET}")
                        print(f"  {RED}  Source   : {pkt.ip.src}:{pkt[pkt.transport_layer].srcport}{RESET}")
                        print(f"  {RED}  Dest     : {pkt.ip.dst}:{pkt[pkt.transport_layer].dstport}{RESET}")
                        print("  " + "=" * 56 + "\n")
                        credentials_found = True
                except AttributeError:
                    pass   # Packet missing expected fields — skip gracefully

    except KeyboardInterrupt:
        pass
    finally:
        capture.close()

    if not credentials_found:
        print(f"  {YELLOW}[INFO] No credentials captured in {captured} packets.{RESET}")
        print(f"         Make sure insecure_server.py is running and you submitted the form.\n")

    return True   # Indicate pyshark strategy was attempted


def sniff_https_pyshark(interface: str, packet_count: int):
    """
    Capture TLS traffic on HTTPS port and display handshake events.
    Demonstrate that payload remains encrypted and unreadable.
    """
    try:
        import pyshark
    except ImportError:
        return False

    print(f"\n  {CYAN}[pyshark] Capturing HTTPS traffic on '{interface}' port {HTTPS_PORT}...{RESET}")
    print(f"  {YELLOW}Connect to https://localhost:{HTTPS_PORT} in your browser now.{RESET}\n")

    capture = pyshark.LiveCapture(
        interface=interface,
        bpf_filter=f"tcp port {HTTPS_PORT}"
    )

    tls_records = []
    captured = 0

    try:
        for pkt in capture.sniff_continuously(packet_count=packet_count):
            captured += 1
            # TLS layer is exposed by Wireshark's dissector
            if hasattr(pkt, "tls"):
                try:
                    handshake_type = getattr(pkt.tls, "handshake_type", None)
                    record_type    = getattr(pkt.tls, "record_content_type", None)

                    type_name = {
                        "1":  "CLIENT HELLO",
                        "2":  "SERVER HELLO",
                        "11": "CERTIFICATE",
                        "12": "SERVER KEY EXCHANGE",
                        "14": "SERVER HELLO DONE",
                        "16": "CLIENT KEY EXCHANGE",
                        "20": "FINISHED",
                    }.get(str(handshake_type), f"type={handshake_type}")

                    record_name = {
                        "20": "Change Cipher Spec",
                        "21": "Alert",
                        "22": "Handshake",
                        "23": "Application Data (ENCRYPTED)",
                    }.get(str(record_type), f"content_type={record_type}")

                    print(f"  {GREEN}[TLS] Pkt #{captured:>3}  Record: {record_name:35s}  "
                          f"Handshake: {type_name}{RESET}")

                    if record_type == "23":
                        print(f"  {GREEN}       └─ Application data is ENCRYPTED — credentials NOT readable!{RESET}")

                    tls_records.append(record_name)
                except AttributeError:
                    pass
            elif captured <= 5:
                # Show raw TCP in early non-TLS packets (SYN/SYN-ACK)
                print(f"  {CYAN}[TCP] Pkt #{captured:>3}  (TCP connection setup){RESET}")

    except KeyboardInterrupt:
        pass
    finally:
        capture.close()

    print(f"\n  {BOLD}{'=' * 56}{RESET}")
    print(f"  {GREEN}{BOLD}[TC-02 RESULT] TLS Verification Summary{RESET}")
    print(f"  {GREEN}  Total packets captured   : {captured}{RESET}")
    print(f"  {GREEN}  TLS records observed     : {len(tls_records)}{RESET}")
    print(f"  {GREEN}  Readable credentials     : NONE (fully encrypted){RESET}")
    print(f"  {BOLD}{'=' * 56}{RESET}\n")

    return True


# ===========================================================================
# Strategy B: tshark subprocess fallback
# ===========================================================================

def _check_tshark():
    """Verify tshark is installed and accessible."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def sniff_http_tshark(interface: str, packet_count: int):
    """
    Fallback: use tshark subprocess to capture and display HTTP POST data.
    Extracts username/password from the http.file_data field.
    """
    if not _check_tshark():
        print(f"  {RED}[ERROR] Neither pyshark nor tshark found.{RESET}")
        print("          Install: sudo apt-get install tshark")
        sys.exit(1)

    print(f"\n  {CYAN}[tshark] Capturing HTTP POST on '{interface}' port {HTTP_PORT}...{RESET}")
    print(f"  {YELLOW}Submit the login form now (http://localhost:{HTTP_PORT}){RESET}\n")

    cmd = [
        "tshark",
        "-i", interface,
        "-f", f"tcp port {HTTP_PORT}",
        "-c", str(packet_count),
        "-Y", "http.request.method == POST",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "http.file_data",
        "-l",                          # line-buffered output
    ]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        print(f"  {CYAN}[tshark] Running (PID {proc.pid}) — waiting for POST...{RESET}\n")

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) >= 3:
                src, dst, payload = parts[0], parts[1], parts[2]

                # Decode hex-encoded or colon-separated payload format if output by tshark
                try:
                    cleaned_payload = payload.replace(":", "")
                    try:
                        decoded_payload = bytes.fromhex(cleaned_payload).decode("utf-8", errors="ignore")
                    except ValueError:
                        decoded_payload = payload

                    # Parse query parameters from the decoded payload
                    params = urllib.parse.parse_qs(urllib.parse.unquote_plus(decoded_payload))
                    username = params.get("username", ["?"])[0]
                    password = params.get("password", ["?"])[0]
                except Exception:
                    username = password = "PARSE_ERROR"

                print("  " + "=" * 56)
                print(f"  {RED}{BOLD}[!!] PLAINTEXT CREDENTIALS CAPTURED (tshark){RESET}")
                print(f"  {RED}  Source   : {src}{RESET}")
                print(f"  {RED}  Dest     : {dst}{RESET}")
                print(f"  {RED}  Username : {BOLD}{username}{RESET}")
                print(f"  {RED}  Password : {BOLD}{password}{RESET}")
                print("  " + "=" * 56 + "\n")
            else:
                print(f"  {YELLOW}[RAW] {line}{RESET}")

    except KeyboardInterrupt:
        proc.terminate()
        print(f"\n  {YELLOW}[INFO] Capture stopped by user.{RESET}")
    except PermissionError:
        print(f"  {RED}[ERROR] Permission denied. Run with sudo.{RESET}")
        sys.exit(1)


def sniff_https_tshark(interface: str, packet_count: int):
    """
    Fallback: tshark TLS handshake inspection for HTTPS traffic.
    Shows TLS record types; payload remains encrypted.
    """
    if not _check_tshark():
        print(f"  {RED}[ERROR] tshark not found.{RESET}")
        sys.exit(1)

    print(f"\n  {CYAN}[tshark] Capturing TLS on '{interface}' port {HTTPS_PORT}...{RESET}")
    print(f"  {YELLOW}Connect to https://localhost:{HTTPS_PORT} now.{RESET}\n")

    cmd = [
        "tshark",
        "-i", interface,
        "-f", f"tcp port {HTTPS_PORT}",
        "-c", str(packet_count),
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tls.record.content_type",
        "-e", "tls.handshake.type",
        "-l",
    ]

    content_type_map = {
        "20": "Change Cipher Spec",
        "21": "Alert",
        "22": "Handshake",
        "23": "Application Data [ENCRYPTED]",
    }
    handshake_map = {
        "1": "Client Hello", "2": "Server Hello",
        "11": "Certificate", "14": "Server Hello Done",
        "16": "Client Key Exchange", "20": "Finished",
    }

    tls_count = 0
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            parts = (line + "\t\t\t\t").split("\t")
            src, dst = parts[0] or "?", parts[1] or "?"
            ct  = content_type_map.get(parts[2].strip(), parts[2] or "TCP")
            hs  = handshake_map.get(parts[3].strip(), "")
            tls_count += 1

            color = GREEN if "ENCRYPTED" in ct else CYAN
            print(f"  {color}[TLS #{tls_count:>3}] {src} → {dst}  | {ct}  {hs}{RESET}")

    except KeyboardInterrupt:
        proc.terminate()

    print(f"\n  {BOLD}[TC-02] TLS captured {tls_count} records — payload UNREADABLE.{RESET}\n")


# ===========================================================================
# Main Entry Point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="IS Lab — Network Sniffer Agent (Module A)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--mode", choices=["http", "https"], default="http",
        help="http  → TC-01: capture plaintext credentials\n"
             "https → TC-02: verify TLS encryption"
    )
    parser.add_argument(
        "--interface", "-i", default="lo",
        help="Network interface to listen on (default: lo for localhost testing)"
    )
    parser.add_argument(
        "--count", "-c", type=int, default=100,
        help="Maximum number of packets to inspect (default: 100)"
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  MODULE A — SNIFFER AGENT")
    print(f"  Mode      : {'HTTP (Plaintext)' if args.mode == 'http' else 'HTTPS (TLS Verification)'}")
    print(f"  Interface : {args.interface}")
    print(f"  Pkt Limit : {args.count}")
    print("=" * 60)

    # Check for root / cap_net_raw
    if os.geteuid() != 0:
        print(f"\n  {YELLOW}[WARNING] Not running as root. Capture may fail.{RESET}")
        print(f"           Re-run with: sudo python3 sniffer_agent.py --mode {args.mode}\n")

    if args.mode == "http":
        success = sniff_http_pyshark(args.interface, args.count)
        if not success:
            print(f"  {YELLOW}[INFO] pyshark not available, falling back to tshark...{RESET}")
            sniff_http_tshark(args.interface, args.count)
    else:
        success = sniff_https_pyshark(args.interface, args.count)
        if not success:
            sniff_https_tshark(args.interface, args.count)


if __name__ == "__main__":
    main()
