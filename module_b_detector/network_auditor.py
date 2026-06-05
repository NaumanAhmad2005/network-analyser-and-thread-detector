#!/usr/bin/env python3
"""
network_auditor.py — Module B: Automated Network Scanner & Rogue Service Detector
===================================================================================
SECURITY CONCEPT: Threat Detection & Vulnerability Assessment

This script automates Nmap scanning of a target subnet to:
  1. Discover all live hosts (host discovery scan)
  2. Profile every active host's open ports and service versions (-sV)
  3. Cross-reference each open port against policy.json
  4. Flag unauthorized / legacy / cleartext services as ROGUE (TC-03, TC-04)

It maps directly to the CIA Triad:
  • Confidentiality  — flags services that transmit data in plaintext (FTP, Telnet)
  • Integrity        — identifies services without authentication (TFTP, anonymous FTP)
  • Availability     — could be extended to flag denial-of-service surface ports

IMPORTANT: Run only on networks you own or have explicit written permission to scan.
           This lab demo is designed for a controlled VirtualBox/VMware lab environment.
Test Cases: TC-03 (subnet discovery + port listing), TC-04 (rogue service flagging)
"""

import subprocess
import json
import os
import sys
import re
import argparse
import socket
import ipaddress
from datetime import datetime
from xml.etree import ElementTree as ET

# ---- ANSI colour codes -------------------------------------------------------
RED      = "\033[91m"
ORANGE   = "\033[33m"
GREEN    = "\033[92m"
YELLOW   = "\033[93m"
CYAN     = "\033[96m"
BLUE     = "\033[94m"
MAGENTA  = "\033[95m"
BOLD     = "\033[1m"
DIM      = "\033[2m"
RESET    = "\033[0m"

POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy.json")

RISK_COLORS = {
    "CRITICAL": RED + BOLD,
    "HIGH":     ORANGE + BOLD,
    "MEDIUM":   YELLOW,
    "LOW":      DIM,
    "UNKNOWN":  MAGENTA,
}


# =============================================================================
# Policy Loading
# =============================================================================

def load_policy(path: str) -> dict:
    """
    Load the security policy JSON file.
    Returns a dict with 'authorized_ports' and 'rogue_ports' mappings.
    """
    if not os.path.exists(path):
        print(f"  {RED}[ERROR] Policy file not found: {path}{RESET}")
        sys.exit(1)

    try:
        with open(path, "r") as f:
            policy = json.load(f)
        print(f"  {GREEN}[✔] Policy loaded: v{policy.get('policy_version', '?')} "
              f"— {policy.get('organization', '')}{RESET}")
        return policy
    except json.JSONDecodeError as e:
        print(f"  {RED}[ERROR] Invalid JSON in policy file: {e}{RESET}")
        sys.exit(1)


# =============================================================================
# Nmap Availability Check
# =============================================================================

def check_nmap() -> str:
    """Return the nmap binary path or exit with a helpful error."""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            version_line = result.stdout.splitlines()[0]
            print(f"  {GREEN}[✔] {version_line}{RESET}")
            return "nmap"
    except FileNotFoundError:
        pass

    print(f"  {RED}[ERROR] nmap is not installed or not in PATH.{RESET}")
    print("          Install: sudo apt-get install nmap")
    sys.exit(1)


# =============================================================================
# Host Discovery — Ping Scan
# =============================================================================

def discover_hosts(subnet: str, nmap_bin: str) -> list:
    """
    Run nmap -sn (ping scan / host discovery) against the subnet.
    Returns a list of live IP address strings.

    -sn : No port scan, only host discovery (ARP ping / ICMP echo / TCP SYN to 80)
    -oX : XML output for reliable machine-parsing
    """
    print(f"\n  {CYAN}[DISCOVERY] Scanning subnet {subnet} for live hosts...{RESET}")

    xml_output = _run_nmap_xml([nmap_bin, "-sn", "--open", subnet])
    if xml_output is None:
        return []

    return _parse_live_hosts(xml_output)


def _run_nmap_xml(cmd: list) -> str | None:
    """
    Execute an nmap command and return its XML output as a string.
    Uses -oX - to write XML to stdout.
    """
    full_cmd = cmd + ["-oX", "-"]

    print(f"  {DIM}  CMD: {' '.join(full_cmd)}{RESET}")

    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True, text=True,
            timeout=300   # Allow up to 5 minutes for large subnet scans
        )
        if result.returncode != 0:
            print(f"  {YELLOW}[WARN] nmap exited with code {result.returncode}: {result.stderr.strip()}{RESET}")
        return result.stdout if result.stdout else None

    except subprocess.TimeoutExpired:
        print(f"  {RED}[ERROR] nmap scan timed out.{RESET}")
        return None
    except PermissionError:
        print(f"  {RED}[ERROR] Permission denied. Some scan types require sudo.{RESET}")
        return None


def _parse_live_hosts(xml_str: str) -> list:
    """Parse nmap XML output and return IPs of hosts with state='up'."""
    hosts = []
    try:
        root = ET.fromstring(xml_str)
        for host_elem in root.findall("host"):
            status = host_elem.find("status")
            if status is not None and status.get("state") == "up":
                addr_elem = host_elem.find("address[@addrtype='ipv4']")
                if addr_elem is not None:
                    hosts.append(addr_elem.get("addr"))
    except ET.ParseError as e:
        print(f"  {YELLOW}[WARN] XML parse error: {e}{RESET}")

    return hosts


# =============================================================================
# Service Version Scan — Per Host
# =============================================================================

def scan_host_services(ip: str, nmap_bin: str) -> list:
    """
    Run nmap -sV against a single host to enumerate open ports and service versions.

    -sV  : Service version detection — probes open ports to determine software/version
           (SECURITY CONCEPT: version data used to identify vulnerable/legacy software)
    -sT  : TCP connect scan (doesn't need raw socket — works without root in some cases)
    --open : Only show open ports (reduces noise)
    -p-  : Scan all 65535 ports (use --top-ports N for speed if needed)

    Returns a list of port dicts: {port, protocol, state, service, version}
    """
    # Scan the 1000 most common ports + our demo ports
    cmd = [
        nmap_bin,
        "-sV",              # Service/version detection
        "-sT",              # TCP connect (no raw socket needed)
        "--open",           # Only open ports
        "--top-ports", "1000",
        ip
    ]

    xml_str = _run_nmap_xml(cmd)
    if not xml_str:
        return []

    return _parse_open_ports(xml_str, ip)


def _parse_open_ports(xml_str: str, target_ip: str) -> list:
    """
    Parse the nmap XML service-scan output and extract open port details.
    Returns a list of port dicts for the target IP.
    """
    ports = []
    try:
        root = ET.fromstring(xml_str)
        for host_elem in root.findall("host"):
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is None or addr_elem.get("addr") != target_ip:
                continue

            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem   = port_elem.find("state")
                service_elem = port_elem.find("service")

                if state_elem is None or state_elem.get("state") != "open":
                    continue

                ports.append({
                    "port":     port_elem.get("portid", "?"),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state":    state_elem.get("state", "?"),
                    "service":  service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                    "version":  (
                        f"{service_elem.get('product', '')} "
                        f"{service_elem.get('version', '')} "
                        f"{service_elem.get('extrainfo', '')}"
                    ).strip() if service_elem is not None else "",
                })

    except ET.ParseError as e:
        print(f"  {YELLOW}[WARN] Port parse error: {e}{RESET}")

    return ports


# =============================================================================
# Policy Enforcement — Rogue Service Flagging (TC-04)
# =============================================================================

def evaluate_ports(ip: str, open_ports: list, policy: dict) -> list:
    """
    Cross-reference each open port on the host against the policy profile.

    Decision logic:
      • Port in authorized_ports → SAFE
      • Port in rogue_ports      → ROGUE (flag with risk level)
      • Port in neither          → UNKNOWN (warn — manual review needed)

    Returns a list of finding dicts for report generation.
    """
    authorized = policy.get("authorized_ports", {})
    rogue      = policy.get("rogue_ports", {})
    findings   = []

    for p in open_ports:
        port_str = str(p["port"])

        if port_str in authorized:
            status = "SAFE"
            risk   = "NONE"
            reason = authorized[port_str].get("note", "")
        elif port_str in rogue:
            status = "ROGUE"
            risk   = rogue[port_str].get("risk", "HIGH")
            reason = rogue[port_str].get("reason", "Unauthorized/insecure service")
        else:
            status = "UNKNOWN"
            risk   = "UNKNOWN"
            reason = "Port not in policy — requires manual review"

        findings.append({
            "ip":      ip,
            "port":    port_str,
            "protocol": p["protocol"],
            "service": p["service"],
            "version": p["version"],
            "status":  status,
            "risk":    risk,
            "reason":  reason,
        })

    return findings


# =============================================================================
# Report Printing
# =============================================================================

def print_host_report(ip: str, findings: list):
    """Print a formatted per-host security report to the terminal."""
    rogue_count = sum(1 for f in findings if f["status"] == "ROGUE")
    safe_count  = sum(1 for f in findings if f["status"] == "SAFE")
    unk_count   = sum(1 for f in findings if f["status"] == "UNKNOWN")

    host_color = RED if rogue_count > 0 else GREEN
    print(f"\n  {host_color}{BOLD}┌─ Host: {ip} "
          f"({len(findings)} open ports | "
          f"{rogue_count} ROGUE | {safe_count} SAFE | {unk_count} UNKNOWN){RESET}")

    for f in findings:
        color  = RISK_COLORS.get(f["risk"], RESET)
        status = f["status"]
        ver    = f" [{f['version']}]" if f["version"] else ""

        if status == "SAFE":
            icon = f"{GREEN}✔{RESET}"
        elif status == "ROGUE":
            icon = f"{RED}✘{RESET}"
        else:
            icon = f"{MAGENTA}?{RESET}"

        print(f"  │  {icon}  Port {f['port']:>5}/{f['protocol']:3}  "
              f"{f['service']:<12}{ver}")

        if status == "ROGUE":
            print(f"  │      {color}⚠ HIGH RISK: Rogue Service Detected{RESET}")
            print(f"  │      {color}  Risk  : {f['risk']}{RESET}")
            print(f"  │      {color}  Reason: {f['reason']}{RESET}")
        elif status == "UNKNOWN":
            print(f"  │      {MAGENTA}⚑ UNKNOWN: {f['reason']}{RESET}")

    print(f"  {host_color}{BOLD}└──────────────────────────────────────────────────────{RESET}")


def print_summary_report(all_findings: list, scan_start: datetime):
    """Print the final aggregated summary report."""
    duration = (datetime.now() - scan_start).total_seconds()

    rogue_findings = [f for f in all_findings if f["status"] == "ROGUE"]
    safe_findings  = [f for f in all_findings if f["status"] == "SAFE"]
    unk_findings   = [f for f in all_findings if f["status"] == "UNKNOWN"]

    print("\n\n" + "=" * 62)
    print(f"  {BOLD}MODULE B — FINAL AUDIT REPORT{RESET}")
    print(f"  Scan Duration  : {duration:.1f} seconds")
    print(f"  Total Findings : {len(all_findings)}")
    print(f"  {GREEN}  SAFE          : {len(safe_findings)}{RESET}")
    print(f"  {MAGENTA}  UNKNOWN       : {len(unk_findings)}{RESET}")
    print(f"  {RED}  ROGUE         : {len(rogue_findings)}{RESET}")
    print("=" * 62)

    if rogue_findings:
        print(f"\n  {RED}{BOLD}CRITICAL FINDINGS — ROGUE SERVICES DETECTED:{RESET}")
        for f in rogue_findings:
            color = RISK_COLORS.get(f["risk"], RESET)
            print(f"  {color}  [{f['risk']:8s}] {f['ip']}:{f['port']}/{f['protocol']} "
                  f"({f['service']}) — {f['reason']}{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}No rogue services detected. Network appears compliant.{RESET}")

    print("\n" + "=" * 62 + "\n")


# =============================================================================
# Main Orchestrator
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="IS Lab — Module B: Network Auditor & Rogue Service Detector",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--subnet", "-s",
        default="127.0.0.1",
        help="Target subnet or IP (e.g. 192.168.56.0/24 or 192.168.56.101)\n"
             "DEFAULT: 127.0.0.1 (localhost only — safe for single-machine demo)"
    )
    parser.add_argument(
        "--policy", "-p",
        default=POLICY_FILE,
        help=f"Path to policy JSON file (default: {POLICY_FILE})"
    )
    parser.add_argument(
        "--skip-discovery", action="store_true",
        help="Skip host discovery (ping scan) and scan --subnet directly as a single host.\n"
             "Use this when pinging is blocked or scanning a single known IP."
    )
    args = parser.parse_args()

    scan_start = datetime.now()

    print("\n" + "=" * 62)
    print(f"  {BOLD}MODULE B — NETWORK AUDITOR & ROGUE SERVICE DETECTOR{RESET}")
    print(f"  Target  : {args.subnet}")
    print(f"  Started : {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 62 + "\n")

    # ── Step 1: Load policy ──────────────────────────────────────────────────
    policy  = load_policy(args.policy)
    nmap_bin = check_nmap()

    # ── Step 2: Host discovery ───────────────────────────────────────────────
    if args.skip_discovery:
        live_hosts = [args.subnet]
        print(f"  {YELLOW}[INFO] Skipping discovery — scanning {args.subnet} directly.{RESET}")
    else:
        try:
            # Validate that the target looks like a subnet or IP
            ipaddress.ip_network(args.subnet, strict=False)
            live_hosts = discover_hosts(args.subnet, nmap_bin)
        except ValueError:
            print(f"  {YELLOW}[INFO] '{args.subnet}' is not a CIDR — treating as single host.{RESET}")
            live_hosts = [args.subnet]

    if not live_hosts:
        print(f"\n  {YELLOW}[INFO] No live hosts found in {args.subnet}.{RESET}")
        print("         Check your subnet, VM network settings, or try --skip-discovery.\n")
        sys.exit(0)

    print(f"\n  {GREEN}[✔] Live hosts discovered: {len(live_hosts)}{RESET}")
    for h in live_hosts:
        print(f"       • {h}")

    # ── Step 3: Service scan per host ────────────────────────────────────────
    all_findings = []
    for ip in live_hosts:
        print(f"\n  {CYAN}[SCAN] Service version scan on {ip}...{RESET}")
        try:
            open_ports = scan_host_services(ip, nmap_bin)
        except Exception as e:
            print(f"  {RED}[ERROR] Scan of {ip} failed: {e}{RESET}")
            continue

        if not open_ports:
            print(f"  {DIM}  No open ports found on {ip} (or scan blocked).{RESET}")
            continue

        # ── Step 4: Policy evaluation ─────────────────────────────────────
        findings = evaluate_ports(ip, open_ports, policy)
        all_findings.extend(findings)
        print_host_report(ip, findings)

    # ── Step 5: Final summary ────────────────────────────────────────────────
    print_summary_report(all_findings, scan_start)


if __name__ == "__main__":
    main()
