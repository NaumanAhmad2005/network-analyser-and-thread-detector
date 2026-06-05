# Network Traffic Inspection & Rogue Service Detection System
### IS Lab Final Project — Information Security Lab

---

## Overview

This project implements two complementary security modules that demonstrate core **Information Security** principles — **Confidentiality**, **Integrity**, and **Threat Detection** — using industry-standard tools: Python, OpenSSL, Wireshark/tshark, and Nmap.

| Module | Focus | Tools |
|--------|-------|-------|
| **Module A** | Network Traffic Inspection & Secure Communication | Python `http.server`, `ssl`, OpenSSL, `pyshark`/`tshark` |
| **Module B** | Threat Detection & Vulnerability Assessment | `nmap`, `python-nmap`, `policy.json` |

---

## Project Structure

```
is_lab_project/
│
├── README.md                       ← This file
├── requirements.txt                ← pip dependencies
│
├── module_a_traffic/
│   ├── insecure_server.py          ← TC-01: Plaintext HTTP server (port 8000)
│   ├── secure_server.py            ← TC-02: TLS-encrypted HTTPS server (port 8443)
│   ├── generate_certs.sh           ← OpenSSL self-signed certificate generator
│   └── sniffer_agent.py            ← Packet sniffer: extracts creds (HTTP) / verifies TLS (HTTPS)
│
└── module_b_detector/
    ├── policy.json                 ← Security policy: authorized vs. rogue ports
    └── network_auditor.py          ← Nmap automation engine + rogue service detector
```

---

## Environment & Dependencies

### System Requirements

- **OS:** Ubuntu Linux (or any Debian-based distro)
- **Python:** 3.10+
- **Required system packages:**

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip tshark nmap openssl
```

> **Note on tshark:** During installation you may be prompted whether non-superusers should be able to capture packets. Select **Yes** and add yourself to the `wireshark` group:
> ```bash
> sudo usermod -aG wireshark $USER
> newgrp wireshark
> ```

### Python Dependencies

```bash
pip3 install -r requirements.txt
```

---

## Module A — Network Traffic Inspection

### Step 1: Generate TLS Certificates (required for TC-02)

```bash
cd module_a_traffic/
bash generate_certs.sh
```

This creates `server.crt` and `server.key` in the same directory.

---

### TC-01 — Plaintext HTTP Credential Capture

**Demonstrates:** Lack of Confidentiality over plain HTTP.

**Terminal 1 — Start the insecure HTTP server:**
```bash
python3 module_a_traffic/insecure_server.py
```

**Terminal 2 — Start the sniffer (requires root for packet capture):**
```bash
sudo python3 module_a_traffic/sniffer_agent.py --mode http --interface lo
```

**Browser / Terminal 3 — Submit a login:**
```bash
curl -d "username=alice&password=secret123" http://localhost:8000/login
```

**Expected Result:** The sniffer prints the credentials in plaintext:
```
[!!] PLAINTEXT CREDENTIALS EXTRACTED FROM WIRE
     Username : alice
     Password : secret123
```

---

### TC-02 — HTTPS TLS Verification

**Demonstrates:** Confidentiality enforced via TLS — credentials are unreadable on the wire.

**Terminal 1 — Start the secure HTTPS server:**
```bash
python3 module_a_traffic/secure_server.py
```

**Terminal 2 — Start the sniffer in HTTPS mode:**
```bash
sudo python3 module_a_traffic/sniffer_agent.py --mode https --interface lo
```

**Terminal 3 — Send a login request (ignore self-signed cert warning with -k):**
```bash
curl -k -d "username=alice&password=secret123" https://localhost:8443/login
```

**Expected Result:** The sniffer shows only TLS handshake records:
```
[TLS #  1]  Record: Handshake                   | CLIENT HELLO
[TLS #  2]  Record: Handshake                   | SERVER HELLO
[TLS #  5]  Record: Application Data [ENCRYPTED]
             └─ Application data is ENCRYPTED — credentials NOT readable!
```

---

## Module B — Rogue Service Detection

### TC-03 — Subnet Discovery & Port Listing

**Scan localhost for demo (safe, no network required):**
```bash
python3 module_b_detector/network_auditor.py --subnet 127.0.0.1 --skip-discovery
```

**Scan a local VM subnet (replace with your actual subnet):**
```bash
python3 module_b_detector/network_auditor.py --subnet 192.168.56.0/24
```

**Expected Result:**
```
[DISCOVERY] Scanning subnet 192.168.56.0/24 for live hosts...
[✔] Live hosts discovered: 2
     • 192.168.56.1
     • 192.168.56.101
```

---

### TC-04 — Rogue Service Flagging

To demonstrate TC-04, start a service on a flagged port **on your lab machine**:

```bash
# Example: start a netcat "telnet-like" listener on port 23 (in another terminal)
# NOTE: This is for demo only — on your own machine
sudo nc -lvp 23
```

Then re-run the auditor. It will flag port 23:
```
✘  Port    23/tcp  telnet
      ⚠ HIGH RISK: Rogue Service Detected
        Risk  : CRITICAL
        Reason: Cleartext remote shell — complete session hijack possible
```

**Final Summary Output Example:**
```
CRITICAL FINDINGS — ROGUE SERVICES DETECTED:
  [CRITICAL] 192.168.56.101:23/tcp (telnet) — Cleartext remote shell...
  [HIGH    ] 192.168.56.101:21/tcp (ftp)    — Credentials exposed on wire
```

---

## Policy Configuration

Edit `module_b_detector/policy.json` to customize the policy:

```json
{
  "authorized_ports": {
    "22":  { "service": "SSH",   "note": "Encrypted remote shell — approved" },
    "443": { "service": "HTTPS", "note": "Encrypted web traffic — approved" }
  },
  "rogue_ports": {
    "23":  { "service": "Telnet", "risk": "CRITICAL", "reason": "Cleartext remote shell" },
    "21":  { "service": "FTP",    "risk": "HIGH",     "reason": "Cleartext file transfer" }
  }
}
```

---

## Security Concepts Demonstrated

| Concept | Module | How |
|---------|--------|-----|
| **Confidentiality** | A (HTTP→HTTPS) | Shows credentials leaked over HTTP; TLS hides them over HTTPS |
| **Integrity** | A (TLS) | TLS AEAD/MAC prevents in-transit data tampering |
| **Identity / Authentication** | A (OpenSSL cert) | Server certificate authenticates server identity to client |
| **Threat Detection** | B (Nmap) | Automated port scanning identifies attack surface |
| **Vulnerability Assessment** | B (Policy) | Policy engine flags legacy cleartext protocols as HIGH/CRITICAL risk |

---

## Ethical & Legal Notice

> All scanning and packet capture must be performed **only** on:
> - Your own personal machine
> - Lab machines you have explicit permission to test
> - Intentionally vulnerable VMs (e.g., Metasploitable, DVWA)
> - Controlled VirtualBox / VMware lab environments
>
> **Unauthorized scanning or sniffing on production or third-party networks is illegal.**

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Permission denied` on sniffer | Run with `sudo` |
| `tshark` not found | `sudo apt-get install tshark` |
| `nmap` not found | `sudo apt-get install nmap` |
| `server.crt` not found | Run `bash generate_certs.sh` first |
| Browser rejects self-signed cert | Click "Advanced → Accept Risk" or use `curl -k` |
| No hosts found in subnet scan | Check VM network adapter is Host-Only or NAT Network |

---

*IS Lab Final Project · Information Security · 4th Semester*
