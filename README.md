# Network Traffic Inspection & Rogue Service Detection System
### IS Lab Final Project — Information Security · 4th Semester

---

## Overview

This project demonstrates core **CIA Triad** principles — Confidentiality, Integrity, and Threat Detection — through two hands-on security modules controlled from a single **TUI dashboard**.

| Module | Focus | Key Tools |
|--------|-------|-----------|
| **Module A** | Network Traffic Inspection & Secure Communication | `http.server`, `ssl`, OpenSSL, `pyshark`/`tshark` |
| **Module B** | Threat Detection & Vulnerability Assessment | `nmap`, `policy.json` |

---

## Quick Start — Unified Dashboard

Everything runs from one entry point:

```bash
pip3 install -r requirements.txt
python3 main_controller.py
```

The dashboard provides a full-screen TUI (built with `rich`) with:
- **Live status bar** — shows HTTP server, HTTPS server, sniffer, and TLS cert state in real time
- **Menu** — launches all test cases without needing to open individual scripts
- **Rolling activity log** — streams output from all background processes

```
Key   Module            Action
─────────────────────────────────────────────────────────
 1    Module A — TC-01  Start Insecure HTTP Server  (port 8000)
 2    Module A — TC-01  Stop  Insecure HTTP Server
 3    Module A — TC-02  Generate TLS Certificates (OpenSSL)
 4    Module A — TC-02  Start Secure HTTPS Server  (port 8443)
 5    Module A — TC-02  Stop  Secure HTTPS Server
 6    Module A — Sniffer  Run Sniffer — HTTP mode  (capture creds)
 7    Module A — Sniffer  Run Sniffer — HTTPS mode (verify TLS)
 8    Module A — Sniffer  Stop Sniffer
 9    Module B — TC-03  Run Network Auditor (subnet scan)
 A    Module B — TC-04  Run Demo: Flag Rogue Service (port 23)
 V    View              Show Last Audit Results
 L    Log               View Live Activity Log
 Q    Quit              Exit Dashboard
```

> Run with `sudo python3 main_controller.py` if tshark requires root for packet capture.

---

## Project Structure

```
is_lab_project/
├── main_controller.py          ← Unified TUI dashboard (single entry point)
├── requirements.txt            ← pip dependencies: rich, pyshark, python-nmap
│
├── module_a_traffic/
│   ├── insecure_server.py      ← TC-01: Plaintext HTTP server (port 8000)
│   ├── secure_server.py        ← TC-02: TLS-encrypted HTTPS server (port 8443)
│   ├── generate_certs.sh       ← OpenSSL self-signed cert generator
│   ├── sniffer_agent.py        ← Packet sniffer: extracts creds (HTTP) / verifies TLS (HTTPS)
│   ├── server.crt              ← Generated TLS certificate (created by generate_certs.sh)
│   └── server.key              ← Generated RSA private key  (created by generate_certs.sh)
│
└── module_b_detector/
    ├── network_auditor.py      ← Nmap automation engine + rogue service detector
    └── policy.json             ← Security policy: authorized vs. rogue port definitions
```

---

## Environment & Dependencies

### System Requirements

- **OS:** Ubuntu / Debian Linux
- **Python:** 3.10+

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip tshark nmap openssl ncat
```

> **tshark / wireshark group:** To run the sniffer without `sudo`:
> ```bash
> sudo usermod -aG wireshark $USER && newgrp wireshark
> ```

### Python Dependencies

```bash
pip3 install -r requirements.txt
# installs: rich>=13.0, pyshark>=0.6, python-nmap>=0.7.1
```

---

## Module A — Network Traffic Inspection

### Step 0: Generate TLS Certificates *(required before TC-02)*

```bash
# Via dashboard:  press [3]
# Or manually:
bash module_a_traffic/generate_certs.sh
```

Produces `server.crt` (X.509 certificate, 2048-bit RSA, valid 365 days) and `server.key` in `module_a_traffic/`.

---

### TC-01 — Plaintext HTTP Credential Capture

**Demonstrates:** Violation of Confidentiality — credentials exposed in plaintext over HTTP.

**Via dashboard:** press `[1]` to start server, `[6]` to start sniffer.

**Manual steps:**
```bash
# Terminal 1 — HTTP server:
python3 module_a_traffic/insecure_server.py

# Terminal 2 — Sniffer (requires root):
sudo python3 module_a_traffic/sniffer_agent.py --mode http --interface lo

# Terminal 3 — Submit login:
curl -d "username=alice&password=secret123" http://localhost:8000/login
```

**Expected output:**
```
[!!] PLAINTEXT CREDENTIALS EXTRACTED FROM WIRE
     Packet   : #47
     Username : alice
     Password : secret123
     Source   : 127.0.0.1:52840
     Dest     : 127.0.0.1:8000
```

The sniffer reads credentials directly from the TCP stream using `pyshark` (primary) or `tshark` subprocess (fallback). No attack required — they are just sitting there in plaintext.

---

### TC-02 — HTTPS TLS Verification

**Demonstrates:** Confidentiality enforced via TLS — credentials are unreadable on the wire.

**Via dashboard:** press `[4]` to start HTTPS server, `[7]` to start sniffer in HTTPS mode.

**Manual steps:**
```bash
# Terminal 1 — Secure HTTPS server:
python3 module_a_traffic/secure_server.py

# Terminal 2 — Sniffer in HTTPS mode:
sudo python3 module_a_traffic/sniffer_agent.py --mode https --interface lo

# Terminal 3 — Submit login (accept self-signed cert with -k):
curl -k -d "username=alice&password=secret123" https://localhost:8443/login
```

**Expected output:**
```
[TLS #  1]  Record: Handshake                    Handshake: CLIENT HELLO
[TLS #  2]  Record: Handshake                    Handshake: SERVER HELLO
[TLS #  3]  Record: Handshake                    Handshake: CERTIFICATE
[TLS #  5]  Record: Handshake                    Handshake: CLIENT KEY EXCHANGE
[TLS #  7]  Record: Application Data (ENCRYPTED)
             └─ Application data is ENCRYPTED — credentials NOT readable!

[TC-02 RESULT] TLS Verification Summary
  Total packets captured   : 7
  TLS records observed     : 7
  Readable credentials     : NONE (fully encrypted)
```

---

## Module B — Rogue Service Detection

The auditor loads `policy.json`, runs Nmap against the target, and cross-references every open port against the policy to label it **SAFE**, **ROGUE**, or **UNKNOWN**.

### Policy Configuration (`module_b_detector/policy.json`)

```json
{
  "authorized_ports": {
    "22":   { "service": "SSH",       "note": "Encrypted remote shell — approved" },
    "443":  { "service": "HTTPS",     "note": "Encrypted web traffic — approved"  },
    "8443": { "service": "HTTPS-alt", "note": "Lab HTTPS server — approved"       },
    "53":   { "service": "DNS",       "note": "Name resolution — approved"        }
  },
  "rogue_ports": {
    "21":  { "service": "FTP",      "risk": "HIGH",     "reason": "Cleartext file transfer" },
    "23":  { "service": "Telnet",   "risk": "CRITICAL", "reason": "Cleartext remote shell — session hijack possible" },
    "80":  { "service": "HTTP",     "risk": "HIGH",     "reason": "Unencrypted web traffic" },
    "8000":{ "service": "HTTP-dev", "risk": "MEDIUM",   "reason": "Dev HTTP server — no encryption" },
    "110": { "service": "POP3",     "risk": "HIGH",     "reason": "Cleartext email retrieval" },
    "69":  { "service": "TFTP",     "risk": "HIGH",     "reason": "No authentication, no encryption" },
    "161": { "service": "SNMP",     "risk": "MEDIUM",   "reason": "SNMPv1/v2 community strings in plaintext" }
  }
}
```

Edit this file to add your own authorized or rogue port rules.

---

### TC-03 — Subnet Discovery & Port Listing

**Via dashboard:** press `[9]`, enter subnet when prompted.

```bash
# Localhost demo (safe, no VM needed):
python3 module_b_detector/network_auditor.py --subnet 127.0.0.1 --skip-discovery

# Full subnet scan (replace with your lab subnet):
python3 module_b_detector/network_auditor.py --subnet 192.168.56.0/24
```

**Expected output:**
```
[✔] Live hosts discovered: 2
     • 192.168.56.1
     • 192.168.56.101

┌─ Host: 127.0.0.1 (3 open ports | 1 ROGUE | 2 SAFE | 0 UNKNOWN)
│  ✔  Port    22/tcp  ssh   [OpenSSH 8.9]
│  ✔  Port  8443/tcp  https-alt
│  ✘  Port  8000/tcp  http-dev
│       ⚠ ROGUE — Risk: MEDIUM
│         Reason: Unauthenticated dev HTTP server — no encryption
└──────────────────────────────────────────────────────
```

---

### TC-04 — Rogue Service Flagging (Telnet Demo)

**Via dashboard:** press `[A]` — fully automated (starts rogue listener, scans, reports, cleans up).

**Manual steps:**
```bash
# Terminal 1 — start a rogue Telnet-like listener:
sudo ncat -lvp 23

# Terminal 2 — run the auditor:
python3 module_b_detector/network_auditor.py --subnet 127.0.0.1 --skip-discovery
```

**Expected output:**
```
│  ✘  Port    23/tcp  telnet
│       ⚠ ROGUE — Risk: CRITICAL
│         Reason: Cleartext remote shell — complete session hijack possible

CRITICAL FINDINGS — ROGUE SERVICES DETECTED:
  [CRITICAL] 127.0.0.1:23/tcp (telnet) — Cleartext remote shell...
```

---

## Security Concepts Summary

| Concept | Module | Demonstrated By |
|---------|--------|-----------------|
| **Confidentiality (violated)** | A — TC-01 | Credentials captured in plaintext from HTTP stream |
| **Confidentiality (enforced)** | A — TC-02 | TLS encrypts the same credentials — sniffer reads nothing |
| **Integrity** | A — TLS | TLS AEAD/MAC prevents in-transit data tampering |
| **Identity / Authentication** | A — OpenSSL | Server certificate authenticates server to client |
| **Threat Detection** | B — TC-03 | Nmap reveals full attack surface of host |
| **Vulnerability Assessment** | B — TC-04 | Policy engine flags CRITICAL/HIGH legacy protocols |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Permission denied` on sniffer | Run with `sudo` or add user to `wireshark` group |
| `tshark` not found | `sudo apt-get install tshark` |
| `nmap` not found | `sudo apt-get install nmap` |
| `ncat`/`nc` not found (TC-04) | `sudo apt-get install ncat` |
| `server.crt` not found | Press `[3]` in dashboard or run `bash generate_certs.sh` |
| Browser rejects self-signed cert | Click "Advanced → Accept Risk" or use `curl -k` |
| No hosts found in subnet scan | Use `--skip-discovery` or check VM network adapter settings |
| Sniffer captures no packets (HTTP) | Ensure HTTP server is running and you submitted the login form |
| `rich` import error | `pip3 install rich` |

---

## Ethical & Legal Notice

> All scanning and packet capture must be performed **only** on:
> - Your own personal machine
> - Lab machines you have explicit written permission to test
> - Intentionally vulnerable VMs (e.g., Metasploitable, DVWA)
> - Controlled VirtualBox / VMware lab environments
>
> **Unauthorized scanning or sniffing on production or third-party networks is illegal.**

---

*IS Lab Final Project · Information Security · 4th Semester · NITDS*
