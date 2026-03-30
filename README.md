# 🦉 OSpecter

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux&logoColor=white&color=0a0c10"/>
  <img src="https://img.shields.io/badge/Category-ORecon-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Requires-Root%20(SYN)-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OSpecter** is a tactical port scanner and service fingerprinter with SYN/Connect scan modes, banner grabbing, OS TTL detection, CVE hints, and dark-themed HTML and JSON report export.

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on hosts you own or have explicit permission to test. SYN scanning requires root privileges. Unauthorised port scanning may be illegal.

---

## 📌 Overview

OSpecter sends raw packets to enumerate open TCP ports on a target, then enriches each result with the service name, grabbed banner, and educational CVE hints. Results are displayed live in the terminal and optionally exported as a polished HTML report or a structured JSON file.

---

## 🔍 Scan Types

| Type | Method | Privileges | Notes |
|------|--------|-----------|-------|
| **SYN** | Sends SYN only — never completes the handshake | Root required | Stealthy. SYN-ACK = open, RST = closed, No reply = filtered |
| **Connect** | Full TCP three-way handshake | No root needed | Slower and more detectable. Auto-fallback if SYN selected without root |

---

## 🖥️ Scan Configuration

| Setting | Options | Default |
|---------|---------|---------|
| **Target** | IP address or hostname (auto-resolved) | — |
| **Ports** | `top100` · `top1000` · `1-65535` · `22,80,443` | `top100` |
| **Scan type** | `syn` · `connect` | `syn` |
| **Threads** | Any integer | `200` |
| **Timeout** | Seconds per port (float) | `1.5` |
| **Banner grab** | y / n | `y` |
| **Show filtered** | y / n | `n` |
| **HTML report** | Filename or skip | — |
| **JSON report** | Filename or skip | — |

---

## 🧠 OS Detection

OSpecter probes the target with an ICMP echo request and reads the TTL of the reply:

| TTL Range | OS Guess |
|-----------|----------|
| ≤ 64 | Linux / Android / macOS |
| ≤ 128 | Windows |
| ≤ 255 | Cisco IOS / Solaris / Network Device |

---

## 🚨 CVE Hints

After each open port, OSpecter displays educational CVE hints for 25+ known services:

| Service | Example Hints |
|---------|--------------|
| **SMB** | EternalBlue CVE-2017-0144 (MS17-010), SambaCry CVE-2017-7494 |
| **RDP** | BlueKeep CVE-2019-0708, DejaBlue CVE-2019-1181/1182 |
| **Redis** | No auth by default, CVE-2022-0543 (Lua sandbox escape) |
| **Docker** | Exposed API = full host RCE, CVE-2019-5736 (runc escape) |
| **Jupyter** | No-auth Jupyter = arbitrary code execution on server |
| **WebLogic** | CVE-2021-2109 (RCE), CVE-2020-14882 (unauth RCE) |
| **K8s Kubelet** | Unauthenticated API = exec into any pod |
| **SSH** | OpenSSH < 8.8 CVE-2021-41617, weak cipher check |
| **FTP** | Anonymous login, ProFTPD mod_copy RCE CVE-2015-3306 |
| **SNMP** | Community string `public` info leak, SNMPv1/v2 cleartext |
| + 15 more | Telnet, SMTP, LDAP, NFS, MongoDB, MySQL, VNC, and others |

---

## 🏷️ Banner Grabbing

OSpecter sends tailored probes per port and captures the first non-empty response line (up to 120 chars):

| Port | Probe |
|------|-------|
| 80 / 8080 / 8443 | `HEAD / HTTP/1.0` |
| 25 (SMTP) | `EHLO specter` |
| 6379 (Redis) | `INFO` |
| 21 / 22 / 110 / 143 / 3306 / 5432 | passive receive |

---

## 📤 Reports

### HTML Report
Dark-themed, fully self-contained report with:
- ASCII banner header
- Summary stat cards: scanned / open / filtered / closed
- OS fingerprint box with TTL value
- Sortable table: Port · State · Service · Banner · CVE Hints

### JSON Report
Machine-readable output containing target, scan type, start time, duration, OS hint (TTL + guess), and full per-port results.

---

## ⚙️ Requirements

- **Linux** (any modern distro)
- **Root privileges** required for SYN scan mode
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
sudo ./OSpecter
```

> Connect scan mode works without root: `./OSpecter` — select `connect` when prompted.

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
