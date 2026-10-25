# 🦉 OSpecter

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-OScan-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.1-cyan?style=flat-square"/>
</p>

> **OSpecter** — Advanced Tactical Port Scanner

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview


OSpecter is an advanced tactical port scanner offering multiple scan modes, service fingerprinting, OS detection and curated CVE hints. It supports SYN/Connect/UDP/NULL/FIN/XMAS scans, banner grabbing, SSL/TLS auditing, WAF/CDN detection and network sweeps, all with a fully threaded engine. Results can be exported to dark-themed HTML, JSON and CSV reports, and two scans can be diffed for delta ports.

---

## ✨ Features


- Scan modes: SYN (stealth), Connect, UDP, NULL, FIN and XMAS, fully threaded with adaptive concurrency
- OS detection via TTL heuristics and TCP window fingerprinting, plus protocol-aware banner grabbing
- SSL/TLS audit (cert expiry, weak ciphers, protocol versions) and WAF/CDN detection from HTTP headers
- CVE hints for 70+ services and a weighted risk score across open ports and dangerous services
- Network sweep (ICMP/ARP, CIDR), traceroute via Scapy, scripted probes and MAC OUI vendor lookup
- Scan diff of two JSON reports and export to HTML, JSON and CSV

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage


```bash
./OSpecter
./OSpecter --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
