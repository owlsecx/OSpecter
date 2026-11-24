#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
#  Tool       : OSpecter — Advanced Tactical Port Scanner
#  Category   : ONetwork / Reconnaissance & Fingerprinting
#  Purpose    : Multi-mode port scanning, service fingerprinting,
#               OS detection, CVE hints, scripted probes, network sweep,
#               traceroute, WAF detection, SSL/TLS audit, JSON/HTML/CSV export
#  Developer  : khaled.s.haddad
#  Website    : owlsec.org
#  Version    : v1.1
#  Year       : 2026
# ╠══════════════════════════════════════════════════════════════════════════╣
#  Features   :
#    ▸ Scan modes  : SYN (stealth/root) · Connect · UDP · NULL · FIN · XMAS
#    ▸ OS detection: TTL heuristics + TCP window fingerprinting
#    ▸ Banner grab : Protocol-aware probes (HTTP/FTP/SSH/SMTP/Redis…)
#    ▸ SSL/TLS audit: certificate expiry, weak ciphers, protocol versions
#    ▸ WAF/CDN detection via HTTP headers
#    ▸ Service version detection via banner parsing
#    ▸ CVE hints  : 70+ services with curated vulnerability references
#    ▸ Risk Score : weighted open-port / CVE / dangerous-service scoring
#    ▸ HTTP Security Headers audit (HSTS, CSP, XFO, XCTO…)
#    ▸ Scan Diff  : compare two JSON reports for delta ports
#    ▸ MAC OUI vendor lookup on ARP sweep
#    ▸ Network sweep (ICMP/ARP ping, CIDR range)
#    ▸ Traceroute  : hop-by-hop TTL probe via Scapy
#    ▸ Scripted probes: HTTP methods, anonymous FTP, Redis ping, SMB enum
#    ▸ Export : HTML · JSON · CSV — all with dark-themed reports
#    ▸ Live progress bar + rate-of-fire display
#    ▸ Fully threaded — ThreadPoolExecutor with adaptive concurrency
#  Requires   : python3 (stdlib), optional: scapy, ssl
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import os
import sys
import json
import csv
import socket
import ssl
import time
import datetime
import threading
import struct
import re
import ipaddress
import hashlib
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Any, Tuple
from collections import defaultdict

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Ether, ARP,
        sr1, srp, conf, RandShort, send
    )
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ════════════════════════════════════════════════════════════════════════════
#   ANSI COLOUR PALETTE
# ════════════════════════════════════════════════════════════════════════════

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    DIM     = "\033[2m"
    ORANGE  = "\033[38;5;214m"
    TEAL    = "\033[38;5;51m"
    PURPLE  = "\033[38;5;141m"
    GRAY    = "\033[38;5;245m"
    UNDER   = "\033[4m"

def c(text, *codes) -> str:
    return "".join(codes) + str(text) + C.RESET

def clr():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input(c("\n  [↩] Press Enter to continue...", C.YELLOW))

def is_root() -> bool:
    if os.name == 'nt':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0

# ════════════════════════════════════════════════════════════════════════════
#   BANNER
# ════════════════════════════════════════════════════════════════════════════

BANNER_ART = r"""
  ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
  ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"""

VERSION   = "v1.1"
DEVELOPER = "khaled.s.haddad"
WEBSITE   = "owlsec.org"

def banner():
    print(c(BANNER_ART, C.MAGENTA))
    print(c(f"       Tactical Port Scanner & Service Fingerprinter  {VERSION}", C.CYAN))
    print(c("   SYN · Connect · UDP · NULL · FIN · XMAS · Risk · Headers · Diff", C.WHITE))
    print()
    print(c("  Author  : ", C.DIM, C.WHITE) + c(DEVELOPER, C.CYAN) +
          c("   |   Website : ", C.DIM, C.WHITE) + c(WEBSITE, C.CYAN) +
          c(f"   |   {VERSION}", C.GRAY))
    print(c("─" * 66, C.MAGENTA))
    if not SCAPY_AVAILABLE:
        print(c("  [!] Scapy not found — SYN/UDP/NULL/FIN/XMAS/Sweep/Traceroute disabled.", C.YELLOW))
    if not is_root():
        print(c("  [!] Not running as root — SYN/raw scans will fall back to connect.", C.YELLOW))
    print()

# ════════════════════════════════════════════════════════════════════════════
#   SERVICE MAP  (240+ ports)
# ════════════════════════════════════════════════════════════════════════════

SERVICE_MAP: Dict[int, str] = {
    7:    "Echo",         9:    "Discard",      11:   "Systat",
    13:   "Daytime",      17:   "QOTD",         19:   "Chargen",
    20:   "FTP-data",     21:   "FTP",           22:   "SSH",
    23:   "Telnet",       25:   "SMTP",          37:   "Time",
    43:   "WHOIS",        49:   "TACACS",        53:   "DNS",
    67:   "DHCP",         68:   "DHCP",          69:   "TFTP",
    70:   "Gopher",       79:   "Finger",        80:   "HTTP",
    88:   "Kerberos",     102:  "ISO-TSAP",      110:  "POP3",
    111:  "RPC",          113:  "Ident",         119:  "NNTP",
    123:  "NTP",          135:  "MSRPC",         137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",  139:  "NetBIOS",       143:  "IMAP",
    161:  "SNMP",         162:  "SNMP-trap",     177:  "XDMCP",
    179:  "BGP",          194:  "IRC",           201:  "AppleTalk",
    264:  "BGMP",         389:  "LDAP",          401:  "UPS",
    443:  "HTTPS",        444:  "SNPP",          445:  "SMB",
    464:  "Kerberos-chpw",465:  "SMTPS",         500:  "IKE/IPsec",
    512:  "rexec",        513:  "rlogin",        514:  "RSH/Syslog",
    515:  "LPD",          520:  "RIP",           523:  "IBM-DB2",
    554:  "RTSP",         587:  "SMTP-sub",      631:  "IPP",
    636:  "LDAPS",        666:  "Doom",          873:  "rsync",
    902:  "VMware",       993:  "IMAPS",         995:  "POP3S",
    1080: "SOCKS",        1194: "OpenVPN",       1433: "MSSQL",
    1521: "Oracle",       1723: "PPTP",          1883: "MQTT",
    1900: "SSDP/UPnP",    2049: "NFS",           2121: "FTP-alt",
    2181: "ZooKeeper",    2375: "Docker",        2376: "Docker-TLS",
    2379: "etcd",         2380: "etcd-peer",     3000: "Grafana/Node",
    3128: "Squid",        3268: "LDAP-GC",       3269: "LDAPS-GC",
    3306: "MySQL",        3389: "RDP",           3690: "SVN",
    4369: "EPMD",         4444: "Metasploit",    4848: "GlassFish",
    5000: "Flask/UPnP",   5432: "PostgreSQL",    5601: "Kibana",
    5672: "AMQP/RabbitMQ",5900: "VNC",           5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",  6379: "Redis",         6443: "K8s API",
    6881: "BitTorrent",   7001: "WebLogic",      7077: "Spark",
    7180: "Cloudera",     7474: "Neo4j",         8000: "HTTP-alt",
    8080: "HTTP-alt",     8081: "HTTP-alt",      8083: "InfluxDB",
    8086: "InfluxDB-HTTP",8088: "HTTP-alt",      8443: "HTTPS-alt",
    8500: "Consul",       8888: "Jupyter",       8983: "Solr",
    9000: "SonarQube",    9042: "Cassandra",     9090: "Prometheus",
    9092: "Kafka",        9093: "Alertmanager",  9200: "Elasticsearch",
    9300: "Elasticsearch",9418: "Git",           9999: "Urchin",
    10000:"Webmin",       10250:"K8s Kubelet",   10255:"K8s Kubelet-RO",
    11211:"Memcached",    15672:"RabbitMQ-Mgmt", 16379:"Redis-Sentinel",
    27017:"MongoDB",      27018:"MongoDB",       28017:"MongoDB-HTTP",
    50000:"SAP",          50070:"Hadoop-HDFS",   50075:"Hadoop-DN",
    54321:"EDB-Postgres", 61616:"ActiveMQ",
}

# ════════════════════════════════════════════════════════════════════════════
#   CVE / RISK HINTS  (70+ services)
# ════════════════════════════════════════════════════════════════════════════

CVE_HINTS: Dict[str, List[str]] = {
    "FTP":           ["Anonymous login? CVE-1999-0497",
                      "ProFTPD <1.3.5 CVE-2015-3306 (mod_copy RCE)",
                      "vsftpd 2.3.4 backdoor CVE-2011-2523"],
    "SSH":           ["OpenSSH <8.8 CVE-2021-41617 (privilege escalation)",
                      "Username enumeration CVE-2018-15473",
                      "Weak ciphers: ssh -Q cipher <host>"],
    "Telnet":        ["Cleartext credentials — replace with SSH immediately",
                      "CVE-2011-4862 (FreeBSD Telnet RCE)"],
    "SMTP":          ["Open relay? test with RCPT TO:<external>",
                      "Postfix <3.5.9 CVE-2021-29214",
                      "VRFY/EXPN user enumeration"],
    "DNS":           ["Zone transfer? dig AXFR @<host> <domain>",
                      "BIND <9.16.6 CVE-2020-8617 (DoS)",
                      "DNS amplification attack vector"],
    "HTTP":          ["Apache <2.4.50 CVE-2021-42013 (path traversal RCE)",
                      "Check security headers: X-Frame-Options, CSP, HSTS",
                      "Directory listing enabled?"],
    "HTTPS":         ["TLS 1.0/1.1 deprecated — enforce TLS 1.2+",
                      "Run testssl.sh or sslyze for full audit",
                      "Heartbleed CVE-2014-0160 if OpenSSL <1.0.1g"],
    "SMB":           ["EternalBlue CVE-2017-0144 (MS17-010) — WannaCry vector",
                      "SambaCry CVE-2017-7494",
                      "PrintNightmare CVE-2021-1675/CVE-2021-34527"],
    "NetBIOS":       ["Null session enumeration: smbclient -N -L //<host>",
                      "NetBIOS name spoofing / NBNS poisoning"],
    "NetBIOS-NS":    ["Null session enumeration possible"],
    "MSRPC":         ["MS03-026 DCOM RPC CVE-2003-0352",
                      "BlueKeep-related exposure"],
    "RDP":           ["BlueKeep CVE-2019-0708 (unauthenticated RCE)",
                      "DejaBlue CVE-2019-1181/1182",
                      "NLA disabled? credential interception possible"],
    "MySQL":         ["Default root with no password?",
                      "MySQL <5.6.51 CVE-2021-22096",
                      "User Defined Function (UDF) privilege escalation"],
    "PostgreSQL":    ["pg_hba.conf 'trust' auth = unauthenticated access",
                      "COPY TO/FROM PROGRAM for RCE if superuser"],
    "MSSQL":         ["xp_cmdshell enabled? OS command execution",
                      "SA account with default/blank password",
                      "CVE-2020-0618 SSRS RCE"],
    "Oracle":        ["Default credentials: scott/tiger, system/manager",
                      "CVE-2012-1675 (TNS Listener poisoning)"],
    "Redis":         ["No auth by default — set requirepass",
                      "CVE-2022-0543 (Lua sandbox escape, Debian/Ubuntu)",
                      "Arbitrary file write via CONFIG SET dir + SAVE"],
    "MongoDB":       ["No auth by default in versions <3.0",
                      "Exposed without bind_ip restriction?",
                      "CVE-2019-2386 (unauthenticated access)"],
    "Elasticsearch": ["No built-in auth pre-6.8/7.1 — data exposure",
                      "CVE-2015-1427 (Groovy sandbox escape)",
                      "Unauthenticated API access?"],
    "Docker":        ["Exposed API = full host RCE (mount /, exec container)",
                      "CVE-2019-5736 (runc container escape)",
                      "CVE-2020-15257 (Containerd abstract socket)"],
    "Docker-TLS":    ["Verify client cert enforcement",
                      "Weak TLS config?"],
    "K8s API":       ["Anonymous API access? kubectl --insecure-skip-tls",
                      "CVE-2018-1002105 (privilege escalation via aggregated API)",
                      "RBAC misconfiguration — ClusterAdmin binding?"],
    "K8s Kubelet":   ["Unauthenticated Kubelet API = exec into any pod",
                      "CVE-2018-1002103 (unauthenticated exec)",
                      "Port 10255 = read-only, no auth required"],
    "K8s Kubelet-RO":["Read-only Kubelet port — pod/node info leak"],
    "etcd":          ["etcd without auth = full cluster key-value RW access",
                      "CVE-2018-16886 (auth bypass)"],
    "VNC":           ["Weak or no password?",
                      "CVE-2019-15681 (LibVNCServer memory leak)",
                      "CVE-2018-7737 (UltraVNC stack overflow)"],
    "SNMP":          ["Community string 'public'? full MIB info leak",
                      "SNMPv1/v2c = cleartext — use SNMPv3",
                      "CVE-2002-0013 (SNMP buffer overflow)"],
    "NFS":           ["no_root_squash = remote root access possible",
                      "showmount -e <host> to enumerate exports"],
    "Kerberos":      ["AS-REP Roasting if pre-auth disabled",
                      "Kerberoastable service accounts?"],
    "LDAP":          ["Anonymous bind allowed?",
                      "CVE-2021-44228 log4j via LDAP JNDI lookup",
                      "LDAP injection in web applications"],
    "Jupyter":       ["No-auth Jupyter = arbitrary Python execution on server",
                      "CVE-2022-24758 (unauthenticated RCE)"],
    "Kibana":        ["CVE-2019-7609 (Timelion prototype pollution RCE)",
                      "CVE-2022-38778 (path traversal)"],
    "WebLogic":      ["CVE-2021-2109 (JNDI RCE)",
                      "CVE-2020-14882 (unauthenticated RCE)",
                      "CVE-2019-2729 (deserialization RCE)"],
    "RPC":           ["portmapper enumeration: rpcinfo -p <host>",
                      "NFS and NIS exposure via RPC"],
    "rsync":         ["Anonymous read/write? rsync <host>::",
                      "CVE-2017-16548 (heap overflow)"],
    "ZooKeeper":     ["No auth by default — full ZNode read/write",
                      "CVE-2019-0201 (ACL bypass)",
                      "stat/dump commands leak cluster info"],
    "WinRM-HTTP":    ["Cleartext WinRM — credential sniffing possible",
                      "CVE-2021-31166 (HTTP.sys RCE)"],
    "WinRM-HTTPS":   ["Check for self-signed cert and weak TLS"],
    "Memcached":     ["No auth — data exposure + amplification DDoS vector",
                      "CVE-2016-8704 (integer overflow RCE)"],
    "Cassandra":     ["Default credentials: cassandra/cassandra",
                      "No auth by default in some configs"],
    "Kafka":         ["No auth by default in older versions",
                      "CVE-2018-17196 (unauthenticated topic deletion)"],
    "RabbitMQ-Mgmt": ["Default credentials: guest/guest",
                      "CVE-2021-22116 (DoS)"],
    "AMQP/RabbitMQ": ["Default credentials: guest/guest",
                      "CVE-2019-11287 (stack overflow)"],
    "Consul":        ["No ACL = full service mesh RW access",
                      "CVE-2021-37219 (raft RCE)"],
    "Grafana/Node":  ["CVE-2021-43798 (path traversal — arbitrary file read)",
                      "Default credentials: admin/admin"],
    "OpenVPN":       ["CVE-2017-7508 (DoS via malformed IPv6)",
                      "Check for weak TLS and certificate pinning"],
    "Webmin":        ["CVE-2019-15107 (unauthenticated RCE)",
                      "CVE-2022-0824 (authenticated RCE)"],
    "GlassFish":     ["CVE-2017-1000028 (path traversal)",
                      "Default admin console exposed?"],
    "Solr":          ["CVE-2019-0193 (DataImportHandler RCE)",
                      "CVE-2021-27905 (SSRF)"],
    "ActiveMQ":      ["CVE-2023-46604 (ClassInfo deserialization RCE)",
                      "Default credentials: admin/admin"],
    "Neo4j":         ["No auth by default in older versions",
                      "Bolt protocol exposed externally?"],
    "MQTT":          ["No auth broker? IoT credential theft",
                      "CVE-2019-11779 (Mosquitto DoS)"],
    "Squid":         ["CVE-2020-25097 (SSRF via Gopher)",
                      "Open proxy? internal network pivoting"],
    "VMware":        ["CVE-2021-22005 (unauthenticated file upload RCE)",
                      "CVE-2021-21985 (vCenter RCE)"],
    "Hadoop-HDFS":   ["Unauthenticated HDFS API — read/write any file",
                      "CVE-2018-11761 (YARN RCE)"],
    "SVN":           ["Anonymous checkout? source code exposure"],
    "Git":           ["Anonymous git-daemon — full repo clone possible"],
    "Metasploit":    ["Metasploit RPC port — ensure strong auth"],
    "Spark":         ["Unauthenticated Spark cluster — RCE via job submission"],
    "SAP":           ["CVE-2020-6287 RECON (unauthenticated admin takeover)",
                      "Default credentials / missing SAP security notes"],
    "IRC":           ["Anonymous access? C2 botnet traffic common on IRC"],
    "TFTP":          ["No auth — arbitrary file read/write",
                      "PXE boot config exposure"],
    "Finger":        ["User enumeration: finger @<host>",
                      "Disable immediately — legacy protocol"],
    "IPP":           ["CVE-2019-8675 (CUPS RCE)",
                      "CVE-2023-32360 (CUPS info disclosure)"],
    "RTSP":          ["Unauthenticated live stream access?",
                      "CVE-2020-3110 (Cisco camera RCE)"],
    "InfluxDB-HTTP": ["No auth by default in InfluxDB 1.x",
                      "CVE-2019-20933 (JWT none algorithm)"],
    "Prometheus":    ["No auth — metrics and target config exposed",
                      "/api/v1/targets leaks internal host inventory"],
}

# ════════════════════════════════════════════════════════════════════════════
#   OS FINGERPRINTING
# ════════════════════════════════════════════════════════════════════════════

TTL_OS_MAP = [
    (64,  "Linux / Android / macOS"),
    (128, "Windows"),
    (254, "Solaris / Network Device"),
    (255, "Cisco IOS / Solaris / Network Device"),
]

TCP_WINDOW_OS = {
    5840:  "Linux (kernel 2.4)",
    14600: "Linux (kernel 2.6+)",
    65535: "macOS / FreeBSD / Windows",
    8192:  "Windows (older)",
    29200: "Linux (kernel 3.x+)",
    64240: "Linux (recent)",
}

def guess_os_from_ttl(ttl: int) -> str:
    for threshold, name in TTL_OS_MAP:
        if ttl <= threshold:
            return name
    return "Unknown"

def probe_ttl(target: str, timeout: float = 2.0) -> Optional[int]:
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt   = IP(dst=target) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply and reply.haslayer(IP):
            return reply[IP].ttl
    except Exception:
        pass
    return None

def probe_tcp_window(target: str, port: int, timeout: float = 2.0) -> Optional[int]:
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt   = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply and reply.haslayer(TCP):
            flags = reply[TCP].flags
            if flags & 0x12:
                rst = IP(dst=target) / TCP(
                    sport=reply[TCP].dport, dport=port,
                    flags="R", seq=reply[TCP].ack)
                sr1(rst, timeout=0.5, verbose=0)
                return reply[TCP].window
    except Exception:
        pass
    return None

# ════════════════════════════════════════════════════════════════════════════
#   SCAN ENGINES
# ════════════════════════════════════════════════════════════════════════════

def syn_scan(target: str, port: int, timeout: float = 1.5) -> str:
    if not SCAPY_AVAILABLE:
        return connect_scan(target, port, timeout)
    try:
        pkt   = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None:
            return "filtered"
        if reply.haslayer(TCP):
            flags = reply[TCP].flags
            if flags & 0x12:
                rst = IP(dst=target) / TCP(
                    sport=reply[TCP].dport, dport=port,
                    flags="R", seq=reply[TCP].ack)
                sr1(rst, timeout=0.5, verbose=0)
                return "open"
            elif flags & 0x04:
                return "closed"
        if reply.haslayer(ICMP):
            icmp = reply[ICMP]
            if icmp.type == 3 and icmp.code in (1, 2, 3, 9, 10, 13):
                return "filtered"
        return "filtered"
    except Exception:
        return "filtered"


def connect_scan(target: str, port: int, timeout: float = 1.5) -> str:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, OSError):
        return "filtered"
    except Exception:
        return "filtered"


def udp_scan(target: str, port: int, timeout: float = 2.0) -> str:
    if not SCAPY_AVAILABLE:
        return "unknown"
    try:
        pkt   = IP(dst=target) / UDP(dport=port) / b"\x00" * 8
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None:
            return "open|filtered"
        if reply.haslayer(UDP):
            return "open"
        if reply.haslayer(ICMP):
            icmp = reply[ICMP]
            if icmp.type == 3 and icmp.code == 3:
                return "closed"
            if icmp.type == 3 and icmp.code in (1, 2, 9, 10, 13):
                return "filtered"
        return "open|filtered"
    except Exception:
        return "unknown"


def null_scan(target: str, port: int, timeout: float = 1.5) -> str:
    if not SCAPY_AVAILABLE:
        return "unknown"
    try:
        pkt   = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags=0)
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None:
            return "open|filtered"
        if reply.haslayer(TCP) and reply[TCP].flags & 0x04:
            return "closed"
        return "open|filtered"
    except Exception:
        return "unknown"


def fin_scan(target: str, port: int, timeout: float = 1.5) -> str:
    if not SCAPY_AVAILABLE:
        return "unknown"
    try:
        pkt   = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="F")
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None:
            return "open|filtered"
        if reply.haslayer(TCP) and reply[TCP].flags & 0x04:
            return "closed"
        return "open|filtered"
    except Exception:
        return "unknown"


def xmas_scan(target: str, port: int, timeout: float = 1.5) -> str:
    if not SCAPY_AVAILABLE:
        return "unknown"
    try:
        pkt   = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="FPU")
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None:
            return "open|filtered"
        if reply.haslayer(TCP) and reply[TCP].flags & 0x04:
            return "closed"
        return "open|filtered"
    except Exception:
        return "unknown"


SCAN_ENGINES = {
    "syn":     syn_scan,
    "connect": connect_scan,
    "udp":     udp_scan,
    "null":    null_scan,
    "fin":     fin_scan,
    "xmas":    xmas_scan,
}

# ════════════════════════════════════════════════════════════════════════════
#   BANNER GRAB  (protocol-aware)
# ════════════════════════════════════════════════════════════════════════════

BANNER_PROBES: Dict[int, bytes] = {
    21:    b"",
    22:    b"",
    25:    b"EHLO ospecter\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: ospecter\r\n\r\n",
    110:   b"",
    143:   b"",
    443:   None,
    3306:  b"",
    5432:  b"",
    6379:  b"PING\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: ospecter\r\n\r\n",
    27017: b"",
    8080:  b"HEAD / HTTP/1.0\r\nHost: ospecter\r\n\r\n",
    8443:  None,
    11211: b"stats\r\n",
}

def grab_banner(target: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        probe = BANNER_PROBES.get(port, b"")
        if probe is None:
            return _grab_ssl_banner(target, port, timeout)
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                s.sendall(probe)
            try:
                data = s.recv(2048)
            except socket.timeout:
                return None
            if not data:
                return None
            decoded = data.decode("utf-8", errors="ignore").strip()
            for line in decoded.splitlines():
                line = line.strip()
                if line:
                    return line[:140]
    except Exception:
        pass
    return None


def _grab_ssl_banner(target: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as s:
                s.settimeout(timeout)
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: ospecter\r\n\r\n")
                try:
                    data = s.recv(2048)
                    if data:
                        line = data.decode("utf-8", errors="ignore").strip().splitlines()[0]
                        return f"[TLS] {line[:120]}"
                except socket.timeout:
                    pass
                ver = s.version()
                return f"[TLS] {ver}" if ver else "[TLS] connected"
    except Exception:
        return None

# ════════════════════════════════════════════════════════════════════════════
#   SSL/TLS AUDITOR
# ════════════════════════════════════════════════════════════════════════════

def ssl_audit(target: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "supported": False,
        "version":   None,
        "cipher":    None,
        "cert_cn":   None,
        "cert_exp":  None,
        "cert_expired": False,
        "issues":    [],
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as s:
                result["supported"] = True
                result["version"]   = s.version()
                result["cipher"]    = s.cipher()[0] if s.cipher() else None
                cert = s.getpeercert()
                if cert:
                    for field in cert.get("subject", []):
                        for k, v in field:
                            if k == "commonName":
                                result["cert_cn"] = v
                    not_after = cert.get("notAfter")
                    if not_after:
                        result["cert_exp"] = not_after
                        exp_dt = datetime.datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z")
                        if exp_dt < datetime.datetime.utcnow():
                            result["cert_expired"] = True
                            result["issues"].append("Certificate EXPIRED")
                        elif exp_dt < datetime.datetime.utcnow() + datetime.timedelta(days=30):
                            result["issues"].append("Certificate expires in <30 days")
                ver = s.version()
                if ver in ("SSLv2", "SSLv3"):
                    result["issues"].append(f"Insecure protocol: {ver}")
                elif ver == "TLSv1":
                    result["issues"].append("Deprecated: TLS 1.0")
                elif ver == "TLSv1.1":
                    result["issues"].append("Deprecated: TLS 1.1")
                cipher_name = result["cipher"] or ""
                if any(w in cipher_name for w in ("RC4", "NULL", "EXPORT")):
                    result["issues"].append(f"Weak cipher: {cipher_name}")
    except ssl.SSLError as e:
        result["issues"].append(f"SSL error: {e.reason}")
    except Exception:
        pass
    return result

# ════════════════════════════════════════════════════════════════════════════
#   WAF DETECTION
# ════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: Dict[str, str] = {
    "cloudflare":    "Cloudflare",
    "cf-ray":        "Cloudflare",
    "__cfduid":      "Cloudflare",
    "x-sucuri":      "Sucuri",
    "x-akamai":      "Akamai",
    "x-cache":       "CDN/Proxy (generic)",
    "x-cdn":         "CDN (generic)",
    "incapsula":     "Imperva Incapsula",
    "x-iinfo":       "Imperva Incapsula",
    "server: bigip": "F5 BIG-IP",
    "x-dynatrace":   "Dynatrace APM",
    "server: awselb":"AWS ELB",
    "x-amzn":        "AWS",
    "fastly":        "Fastly CDN",
    "x-distil":      "Distil Networks",
    "barracuda":     "Barracuda WAF",
}

def detect_waf(target: str, port: int = 80, timeout: float = 5.0) -> Optional[str]:
    try:
        use_ssl = port in (443, 8443)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = socket.create_connection((target, port), timeout=timeout)
            s   = ctx.wrap_socket(raw, server_hostname=target)
        else:
            s = socket.create_connection((target, port), timeout=timeout)
        with s:
            s.settimeout(timeout)
            req = (f"GET /?x=<script>alert(1)</script> HTTP/1.0\r\n"
                   f"Host: {target}\r\n"
                   f"User-Agent: OSpecter-WAF-Probe/2.0\r\n\r\n")
            s.sendall(req.encode())
            resp = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
                    if len(resp) > 8192: break
                except socket.timeout:
                    break
        resp_lower = resp.decode("utf-8", errors="ignore").lower()
        for sig, name in WAF_SIGNATURES.items():
            if sig.lower() in resp_lower:
                return name
        if b"HTTP/1" in resp[:20] and (b" 403 " in resp[:50] or b" 406 " in resp[:50]):
            if any(w in resp_lower for w in ["blocked", "forbidden", "firewall", "waf"]):
                return "Generic WAF (blocked request)"
    except Exception:
        pass
    return None

# ════════════════════════════════════════════════════════════════════════════
#   SCRIPTED PROBES
# ════════════════════════════════════════════════════════════════════════════

def probe_http_methods(target: str, port: int, timeout: float = 5.0) -> List[str]:
    allowed = []
    methods = ["GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE", "TRACE", "PATCH"]
    try:
        use_ssl = port in (443, 8443)
        for method in methods:
            try:
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    raw = socket.create_connection((target, port), timeout=timeout)
                    s   = ctx.wrap_socket(raw, server_hostname=target)
                else:
                    s = socket.create_connection((target, port), timeout=timeout)
                with s:
                    s.settimeout(timeout)
                    req = f"{method} / HTTP/1.0\r\nHost: {target}\r\n\r\n"
                    s.sendall(req.encode())
                    resp = s.recv(512).decode("utf-8", errors="ignore")
                    code = resp[9:12] if len(resp) > 12 else "???"
                    if code not in ("405", "501"):
                        allowed.append(f"{method} → {code}")
            except Exception:
                pass
    except Exception:
        pass
    return allowed


def probe_ftp_anonymous(target: str, port: int = 21, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.recv(1024)
            s.sendall(b"USER anonymous\r\n")
            s.recv(512)
            s.sendall(b"PASS ospecter@owlsec.org\r\n")
            r2 = s.recv(512).decode("utf-8", errors="ignore")
            return "230" in r2
    except Exception:
        return False


def probe_redis_info(target: str, port: int = 6379, timeout: float = 3.0) -> Optional[str]:
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"INFO server\r\n")
            data = s.recv(4096).decode("utf-8", errors="ignore")
            for line in data.splitlines():
                if line.startswith("redis_version"):
                    return line.strip()
    except Exception:
        pass
    return None


def probe_smb_null_session(target: str, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((target, 445), timeout=timeout) as s:
            s.settimeout(timeout)
            neg = (
                b"\x00\x00\x00\x2f"
                b"\xff\x53\x4d\x42"
                b"\x72"
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00"
                b"\xff\xff\x00\x00\x00\x00"
                b"\x00\x0c\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
            )
            s.sendall(neg)
            resp = s.recv(512)
            return len(resp) > 32 and b"\xff\x53\x4d\x42" in resp
    except Exception:
        return False

# ════════════════════════════════════════════════════════════════════════════
#   NETWORK SWEEP
# ════════════════════════════════════════════════════════════════════════════

def arp_sweep(cidr: str, timeout: float = 2.0) -> List[Dict[str, str]]:
    if not SCAPY_AVAILABLE:
        return []
    try:
        net    = ipaddress.IPv4Network(cidr, strict=False)
        pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        ans, _ = srp(pkt, timeout=timeout, verbose=0)
        return sorted(
            [{"ip": rcv[ARP].psrc, "mac": rcv[Ether].src} for _, rcv in ans],
            key=lambda x: ipaddress.IPv4Address(x["ip"])
        )
    except Exception:
        return []


def icmp_sweep(cidr: str, timeout: float = 2.0) -> List[str]:
    if not SCAPY_AVAILABLE:
        return []
    try:
        net   = ipaddress.IPv4Network(cidr, strict=False)
        hosts = [str(h) for h in net.hosts()]
        live  = []
        lock  = threading.Lock()

        def ping(ip):
            try:
                reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0)
                if reply:
                    with lock:
                        live.append(ip)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as ex:
            list(ex.map(ping, hosts))
        return sorted(live, key=lambda x: ipaddress.IPv4Address(x))
    except Exception:
        return []

# ════════════════════════════════════════════════════════════════════════════
#   TRACEROUTE
# ════════════════════════════════════════════════════════════════════════════

def traceroute_host(target: str, max_hops: int = 30,
                    timeout: float = 2.0) -> List[Dict[str, Any]]:
    if not SCAPY_AVAILABLE:
        return []
    hops = []
    for ttl in range(1, max_hops + 1):
        try:
            pkt   = IP(dst=target, ttl=ttl) / ICMP()
            t0    = time.time()
            reply = sr1(pkt, timeout=timeout, verbose=0)
            rtt   = round((time.time() - t0) * 1000, 2)
            if reply is None:
                hops.append({"ttl": ttl, "ip": "*", "rtt_ms": None})
            else:
                hop_ip = reply[IP].src
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except Exception:
                    hostname = hop_ip
                hops.append({"ttl": ttl, "ip": hop_ip,
                             "hostname": hostname, "rtt_ms": rtt})
                if hop_ip == target:
                    break
        except Exception:
            hops.append({"ttl": ttl, "ip": "error", "rtt_ms": None})
    return hops


# ════════════════════════════════════════════════════════════════════════════
#   RISK SCORE ENGINE  (NEW v1.1)
# ════════════════════════════════════════════════════════════════════════════

RISK_WEIGHTS: Dict[int, int] = {
    21: 40, 23: 50, 445: 70, 3389: 65, 5900: 55, 6379: 60,
    27017: 60, 9200: 55, 2375: 80, 10250: 75, 11211: 50,
    1433: 55, 3306: 45, 5432: 45, 161: 40, 2049: 55,
    4444: 70, 7001: 65, 8080: 20, 80: 10, 443: 10, 22: 15,
    25: 25, 110: 20, 143: 20, 389: 35, 636: 30, 873: 40,
    50000: 50, 61616: 55, 15672: 45, 8500: 50, 6443: 60,
}

def compute_risk_score(open_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate a 0-100 risk score from open ports + CVE hint presence."""
    score = 0
    findings: List[str] = []
    for r in open_results:
        port = r.get("port", 0)
        svc  = r.get("service", "unknown")
        w = RISK_WEIGHTS.get(port, 12 if svc != "unknown" else 5)
        score += w
        if CVE_HINTS.get(svc):
            score += 8
            findings.append(f":{port}/{svc} (+{w}+CVE)")
        else:
            findings.append(f":{port}/{svc} (+{w})")
    score = min(100, score)
    if score >= 75:
        tier, color = "CRITICAL", C.RED
    elif score >= 50:
        tier, color = "HIGH", C.ORANGE
    elif score >= 25:
        tier, color = "MEDIUM", C.YELLOW
    elif score > 0:
        tier, color = "LOW", C.GREEN
    else:
        tier, color = "NONE", C.DIM
    return {"score": score, "tier": tier, "color": color, "findings": findings}


# ════════════════════════════════════════════════════════════════════════════
#   HTTP SECURITY HEADERS  (NEW v1.1)
# ════════════════════════════════════════════════════════════════════════════

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
)

def probe_http_security_headers(target: str, port: int = 443,
                                timeout: float = 5.0) -> Dict[str, Any]:
    """Fetch response headers and report missing security headers."""
    use_ssl = port in (443, 8443, 9443)
    result: Dict[str, Any] = {
        "port": port, "present": {}, "missing": [], "server": None, "status": None
    }
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((target, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=target)
        else:
            sock = socket.create_connection((target, port), timeout=timeout)
        req = (
            f"GET / HTTP/1.1\r\nHost: {target}\r\n"
            f"User-Agent: OSpecter/1.1\r\nConnection: close\r\n\r\n"
        )
        sock.settimeout(timeout)
        sock.sendall(req.encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536 or b"\r\n\r\n" in data:
                break
        sock.close()
        header_blob = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
        lines = header_blob.split("\r\n")
        if lines:
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                result["status"] = int(parts[1])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        result["server"] = headers.get("server")
        for h in SECURITY_HEADERS:
            val = headers.get(h.lower())
            if val:
                result["present"][h] = val[:120]
            else:
                result["missing"].append(h)
    except Exception as e:
        result["error"] = str(e)
    return result


# ════════════════════════════════════════════════════════════════════════════
#   MAC OUI VENDOR LOOKUP  (NEW v1.1)
# ════════════════════════════════════════════════════════════════════════════

OUI_VENDORS: Dict[str, str] = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:1C:42": "Parallels", "00:15:5D": "Hyper-V / Microsoft",
    "00:16:3E": "Xen", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "F0:18:98": "Apple", "AC:DE:48": "Apple", "3C:22:FB": "Apple",
    "00:1E:C2": "Apple", "28:CF:E9": "Apple", "00:26:BB": "Apple",
    "A4:83:E7": "Apple", "F4:F5:D8": "Google", "3C:5A:B4": "Google",
    "00:1A:11": "Google", "18:B4:30": "Nest",
    "00:E0:4C": "Realtek", "00:0D:3A": "Microsoft Azure",
    "D8:9D:67": "Huawei", "00:E0:FC": "Huawei",
    "00:1D:7E": "Cisco-Linksys", "00:0F:66": "Cisco-Linksys",
    "00:1A:A1": "Cisco", "00:1B:0D": "Cisco", "00:1C:0E": "Cisco",
    "00:23:04": "Cisco", "00:25:45": "Cisco", "68:86:A7": "Cisco",
    "00:24:D7": "Intel", "00:1E:67": "Intel", "3C:97:0E": "Intel",
    "A0:36:9F": "Intel", "00:25:90": "Super Micro",
}

def mac_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    oui = mac.upper().replace("-", ":")[:8]
    return OUI_VENDORS.get(oui, "Unknown")


# ════════════════════════════════════════════════════════════════════════════
#   SCAN DIFF  (NEW v1.1)
# ════════════════════════════════════════════════════════════════════════════

def diff_scan_reports(path_a: str, path_b: str) -> Dict[str, Any]:
    """Compare two OSpecter JSON reports; return added/removed/changed ports."""
    with open(path_a, "r", encoding="utf-8") as f:
        a = json.load(f)
    with open(path_b, "r", encoding="utf-8") as f:
        b = json.load(f)

    def open_map(data: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
        out = {}
        for r in data.get("results", []):
            if "open" in str(r.get("state", "")):
                out[int(r["port"])] = r
        return out

    ma, mb = open_map(a), open_map(b)
    added   = sorted(set(mb) - set(ma))
    removed = sorted(set(ma) - set(mb))
    common  = sorted(set(ma) & set(mb))
    changed = []
    for port in common:
        sa, sb = ma[port].get("service"), mb[port].get("service")
        ba = (ma[port].get("banner") or "")[:80]
        bb = (mb[port].get("banner") or "")[:80]
        if sa != sb or ba != bb:
            changed.append({"port": port, "old_service": sa, "new_service": sb,
                            "old_banner": ba, "new_banner": bb})
    return {
        "target_a": a.get("target"), "target_b": b.get("target"),
        "added": [{"port": port, "service": mb[port].get("service"),
                   "banner": mb[port].get("banner")} for port in added],
        "removed": [{"port": port, "service": ma[port].get("service"),
                     "banner": ma[port].get("banner")} for port in removed],
        "changed": changed,
    }


# ════════════════════════════════════════════════════════════════════════════
#   PORT PARSER
# ════════════════════════════════════════════════════════════════════════════

TOP_100  = sorted(SERVICE_MAP.keys())[:100]
TOP_1000 = sorted(set(list(SERVICE_MAP.keys()) + list(range(1, 1025))))[:1000]
ALL_PORTS = list(range(1, 65536))

def parse_ports(port_str: str) -> List[int]:
    port_str = port_str.strip().lower()
    if port_str in ("top100", ""):   return TOP_100
    if port_str == "top1000":        return TOP_1000
    if port_str in ("all", "1-65535"): return ALL_PORTS
    ports: set = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    if not ports:
        raise ValueError("No valid ports.")
    return sorted(ports)

# ════════════════════════════════════════════════════════════════════════════
#   SCAN RUNNER
# ════════════════════════════════════════════════════════════════════════════

def run_scan(
    target:        str,
    ports:         List[int],
    scan_type:     str   = "syn",
    threads:       int   = 200,
    timeout:       float = 1.5,
    banner_grab:   bool  = True,
    show_closed:   bool  = False,
    show_filtered: bool  = False,
) -> List[Dict[str, Any]]:

    root   = is_root()
    raw_ok = root and SCAPY_AVAILABLE

    if scan_type == "syn" and not root:
        print(c("  [!] SYN requires root — falling back to connect.", C.YELLOW))
        scan_type = "connect"
    elif scan_type in ("udp", "null", "fin", "xmas") and not raw_ok:
        reason = "root" if not root else "Scapy"
        print(c(f"  [!] {scan_type.upper()} requires {reason} — falling back to connect.", C.YELLOW))
        scan_type = "connect"

    scan_fn = SCAN_ENGINES.get(scan_type, connect_scan)
    results:    List[Dict[str, Any]] = []
    done        = 0
    total       = len(ports)
    open_count  = 0
    lock        = threading.Lock()
    t_start     = time.time()

    def scan_port(port: int) -> Dict[str, Any]:
        state = scan_fn(target, port, timeout)
        entry = {
            "port":    port,
            "state":   state,
            "service": SERVICE_MAP.get(port, "unknown"),
            "banner":  None,
            "ssl":     None,
        }
        if state in ("open", "open|filtered") and banner_grab:
            entry["banner"] = grab_banner(target, port, min(timeout + 0.5, 3.0))
        if state in ("open", "open|filtered") and port in (443, 8443, 636, 993, 995):
            entry["ssl"] = ssl_audit(target, port)
        return entry

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, p): p for p in ports}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                port   = futures[future]
                result = {"port": port, "state": "filtered",
                          "service": SERVICE_MAP.get(port, "unknown"),
                          "banner": None, "ssl": None}

            with lock:
                done += 1
                results.append(result)
                state = result["state"]
                port  = result["port"]
                svc   = result["service"]

                if "open" in state:
                    open_count += 1

                elapsed = time.time() - t_start
                rate    = done / elapsed if elapsed > 0 else 0
                pct     = int(done / total * 40)
                bar     = c("█" * pct, C.MAGENTA) + c("░" * (40 - pct), C.DIM)
                eta     = (total - done) / rate if rate > 0 else 0
                sys.stdout.write(
                    f"\r  [{bar}] {done}/{total}  "
                    f"{c(f'{rate:.0f} p/s', C.GRAY)}  "
                    f"ETA {c(f'{eta:.0f}s', C.GRAY)}  "
                    f"Open: {c(str(open_count), C.GREEN)}  "
                )
                sys.stdout.flush()

                if "open" in state:
                    bnr     = f" → {result['banner']}" if result.get("banner") else ""
                    ssl_tag = c(" [TLS]", C.TEAL) if result.get("ssl", {}) and \
                        result["ssl"].get("supported") else ""
                    print(
                        f"\r  {c('[' + state.upper() + ']', C.GREEN + C.BOLD):<26} "
                        f"{c(str(port), C.WHITE):<8} "
                        f"{c(svc, C.CYAN):<22}"
                        f"{ssl_tag}"
                        f"{c(bnr[:60], C.DIM)}" + " " * 8
                    )
                elif state == "closed" and show_closed:
                    print(f"\r  {c('[CLOSED]', C.GRAY):<26} "
                          f"{c(str(port), C.DIM):<8} {svc}" + " " * 10)
                elif state == "filtered" and show_filtered:
                    print(f"\r  {c('[FILT]', C.YELLOW):<26} "
                          f"{c(str(port), C.DIM):<8} {svc}" + " " * 10)
    print()
    return results

# ════════════════════════════════════════════════════════════════════════════
#   HTML REPORT
# ════════════════════════════════════════════════════════════════════════════

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSpecter Report — {target}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
:root{{--bg:#07090d;--panel:#0d1118;--panel2:#101520;--border:#1e2630;
      --accent:#a855f7;--cyan:#06b6d4;--green:#22c55e;--yellow:#eab308;
      --red:#ef4444;--orange:#f97316;--teal:#2dd4bf;
      --text:#d1dce8;--dim:#4b5a6b;--dim2:#6e7e8f;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);
     font-family:'Share Tech Mono',monospace;font-size:13px;
     line-height:1.65;padding:2.5rem;}}
header{{border-bottom:1px solid var(--accent);padding-bottom:1.5rem;margin-bottom:2rem;}}
header pre{{color:var(--accent);font-size:10.5px;line-height:1.2;}}
h1{{font-family:'Rajdhani',sans-serif;font-size:2.2rem;color:var(--cyan);font-weight:700;margin:.5rem 0;}}
h2{{font-family:'Rajdhani',sans-serif;font-size:1.15rem;color:var(--accent);
    margin:2rem 0 .6rem;text-transform:uppercase;letter-spacing:2px;
    border-left:3px solid var(--accent);padding-left:10px;}}
.meta{{color:var(--dim2);margin:.4rem 0 1rem;font-size:12px;}}
.meta span{{color:var(--text);}}
table{{width:100%;border-collapse:collapse;margin-bottom:1.5rem;font-size:12.5px;}}
th{{background:var(--panel2);color:var(--cyan);padding:9px 14px;text-align:left;
    border-bottom:2px solid var(--border);font-family:'Rajdhani',sans-serif;
    font-weight:600;letter-spacing:1px;font-size:13px;}}
td{{padding:8px 14px;border-bottom:1px solid var(--border);vertical-align:top;}}
tr:hover td{{background:#0f151e;}}
.open{{color:var(--green);font-weight:bold;}}
.openf{{color:var(--teal);font-weight:bold;}}
.svc{{color:var(--cyan);}}
.banner{{color:var(--dim2);font-size:11.5px;word-break:break-all;}}
.tls{{color:var(--teal);font-size:11.5px;}}
.issue{{color:var(--red);font-size:11.5px;}}
.cve{{color:var(--yellow);font-size:11.5px;}}
.cve li{{list-style:none;padding-left:1em;margin:2px 0;}}
.cve li::before{{content:"⚑ ";color:var(--red);}}
.os-box,.stat{{display:inline-block;background:var(--panel);
    border:1px solid var(--border);padding:10px 20px;
    border-radius:6px;margin:6px 6px 6px 0;}}
.stat-bar{{display:flex;flex-wrap:wrap;gap:.5rem;margin:1rem 0;}}
.stat .num{{font-size:1.7rem;font-family:'Rajdhani',sans-serif;font-weight:700;}}
.stat .lbl{{color:var(--dim2);font-size:11px;text-transform:uppercase;letter-spacing:1px;}}
.os-box .label{{color:var(--dim2);font-size:11px;}}
.os-box .value{{color:var(--cyan);font-size:1.1rem;}}
.os-box .ttl{{color:var(--accent);}}
.pill{{display:inline-block;background:var(--panel2);border:1px solid var(--border);
       border-radius:3px;padding:1px 7px;font-size:11px;margin:1px;}}
footer{{color:var(--dim);font-size:11px;margin-top:3rem;
        border-top:1px solid var(--border);padding-top:1rem;text-align:center;}}
.waf-box{{display:inline-block;background:#1a0a2e;border:1px solid var(--accent);
          color:var(--accent);border-radius:4px;padding:4px 12px;margin:4px 0;}}
.hop-table td:nth-child(1){{color:var(--dim2);width:40px;}}
.hop-table td:nth-child(2){{color:var(--cyan);}}
.hop-table td:nth-child(3){{color:var(--text);}}
.hop-table td:nth-child(4){{color:var(--green);}}
</style>
</head>
<body>
<header>
<pre>{banner_art}</pre>
<h1>Scan Report</h1>
<div class="meta">
  Target: <span>{target}</span> &nbsp;|&nbsp;
  Scan: <span>{scan_type}</span> &nbsp;|&nbsp;
  Started: <span>{start_time}</span> &nbsp;|&nbsp;
  Duration: <span>{duration}s</span>
</div>
</header>
{summary_html}
{os_html}
{waf_html}
{ssl_html}
{ports_html}
{traceroute_html}
{scripted_html}
<footer>
  OSpecter {version} &nbsp;|&nbsp; {website} &nbsp;|&nbsp; {developer}
  &nbsp;|&nbsp; Generated: {generated_at}
  &nbsp;|&nbsp; <em>For authorized use only.</em>
</footer>
</body>
</html>"""


def build_html_report(
    target:     str,
    scan_type:  str,
    start_time: str,
    duration:   float,
    results:    List[Dict[str, Any]],
    ttl:        Optional[int],
    os_guess:   str,
    waf:        Optional[str] = None,
    traceroute: Optional[List[Dict[str, Any]]] = None,
    scripted:   Optional[Dict[str, Any]] = None,
) -> str:

    def esc(s: str) -> str:
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    open_r   = [r for r in results if "open" in r["state"]]
    filt_r   = [r for r in results if r["state"] == "filtered"]
    closed_r = [r for r in results if r["state"] == "closed"]

    summary_html = (
        '<h2>Summary</h2><div class="stat-bar">'
        f'<div class="stat"><div class="num">{len(results)}</div><div class="lbl">Scanned</div></div>'
        f'<div class="stat"><div class="num open">{len(open_r)}</div><div class="lbl">Open</div></div>'
        f'<div class="stat"><div class="num" style="color:var(--yellow)">{len(filt_r)}</div><div class="lbl">Filtered</div></div>'
        f'<div class="stat"><div class="num" style="color:var(--dim2)">{len(closed_r)}</div><div class="lbl">Closed</div></div>'
        '</div>'
    )

    os_html = (
        f'<h2>OS Fingerprint</h2><div class="os-box">'
        f'<div class="label">TTL-based heuristic</div>'
        f'<div class="value">{esc(os_guess)}</div>'
        f'<div class="ttl">TTL = {ttl}</div></div>'
    ) if ttl else (
        '<h2>OS Fingerprint</h2><div class="os-box">'
        '<div class="value" style="color:var(--dim2)">Could not determine</div></div>'
    )

    waf_html = f'<h2>WAF / CDN Detected</h2><div class="waf-box">⚡ {esc(waf)}</div>' \
        if waf else ""

    ssl_rows = []
    for r in open_r:
        si = r.get("ssl")
        if si and si.get("supported"):
            port    = r["port"]
            ver     = esc(si.get("version") or "?")
            cipher  = esc(si.get("cipher")  or "?")
            cn      = esc(si.get("cert_cn") or "?")
            exp     = esc(si.get("cert_exp") or "?")
            expired = si.get("cert_expired", False)
            issues  = si.get("issues", [])
            iss_h   = "".join(f'<div class="issue">⚠ {esc(i)}</div>' for i in issues)
            exp_style = 'style="color:var(--red)"' if expired else ''
            ssl_rows.append(
                f"<tr><td>{port}</td><td>{ver}</td><td>{cipher}</td>"
                f"<td>{cn}</td><td {exp_style}>{exp}</td>"
                f"<td>{iss_h or '—'}</td></tr>"
            )
    ssl_html = (
        "<h2>SSL/TLS Audit</h2>"
        "<table><tr><th>Port</th><th>Version</th><th>Cipher</th>"
        "<th>CN</th><th>Expires</th><th>Issues</th></tr>"
        + "".join(ssl_rows) + "</table>"
    ) if ssl_rows else ""

    if open_r:
        rows = ""
        for r in sorted(open_r, key=lambda x: x["port"]):
            svc   = esc(r.get("service","—"))
            bnr   = esc((r.get("banner") or "")[:120])
            hints = CVE_HINTS.get(r.get("service",""), [])
            cve_h = ('<ul class="cve">' +
                     "".join(f"<li>{esc(h)}</li>" for h in hints) +
                     "</ul>") if hints else "—"
            st    = r["state"]
            sc    = "open" if st == "open" else "openf"
            rows += (f"<tr><td>{r['port']}</td>"
                     f"<td class='{sc}'>{st.upper()}</td>"
                     f"<td class='svc'>{svc}</td>"
                     f"<td class='banner'>{bnr or '—'}</td>"
                     f"<td>{cve_h}</td></tr>")
        ports_html = (
            "<h2>Open Ports</h2>"
            "<table><tr><th>Port</th><th>State</th><th>Service</th>"
            "<th>Banner</th><th>CVE Hints</th></tr>"
            + rows + "</table>"
        )
    else:
        ports_html = "<h2>Open Ports</h2><p style='color:var(--dim2)'>No open ports found.</p>"

    traceroute_html = ""
    if traceroute:
        def _rtt(h):
            return f"{h['rtt_ms']} ms" if h.get('rtt_ms') else '*'
        rows = "".join(
            f"<tr><td>{h['ttl']}</td><td>{esc(h.get('ip','*'))}</td>"
            f"<td>{esc(h.get('hostname', h.get('ip','*')))}</td>"
            f"<td>{_rtt(h)}</td></tr>"
            for h in traceroute
        )
        traceroute_html = (
            "<h2>Traceroute</h2>"
            "<table class='hop-table'><tr><th>Hop</th><th>IP</th>"
            "<th>Hostname</th><th>RTT</th></tr>" + rows + "</table>"
        )

    scripted_html = ""
    if scripted:
        parts = []
        if scripted.get("http_methods"):
            parts.append("<b>HTTP Methods:</b> " +
                "".join(f'<span class="pill">{esc(m)}</span>'
                        for m in scripted["http_methods"]))
        if scripted.get("ftp_anon") is not None:
            val = ('<span style="color:var(--red)">ALLOWED — anonymous login</span>'
                   if scripted["ftp_anon"] else
                   '<span style="color:var(--green)">Blocked</span>')
            parts.append(f"<b>FTP Anonymous:</b> {val}")
        if scripted.get("redis_info"):
            parts.append(f"<b>Redis:</b> {esc(scripted['redis_info'])}")
        if scripted.get("smb_null") is not None:
            val = ('<span style="color:var(--red)">NULL session possible</span>'
                   if scripted["smb_null"] else
                   '<span style="color:var(--green)">Blocked</span>')
            parts.append(f"<b>SMB Null Session:</b> {val}")
        if parts:
            scripted_html = "<h2>Scripted Probes</h2>" + "<br>".join(parts)

    return HTML_TEMPLATE.format(
        banner_art      = BANNER_ART,
        target          = target,
        scan_type       = scan_type,
        start_time      = start_time,
        duration        = f"{duration:.1f}",
        summary_html    = summary_html,
        os_html         = os_html,
        waf_html        = waf_html,
        ssl_html        = ssl_html,
        ports_html      = ports_html,
        traceroute_html = traceroute_html,
        scripted_html   = scripted_html,
        version         = VERSION,
        website         = WEBSITE,
        developer       = DEVELOPER,
        generated_at    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

# ════════════════════════════════════════════════════════════════════════════
#   CSV EXPORT
# ════════════════════════════════════════════════════════════════════════════

def save_csv(path: str, target: str, results: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["target","port","state","service","banner",
                    "ssl_version","ssl_issues"])
        for r in sorted(results, key=lambda x: x["port"]):
            si = r.get("ssl") or {}
            w.writerow([
                target,
                r["port"],
                r["state"],
                r.get("service",""),
                (r.get("banner") or "").replace("\n"," "),
                si.get("version",""),
                "; ".join(si.get("issues",[])),
            ])

# ════════════════════════════════════════════════════════════════════════════
#   HELP
# ════════════════════════════════════════════════════════════════════════════

def show_help():
    W = 70
    def box_line(text="", color_code=C.WHITE):
        content = f"  {text}"
        pad = W - len(content) - 2
        print(c("║", C.MAGENTA) + c(content, color_code) +
              " " * max(pad, 0) + c("║", C.MAGENTA))

    print()
    print(c("╔" + "═" * W + "╗", C.MAGENTA))
    box_line("OSpecter v1.0 — Help & Reference", C.BOLD + C.CYAN)
    print(c("╠" + "═" * W + "╣", C.MAGENTA))

    sections = [
        ("SCAN MODES", [
            "syn      Stealth SYN scan (root + Scapy required)",
            "connect  Full TCP handshake — no root needed",
            "udp      UDP scan (root + Scapy required)",
            "null     NULL flags — RFC 793 FW bypass heuristic",
            "fin      FIN scan — stealthy vs stateless firewalls",
            "xmas     XMAS scan (FIN+PSH+URG flags)",
        ]),
        ("MENU OPTIONS", [
            "[1]  New Scan          — Configure & launch a port scan",
            "[2]  Network Sweep     — ICMP/ARP ping a CIDR range",
            "[3]  Traceroute        — Hop-by-hop path to target",
            "[4]  SSL/TLS Audit     — Certificate & cipher inspection",
            "[5]  Scripted Probes   — HTTP methods, FTP anon, Redis, SMB",
            "[H]  Help              — This page",
            "[0]  Exit",
        ]),
        ("PORT SPECS", [
            "top100     100 most common ports (default)",
            "top1000    1000 most common ports",
            "all        All 65535 ports",
            "1-1024     Port range",
            "22,80,443  Comma-separated list",
        ]),
        ("OS DETECTION", [
            "ICMP TTL:  <=64=Linux/macOS  <=128=Windows  <=255=Cisco",
            "TCP window size used as secondary indicator",
        ]),
        ("OUTPUTS", [
            "HTML  Dark-themed report with CVE hints & SSL audit",
            "JSON  Machine-readable — suitable for CI/CD pipelines",
            "CSV   Spreadsheet-compatible port list",
        ]),
        ("DISCLAIMER", [
            "SYN/NULL/FIN/XMAS/UDP require root + Scapy.",
            "Use ONLY on systems you own or have written authorization.",
            "Unauthorized scanning may violate computer crime laws.",
        ]),
    ]
    for title, lines in sections:
        print(c("║", C.MAGENTA) + " " * (W + 2) + c("║", C.MAGENTA))
        box_line(f"┌─ {title}", C.YELLOW + C.BOLD)
        for line in lines:
            box_line(f"│  {line}", C.WHITE)
    print(c("╚" + "═" * W + "╝", C.MAGENTA))
    print()

# ════════════════════════════════════════════════════════════════════════════
#   HELPERS
# ════════════════════════════════════════════════════════════════════════════

def print_header(title: str):
    print()
    print(c("─" * 66, C.MAGENTA))
    print(c(f"  {title}", C.BOLD + C.MAGENTA))
    print(c("─" * 66, C.MAGENTA))

def sec(title: str):
    print()
    print(c(f"  ┌─ {title}", C.YELLOW + C.BOLD))

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return input(c(f"  [»] {prompt}{suffix}: ", C.CYAN)).strip() or default

def ask_yn(prompt: str, default: bool = True) -> bool:
    d = "y" if default else "n"
    return (ask(prompt + " (y/n)", d).lower() != "n")

def resolve(target: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(c(f"  [*] Resolved: {target} → {ip}", C.DIM))
        return ip
    except socket.gaierror:
        print(c(f"  [✘] Cannot resolve: {target}", C.RED))
        return None

def print_open_summary(open_ports: List[Dict[str, Any]]):
    if not open_ports:
        return
    sec("Open Ports — Summary")
    print(f"  {c('PORT', C.DIM):<10} {c('STATE', C.DIM):<16} "
          f"{c('SERVICE', C.DIM):<22} {c('BANNER', C.DIM)}")
    print(c("  " + "─" * 68, C.DIM))
    for r in sorted(open_ports, key=lambda x: x["port"]):
        bnr   = (r.get("banner") or "")[:55]
        ssl_t = c(" [TLS]", C.TEAL) if r.get("ssl", {}) and \
            r["ssl"].get("supported") else ""
        print(f"  {c(str(r['port']), C.WHITE):<10} "
              f"{c(r['state'].upper(), C.GREEN):<22} "
              f"{c(r['service'], C.CYAN):<22}"
              f"{ssl_t} {c(bnr, C.DIM)}")
        for hint in CVE_HINTS.get(r.get("service",""), []):
            print(f"  {c('│', C.DIM)}  {c('⚑ ' + hint, C.YELLOW)}")

    # Risk score (v1.1)
    risk = compute_risk_score(open_ports)
    print()
    print(f"  {c('Risk Score:', C.WHITE)} {c(str(risk['score']), risk['color'] + C.BOLD)}/100  "
          f"[{c(risk['tier'], risk['color'] + C.BOLD)}]")
    if risk["findings"][:8]:
        for fnd in risk["findings"][:8]:
            print(c(f"    · {fnd}", C.DIM))
        if len(risk["findings"]) > 8:
            print(c(f"    · … +{len(risk['findings'])-8} more", C.DIM))



# ════════════════════════════════════════════════════════════════════════════
#   MODULE: NEW SCAN
# ════════════════════════════════════════════════════════════════════════════

def module_new_scan():
    print_header("New Scan — Configure & Launch")

    target_raw = ask("Target IP or hostname")
    if not target_raw:
        print(c("  [✘] No target provided.", C.RED)); return
    target = resolve(target_raw)
    if not target: return

    port_str  = ask("Ports", "top100")
    try:
        ports = parse_ports(port_str)
    except ValueError as e:
        print(c(f"  [✘] {e}", C.RED)); return

    scan_type = ask("Scan type (syn/connect/udp/null/fin/xmas)", "syn").lower()
    if scan_type not in SCAN_ENGINES:
        scan_type = "syn"

    try:
        threads = int(ask("Threads", "200"))
        if threads < 1: threads = 200
    except ValueError:
        threads = 200

    try:
        timeout = float(ask("Timeout (seconds)", "1.5"))
        if timeout <= 0: timeout = 1.5
    except ValueError:
        timeout = 1.5

    banner_grab   = ask_yn("Grab banners",                     True)
    show_closed   = ask_yn("Show closed ports",                False)
    show_filtered = ask_yn("Show filtered ports",              False)
    do_waf        = ask_yn("WAF/CDN detection",                False)
    do_ssl        = ask_yn("Deep SSL/TLS audit on TLS ports",  True)
    do_scripted   = ask_yn("Run scripted probes",              False)
    do_traceroute = ask_yn("Run traceroute after scan",        False)

    html_out = ask("HTML report filename (Enter to skip)", "")
    json_out = ask("JSON report filename (Enter to skip)", "")
    csv_out  = ask("CSV report filename (Enter to skip)",  "")

    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    t0         = time.time()

    sec("OS Fingerprint")
    ttl      = probe_ttl(target)
    os_guess = guess_os_from_ttl(ttl) if ttl else "Unknown"
    if ttl:
        win = probe_tcp_window(target, 80) or probe_tcp_window(target, 443)
        print(f"  {c('[✔]', C.GREEN)} TTL = {c(str(ttl), C.CYAN)} → {c(os_guess, C.WHITE)}")
        if win:
            win_hint = TCP_WINDOW_OS.get(win, f"Window={win}")
            print(f"  {c('[✔]', C.GREEN)} TCP Window → {c(win_hint, C.WHITE)}")
    else:
        print(c("  [!] No ICMP reply — OS unknown.", C.YELLOW))

    waf_result = None
    if do_waf:
        sec("WAF / CDN Detection")
        for waf_port in (80, 443):
            waf_result = detect_waf(target, waf_port)
            if waf_result:
                print(f"  {c('[⚡]', C.PURPLE + C.BOLD)} Detected: {c(waf_result, C.PURPLE)}")
                break
        if not waf_result:
            print(c("  [*] No WAF/CDN signatures detected.", C.DIM))

    sec(f"Scanning {len(ports)} ports  [{scan_type.upper()} | {threads} threads | {timeout}s]")
    print()
    results  = run_scan(target, ports, scan_type, threads, timeout,
                        banner_grab, show_closed, show_filtered)
    duration = time.time() - t0
    open_r   = [r for r in results if "open" in r["state"]]

    if do_ssl:
        for r in open_r:
            if r["port"] in (443, 8443, 636, 993, 995) and not r.get("ssl"):
                r["ssl"] = ssl_audit(target, r["port"])

    print(c("─" * 66, C.MAGENTA))
    print(c(f"  [✔] Scan complete in {duration:.1f}s", C.GREEN + C.BOLD))
    print(f"  {c('Open:', C.WHITE)} {c(str(len(open_r)), C.GREEN + C.BOLD)}  "
          f"{c('of', C.DIM)} {c(str(len(ports)), C.WHITE)} ports scanned")

    print_open_summary(open_r)

    scripted_result: Dict[str, Any] = {}
    if do_scripted and open_r:
        sec("Scripted Probes")
        open_set = {r["port"] for r in open_r}

        if any(p in open_set for p in (80, 443, 8080, 8443)):
            probe_port = next(p for p in (443, 80, 8443, 8080) if p in open_set)
            methods = probe_http_methods(target, probe_port)
            scripted_result["http_methods"] = methods
            print(c(f"  [HTTP] Methods on :{probe_port}: ", C.CYAN) +
                  "  ".join(c(m, C.WHITE) for m in methods))
            dangerous = [m for m in methods if any(d in m for d in ("PUT →","DELETE →","TRACE →"))]
            if dangerous:
                print(c(f"  [!] Dangerous: {', '.join(dangerous)}", C.YELLOW))

        if 21 in open_set:
            anon = probe_ftp_anonymous(target)
            scripted_result["ftp_anon"] = anon
            print((c("  [!] FTP ANONYMOUS LOGIN ALLOWED!", C.RED + C.BOLD)
                   if anon else c("  [✔] Anonymous FTP blocked.", C.GREEN)))

        if 6379 in open_set:
            info = probe_redis_info(target)
            scripted_result["redis_info"] = info
            if info:
                print(f"  {c('[REDIS]', C.CYAN)} {info}")
                print(c("  [!] Redis responding without auth!", C.RED))

        if 445 in open_set:
            smb = probe_smb_null_session(target)
            scripted_result["smb_null"] = smb
            print((c("  [!] SMB null session succeeded.", C.RED)
                   if smb else c("  [✔] SMB null session blocked.", C.GREEN)))

    trace_result = None
    if do_traceroute:
        if not SCAPY_AVAILABLE:
            print(c("  [!] Traceroute requires Scapy.", C.YELLOW))
        else:
            sec("Traceroute")
            try:
                max_hops = int(ask("Max hops", "30"))
            except ValueError:
                max_hops = 30
            trace_result = traceroute_host(target, max_hops)
            print(f"  {'HOP':<6} {'IP':<18} {'HOSTNAME':<35} RTT")
            print(c("  " + "─" * 66, C.DIM))
            for hop in trace_result:
                ip  = hop.get("ip","*")
                hn  = hop.get("hostname", ip)
                rtt = f"{hop['rtt_ms']} ms" if hop.get("rtt_ms") else "*"
                print(f"  {c(str(hop['ttl']), C.DIM):<12} {c(ip, C.CYAN):<24} "
                      f"{c(hn[:32], C.WHITE):<41} {c(rtt, C.GREEN)}")

    if html_out:
        try:
            html = build_html_report(target, scan_type.upper(), start_time,
                                     duration, results, ttl, os_guess,
                                     waf_result, trace_result, scripted_result)
            with open(html_out, "w", encoding="utf-8") as f:
                f.write(html)
            print(c(f"\n  [✔] HTML report → {html_out}", C.GREEN))
        except OSError as e:
            print(c(f"  [✘] HTML save failed: {e}", C.RED))

    if json_out:
        try:
            risk = compute_risk_score(open_r)
            data = {"target": target, "scan_type": scan_type,
                    "start_time": start_time, "duration_s": round(duration, 2),
                    "os_hint": {"ttl": ttl, "guess": os_guess},
                    "waf": waf_result, "results": results,
                    "risk": {"score": risk["score"], "tier": risk["tier"],
                             "findings": risk["findings"]},
                    "traceroute": trace_result, "scripted": scripted_result}
            with open(json_out, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(c(f"  [✔] JSON report → {json_out}", C.GREEN))
        except OSError as e:
            print(c(f"  [✘] JSON save failed: {e}", C.RED))

    if csv_out:
        try:
            save_csv(csv_out, target, results)
            print(c(f"  [✔] CSV report  → {csv_out}", C.GREEN))
        except OSError as e:
            print(c(f"  [✘] CSV save failed: {e}", C.RED))

# ════════════════════════════════════════════════════════════════════════════
#   MODULE: NETWORK SWEEP
# ════════════════════════════════════════════════════════════════════════════

def module_sweep():
    print_header("Network Sweep — CIDR Range Discovery")
    if not SCAPY_AVAILABLE:
        print(c("  [!] Network sweep requires Scapy.", C.YELLOW)); return

    cidr = ask("CIDR range (e.g. 192.168.1.0/24)")
    if not cidr:
        print(c("  [✘] No CIDR provided.", C.RED)); return
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as e:
        print(c(f"  [✘] Invalid CIDR: {e}", C.RED)); return

    try:
        timeout = float(ask("Timeout per host (s)", "2.0"))
    except ValueError:
        timeout = 2.0

    sweep_type = ask("Sweep method (arp/icmp/both)", "both").lower()
    live_ips: List[str] = []

    if sweep_type in ("arp", "both"):
        sec("ARP Sweep")
        print(c(f"  [*] ARP pinging {net.num_addresses} addresses…", C.DIM))
        for h in arp_sweep(cidr, timeout):
            vendor = mac_vendor(h.get("mac", ""))
            print(f"  {c('[ARP]', C.GREEN + C.BOLD)} {c(h['ip'], C.WHITE):<20} MAC: {c(h['mac'], C.CYAN)}  {c(vendor, C.DIM)}")
            live_ips.append(h["ip"])
        if not live_ips:
            print(c("  [*] No ARP responses.", C.DIM))

    if sweep_type in ("icmp", "both"):
        sec("ICMP Sweep")
        for h in icmp_sweep(cidr, timeout):
            if h not in live_ips:
                print(f"  {c('[ALIVE]', C.GREEN + C.BOLD)} {c(h, C.WHITE)}")
                live_ips.append(h)

    print(c(f"\n  [✔] Total live hosts: {len(set(live_ips))}", C.GREEN + C.BOLD))

# ════════════════════════════════════════════════════════════════════════════
#   MODULE: TRACEROUTE
# ════════════════════════════════════════════════════════════════════════════

def module_traceroute():
    print_header("Traceroute — Path Discovery")
    if not SCAPY_AVAILABLE:
        print(c("  [!] Traceroute requires Scapy.", C.YELLOW)); return

    target_raw = ask("Target IP or hostname")
    if not target_raw: return
    target = resolve(target_raw)
    if not target: return

    try:
        max_hops = int(ask("Max hops", "30"))
    except ValueError:
        max_hops = 30
    try:
        timeout = float(ask("Timeout per hop (s)", "2.0"))
    except ValueError:
        timeout = 2.0

    print()
    print(f"  {c('HOP', C.DIM):<8} {c('IP', C.DIM):<20} {c('HOSTNAME', C.DIM):<36} {c('RTT', C.DIM)}")
    print(c("  " + "─" * 70, C.DIM))
    hops = traceroute_host(target, max_hops, timeout)
    for hop in hops:
        ip  = hop.get("ip","*")
        hn  = hop.get("hostname", ip)
        rtt = f"{hop['rtt_ms']} ms" if hop.get("rtt_ms") else "*"
        print(f"  {c(str(hop['ttl']), C.DIM):<14} {c(ip, C.CYAN):<26} "
              f"{c(hn[:32], C.WHITE):<42} {c(rtt, C.GREEN)}")
    print(c(f"\n  [✔] {len(hops)} hops traced.", C.GREEN))

# ════════════════════════════════════════════════════════════════════════════
#   MODULE: SSL AUDIT
# ════════════════════════════════════════════════════════════════════════════

def module_ssl_audit():
    print_header("SSL/TLS Audit — Certificate & Cipher Inspector")

    target_raw = ask("Target IP or hostname")
    if not target_raw: return
    target = resolve(target_raw)
    if not target: return

    try:
        port = int(ask("Port", "443"))
    except ValueError:
        port = 443

    print(c(f"\n  [*] TLS audit on {target}:{port}…", C.DIM))
    r = ssl_audit(target, port)

    if not r["supported"]:
        print(c(f"  [✘] No TLS on {target}:{port}", C.RED)); return

    print(f"  {c('[✔]', C.GREEN)} TLS supported")
    print(f"  Version : {c(r['version'] or '?', C.CYAN)}")
    print(f"  Cipher  : {c(r['cipher']  or '?', C.WHITE)}")
    print(f"  Cert CN : {c(r['cert_cn'] or '?', C.WHITE)}")
    col = C.RED if r["cert_expired"] else C.GREEN
    print(f"  Expires : {c(r['cert_exp'] or '?', col)}")
    if r["issues"]:
        print()
        for issue in r["issues"]:
            print(c(f"  ⚠ {issue}", C.RED))
    else:
        print(c("  [✔] No TLS issues detected.", C.GREEN))

# ════════════════════════════════════════════════════════════════════════════
#   MODULE: SCRIPTED PROBES
# ════════════════════════════════════════════════════════════════════════════

def module_scripted_probes():
    print_header("Scripted Probes — Service Interaction")

    target_raw = ask("Target IP or hostname")
    if not target_raw: return
    target = resolve(target_raw)
    if not target: return

    options = {
        "1": ("HTTP Methods",     lambda: probe_http_methods(target, int(ask("Port","80")))),
        "2": ("FTP Anonymous",    lambda: probe_ftp_anonymous(target)),
        "3": ("Redis INFO",       lambda: probe_redis_info(target)),
        "4": ("SMB Null Session", lambda: probe_smb_null_session(target)),
    }
    print()
    for k, (name, _) in options.items():
        print(f"  {c('[' + k + ']', C.GREEN)}  {name}")
    print(f"  {c('[A]', C.CYAN)}  Run All")
    print()

    choice       = ask("Select probe").upper()
    probes_to_run = list(options.values()) if choice == "A" \
                    else ([options[choice]] if choice in options else [])

    for name, fn in probes_to_run:
        sec(name)
        try:
            result = fn()
            if isinstance(result, list):
                for item in result:
                    print(f"  {c('→', C.CYAN)} {item}")
                if not result:
                    print(c("  [*] No results.", C.DIM))
            elif isinstance(result, bool):
                if result:
                    print(c(f"  [!] {name}: VULNERABLE / ACCESSIBLE", C.RED + C.BOLD))
                else:
                    print(c(f"  [✔] {name}: Secured / Blocked", C.GREEN))
            elif result:
                print(f"  {c('→', C.CYAN)} {result}")
            else:
                print(c("  [*] No response.", C.DIM))
        except Exception as e:
            print(c(f"  [✘] Probe error: {e}", C.RED))


# ════════════════════════════════════════════════════════════════════════════
#   MODULE: HTTP SECURITY HEADERS  (NEW v1.1)
# ════════════════════════════════════════════════════════════════════════════

def module_http_headers():
    print_header("HTTP Security Headers — Missing Header Audit")
    target_raw = ask("Target IP or hostname")
    if not target_raw:
        return
    target = resolve(target_raw)
    if not target:
        return
    try:
        port = int(ask("Port", "443"))
    except ValueError:
        port = 443
    print(c(f"\n  [*] Probing security headers on {target}:{port}…", C.DIM))
    r = probe_http_security_headers(target, port)
    if r.get("error"):
        print(c(f"  [✘] {r['error']}", C.RED))
        return
    if r.get("status"):
        print(f"  {c('[✔]', C.GREEN)} HTTP status: {c(str(r['status']), C.CYAN)}")
    if r.get("server"):
        print(f"  Server : {c(r['server'], C.WHITE)}")
    print()
    sec("Present headers")
    if r["present"]:
        for k, v in r["present"].items():
            print(f"  {c('[✔]', C.GREEN)} {c(k, C.CYAN)}: {c(v, C.DIM)}")
    else:
        print(c("  [*] None of the tracked security headers present.", C.YELLOW))
    sec("Missing headers")
    if r["missing"]:
        for h in r["missing"]:
            print(c(f"  [!] {h}", C.RED))
    else:
        print(c("  [✔] All tracked security headers present.", C.GREEN))


# ════════════════════════════════════════════════════════════════════════════
#   MODULE: SCAN DIFF  (NEW v1.1)
# ════════════════════════════════════════════════════════════════════════════

def module_scan_diff():
    print_header("Scan Diff — Compare Two JSON Reports")
    path_a = ask("Baseline JSON report path")
    path_b = ask("New JSON report path")
    if not path_a or not path_b:
        print(c("  [✘] Both paths required.", C.RED))
        return
    if not os.path.isfile(path_a) or not os.path.isfile(path_b):
        print(c("  [✘] One or both files not found.", C.RED))
        return
    try:
        d = diff_scan_reports(path_a, path_b)
    except Exception as e:
        print(c(f"  [✘] Diff failed: {e}", C.RED))
        return
    print(f"\n  Baseline target: {c(str(d['target_a']), C.CYAN)}")
    print(f"  New target     : {c(str(d['target_b']), C.CYAN)}")
    sec(f"Added open ports ({len(d['added'])})")
    for item in d["added"]:
        print(f"  {c('[+]', C.GREEN)} :{item['port']:<6} {c(item.get('service') or '?', C.CYAN)}")
    if not d["added"]:
        print(c("  [*] None", C.DIM))
    sec(f"Removed open ports ({len(d['removed'])})")
    for item in d["removed"]:
        print(f"  {c('[-]', C.RED)} :{item['port']:<6} {c(item.get('service') or '?', C.CYAN)}")
    if not d["removed"]:
        print(c("  [*] None", C.DIM))
    sec(f"Changed services/banners ({len(d['changed'])})")
    for item in d["changed"]:
        print(f"  {c('[~]', C.YELLOW)} :{item['port']}  "
              f"{item.get('old_service')} → {item.get('new_service')}")
    if not d["changed"]:
        print(c("  [*] None", C.DIM))
    out = ask("Save diff JSON (Enter to skip)", "")
    if out:
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=2)
            print(c(f"  [✔] Diff saved → {out}", C.GREEN))
        except OSError as e:
            print(c(f"  [✘] Save failed: {e}", C.RED))


# ════════════════════════════════════════════════════════════════════════════
#   MAIN MENU
# ════════════════════════════════════════════════════════════════════════════

def main_menu():
    while True:
        clr()
        banner()

        items = [
            ("[1]", C.GREEN,  "New Scan",       "Configure & launch a port scan"),
            ("[2]", C.TEAL,   "Network Sweep",  "ICMP/ARP ping a CIDR range"),
            ("[3]", C.BLUE,   "Traceroute",     "Hop-by-hop path to target"),
            ("[4]", C.CYAN,   "SSL/TLS Audit",  "Certificate & cipher inspection"),
            ("[5]", C.PURPLE, "Scripted Probes","HTTP methods, FTP anon, Redis, SMB"),
            ("[6]", C.ORANGE, "HTTP Headers",   "Security header presence audit"),
            ("[7]", C.YELLOW, "Scan Diff",      "Compare two JSON scan reports"),
        ]
        for key, col, name, desc in items:
            print(f"  {c(key, col)}  {c(name + ' ' * (18 - len(name)), C.WHITE)}"
                  f"{c('─ ' + desc, C.DIM)}")
        print()
        print(f"  {c('[H]', C.YELLOW)}  {c('Help', C.WHITE)}               {c('─ Reference & usage guide', C.DIM)}")
        print(f"  {c('[0]', C.RED)}  {c('Exit', C.WHITE)}")
        print()
        print(c("─" * 66, C.MAGENTA))

        choice = input(c("\n  [»] Select option: ", C.CYAN)).strip().upper()

        dispatch = {
            "0": lambda: sys.exit(print(c("\n  [✔] OSpecter stopped. — owlsec.org\n", C.GREEN)) or 0),
            "H": lambda: (clr(), banner(), show_help(), pause()),
            "1": lambda: (module_new_scan(), pause()),
            "2": lambda: (module_sweep(), pause()),
            "3": lambda: (module_traceroute(), pause()),
            "4": lambda: (module_ssl_audit(), pause()),
            "5": lambda: (module_scripted_probes(), pause()),
            "6": lambda: (module_http_headers(), pause()),
            "7": lambda: (module_scan_diff(), pause()),
        }

        fn = dispatch.get(choice)
        if fn:
            fn()
        else:
            print(c("  [✘] Invalid option. Type H for help.", C.RED))
            pause()

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(c("\n\n  [✔] OSpecter stopped by user. — owlsec.org\n", C.YELLOW))
    except Exception as e:
        print(c(f"\n  [✘] Fatal error: {e}", C.RED))
        raise
