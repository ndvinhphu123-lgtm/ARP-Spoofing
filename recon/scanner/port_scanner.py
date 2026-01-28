import asyncio
import logging
import socket
from typing import Dict, List
import xml.etree.ElementTree as ET
from scanner.base import BaseScanner
from utils.proxy_manager import socks_open_connection
from config import COMMON_PORTS

logger = logging.getLogger(__name__)

class PortScanner(BaseScanner):
    async def scan(self, ip_list: List[str]) -> Dict[str, Dict]:
        logger.info(f"[PORT] Scanning {len(ip_list)} IPs")
        results = {}
        if self.dry_run:
            for ip in ip_list: results[ip] = {80:{"state":"OPEN","service":"http"}}
            return results
            
        # Ưu tiên Nmap nếu không dùng Proxy
        if not self.proxies:
            try:
                return await self._run_nmap(ip_list)
            except Exception as e:
                logger.warning(f"Nmap failed ({e}), fallback to socket")
        
        return await self._socket_scan(ip_list)

    async def _run_nmap(self, ip_list):
        cmd = ["nmap", "-sS", "-sV", "-T4", "--open", "-p", ",".join(map(str, COMMON_PORTS)), "-oX", "-"] + ip_list
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        return self._parse_xml(stdout.decode(errors='ignore'))

    def _parse_xml(self, xml):
        res = {}
        try:
            root = ET.fromstring(xml)
            for host in root.findall('host'):
                ip = host.find('address').get('addr')
                res[ip] = {}
                for port in host.findall('.//port'):
                    if port.find('state').get('state') == 'open':
                        pid = int(port.get('portid'))
                        svc = port.find('service').get('name') if port.find('service') is not None else 'unknown'
                        res[ip][pid] = {"state":"OPEN", "service":svc}
        except: pass
        return res

    async def _socket_scan(self, ip_list):
        res = {ip: {} for ip in ip_list}
        sem = asyncio.Semaphore(self.config.max_workers)
        
        async def check(ip, port):
            async with sem:
                await self._pre_request()
                await self.token_bucket.consume()
                try:
                    ph, pp = self._get_random_proxy()
                    if ph:
                        async with socks_open_connection(ph, pp, ip, port) as (r,w): pass
                    else:
                        c = await asyncio.open_connection(ip, port)
                        c[1].close(); await c[1].wait_closed()
                    return ip, port
                except: return None
        
        tasks = [check(ip, p) for ip in ip_list for p in COMMON_PORTS]
        found = await asyncio.gather(*tasks)
        for f in found:
            if f: res[f[0]][f[1]] = {"state":"OPEN", "service":"unknown"}
        return res