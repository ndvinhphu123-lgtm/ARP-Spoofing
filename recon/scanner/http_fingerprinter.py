import asyncio
import logging
import ssl
import random
from scanner.base import BaseScanner
from utils.proxy_manager import socks_open_connection
from config import USER_AGENTS

logger = logging.getLogger(__name__)

class HTTPFingerprinter(BaseScanner):
    async def scan(self, assets: Dict[str, any]) -> Dict[str, Dict]:
        logger.info("[HTTP] Fingerprinting")
        res = {}
        sem = asyncio.Semaphore(10)
        
        async def finger(ip, asset):
            async with sem:
                await self._pre_request()
                await self.token_bucket.consume()
                if self.dry_run:
                    asset.http_info = {"http://dummy": {"status":200, "server":"nginx"}}
                    return ip, asset.http_info
                
                info = {}
                ports = [p for p in asset.ports if p in [80, 443, 8080, 8443]]
                for p in ports:
                    scheme = "https" if p in [443, 8443] else "http"
                    url = f"{scheme}://{ip}:{p}"
                    try:
                        data = await self._req(ip, p, scheme=="https")
                        info[url] = data
                        logger.info(f"[HTTP✓] {url} - {data['status']}")
                    except: pass
                asset.http_info = info
                return ip, info

        tasks = [finger(ip, a) for ip, a in assets.items()]
        completed = await asyncio.gather(*tasks)
        for ip, info in completed:
            if info: res[ip] = info
        return res

    async def _req(self, host, port, use_ssl):
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        ph, pp = self._get_random_proxy()
        
        if ph:
            async with socks_open_connection(ph, pp, host, port) as (r, w):
                if use_ssl:
                    # Upgrade SOCKS connection to SSL
                    loop = asyncio.get_running_loop()
                    w._transport = await loop.start_tls(w._transport, w._protocol, ctx, server_side=False)
                    r._transport = w._transport
                return await self._send_http(r, w, host)
        else:
            r, w = await asyncio.open_connection(host, port, ssl=ctx if use_ssl else None)
            try: return await self._send_http(r, w, host)
            finally: w.close(); await w.wait_closed()

    async def _send_http(self, r, w, host):
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nConnection: close\r\n\r\n"
        w.write(req.encode()); await w.drain()
        line = await r.readline()
        status = int(line.split()[1])
        headers = {}
        while True:
            l = await r.readline()
            if l == b'\r\n': break
            k,v = l.decode(errors='ignore').strip().split(':',1)
            headers[k.strip()] = v.strip()
        return {"status":status, "headers":headers, "server":headers.get("Server","unknown")}