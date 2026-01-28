import asyncio
import socket
import logging
from typing import Dict
from pathlib import Path
from scanner.base import BaseScanner
from utils.models import Asset
from utils.proxy_manager import async_socks_resolve
from config import COMMON_SUBDOMAINS

logger = logging.getLogger(__name__)

class DNSResolver(BaseScanner):
    def __init__(self, config, token_bucket, executor):
        super().__init__(config, token_bucket)
        self.executor = executor
        self.subdomains = COMMON_SUBDOMAINS
        if Path(config.subdomain_wordlist).exists():
            with open(config.subdomain_wordlist, 'r') as f:
                self.subdomains += [l.strip() for l in f if l.strip()]

    async def scan(self, target_domain: str) -> Dict[str, Asset]:
        logger.info(f"[DNS] Resolving {target_domain}")
        assets = {}
        subs = [target_domain] + [f"{s}.{target_domain}" for s in self.subdomains]
        sem = asyncio.Semaphore(self.config.max_workers)

        async def resolve(domain):
            async with sem:
                await self._pre_request()
                await self.token_bucket.consume()
                if self.dry_run:
                    return domain, f"192.168.1.{abs(hash(domain))%254}"
                
                proxy_host, proxy_port = self._get_random_proxy()
                try:
                    if proxy_host:
                        ip = await self._retry_request(async_socks_resolve, domain, proxy_host, proxy_port)
                    else:
                        ip = await asyncio.get_event_loop().run_in_executor(
                            self.executor, lambda: socket.gethostbyname(domain))
                    return domain, ip
                except: return None

        tasks = [asyncio.create_task(resolve(d)) for d in subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if res and isinstance(res, tuple):
                d, ip = res
                if ip:
                    if ip not in assets: assets[ip] = Asset(ip=ip)
                    assets[ip].domains.add(d)
        return assets