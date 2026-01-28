import asyncio
import random
import logging
from typing import Dict, Optional, Tuple
from utils.models import WAFInfo, CDNInfo  # Import từ utils
from config import WAF_SIGNATURES, CDN_SIGNATURES, USER_AGENTS
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)

class WAFDetector(BaseScanner):
    """Detect Web Application Firewalls and CDNs"""
    
    async def scan(self, assets: Dict[str, any]) -> Dict[str, Dict]:
        logger.info("[WAF] Starting WAF/CDN detection")
        results = {}
        
        if self.dry_run:
            for ip in assets:
                assets[ip].waf_info = WAFInfo(
                    detected=True,
                    waf_name="Cloudflare",
                    confidence=0.85,
                    indicators=["cf-ray header"]
                )
                assets[ip].cdn_info = CDNInfo(
                    detected=True,
                    cdn_name="Cloudflare",
                    asn=13335
                )
            return results
        
        sem = asyncio.Semaphore(self.config.max_workers)
        
        async def detect_waf_for_ip(ip: str, asset):
            async with sem:
                await self._pre_request()
                await self.token_bucket.consume()
                waf_info = await self._detect_waf(ip, asset)
                cdn_info = await self._detect_cdn(ip, asset)
                asset.waf_info = waf_info
                asset.cdn_info = cdn_info
                if waf_info.detected:
                    logger.info(f"[WAF✓] {ip} -> {waf_info.waf_name}")
                return ip, {"waf": waf_info, "cdn": cdn_info}
        
        tasks = [asyncio.create_task(detect_waf_for_ip(ip, asset)) for ip, asset in assets.items()]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in all_results:
            if not isinstance(res, Exception) and res:
                ip, info = res
                results[ip] = info
        
        return results
    
    async def _detect_waf(self, ip: str, asset) -> WAFInfo:
        """Detect WAF by analyzing HTTP headers and responses"""
        indicators = []
        scores = {}
        
        # Check HTTP headers from previous scans
        for http_key, http_info in asset.http_info.items():
            headers = http_info.get("headers", {})
            
            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    # Check headers
                    for header_key, header_value in headers.items():
                        if sig.lower() in header_key.lower() or sig.lower() in str(header_value).lower():
                            indicators.append(f"Header: {header_key}")
                            scores[waf_name] = scores.get(waf_name, 0) + 0.3
            
            # Check for WAF behavior patterns
            status = http_info.get("status")
            if status in [403, 406, 429, 503]:
                indicators.append(f"Blocking status: {status}")
                scores["Generic WAF"] = scores.get("Generic WAF", 0) + 0.2
        
        # Additional tests: Send malicious payloads
        test_result = await self._send_waf_probe(ip, asset)
        if test_result:
            waf_detected, waf_name = test_result
            if waf_detected:
                indicators.append("Blocked malicious payload")
                scores[waf_name] = scores.get(waf_name, 0) + 0.5
        
        if scores:
            detected_waf = max(scores.items(), key=lambda x: x[1])
            return WAFInfo(
                detected=True,
                waf_name=detected_waf[0],
                confidence=min(detected_waf[1], 1.0),
                indicators=indicators
            )
        
        return WAFInfo(detected=False)
    
    async def _send_waf_probe(self, ip: str, asset) -> Optional[tuple]:
        """Send malicious-looking requests to trigger WAF"""
        # Simple SQL injection probe
        malicious_paths = ["/?id=1' OR '1'='1", "/<script>alert(1)</script>"]
        
        try:
            # Get a web port
            web_port = None
            for port in [80, 443, 8080]:
                if port in asset.ports and asset.ports[port].get("state") == "OPEN":
                    web_port = port
                    break
            
            if not web_port:
                return None
            
            # Send probe
            for path in malicious_paths:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, web_port), timeout=self.config.timeout
                )
                request = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                
                # --- FIX LỖI Ở ĐÂY ---
                try:
                    response_line = await reader.readline()
                    if not response_line:
                        writer.close()
                        await writer.wait_closed()
                        return (True, "Aggressive WAF (Drop Connection)")
                    status = int(response_line.split()[1])
                except Exception:
                    writer.close()
                    await writer.wait_closed()
                    return None
                # ---------------------

                writer.close()
                await writer.wait_closed()
                
                if status in [403, 406, 503]:
                    return (True, "Generic WAF Block")
                    
        except Exception as e:
            logger.debug(f"WAF probe failed: {e}")
        return None
    
    async def _detect_cdn(self, ip: str, asset) -> CDNInfo:
        """Detect CDN by checking IP ranges and headers"""
        # Check HTTP headers
        for http_key, http_info in asset.http_info.items():
            headers = http_info.get("headers", {})
            server = headers.get("Server", "").lower()
            
            for cdn_name, cdn_data in CDN_SIGNATURES.items():
                for cdn_server in cdn_data.get("servers", []):
                    if cdn_server in server:
                        return CDNInfo(
                            detected=True,
                            cdn_name=cdn_name
                        )
        
        # Check IP range (simplified - would need real IP range database)
        # This is a placeholder
        return CDNInfo(detected=False)
