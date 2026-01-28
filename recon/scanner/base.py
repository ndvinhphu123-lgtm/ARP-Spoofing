import asyncio
import random
import logging
from typing import Dict, Any, Tuple, Optional
from utils.rate_limiter import AsyncTokenBucket
from utils.proxy_manager import TorController

logger = logging.getLogger(__name__)

class BaseScanner:
    def __init__(self, config, token_bucket: AsyncTokenBucket):
        self.config = config
        self.dry_run = config.dry_run
        self.token_bucket = token_bucket
        self.proxies = config.proxies or []
        self.tor_controller = None
        self.request_count = 0
        
        if self.proxies:
            try:
                self.tor_controller = TorController(config.tor_control_port)
            except Exception as e:
                logger.warning(f"Tor init failed: {e}")

    async def _pre_request(self):
        await asyncio.sleep(random.uniform(0.1, 0.5))
        if self.tor_controller:
            self.request_count += 1
            if self.request_count % self.config.renew_tor_every == 0:
                self.tor_controller.renew_identity()
                await asyncio.sleep(5)

    def _get_random_proxy(self) -> Tuple[Optional[str], int]:
        if not self.proxies: return None, 0
        p = random.choice(self.proxies).split(':')
        return p[0], int(p[1]) if len(p)>1 else 9050

    async def _retry_request(self, func, *args, **kwargs):
        for i in range(self.config.max_retries):
            try: return await func(*args, **kwargs)
            except Exception as e:
                await asyncio.sleep(2**i)
        raise RuntimeError("Max retries exceeded")