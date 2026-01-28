import asyncio
import ssl
from scanner.base import BaseScanner
from utils.proxy_manager import socks_open_connection

class TLSScanner(BaseScanner):
    async def scan(self, assets):
        pass