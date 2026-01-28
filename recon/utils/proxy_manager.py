import asyncio
import struct
import socket
from typing import Optional
from contextlib import asynccontextmanager

# Kiểm tra thư viện stem
try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False
    Controller = None

class TorController:
    def __init__(self, control_port: int):
        if not STEM_AVAILABLE:
            pass # Silent fail if not available
        else:
            try:
                self.controller = Controller.from_port(port=control_port)
                self.controller.authenticate()
            except Exception:
                self.controller = None # Handle connection refused
        
    def renew_identity(self):
        if self.controller:
            self.controller.signal(Signal.NEWNYM)
        
    def close(self):
        if self.controller:
            self.controller.close()

async def async_socks_resolve(domain: str, proxy_host: str, proxy_port: int) -> Optional[str]:
    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        if (await reader.readexactly(2)) != b'\x05\x00':
            raise ValueError("SOCKS handshake failed")
        
        # SOCKS5 Resolve Command (0xF0 is typical for Tor, or use standard connect logic)
        # Using Tor-specific resolve extension or standard logic
        # For simplicity in this context, we try standard connect but this func specifically implies remote resolve
        # Note: Standard SOCKS5 doesn't always support remote DNS resolve command widely, 
        # but Tor does via command 0xF0 usually. Let's use basic resolve logic manually if needed.
        # IMPLEMENTATION: Sending domain address type to proxy
        
        cmd = b'\xF0' # TOR RESOLVE
        writer.write(b'\x05' + cmd + b'\x00\x03' + struct.pack('!B', len(domain)) + domain.encode() + struct.pack('!H', 0))
        await writer.drain()
        
        resp = await reader.readexactly(4) # ver, rep, rsv, atyp
        if resp[1] != 0: return None
        
        if resp[3] == 1: # IPv4
            ip = socket.inet_ntoa(await reader.readexactly(4))
        else:
            return None # Ignore IPv6/Domain responses for now
            
        await reader.readexactly(2) # Port
        writer.close()
        await writer.wait_closed()
        return ip
    except Exception:
        return None

@asynccontextmanager
async def socks_open_connection(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int):
    reader = None
    writer = None
    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        if (await reader.readexactly(2)) != b'\x05\x00': raise ValueError("Handshake failed")
        
        cmd = b'\x01' # Connect
        if dest_host.replace('.', '').isdigit():
            atyp = b'\x01'; host = socket.inet_aton(dest_host)
        else:
            atyp = b'\x03'; host = struct.pack('!B', len(dest_host)) + dest_host.encode()
            
        writer.write(b'\x05' + cmd + b'\x00' + atyp + host + struct.pack('!H', dest_port))
        await writer.drain()
        
        resp = await reader.readexactly(4)
        if resp[1] != 0: raise ValueError(f"Connect error {resp[1]}")
        
        if resp[3] == 1: await reader.readexactly(4)
        elif resp[3] == 3: await reader.readexactly((await reader.readexactly(1))[0])
        elif resp[3] == 4: await reader.readexactly(16)
        await reader.readexactly(2)
        
        yield reader, writer
    finally:
        if writer:
            writer.close()
            try: await writer.wait_closed()
            except: pass