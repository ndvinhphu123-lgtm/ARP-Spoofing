import asyncio
from typing import Optional

class AsyncTokenBucket:
    def __init__(self, rate: float, capacity: Optional[int] = None):
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(1, int(rate))
        self._tokens = self.capacity
        self._last = asyncio.get_event_loop().time()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1):
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last
            add = elapsed * self.rate
            if add > 0:
                self._tokens = min(self.capacity, self._tokens + add)
                self._last = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            needed = tokens - self._tokens
            wait_time = needed / self.rate
        await asyncio.sleep(wait_time)
        await self.consume(tokens)