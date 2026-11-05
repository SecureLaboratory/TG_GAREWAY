"""Small in-memory sliding-window rate limiter (one gateway process; Redis when scaled out)."""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_requests: int, window: int) -> None:
        self.max_requests = max_requests
        self.window = window
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        if len(self._hits) > 10_000:  # bound memory: forget idle keys
            for k in [k for k, v in self._hits.items() if not v]:
                del self._hits[k]
        return True

    def reset(self) -> None:
        self._hits.clear()
