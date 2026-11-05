"""In-process fan-out of live events (new messages, file status) to browser tabs."""
import asyncio
from collections import defaultdict


class Hub:
    def __init__(self) -> None:
        self._subs: dict[int, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, user_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subs[user_id].add(q)
        return q

    def unsubscribe(self, user_id: int, q: asyncio.Queue) -> None:
        self._subs[user_id].discard(q)

    def publish(self, user_id: int, event: dict) -> None:
        for q in list(self._subs.get(user_id, ())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # slow tab; it refreshes on the next event


hub = Hub()
