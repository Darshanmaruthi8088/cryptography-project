"""Simple in-memory sliding-window rate limiter."""

from collections import defaultdict, deque
from time import time

from config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS


class RateLimiter:
    def __init__(self, max_requests: int = RATE_LIMIT_REQUESTS, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets = defaultdict(deque)

    def is_limited(self, key: str) -> bool:
        now = time()
        bucket = self._buckets[key]
        cutoff = now - self.window_seconds

        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            return True

        bucket.append(now)
        return False

