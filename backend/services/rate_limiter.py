"""Rate limiter + cache — prevents API abuse, saves quota."""
import time
import sqlite3
import hashlib
import json
from typing import Optional
from config import RATE_LIMITS, CACHE_TTL


class RateLimiter:
    def __init__(self, db_path: str = "ratelimit.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self._counters: dict[str, list[float]] = {}

    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at REAL
            )
        """)
        self.conn.commit()

    def _cache_key(self, service: str, query: str) -> str:
        return hashlib.md5(f"{service}:{query}".encode()).hexdigest()

    def get_cached(self, service: str, query: str) -> Optional[dict]:
        key = self._cache_key(service, query)
        row = self.conn.execute(
            "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row and row[1] > time.time():
            return json.loads(row[0])
        if row:
            self.conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self.conn.commit()
        return None

    def set_cache(self, service: str, query: str, data: dict):
        ttl = CACHE_TTL.get(service, 1800)
        key = self._cache_key(service, query)
        self.conn.execute(
            "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
            (key, json.dumps(data), time.time() + ttl)
        )
        self.conn.commit()

    def can_request(self, service: str) -> bool:
        limit = RATE_LIMITS.get(service, 10)
        now = time.time()
        window = 60  # 1 minute

        if service not in self._counters:
            self._counters[service] = []

        # Remove old entries
        self._counters[service] = [t for t in self._counters[service] if now - t < window]

        if len(self._counters[service]) >= limit:
            return False

        self._counters[service].append(now)
        return True

    def wait_time(self, service: str) -> float:
        limit = RATE_LIMITS.get(service, 10)
        if service not in self._counters or len(self._counters[service]) < limit:
            return 0.0

        oldest = min(self._counters[service])
        return max(0, 60 - (time.time() - oldest))

    def cleanup(self):
        self.conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
        self.conn.commit()
