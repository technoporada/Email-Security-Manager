import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from services.rate_limiter import RateLimiter


def test_rate_limiter_init():
    limiter = RateLimiter(":memory:")
    assert limiter is not None


def test_can_request_within_limit():
    limiter = RateLimiter(":memory:")
    for _ in range(3):
        assert limiter.can_request("virustotal") is True


def test_set_and_get_cache():
    limiter = RateLimiter(":memory:")
    limiter.set_cache("test", "query1", {"result": "ok"})
    cached = limiter.get_cached("test", "query1")
    assert cached is not None
    assert cached["result"] == "ok"


def test_cache_miss():
    limiter = RateLimiter(":memory:")
    cached = limiter.get_cached("test", "nonexistent")
    assert cached is None


def test_cleanup():
    limiter = RateLimiter(":memory:")
    limiter.set_cache("test", "key", {"data": 1})
    limiter.cleanup()
    # Should not crash
