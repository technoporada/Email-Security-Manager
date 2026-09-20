import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from database import Database


@pytest.fixture
def db():
    return Database(":memory:")


def test_save_and_get_scan(db):
    scan_id = db.save_scan("link_check", "https://example.com", {"safe": True}, 0)
    assert scan_id > 0
    scans = db.get_scans("link_check")
    assert len(scans) == 1
    assert scans[0]["target"] == "https://example.com"


def test_blacklist_add_and_check(db):
    assert db.add_blacklist("ip", "1.2.3.4", "test reason") is True
    assert db.is_blacklisted("ip", "1.2.3.4") is True
    assert db.is_blacklisted("ip", "5.6.7.8") is False


def test_blacklist_duplicate(db):
    db.add_blacklist("ip", "1.2.3.4")
    assert db.add_blacklist("ip", "1.2.3.4") is False


def test_blacklist_remove(db):
    db.add_blacklist("ip", "1.2.3.4")
    assert db.remove_blacklist("1.2.3.4") is True
    assert db.is_blacklisted("ip", "1.2.3.4") is False


def test_stats(db):
    stats = db.get_stats()
    assert stats["total_scans"] == 0
    assert stats["threats_found"] == 0

    db.save_scan("test", "target", {}, 5)
    stats = db.get_stats()
    assert stats["total_scans"] == 1
    assert stats["threats_found"] == 1


def test_abuse_report(db):
    report_id = db.save_abuse_report("hosting", "evil.com", "report body", ["abuse@test.com"])
    assert report_id > 0
