import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from services.email_parser import parse_headers, _is_private_ip, _extract_ips, _extract_domains


SAMPLE_HEADERS = """From: sender@suspicious-bank.tk
To: victim@example.com
Subject: URGENT: Verify your account
Date: Mon, 20 Sep 2026 10:00:00 +0000
Message-ID: <12345@suspicious-bank.tk>
Reply-To: real@different-domain.com
X-Mailer: PHPMailer 6.1
Received: from 185.23.144.5 (helo=mail.suspicious-bank.tk)
    by mx.example.com with ESMTP id abc123
Authentication-Results: mx.example.com;
    spf=fail;
    dkim=fail;
    dmarc=fail
Return-Path: <bounces@suspicious-bank.tk>
"""


def test_parse_headers_from():
    result = parse_headers(SAMPLE_HEADERS)
    assert "suspicious-bank.tk" in result["from"]


def test_parse_headers_subject():
    result = parse_headers(SAMPLE_HEADERS)
    assert "URGENT" in result["subject"]


def test_parse_headers_ips():
    result = parse_headers(SAMPLE_HEADERS)
    assert "185.23.144.5" in result["ips"]


def test_parse_headers_domains():
    result = parse_headers(SAMPLE_HEADERS)
    assert "suspicious-bank.tk" in result["domains"]


def test_parse_headers_spf_fail():
    result = parse_headers(SAMPLE_HEADERS)
    assert result["spf"] == "fail"


def test_parse_headers_dkim_fail():
    result = parse_headers(SAMPLE_HEADERS)
    assert result["dkim"] == "fail"


def test_parse_headers_dmarc_fail():
    result = parse_headers(SAMPLE_HEADERS)
    assert result["dmarc"] == "fail"


def test_parse_headers_reply_to_different():
    result = parse_headers(SAMPLE_HEADERS)
    assert result["reply_to"] != ""
    assert "different-domain.com" in result["reply_to"]


def test_parse_headers_risks_detected():
    result = parse_headers(SAMPLE_HEADERS)
    assert len(result["risks"]) > 0
    assert result["risk_score"] > 0


def test_is_private_ip_10():
    assert _is_private_ip("10.0.0.1") is True


def test_is_private_ip_192():
    assert _is_private_ip("192.168.1.1") is True


def test_is_private_ip_172():
    assert _is_private_ip("172.16.0.1") is True


def test_is_private_ip_127():
    assert _is_private_ip("127.0.0.1") is True


def test_is_private_ip_public():
    assert _is_private_ip("8.8.8.8") is False


def test_extract_ips_filters_private():
    headers = "Received: from 10.0.0.1 by 8.8.8.8"
    ips = _extract_ips(headers)
    assert "8.8.8.8" in ips
    assert "10.0.0.1" not in ips


def test_extract_domains():
    headers = "From: user@example.com\nReceived: from mail.test.org"
    domains = _extract_domains(headers)
    assert "example.com" in domains
    assert "mail.test.org" in domains
