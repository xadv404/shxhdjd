"""Tests filtre zero spam."""

from domain_grabber.spam import SpamFilter, SpamFilterConfig, build_spam_filter


def test_keeps_legit():
    f = SpamFilter()
    assert f.accept("example.com")
    assert f.accept("blog.github.com")
    assert f.accept("shop.nike.com")


def test_blocks_free_dns():
    f = SpamFilter()
    assert f.reject_reason("foo.duckdns.org") == "suffix:duckdns.org"
    assert f.reject_reason("x.myftpupload.com") == "suffix:myftpupload.com"


def test_blocks_cloud_noise():
    f = SpamFilter()
    assert f.reject_reason("foo.mongodb.net") is not None
    assert f.reject_reason("i-0ab550c06ec35e6c9.prd.workdaysuv.com") is not None
    assert f.reject_reason("device-local-225be5c8-1640-445b-92e9-c85b61a637dc.remotewd.com") is not None


def test_blocks_hex_and_entropy():
    f = SpamFilter()
    assert f.reject_reason("a1b2c3d4e5f67890.example.com") == "hex_label"
    assert f.reject_reason("xqzmtplkwrjnhvbs.example.com") is not None  # high entropy / no vowels


def test_blocks_parking_tld():
    f = SpamFilter()
    assert f.reject_reason("randomstuff.xyz") is not None
    assert f.reject_reason("whatever.tk") is not None


def test_disabled():
    f = SpamFilter(SpamFilterConfig(enabled=False))
    assert f.accept("foo.duckdns.org")


def test_build_from_config():
    f = build_spam_filter({"filters": {"zero_spam": True}})
    assert f.config.enabled is True
    f2 = build_spam_filter({"filters": {"zero_spam": {"enabled": True, "allow_suffixes": ["xyz"]}}})
    assert f2.accept("okdomain.xyz")
