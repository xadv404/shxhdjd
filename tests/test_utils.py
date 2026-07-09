"""Tests unitaires."""

from domain_grabber.filters import FilterConfig, VulnerabilityFilter
from domain_grabber.scanner import _is_vulnerable_nextjs
from domain_grabber.utils import extract_apex, is_punycode, normalize_domain


def test_normalize_domain():
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain("*.foo.example.com") == "foo.example.com"
    assert normalize_domain("https://test.io/path") == "test.io"
    assert normalize_domain("") is None
    assert normalize_domain("not-a-domain") is None


def test_extract_apex():
    assert extract_apex("sub.example.com") == "example.com"
    assert extract_apex("example.co.uk") == "example.co.uk"


def test_punycode():
    assert is_punycode("xn--test.com")
    assert not is_punycode("example.com")


def test_filter_optional():
    f = VulnerabilityFilter(FilterConfig(require_match=False))
    ok, reasons = f.accept("example.com")
    assert ok is True


def test_react2shell_versions():
    assert _is_vulnerable_nextjs("15.0.3") is True
    assert _is_vulnerable_nextjs("14.2.0") is False


def test_noise_filter():
    from domain_grabber.utils import is_infrastructure_noise, normalize_domain

    assert is_infrastructure_noise("ocsp.sectigo.com")
    assert normalize_domain("crt.sectigo.com") is None
    assert normalize_domain("example.com") == "example.com"
