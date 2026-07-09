"""Tests du pipeline de vérification."""

from domain_grabber.verify import (
    Toolchain,
    VerifyConfig,
    _parse_massdns_output,
    _parse_masscan_json,
    _unique_domains,
)


def test_unique_domains():
    assert _unique_domains(["a.com", "b.com", "a.com"]) == ["a.com", "b.com"]


def test_parse_massdns_output():
    text = "example.com. A 93.184.216.34\nwww.example.com. A 93.184.216.34\n"
    result = _parse_massdns_output(text)
    assert result["example.com"] == ["93.184.216.34"]
    assert result["www.example.com"] == ["93.184.216.34"]


def test_parse_masscan_json():
    text = '[{"ip": "1.2.3.4", "ports": [{"port": 443}]}]\n'
    pairs = _parse_masscan_json(text)
    assert ("1.2.3.4", 443) in pairs


def test_verify_config_defaults():
    cfg = VerifyConfig()
    assert cfg.batch_size == 2000
    assert cfg.ports == (443, 80)
    assert cfg.require_http is True


def test_toolchain_describe():
    tools = Toolchain()
    assert tools.describe() in ("async-fallback", "massdns", "massdns+masscan", "massdns+httpx", "httpx", "massdns+masscan+httpx")
