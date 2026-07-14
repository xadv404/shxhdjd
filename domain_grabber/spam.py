"""Filtre anti-spam domains (zero spam) pour le grab CT."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from domain_grabber.utils import extract_apex, normalize_domain

# Suffixes / apex souvent spam, parking, free DNS, probes CT
SPAM_SUFFIXES: tuple[str, ...] = (
    # free / dynamic DNS
    "duckdns.org",
    "hopto.org",
    "zapto.org",
    "sytes.net",
    "ddns.net",
    "no-ip.com",
    "no-ip.org",
    "servehttp.com",
    "myftpupload.com",
    "webredirect.org",
    "redirectme.net",
    # parking / abuse / junk
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "icu",
    "cfd",
    "sbs",
    "cyou",
    "shop",
    "mom",
    "lol",
    "zip",
    "mov",
    # cloud free pages / temp
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "ngrok.io",
    "ngrok.app",
    "trycloudflare.com",
    "localtunnel.me",
    # infra SaaS probes / ephemeral
    "mongodb.net",
    "mesh.mongodb.net",
    "remotewd.com",
    "workdaysuv.com",
    "workdaysuvcareers.com",
    "projectmy.net",
    "certsbridge.com",
    "acm-validations.aws",
    "cloudfront.net",
    "elb.amazonaws.com",
    "execute-api.amazonaws.com",
    "amazonaws.com",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "cloudfunctions.net",
    "appspot.com",
)

# Labels typiques spam / infra
_SPAM_LABEL_RE = re.compile(
    r"("
    r"device-local-|"
    r"i-[0-9a-f]{8,}|"
    r"ec2-|ip-\d{1,3}-\d{1,3}|"
    r"cdn-edge|ssl-probe|ct-test|cert-test|"
    r"mailgun|sendgrid|amazonses|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # uuid
    r")",
    re.IGNORECASE,
)

_HEXISH_RE = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)
_DIGIT_HEAVY_RE = re.compile(r"^\d{6,}$")
_VOWELS = set("aeiouy")


@dataclass
class SpamFilterConfig:
    enabled: bool = True
    block_free_dns: bool = True
    block_parking_tlds: bool = True
    block_cloud_noise: bool = True
    block_high_entropy: bool = True
    max_labels: int = 5
    max_label_len: int = 32
    min_entropy_reject: float = 3.8  # labels trop random
    extra_block_suffixes: list[str] = field(default_factory=list)
    allow_suffixes: list[str] = field(default_factory=list)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _has_vowels(s: str) -> bool:
    return any(c in _VOWELS for c in s.lower())


class SpamFilter:
    """Rejette le bruit CT / parking / domaines random (zero spam)."""

    def __init__(self, config: SpamFilterConfig | None = None) -> None:
        self.config = config or SpamFilterConfig()
        suffixes = set(SPAM_SUFFIXES)
        if not self.config.block_parking_tlds:
            suffixes -= {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "cfd", "sbs", "cyou", "shop", "mom", "lol", "zip", "mov"}
        if not self.config.block_free_dns:
            suffixes -= {
                "duckdns.org", "hopto.org", "zapto.org", "sytes.net", "ddns.net",
                "no-ip.com", "no-ip.org", "servehttp.com", "myftpupload.com",
            }
        if not self.config.block_cloud_noise:
            suffixes -= {
                "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app",
                "firebaseapp.com", "ngrok.io", "ngrok.app", "trycloudflare.com",
                "mongodb.net", "mesh.mongodb.net", "remotewd.com",
                "workdaysuv.com", "workdaysuvcareers.com", "amazonaws.com",
                "cloudfront.net", "elb.amazonaws.com", "azurewebsites.net",
            }
        suffixes.update(s.lower().lstrip(".") for s in self.config.extra_block_suffixes)
        for a in self.config.allow_suffixes:
            suffixes.discard(a.lower().lstrip("."))
        self._suffixes = suffixes

    def _blocked_suffix(self, domain: str) -> str | None:
        d = domain.lower()
        for s in self._suffixes:
            if d == s or d.endswith("." + s):
                return s
        return None

    def reject_reason(self, domain: str) -> str | None:
        """Retourne la raison du rejet, ou None si OK."""
        if not self.config.enabled:
            return None

        normalized = normalize_domain(domain)
        if not normalized:
            return "invalid"

        labels = normalized.split(".")
        if len(labels) > self.config.max_labels:
            return "too_deep"

        for label in labels[:-1]:  # hors TLD
            if len(label) > self.config.max_label_len:
                return "long_label"
            if _HEXISH_RE.match(label):
                return "hex_label"
            if _DIGIT_HEAVY_RE.match(label):
                return "digit_label"
            if _SPAM_LABEL_RE.search(label):
                return "spam_pattern"
            if (
                self.config.block_high_entropy
                and len(label) >= 14
                and not _has_vowels(label)
                and _shannon(label) >= self.config.min_entropy_reject
            ):
                return "high_entropy"
            if (
                self.config.block_high_entropy
                and len(label) >= 20
                and _shannon(label) >= self.config.min_entropy_reject
            ):
                return "high_entropy"

        blocked = self._blocked_suffix(normalized)
        if blocked:
            return f"suffix:{blocked}"

        # apex trop court + TLD spam déjà couvert; apex = 1 char
        apex = extract_apex(normalized)
        if apex:
            name = apex.rsplit(".", 1)[0]
            if len(name) <= 1:
                return "short_apex"

        return None

    def accept(self, domain: str) -> bool:
        return self.reject_reason(domain) is None

    def filter_list(self, domains: list[str]) -> tuple[list[str], int]:
        """Retourne (kept, rejected_count)."""
        kept: list[str] = []
        rejected = 0
        for d in domains:
            if self.accept(d):
                kept.append(d)
            else:
                rejected += 1
        return kept, rejected


def build_spam_filter(cfg: dict) -> SpamFilter:
    f = cfg.get("filters", {})
    zs = f.get("zero_spam", {})
    if isinstance(zs, bool):
        zs = {"enabled": zs}
    return SpamFilter(
        SpamFilterConfig(
            enabled=bool(zs.get("enabled", True)),
            block_free_dns=bool(zs.get("block_free_dns", True)),
            block_parking_tlds=bool(zs.get("block_parking_tlds", True)),
            block_cloud_noise=bool(zs.get("block_cloud_noise", True)),
            block_high_entropy=bool(zs.get("block_high_entropy", True)),
            max_labels=int(zs.get("max_labels", 5)),
            max_label_len=int(zs.get("max_label_len", 32)),
            min_entropy_reject=float(zs.get("min_entropy_reject", 3.8)),
            extra_block_suffixes=list(zs.get("extra_block_suffixes") or []),
            allow_suffixes=list(zs.get("allow_suffixes") or []),
        )
    )
