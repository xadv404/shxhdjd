"""Utilitaires partagés pour l'extraction et la normalisation de domaines."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract

# Domaine valide (simplifié, couvre la majorité des cas réels)
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

_WILDCARD_PREFIXES = ("*.",)


# Domaines infrastructure / CA à ignorer lors de l'extraction CT
_NOISE_SUFFIXES = (
    ".crl",
    ".cer",
    ".crt",
    "ocsp.",
    "crl.",
    "cacerts.",
    "crt.",
    "ct.googleapis.com",
    "digicert.com",
    "sectigo.com",
    "godaddy.com",
    "comodoca.com",
    "usertrust.com",
    "letsencrypt.org",
    "pki.goog",
    "amazontrust.com",
    "globalsign.com",
)


def is_infrastructure_noise(domain: str) -> bool:
    d = domain.lower()
    if any(d.endswith(s.lstrip(".")) or d.startswith(s) for s in _NOISE_SUFFIXES if not s.startswith(".")):
        return True
    if any(d.endswith(s) for s in _NOISE_SUFFIXES if s.startswith(".")):
        return True
    if any(part in d for part in ("digicert", "sectigo", "comodoca", "usertrust", "amazontrust")):
        return True
    tld = d.rsplit(".", 1)[-1]
    if tld in {"crt", "crl", "cer", "pem"}:
        return True
    if d.count(".") == 1 and d.split(".")[0] in {"ocsp", "crl", "crt", "cacerts"}:
        return True
    return False


def normalize_domain(raw: str) -> str | None:
    """Normalise une entrée brute en FQDN apex ou sous-domaine."""
    if not raw or not isinstance(raw, str):
        return None

    value = raw.strip().lower()
    if not value:
        return None

    # Retirer wildcard
    for prefix in _WILDCARD_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix) :]

    # Retirer schéma / chemin si URL
    if "://" in value or value.startswith("//"):
        parsed = urlparse(value if "://" in value else f"//{value}")
        value = parsed.hostname or ""

    value = value.rstrip(".").split("/")[0].split(":")[0]
    if not value or value.startswith(".") or " " in value:
        return None

    if not _DOMAIN_RE.match(value):
        return None

    if is_infrastructure_noise(value):
        return None

    return value


def extract_apex(domain: str) -> str | None:
    """Retourne le domaine apex (ex: sub.example.com -> example.com)."""
    normalized = normalize_domain(domain)
    if not normalized:
        return None
    extracted = tldextract.extract(normalized)
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}".lower()


def is_punycode(domain: str) -> bool:
    return domain.startswith("xn--") or ".xn--" in domain


def has_ip_literal(domain: str) -> bool:
    """Détecte les SAN de type IP dans une chaîne domaine."""
    ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return bool(ipv4.match(domain))


def iter_domains_from_cert_names(names: list[str]) -> set[str]:
    """Extrait les domaines uniques d'une liste de noms de certificat."""
    result: set[str] = set()
    for name in names:
        normalized = normalize_domain(name)
        if normalized:
            result.add(normalized)
    return result
