"""Filtres heuristiques pour domaines potentiellement vulnérables."""

from __future__ import annotations

from dataclasses import dataclass, field

from domain_grabber.utils import extract_apex, has_ip_literal, is_punycode, normalize_domain


@dataclass
class FilterConfig:
    punycode: bool = True
    ip_in_san: bool = True
    suspicious_tlds: list[str] = field(default_factory=list)
    min_domain_length: int = 3
    max_domain_length: int = 253
    # Si activé, ne garde que les domaines matchant au moins un critère
    require_match: bool = True


class VulnerabilityFilter:
    """Applique des heuristiques simples sur les domaines collectés."""

    def __init__(self, config: FilterConfig | None = None) -> None:
        self.config = config or FilterConfig()
        self._suspicious = {tld.lower().lstrip(".") for tld in self.config.suspicious_tlds}

    def _get_tld(self, domain: str) -> str:
        apex = extract_apex(domain) or domain
        return apex.rsplit(".", 1)[-1].lower()

    def _matches(self, domain: str) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        normalized = normalize_domain(domain)
        if not normalized:
            return False, []

        if not (self.config.min_domain_length <= len(normalized) <= self.config.max_domain_length):
            return False, []

        if self.config.punycode and is_punycode(normalized):
            reasons.append("punycode")

        if self.config.ip_in_san and has_ip_literal(normalized):
            reasons.append("ip_in_san")

        tld = self._get_tld(normalized)
        if tld in self._suspicious:
            reasons.append(f"suspicious_tld:{tld}")

        # Longueur anormale du sous-domaine (souvent DGA / phishing)
        labels = normalized.split(".")
        if len(labels) >= 2 and len(labels[0]) > 40:
            reasons.append("long_subdomain")

        # Nombre élevé de labels (souvent infra suspecte)
        if len(labels) > 5:
            reasons.append("deep_subdomain")

        if self.config.require_match:
            return bool(reasons), reasons
        return True, reasons

    def accept(self, domain: str) -> tuple[bool, list[str]]:
        return self._matches(domain)

    def accept_all(self, domains: set[str]) -> dict[str, list[str]]:
        accepted: dict[str, list[str]] = {}
        for domain in domains:
            ok, reasons = self.accept(domain)
            if ok:
                accepted[domain] = reasons
        return accepted
