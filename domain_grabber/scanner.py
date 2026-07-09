"""Moteur de scan vulnérabilités (détection passive/safe par défaut)."""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

# Indicateurs LFI (lecture passive des réponses)
LFI_INDICATORS = [
    b"root:x:0:0",
    b"[boot loader]",
    b"<?php",
    b"/etc/passwd",
    b"bin/bash",
    b"DOCUMENT_ROOT",
]

GIT_HEAD_RE = re.compile(r"^ref: refs/heads/", re.MULTILINE)
GIT_CONFIG_RE = re.compile(r"\[core\]", re.IGNORECASE)

NEXTJS_MARKERS = [
    re.compile(r'"buildId"\s*:\s*"[^"]+"'),
    re.compile(r"/_next/static/"),
    re.compile(r"__NEXT_DATA__"),
    re.compile(r"react-server-dom"),
]

RSC_HEADERS = {"rsc", "next-router-state-tree", "next-action"}

XXE_ENDPOINT_HINTS = [
    "/soap",
    "/api/xml",
    "/xml",
    "/wsdl",
    "/upload",
    "/import",
    "/feed",
]

SSRF_PARAM_HINTS = ["url", "uri", "path", "dest", "redirect", "next", "target", "rurl", "return"]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/playground"]

ENV_SECRET_MARKERS = [
    b"DB_PASSWORD",
    b"SECRET_KEY",
    b"API_KEY",
    b"AWS_ACCESS",
    b"PRIVATE_KEY",
    b"MAIL_PASSWORD",
    b"APP_KEY",
]


@dataclass
class Finding:
    domain: str
    check: str
    severity: str
    url: str
    evidence: str
    metadata: dict[str, Any] = field(default_factory=dict)


DEFAULT_CHECKS: dict[str, bool] = {
    "lfi": True,
    "private_paths": True,
    "git_dump": True,
    "react2shell": True,
    "xxe": True,
    "ssrf": True,
    "ggb": True,
    "secrets": True,
}

DEFAULT_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/HEAD",
    "/.git/config",
    "/config.json",
    "/backup.sql",
    "/graphql",
    "/api/graphql",
]

DEFAULT_LFI_PARAMS = ["file", "page", "path", "template", "include", "doc"]

DEFAULT_SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"sk_live_[0-9a-zA-Z]{24,}",
    r"ghp_[0-9a-zA-Z]{36}",
]


@dataclass
class ScanConfig:
    concurrency: int = 50
    timeout: int = 10
    aggressive: bool = False
    callback_url: str = ""
    checks: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_CHECKS))
    paths: list[str] = field(default_factory=lambda: list(DEFAULT_PATHS))
    lfi_params: list[str] = field(default_factory=lambda: list(DEFAULT_LFI_PARAMS))
    secret_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_SECRET_PATTERNS))


class VulnScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._secret_res = [re.compile(p) for p in config.secret_patterns]

    def _base_urls(self, domain: str) -> list[str]:
        return [f"https://{domain}", f"http://{domain}"]

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
        **kwargs: Any,
    ) -> tuple[int | None, bytes, dict[str, str], str | None]:
        try:
            async with session.request(
                method,
                url,
                allow_redirects=True,
                **kwargs,
            ) as resp:
                body = await resp.read()
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, body[:500_000], headers, str(resp.url)
        except Exception as exc:
            return None, b"", {}, f"{type(exc).__name__}: {exc}"

    async def scan_domain(self, session: aiohttp.ClientSession, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        checks = self.config.checks

        alive_url = None
        for base in self._base_urls(domain):
            status, body, headers, final = await self._fetch(session, base)
            if status and status < 500:
                alive_url = final or base
                break

        if not alive_url:
            return findings

        tasks = []
        if checks.get("private_paths") or checks.get("secrets"):
            tasks.append(self._check_paths(session, domain, alive_url))
        if checks.get("git_dump"):
            tasks.append(self._check_git(session, domain, alive_url))
        if checks.get("react2shell"):
            tasks.append(self._check_react2shell(session, domain, alive_url))
        if checks.get("xxe"):
            tasks.append(self._check_xxe_surface(session, domain, alive_url))
        if checks.get("ssrf"):
            tasks.append(self._check_ssrf_surface(session, domain, alive_url))
        if checks.get("ggb"):
            tasks.append(self._check_graphql(session, domain, alive_url))
        if checks.get("lfi"):
            tasks.append(self._check_lfi(session, domain, alive_url))
        if checks.get("secrets"):
            tasks.append(self._check_js_secrets(session, domain, alive_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        return findings

    async def _check_paths(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for path in self.config.paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            status, body, _, final = await self._fetch(session, url)
            if status != 200:
                continue

            evidence = ""
            severity = "medium"
            check = "private_path"

            if path.endswith(".env") or ".env" in path:
                check = "secrets"
                severity = "critical"
                if any(marker in body for marker in ENV_SECRET_MARKERS):
                    evidence = "Fichier .env exposé avec secrets"
                else:
                    evidence = "Fichier .env accessible"
            elif "git" in path:
                continue  # géré par git_dump
            else:
                evidence = f"Path sensible accessible: {path}"

            findings.append(
                Finding(domain, check, severity, final or url, evidence, {"path": path, "status": status})
            )
        return findings

    async def _check_git(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for path in ["/.git/HEAD", "/.git/config"]:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            status, body, _, final = await self._fetch(session, url)
            if status != 200:
                continue
            text = body.decode("utf-8", errors="ignore")
            if path.endswith("HEAD") and GIT_HEAD_RE.search(text):
                findings.append(
                    Finding(
                        domain,
                        "git_dump",
                        "critical",
                        final or url,
                        "Repository .git exposé (HEAD)",
                        {"path": path},
                    )
                )
            elif path.endswith("config") and GIT_CONFIG_RE.search(text):
                findings.append(
                    Finding(
                        domain,
                        "git_dump",
                        "critical",
                        final or url,
                        "Repository .git exposé (config)",
                        {"path": path},
                    )
                )
        return findings

    async def _check_react2shell(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        status, body, headers, final = await self._fetch(session, base_url)
        if not status:
            return findings

        text = body.decode("utf-8", errors="ignore")
        has_next = any(marker.search(text) for marker in NEXTJS_MARKERS)
        has_rsc = any(h in headers for h in RSC_HEADERS)

        if has_next or has_rsc:
            version_hint = ""
            ver_match = re.search(r"next[@\-/](\d+\.\d+\.\d+)", text, re.I)
            if ver_match:
                version_hint = ver_match.group(1)

            potentially_vuln = False
            if version_hint:
                potentially_vuln = _is_vulnerable_nextjs(version_hint)

            findings.append(
                Finding(
                    domain,
                    "react2shell",
                    "critical" if potentially_vuln else "high",
                    final or base_url,
                    "Next.js / RSC détecté — candidat React2Shell (CVE-2025-55182)",
                    {
                        "has_rsc_headers": has_rsc,
                        "nextjs_detected": has_next,
                        "version_hint": version_hint,
                        "potentially_vulnerable": potentially_vuln,
                        "cve": ["CVE-2025-55182", "CVE-2025-66478"],
                    },
                )
            )
        return findings

    async def _check_xxe_surface(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(base_url)

        for hint in XXE_ENDPOINT_HINTS:
            url = f"{parsed.scheme}://{parsed.netloc}{hint}"
            status, body, headers, final = await self._fetch(session, url)
            if status and status < 404:
                ct = headers.get("content-type", "")
                if "xml" in ct or hint in url:
                    findings.append(
                        Finding(
                            domain,
                            "xxe",
                            "medium",
                            final or url,
                            "Endpoint XML/SOAP potentiellement vulnérable XXE",
                            {"endpoint": hint, "content_type": ct},
                        )
                    )

        if self.config.aggressive and self.config.callback_url:
            # Probe safe: envoi XML minimal sans entité externe
            test_url = f"{parsed.scheme}://{parsed.netloc}/"
            payload = '<?xml version="1.0"?><root>probe</root>'
            status, _, headers, final = await self._fetch(
                session,
                test_url,
                method="POST",
                data=payload,
                headers={"Content-Type": "application/xml"},
            )
            if status and status < 500:
                findings.append(
                    Finding(
                        domain,
                        "xxe",
                        "info",
                        final or test_url,
                        "Endpoint accepte XML (surface XXE à tester manuellement)",
                        {},
                    )
                )
        return findings

    async def _check_ssrf_surface(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(base_url)

        for param in SSRF_PARAM_HINTS:
            url = f"{parsed.scheme}://{parsed.netloc}/?{param}=http://127.0.0.1/"
            status, body, _, final = await self._fetch(session, url)
            if status and status < 500 and len(body) > 0:
                # Heuristique: réponse différente ou réflexion d'URL
                if b"127.0.0.1" in body or b"localhost" in body:
                    findings.append(
                        Finding(
                            domain,
                            "ssrf",
                            "high",
                            final or url,
                            f"Paramètre SSRF potentiel: {param}",
                            {"param": param},
                        )
                    )
        return findings

    async def _check_graphql(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(base_url)
        introspection = '{"query":"{__schema{types{name}}}"}'

        for path in GRAPHQL_PATHS:
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            status, body, _, final = await self._fetch(
                session,
                url,
                method="POST",
                data=introspection,
                headers={"Content-Type": "application/json"},
            )
            if status == 200 and b"__schema" in body:
                findings.append(
                    Finding(
                        domain,
                        "ggb",
                        "high",
                        final or url,
                        "GraphQL introspection activée (GGB)",
                        {"path": path},
                    )
                )
            elif status and status < 404:
                status_get, body_get, _, final_get = await self._fetch(session, url)
                if status_get == 200 and (b"graphiql" in body_get.lower() or b"graphql" in body_get.lower()):
                    findings.append(
                        Finding(
                            domain,
                            "ggb",
                            "medium",
                            final_get or url,
                            "Interface GraphQL exposée",
                            {"path": path},
                        )
                    )
        return findings

    async def _check_lfi(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(base_url)
        payloads = ["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd"]

        for param in self.config.lfi_params:
            for payload in payloads:
                url = f"{parsed.scheme}://{parsed.netloc}/?{param}={payload}"
                status, body, _, final = await self._fetch(session, url)
                if not status or status >= 500:
                    continue
                if any(indicator in body for indicator in LFI_INDICATORS):
                    findings.append(
                        Finding(
                            domain,
                            "lfi",
                            "critical",
                            final or url,
                            f"LFI potentiel via paramètre {param}",
                            {"param": param, "payload": payload},
                        )
                    )
                    return findings
        return findings

    async def _check_js_secrets(
        self, session: aiohttp.ClientSession, domain: str, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        status, body, _, final = await self._fetch(session, base_url)
        if not status:
            return findings

        text = body.decode("utf-8", errors="ignore")
        js_urls = set(re.findall(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', text, re.I))

        for rel in list(js_urls)[:15]:
            js_url = urljoin(final or base_url, rel)
            _, js_body, _, js_final = await self._fetch(session, js_url)
            js_text = js_body.decode("utf-8", errors="ignore")
            for pattern in self._secret_res:
                match = pattern.search(js_text)
                if match:
                    findings.append(
                        Finding(
                            domain,
                            "secrets",
                            "critical",
                            js_final or js_url,
                            f"Secret détecté dans JS: {match.group()[:20]}...",
                            {"pattern": pattern.pattern},
                        )
                    )
        return findings

    async def scan_many(
        self,
        domains: list[str],
        on_result: Any | None = None,
    ) -> list[Finding]:
        semaphore = asyncio.Semaphore(self.config.concurrency)
        all_findings: list[Finding] = []
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": "DomainGrabber/1.0 (security-research)"}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async def scan_one(domain: str) -> list[Finding]:
                async with semaphore:
                    return await self.scan_domain(session, domain)

            tasks = [scan_one(d) for d in domains]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                all_findings.extend(result)
                if on_result:
                    on_result(result)
        return all_findings


def _is_vulnerable_nextjs(version: str) -> bool:
    """Versions Next.js connues comme affectées par React2Shell."""
    vulnerable_ranges = [
        ("15.0.0", "15.0.4"),
        ("15.1.0", "15.1.8"),
        ("15.2.0", "15.2.5"),
        ("15.3.0", "15.3.5"),
        ("15.4.0", "15.4.7"),
        ("15.5.0", "15.5.6"),
        ("16.0.0", "16.0.6"),
    ]

    def parse(v: str) -> tuple[int, ...]:
        parts = []
        for p in v.split("."):
            try:
                parts.append(int(re.sub(r"[^0-9]", "", p) or "0"))
            except ValueError:
                parts.append(0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    ver = parse(version)
    for low, high in vulnerable_ranges:
        if parse(low) <= ver <= parse(high):
            return True
    return False


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps(
        [
            {
                "domain": f.domain,
                "check": f.check,
                "severity": f.severity,
                "url": f.url,
                "evidence": f.evidence,
                "metadata": f.metadata,
            }
            for f in findings
        ],
        ensure_ascii=False,
    )
