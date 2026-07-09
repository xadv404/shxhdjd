"""Source gratuite : téléchargement parallèle des logs CT publics (Google)."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from domain_grabber.utils import iter_domains_from_cert_names, normalize_domain


async def _get_tree_size(session: aiohttp.ClientSession, log_url: str) -> int:
    url = f"{log_url.rstrip('/')}/ct/v1/get-sth"
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
        if resp.status != 200:
            return 0
        data = await resp.json()
        return int(data.get("tree_size", 0))


async def _fetch_entries(
    session: aiohttp.ClientSession,
    log_url: str,
    start: int,
    end: int,
) -> list[dict[str, Any]]:
    if end < start:
        return []
    url = f"{log_url.rstrip('/')}/ct/v1/get-entries"
    params = {"start": start, "end": end}
    async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=60)) as resp:
        if resp.status != 200:
            return []
        data = await resp.json()
        if isinstance(data, dict):
            return data.get("entries", [])
        return data if isinstance(data, list) else []


def _parse_ct_entry(entry: dict[str, Any]) -> bytes | None:
    """Extrait le certificat X.509 depuis une entrée CT (Merkle leaf RFC 6962)."""
    leaf_input = entry.get("leaf_input")
    if not leaf_input:
        return None
    try:
        raw = base64.b64decode(leaf_input)
        if len(raw) < 15:
            return None
        entry_type = int.from_bytes(raw[10:12], "big")
        # x509_entry (0): 3-byte length + DER certificate
        if entry_type == 0:
            cert_len = int.from_bytes(raw[12:15], "big")
            cert_data = raw[15 : 15 + cert_len]
            return cert_data
        # precert_entry (1): parse extra_data chain
        if entry_type == 1 and entry.get("extra_data"):
            extra = base64.b64decode(entry["extra_data"])
            if len(extra) > 6:
                cert_len = int.from_bytes(extra[3:6], "big")
                return extra[6 : 6 + cert_len]
        return None
    except Exception:
        return None


def _extract_domains_from_entry(entry: dict[str, Any]) -> set[str]:
    """Parse le certificat proprement (CN + SAN) — évite le bruit type stream_index.dat."""
    domains: set[str] = set()
    cert_bytes = _parse_ct_entry(entry)
    if not cert_bytes:
        return domains

    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
    except Exception:
        return domains

    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for attr in cn_attrs:
            domains.update(iter_domains_from_cert_names([str(attr.value)]))
    except Exception:
        pass

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san.value:
            if isinstance(name, x509.DNSName):
                domains.update(iter_domains_from_cert_names([name.value]))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    return {d for d in domains if normalize_domain(d)}


async def stream_ct_logs(
    log_urls: list[str],
    batch_size: int = 512,
    workers: int = 8,
    start_index: int = 0,
    tail: bool = True,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Parcourt les logs CT publics — mode tail pour les nouveaux certificats."""
    semaphore = asyncio.Semaphore(workers)

    async with aiohttp.ClientSession() as session:
        indices: dict[str, int] = {}
        for log_url in log_urls:
            if tail:
                size = await _get_tree_size(session, log_url)
                indices[log_url] = max(0, size - batch_size * 4) if size else start_index
            else:
                indices[log_url] = start_index

        while True:
            tasks = []
            for log_url in log_urls:
                start = indices[log_url]
                end = start + batch_size - 1
                tasks.append((log_url, start, end))

            async def fetch_one(log_url: str, start: int, end: int) -> tuple[str, int, set[str]]:
                async with semaphore:
                    entries = await _fetch_entries(session, log_url, start, end)
                    found: set[str] = set()
                    for entry in entries:
                        found.update(_extract_domains_from_entry(entry))
                    return log_url, end + 1, found

            results = await asyncio.gather(
                *[fetch_one(url, s, e) for url, s, e in tasks],
                return_exceptions=True,
            )

            any_progress = False
            for result in results:
                if isinstance(result, Exception):
                    continue
                log_url, next_index, domains = result
                indices[log_url] = next_index
                if domains:
                    any_progress = True
                    for domain in domains:
                        yield domain, {"ct_log": log_url, "index": next_index}

            if not any_progress:
                await asyncio.sleep(3)
