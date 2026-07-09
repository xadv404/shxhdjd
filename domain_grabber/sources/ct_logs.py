"""Source gratuite : téléchargement parallèle des logs CT publics (Google)."""

from __future__ import annotations

import asyncio
import base64
import json
import re
from collections.abc import AsyncIterator
from typing import Any

import aiohttp

from domain_grabber.utils import iter_domains_from_cert_names

_DNS_RE = re.compile(r"([a-zA-Z0-9*][a-zA-Z0-9.*_-]{1,253}\.[a-zA-Z]{2,})")


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


def _extract_domains_from_entry(entry: dict[str, Any]) -> set[str]:
    domains: set[str] = set()
    leaf_input = entry.get("leaf_input")
    if not leaf_input:
        return domains

    try:
        decoded = base64.b64decode(leaf_input)
        text = decoded.decode("latin-1", errors="ignore")
        for match in _DNS_RE.findall(text):
            if "." in match and not match.startswith("."):
                domains.update(iter_domains_from_cert_names([match]))
    except Exception:
        pass

    raw = json.dumps(entry)
    for match in re.findall(r"DNS:([a-zA-Z0-9.*_-]+)", raw):
        domains.update(iter_domains_from_cert_names([match]))

    return domains


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
