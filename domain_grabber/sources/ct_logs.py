"""CT logs haute performance — cible 2-3k domaines/s."""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from domain_grabber.utils import iter_domains_from_cert_names, normalize_domain

# Logs CT Google actifs (fallback si découverte échoue)
DEFAULT_CT_LOGS = [
    "https://ct.googleapis.com/logs/us1/argon2025h2",
    "https://ct.googleapis.com/logs/us1/argon2025h1",
    "https://ct.googleapis.com/logs/eu1/xenon2025h2",
    "https://ct.googleapis.com/logs/eu1/xenon2025h1",
]

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
_log_list_cache: tuple[float, list[str]] | None = None

_parse_pool: ThreadPoolExecutor | None = None


def _get_parse_pool(workers: int) -> ThreadPoolExecutor:
    global _parse_pool
    if _parse_pool is None or (_parse_pool._max_workers or 0) < workers:  # noqa: SLF001
        if _parse_pool is not None:
            _parse_pool.shutdown(wait=False)
        _parse_pool = ThreadPoolExecutor(max_workers=workers)
    return _parse_pool


async def discover_google_ct_logs(
    session: aiohttp.ClientSession | None = None,
    max_logs: int = 8,
    cache_ttl: float = 3600,
) -> list[str]:
    """Récupère les logs CT Google actifs (usable) depuis la log list officielle."""
    global _log_list_cache
    now = time.time()
    if _log_list_cache and (now - _log_list_cache[0]) < cache_ttl:
        return _log_list_cache[1][:max_logs]

    close_session = False
    if session is None:
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20))
        close_session = True

    urls: list[str] = []
    try:
        async with session.get(LOG_LIST_URL) as resp:
            if resp.status != 200:
                return DEFAULT_CT_LOGS
            data = await resp.json()
        for op in data.get("operators", []):
            for log in op.get("logs", []):
                url = log.get("url", "")
                state = log.get("state", {})
                if not url.startswith("https://ct.googleapis.com/"):
                    continue
                if state.get("usable") or state.get("qualified"):
                    urls.append(url.rstrip("/"))
        if not urls:
            urls = list(DEFAULT_CT_LOGS)
    except Exception:
        urls = list(DEFAULT_CT_LOGS)
    finally:
        if close_session:
            await session.close()

    # Préférer les logs récents (argon/xenon 2025)
    urls.sort(key=lambda u: ("2025" not in u, "argon" not in u and "xenon" not in u, u))
    _log_list_cache = (now, urls)
    return urls[:max_logs]


def _parse_ct_entry(entry: dict[str, Any]) -> bytes | None:
    leaf_input = entry.get("leaf_input")
    if not leaf_input:
        return None
    try:
        raw = base64.b64decode(leaf_input)
        if len(raw) < 15:
            return None
        entry_type = int.from_bytes(raw[10:12], "big")
        if entry_type == 0:
            cert_len = int.from_bytes(raw[12:15], "big")
            return raw[15 : 15 + cert_len]
        if entry_type == 1 and entry.get("extra_data"):
            extra = base64.b64decode(entry["extra_data"])
            if len(extra) > 6:
                cert_len = int.from_bytes(extra[3:6], "big")
                return extra[6 : 6 + cert_len]
    except Exception:
        pass
    return None


def _domains_from_cert_bytes(cert_bytes: bytes) -> set[str]:
    domains: set[str] = set()
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
    except Exception:
        return domains
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            domains.update(iter_domains_from_cert_names([str(attr.value)]))
    except Exception:
        pass
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san.value:
            if isinstance(name, x509.DNSName):
                domains.update(iter_domains_from_cert_names([name.value]))
    except Exception:
        pass
    return {d for d in domains if normalize_domain(d)}


def parse_entries_batch(entries: list[dict[str, Any]]) -> list[str]:
    """Parse un lot d'entrées CT (CPU-bound, exécuter dans un thread pool)."""
    out: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        cert_bytes = _parse_ct_entry(entry)
        if not cert_bytes:
            continue
        for domain in _domains_from_cert_bytes(cert_bytes):
            if domain not in seen:
                seen.add(domain)
                out.append(domain)
    return out


async def _get_tree_size(session: aiohttp.ClientSession, log_url: str) -> int:
    url = f"{log_url.rstrip('/')}/ct/v1/get-sth"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return 0
            data = await resp.json()
            return int(data.get("tree_size", 0))
    except Exception:
        return 0


async def _fetch_entries(
    session: aiohttp.ClientSession,
    log_url: str,
    start: int,
    end: int,
) -> list[dict[str, Any]]:
    if end < start:
        return []
    url = f"{log_url.rstrip('/')}/ct/v1/get-entries"
    try:
        async with session.get(
            url,
            params={"start": start, "end": end},
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            if isinstance(data, dict):
                return data.get("entries", [])
            return data if isinstance(data, list) else []
    except Exception:
        return []


async def _log_pump(
    session: aiohttp.ClientSession,
    log_url: str,
    queue: asyncio.Queue,
    batch_size: int,
    inflight: int,
    tail: bool,
    parse_workers: int,
    stop: asyncio.Event,
    start_offset: int = 200_000,
) -> None:
    """Pump continu pour un log CT — fetch pipeliné + parse thread pool."""
    loop = asyncio.get_running_loop()
    pool = _get_parse_pool(parse_workers)
    sem = asyncio.Semaphore(inflight)

    try:
        size = await _get_tree_size(session, log_url)
        if size <= 0:
            return

        # CT API renvoie ~32 entrées max/requête
        batch_size = min(batch_size, 32)

        if tail:
            index = max(0, size - batch_size * 4)
            window_end: int | None = None
        else:
            index = max(0, size - start_offset)
            window_end = size

        last_size_refresh = time.time()

        async def fetch_and_parse(start: int, end: int) -> list[str]:
            async with sem:
                entries = await _fetch_entries(session, log_url, start, end)
            return await loop.run_in_executor(pool, parse_entries_batch, entries)

        pending: set[asyncio.Task] = set()

        while not stop.is_set():
            limit = window_end if window_end is not None else size

            if tail:
                now = time.time()
                if now - last_size_refresh > 2.0:
                    size = await _get_tree_size(session, log_url)
                    last_size_refresh = now
                    limit = size
                if index >= limit:
                    if pending:
                        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                        for task in done:
                            await _emit_domains(queue, log_url, task)
                    else:
                        await asyncio.sleep(0.1)
                    continue

            if window_end is not None and index >= window_end and not pending:
                break

            while len(pending) < inflight and index < limit and not stop.is_set():
                end = min(index + batch_size - 1, limit - 1)
                pending.add(asyncio.create_task(fetch_and_parse(index, end)))
                index = end + 1

            if not pending:
                break

            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                await _emit_domains(queue, log_url, task)

        if pending:
            done, _ = await asyncio.wait(pending)
            for task in done:
                await _emit_domains(queue, log_url, task)
    finally:
        await queue.put((log_url, None))


async def _emit_domains(
    queue: asyncio.Queue,
    log_url: str,
    task: asyncio.Task,
) -> None:
    try:
        domains = task.result()
    except Exception:
        return
    if domains:
        await queue.put((log_url, domains))


async def stream_ct_logs_batches(
    log_urls: list[str] | None = None,
    batch_size: int = 32,
    inflight_per_log: int = 16,
    tail: bool = False,
    parse_workers: int = 24,
    queue_size: int = 0,
    start_offset: int = 200_000,
    discover: bool = True,
) -> AsyncIterator[tuple[list[str], dict[str, Any]]]:
    """Yield des lots de domaines (meilleur débit)."""
    connector = aiohttp.TCPConnector(limit=0, limit_per_host=0)
    timeout = aiohttp.ClientTimeout(total=60)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        urls = log_urls
        if discover and (not urls or urls == DEFAULT_CT_LOGS):
            urls = await discover_google_ct_logs(session)

        urls = urls or DEFAULT_CT_LOGS
        queue: asyncio.Queue[tuple[str, list[str] | None] | None] = asyncio.Queue(maxsize=queue_size)
        stop = asyncio.Event()

        pumps = [
            asyncio.create_task(
                _log_pump(
                    session,
                    url,
                    queue,
                    batch_size,
                    inflight_per_log,
                    tail,
                    parse_workers,
                    stop,
                    start_offset,
                )
            )
            for url in urls
        ]

        active = len(urls)
        try:
            while active > 0:
                item = await queue.get()
                if item is None:
                    continue
                _log_url, domains = item
                if domains is None:
                    active -= 1
                    continue
                yield domains, {"ct_log": _log_url, "count": len(domains)}
        finally:
            stop.set()
            for p in pumps:
                p.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)


async def stream_ct_logs_fast(
    log_urls: list[str] | None = None,
    batch_size: int = 32,
    inflight_per_log: int = 16,
    tail: bool = False,
    parse_workers: int = 24,
    start_offset: int = 200_000,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    async for domains, meta in stream_ct_logs_batches(
        log_urls=log_urls,
        batch_size=batch_size,
        inflight_per_log=inflight_per_log,
        tail=tail,
        parse_workers=parse_workers,
        start_offset=start_offset,
    ):
        for domain in domains:
            yield domain, meta


# Compatibilité avec l'ancienne API
async def stream_ct_logs(
    log_urls: list[str],
    batch_size: int = 512,
    workers: int = 8,
    start_index: int = 0,
    tail: bool = True,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    async for item in stream_ct_logs_fast(
        log_urls=log_urls,
        batch_size=batch_size,
        inflight_per_log=max(2, workers // max(1, len(log_urls))),
        tail=tail,
        parse_workers=workers,
    ):
        yield item
