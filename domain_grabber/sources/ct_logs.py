"""CT logs multi-sources — débit max (cible 10-15k domaines/s)."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from domain_grabber.utils import iter_domains_from_cert_names, normalize_domain

DEFAULT_CT_LOGS = [
    "https://ct.googleapis.com/logs/us1/argon2026h2",
    "https://ct.googleapis.com/logs/us1/argon2025h2",
    "https://ct.googleapis.com/logs/eu1/xenon2026h2",
    "https://ct.googleapis.com/logs/eu1/xenon2025h2",
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


def _domains_from_cert_bytes(cert_bytes: bytes) -> list[str]:
    out: list[str] = []
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
    except Exception:
        return out
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            out.extend(iter_domains_from_cert_names([str(attr.value)]))
    except Exception:
        pass
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san.value:
            if isinstance(name, x509.DNSName):
                out.extend(iter_domains_from_cert_names([name.value]))
    except Exception:
        pass
    seen: set[str] = set()
    uniq: list[str] = []
    for d in out:
        if d and d not in seen and normalize_domain(d):
            seen.add(d)
            uniq.append(d)
    return uniq


def parse_entries_batch(entries: list[dict[str, Any]]) -> list[str]:
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
    try:
        async with session.get(
            f"{log_url.rstrip('/')}/ct/v1/get-sth",
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            if resp.status != 200:
                return 0
            data = await resp.json(content_type=None)
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
    try:
        async with session.get(
            f"{log_url.rstrip('/')}/ct/v1/get-entries",
            params={"start": start, "end": end},
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
            if isinstance(data, dict):
                return data.get("entries", [])
            return data if isinstance(data, list) else []
    except Exception:
        return []


async def discover_ct_logs(
    session: aiohttp.ClientSession | None = None,
    max_logs: int = 24,
) -> list[str]:
    """Découvre les logs CT utilisables (tous opérateurs)."""
    global _log_list_cache
    import time

    now = time.time()
    if _log_list_cache and (now - _log_list_cache[0]) < 3600:
        return _log_list_cache[1][:max_logs]

    close = False
    if session is None:
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20))
        close = True

    urls: list[str] = []
    try:
        async with session.get(LOG_LIST_URL) as resp:
            if resp.status != 200:
                return list(DEFAULT_CT_LOGS)
            data = await resp.json(content_type=None)
        for op in data.get("operators", []):
            for log in op.get("logs", []):
                url = (log.get("url") or "").rstrip("/")
                state = log.get("state", {})
                if not url.startswith("https://"):
                    continue
                if any(k in state for k in ("usable", "qualified", "readonly")):
                    urls.append(url)
    except Exception:
        urls = list(DEFAULT_CT_LOGS)
    finally:
        if close:
            await session.close()

    urls = list(dict.fromkeys(urls or DEFAULT_CT_LOGS))
    # Prioriser Google (meilleurs débits mesurés)
    urls.sort(
        key=lambda u: (
            "googleapis" not in u,
            "2026" not in u and "2025" not in u,
            u,
        )
    )
    _log_list_cache = (now, urls)
    return urls[:max_logs]


async def probe_working_logs(
    session: aiohttp.ClientSession,
    urls: list[str],
    limit: int = 12,
) -> list[str]:
    """Garde les logs avec tree_size > 0 ET au moins 1 entry."""
    sem = asyncio.Semaphore(16)

    async def one(url: str) -> tuple[str, int]:
        async with sem:
            size = await _get_tree_size(session, url)
            if size <= 32:
                return url, 0
            entries = await _fetch_entries(session, url, size - 8, size - 1)
            return url, size if entries else 0

    results = await asyncio.gather(*[one(u) for u in urls])
    alive = [(u, s) for u, s in results if s > 0]
    alive.sort(key=lambda x: ("googleapis" not in x[0], -x[1]))
    return [u for u, _ in alive[:limit]]


async def _log_pump(
    session: aiohttp.ClientSession,
    log_url: str,
    queue: asyncio.Queue,
    batch_size: int,
    inflight: int,
    parse_workers: int,
    stop: asyncio.Event,
    start_offset: int,
) -> None:
    loop = asyncio.get_running_loop()
    pool = _get_parse_pool(parse_workers)
    sem = asyncio.Semaphore(inflight)
    batch_size = min(batch_size, 32)

    try:
        size = await _get_tree_size(session, log_url)
        if size <= 0:
            return
        index = max(0, size - start_offset)
        window_end = size
        pending: set[asyncio.Task] = set()

        async def fetch_parse(start: int, end: int) -> list[str]:
            async with sem:
                entries = await _fetch_entries(session, log_url, start, end)
            if not entries:
                return []
            return await loop.run_in_executor(pool, parse_entries_batch, entries)

        while not stop.is_set() and (index < window_end or pending):
            while len(pending) < inflight and index < window_end and not stop.is_set():
                end = min(index + batch_size - 1, window_end - 1)
                pending.add(asyncio.create_task(fetch_parse(index, end)))
                index = end + 1

            if not pending:
                break

            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    domains = task.result()
                except Exception:
                    continue
                if domains:
                    await queue.put((log_url, domains))

        if pending:
            done, _ = await asyncio.wait(pending)
            for task in done:
                try:
                    domains = task.result()
                except Exception:
                    continue
                if domains:
                    await queue.put((log_url, domains))
    finally:
        await queue.put((log_url, None))


async def stream_ct_logs_batches(
    log_urls: list[str] | None = None,
    batch_size: int = 32,
    inflight_per_log: int = 48,
    tail: bool = False,
    parse_workers: int = 32,
    queue_size: int = 0,
    start_offset: int = 500_000,
    discover: bool = True,
    max_logs: int = 8,
) -> AsyncIterator[tuple[list[str], dict[str, Any]]]:
    """Yield des lots depuis plusieurs CT logs en parallèle."""
    connector = aiohttp.TCPConnector(limit=0, limit_per_host=0, ttl_dns_cache=300)
    timeout = aiohttp.ClientTimeout(total=40)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        urls = list(log_urls) if log_urls else []
        if not urls:
            # Défaut rapide: 4 logs Google connus (meilleurs débits)
            urls = list(DEFAULT_CT_LOGS)
            if discover:
                extra = await discover_ct_logs(session, max_logs=20)
                # Ajouter d'autres logs Google/Cloudflare/DigiCert qui marchent
                extras = [u for u in extra if u not in urls]
                working = await probe_working_logs(session, extras[:12], limit=max(0, max_logs - len(urls)))
                urls = (urls + working)[:max_logs]
        elif discover:
            urls = await probe_working_logs(session, urls, limit=max_logs) or urls

        urls = urls or list(DEFAULT_CT_LOGS)

        queue: asyncio.Queue[tuple[str, list[str] | None]] = asyncio.Queue(maxsize=queue_size)
        stop = asyncio.Event()
        # expose for caller
        session._dg_sources = len(urls)  # type: ignore[attr-defined]
        session._dg_urls = list(urls)  # type: ignore[attr-defined]

        pumps = [
            asyncio.create_task(
                _log_pump(
                    session,
                    url,
                    queue,
                    batch_size,
                    inflight_per_log,
                    parse_workers,
                    stop,
                    start_offset,
                )
            )
            for url in urls
        ]

        # Premier yield meta: annoncer le nombre de sources via yield vide? 
        # On yield un marqueur spécial __sources__
        yield [], {"sources": len(urls), "ct_logs": urls}

        active = len(urls)
        try:
            while active > 0:
                item = await queue.get()
                log_url, domains = item
                if domains is None:
                    active -= 1
                    continue
                yield domains, {"ct_log": log_url, "count": len(domains), "sources": len(urls)}
        finally:
            stop.set()
            for p in pumps:
                p.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)


async def stream_single_ct(
    *,
    log_url: str | None = None,
    batch_size: int = 32,
    inflight: int = 64,
    parse_workers: int = 32,
    start_offset: int = 500_000,
) -> AsyncIterator[tuple[list[str], dict[str, Any]]]:
    urls = [log_url] if log_url else None
    async for item in stream_ct_logs_batches(
        log_urls=urls,
        batch_size=batch_size,
        inflight_per_log=inflight,
        parse_workers=parse_workers,
        start_offset=start_offset,
        discover=log_url is None,
        max_logs=1,
    ):
        if item[0] or item[1].get("ct_log"):
            yield item


async def stream_ct_logs(
    log_urls: list[str],
    batch_size: int = 512,
    workers: int = 8,
    start_index: int = 0,
    tail: bool = True,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    async for domains, meta in stream_ct_logs_batches(
        log_urls=log_urls or None,
        batch_size=batch_size,
        inflight_per_log=max(8, workers),
        parse_workers=workers,
        discover=not log_urls,
    ):
        for d in domains:
            yield d, meta


# alias
discover_google_ct_logs = discover_ct_logs
