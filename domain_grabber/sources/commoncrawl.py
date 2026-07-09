"""Source gratuite : Common Crawl CDX Index API."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

import aiohttp

from domain_grabber.utils import normalize_domain


async def _fetch_cdx_page(
    session: aiohttp.ClientSession,
    coll: str,
    pattern: str,
    page: int,
) -> list[dict[str, Any]]:
    base = f"https://index.commoncrawl.org/{coll}-index"
    params = {
        "url": pattern,
        "output": "json",
        "page": page,
    }
    async with session.get(base, params=params, timeout=aiohttp.ClientTimeout(total=120)) as resp:
        if resp.status != 200:
            return []
        text = await resp.text()
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                import json

                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


async def _get_latest_collection(session: aiohttp.ClientSession) -> str:
    async with session.get(
        "https://index.commoncrawl.org/collinfo.json",
        timeout=aiohttp.ClientTimeout(total=30),
    ) as resp:
        data = await resp.json()
        return data[0]["id"]


def _url_to_domain(url: str) -> str | None:
    value = url.lower()
    for prefix in ("http://", "https://"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    host = value.split("/")[0].split(":")[0]
    return normalize_domain(host)


async def stream_commoncrawl(
    tlds: list[str],
    workers: int = 4,
    max_per_tld: int = 0,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Extrait les domaines via l'index CDX Common Crawl (gratuit)."""
    semaphore = asyncio.Semaphore(workers)

    async with aiohttp.ClientSession() as session:
        collection = await _get_latest_collection(session)

        async def crawl_tld(tld: str) -> AsyncIterator[tuple[str, dict[str, Any]]]:
            pattern = f"*.{tld}"
            page = 0
            count = 0
            while True:
                async with semaphore:
                    rows = await _fetch_cdx_page(session, collection, pattern, page)
                if not rows:
                    break
                for row in rows:
                    url = row.get("url", "")
                    domain = _url_to_domain(url)
                    if domain:
                        count += 1
                        yield domain, {"tld": tld, "collection": collection, "url": url}
                        if max_per_tld and count >= max_per_tld:
                            return
                page += 1
                await asyncio.sleep(0.2)  # respecter l'index server

        iterators = [crawl_tld(tld) for tld in tlds]
        pending = {asyncio.create_task(it.__anext__()): it for it in iterators}

        while pending:
            done, _ = await asyncio.wait(pending.keys(), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                it = pending.pop(task)
                try:
                    item = task.result()
                    yield item
                    pending[asyncio.create_task(it.__anext__())] = it
                except StopAsyncIteration:
                    pass
