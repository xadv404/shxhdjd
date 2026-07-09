"""Source gratuite : flux Certificate Transparency via Certstream."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import websockets

DEFAULT_URLS = [
    "wss://certstream.calidog.io/domains-only",
    "wss://certstream.calidog.io/",
]


async def _stream_sse(url: str) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Fallback SSE si WebSocket indisponible."""
    sse_url = url.replace("wss://", "https://").replace("ws://", "http://")
    if "domains-only" in sse_url:
        sse_url = sse_url.replace("/domains-only", "/sse?stream=domains")
    elif not sse_url.endswith("/sse"):
        sse_url = sse_url.rstrip("/") + "/sse?stream=domains"

    timeout = aiohttp.ClientTimeout(total=None, sock_read=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(sse_url) as resp:
            async for line in resp.content:
                text = line.decode("utf-8", errors="ignore").strip()
                if not text.startswith("data:"):
                    continue
                payload = text[5:].strip()
                if not payload:
                    continue
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                domains = data.get("data", [])
                if isinstance(domains, list):
                    for domain in domains:
                        if isinstance(domain, str):
                            yield domain, {"transport": "sse"}
                elif isinstance(domains, dict):
                    for name in domains.get("leaf_cert", {}).get("all_domains", []):
                        if isinstance(name, str):
                            yield name, {"transport": "sse"}


async def stream_certstream(
    url: str | None = None,
    fallback_urls: list[str] | None = None,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Écoute Certstream (WebSocket) avec fallbacks."""
    urls = [url] if url else []
    urls.extend(fallback_urls or DEFAULT_URLS)
    urls = list(dict.fromkeys(u for u in urls if u))

    backoff = 1
    url_index = 0

    while True:
        current = urls[url_index % len(urls)]
        try:
            async with websockets.connect(
                current,
                ping_interval=20,
                ping_timeout=20,
                open_timeout=15,
            ) as ws:
                backoff = 1
                async for message in ws:
                    try:
                        payload = json.loads(message)
                    except json.JSONDecodeError:
                        continue

                    data = payload.get("data")
                    if isinstance(data, list):
                        for domain in data:
                            if isinstance(domain, str):
                                yield domain, {"message_type": payload.get("message_type")}
                    elif isinstance(data, dict):
                        names = data.get("leaf_cert", {}).get("all_domains", [])
                        for domain in names:
                            if isinstance(domain, str):
                                yield domain, {"message_type": payload.get("message_type")}
        except asyncio.CancelledError:
            raise
        except Exception:
            url_index += 1
            if url_index >= len(urls):
                url_index = 0
                # Dernier recours : SSE sur calidog
                try:
                    async for item in _stream_sse(current):
                        yield item
                        backoff = 1
                except Exception:
                    pass
            await asyncio.sleep(min(backoff, 30))
            backoff *= 2
