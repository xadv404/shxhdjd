"""Source gratuite : certificats récents via crt.sh."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

from domain_grabber.utils import iter_domains_from_cert_names


async def stream_crtsh(
    percent: str = "%",
    poll_interval: int = 60,
    max_age_hours: int = 24,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Interroge crt.sh pour les certificats récents (gratuit, rate-limited)."""
    seen_ids: set[int] = set()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

    async with aiohttp.ClientSession() as session:
        while True:
            url = "https://crt.sh/"
            params = {"q": percent, "deduplicate": "Y", "output": "json"}
            try:
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as resp:
                    if resp.status != 200:
                        await asyncio.sleep(poll_interval)
                        continue
                    text = await resp.text()
                    if not text.strip():
                        await asyncio.sleep(poll_interval)
                        continue
                    records = await asyncio.to_thread(__import__("json").loads, text)
            except Exception:
                await asyncio.sleep(poll_interval)
                continue

            for record in records:
                cert_id = record.get("id")
                if cert_id in seen_ids:
                    continue

                not_before = record.get("not_before")
                if not_before:
                    try:
                        issued = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                        if issued.tzinfo is None:
                            issued = issued.replace(tzinfo=timezone.utc)
                        if issued < cutoff:
                            continue
                    except ValueError:
                        pass

                seen_ids.add(cert_id)
                names = record.get("name_value", "")
                for line in str(names).split("\n"):
                    for domain in iter_domains_from_cert_names([line.strip()]):
                        yield domain, {
                            "source_id": "crtsh",
                            "cert_id": cert_id,
                            "issuer": record.get("issuer_name", ""),
                        }

            await asyncio.sleep(poll_interval)
