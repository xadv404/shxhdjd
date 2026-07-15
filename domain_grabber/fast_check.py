"""Checker ultra-rapide ports 80/443 (TCP) — option HTTP.

Cible: plusieurs centaines à 1k+/s selon la connexion.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CheckStats:
    total: int = 0
    done: int = 0
    open_ports: int = 0
    alive: int = 0
    start: float = 0.0

    @property
    def probe_rate(self) -> float:
        return self.done / max(time.time() - self.start, 0.001)

    @property
    def alive_rate(self) -> float:
        return self.alive / max(time.time() - self.start, 0.001)


def _load_domains(path: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip().lower().rstrip(".")
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                try:
                    line = str(json.loads(line).get("domain", "")).lower().rstrip(".")
                except json.JSONDecodeError:
                    continue
            if not line or line in seen:
                continue
            seen.add(line)
            out.append(line)
    return out


def _emit(stats: CheckStats, mode: str) -> None:
    print(
        f"[CHECK] {stats.done}/{stats.total} | open={stats.open_ports} | "
        f"alive={stats.alive} | {int(stats.probe_rate)} probe/s | "
        f"{int(stats.alive_rate)} alive/s | mode={mode}",
        flush=True,
    )


async def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _http_alive(host: str, port: int, timeout: float) -> bool:
    """HTTP HEAD minimal via raw socket (plus léger qu'aiohttp)."""
    import ssl

    try:
        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        req = (
            f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: dg-check\r\nConnection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.startswith(b"HTTP/")
    except Exception:
        return False


async def run_fast_check(
    input_file: Path,
    output_file: Path,
    *,
    concurrency: int = 2000,
    timeout: float = 0.8,
    require_http: bool = False,
    log_interval: float = 2.0,
    chunk_size: int = 2000,
) -> CheckStats:
    """
    require_http=False → port 80/443 ouvert = alive (max speed)
    require_http=True  → + réponse HTTP
    """
    domains = _load_domains(input_file)
    stats = CheckStats(total=len(domains), start=time.time())
    mode = "tcp+http" if require_http else "tcp"
    if not domains:
        print("[CHECK] 0 domaines", flush=True)
        return stats

    # Cap workers selon mode
    workers = min(concurrency, 3000 if not require_http else 800)
    print(
        f"[CHECK] {len(domains)} domaines | mode={mode} | "
        f"workers={workers} | timeout={timeout}s | ports=80,443",
        flush=True,
    )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    out = output_file.open("w", encoding="utf-8")
    lock = asyncio.Lock()
    last_log = time.time()

    async def handle(domain: str) -> None:
        nonlocal last_log
        open_port = 0
        if await _tcp_open(domain, 443, timeout):
            open_port = 443
        elif await _tcp_open(domain, 80, timeout):
            open_port = 80

        alive = False
        if open_port:
            if require_http:
                alive = await _http_alive(domain, open_port, timeout)
            else:
                alive = True

        async with lock:
            stats.done += 1
            if open_port:
                stats.open_ports += 1
            if alive:
                stats.alive += 1
                out.write(domain + "\n")
                if stats.alive % 200 == 0:
                    out.flush()
            now = time.time()
            if now - last_log >= log_interval:
                _emit(stats, mode)
                last_log = now

    # Chunks = évite saturate FD
    for i in range(0, len(domains), chunk_size):
        chunk = domains[i : i + chunk_size]
        sem = asyncio.Semaphore(workers)

        async def one(d: str) -> None:
            async with sem:
                await handle(d)

        await asyncio.gather(*[one(d) for d in chunk])
        await asyncio.sleep(0.05)

    out.flush()
    out.close()
    _emit(stats, mode)
    elapsed = max(time.time() - stats.start, 0.001)
    print(
        f"[DONE] {stats.alive}/{stats.total} ALIVE ({100 * stats.alive / max(stats.total, 1):.0f}%) | "
        f"{int(stats.done / elapsed)} probe/s | {int(stats.alive / elapsed)} alive/s | "
        f"→ {output_file}",
        flush=True,
    )
    return stats
