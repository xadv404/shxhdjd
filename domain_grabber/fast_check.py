"""Check ports 80/443 (TCP) — ultra rapide."""

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
    start: float = 0.0

    @property
    def probe_rate(self) -> float:
        return self.done / max(time.time() - self.start, 0.001)

    @property
    def open_rate(self) -> float:
        return self.open_ports / max(time.time() - self.start, 0.001)


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


def _emit(stats: CheckStats) -> None:
    print(
        f"[CHECK] {stats.done}/{stats.total} | open={stats.open_ports} | "
        f"{int(stats.probe_rate)} probe/s | {int(stats.open_rate)} open/s",
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


async def run_fast_check(
    input_file: Path,
    output_file: Path,
    *,
    concurrency: int = 2000,
    timeout: float = 0.8,
    require_http: bool = False,  # ignoré — ports only
    log_interval: float = 2.0,
    chunk_size: int = 2000,
) -> CheckStats:
    """Exporte les domaines avec port 80 ou 443 ouvert."""
    domains = _load_domains(input_file)
    stats = CheckStats(total=len(domains), start=time.time())
    if not domains:
        print("[CHECK] 0 domaines", flush=True)
        return stats

    workers = min(concurrency, 3000)
    print(
        f"[CHECK] {len(domains)} domaines | TCP 80/443 | "
        f"workers={workers} | timeout={timeout}s",
        flush=True,
    )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    out = output_file.open("w", encoding="utf-8")
    lock = asyncio.Lock()
    last_log = time.time()

    async def handle(domain: str) -> None:
        nonlocal last_log
        opened = await _tcp_open(domain, 443, timeout) or await _tcp_open(domain, 80, timeout)
        async with lock:
            stats.done += 1
            if opened:
                stats.open_ports += 1
                out.write(domain + "\n")
                if stats.open_ports % 200 == 0:
                    out.flush()
            now = time.time()
            if now - last_log >= log_interval:
                _emit(stats)
                last_log = now

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
    _emit(stats)
    elapsed = max(time.time() - stats.start, 0.001)
    print(
        f"[DONE] {stats.open_ports}/{stats.total} OPEN "
        f"({100 * stats.open_ports / max(stats.total, 1):.0f}%) | "
        f"{int(stats.done / elapsed)} probe/s | → {output_file}",
        flush=True,
    )
    return stats
