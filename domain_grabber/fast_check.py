"""Checker HTTP ultra-rapide — ports 80 / 443.

Stratégie:
1) TCP connect rapide sur 443 puis 80
2) HTTP HEAD/GET uniquement si port ouvert
→ élimine vite les domaines morts sans handshake TLS.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from urllib.parse import urlparse

import aiohttp


@dataclass
class CheckStats:
    total: int = 0
    done: int = 0
    ports_open: int = 0
    alive: int = 0
    start: float = 0.0

    @property
    def rate(self) -> float:
        return self.done / max(time.time() - self.start, 0.001)

    @property
    def alive_rate(self) -> float:
        return self.alive / max(time.time() - self.start, 0.001)


def _load_domains(path: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                try:
                    line = str(json.loads(line).get("domain", ""))
                except json.JSONDecodeError:
                    continue
            line = line.lower().rstrip(".")
            if not line or line in seen:
                continue
            seen.add(line)
            out.append(line)
    return out


def _emit(stats: CheckStats) -> None:
    print(
        f"[CHECK] {stats.done}/{stats.total} | ports={stats.ports_open} | "
        f"alive={stats.alive} | {int(stats.alive_rate)} domain/s",
        flush=True,
    )


async def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _http_ok(
    session: aiohttp.ClientSession,
    domain: str,
    scheme: str,
    status_max: int,
) -> bool:
    url = f"{scheme}://{domain}"
    try:
        async with session.head(url, allow_redirects=True, ssl=False) as resp:
            await resp.read()
            if 0 < resp.status <= status_max:
                return True
            if resp.status not in (405, 501):
                return False
    except Exception:
        pass
    try:
        async with session.get(
            url,
            allow_redirects=True,
            ssl=False,
            headers={"Range": "bytes=0-0"},
        ) as resp:
            await resp.content.read(64)
            return 0 < resp.status <= status_max
    except Exception:
        return False


async def _check_one(
    session: aiohttp.ClientSession,
    domain: str,
    tcp_timeout: float,
    status_max: int,
) -> tuple[bool, bool]:
    """Retourne (port_open, http_alive)."""
    # 443 d'abord (HTTPS), sinon 80
    if await _tcp_open(domain, 443, tcp_timeout):
        ok = await _http_ok(session, domain, "https", status_max)
        return True, ok
    if await _tcp_open(domain, 80, tcp_timeout):
        ok = await _http_ok(session, domain, "http", status_max)
        return True, ok
    return False, False


async def _check_async(
    domains: list[str],
    out_fh: TextIO,
    concurrency: int,
    timeout: float,
    status_max: int,
    stats: CheckStats,
    log_interval: float,
) -> None:
    # Traiter par chunks pour éviter la saturation OS/DNS
    chunk_size = min(500, max(100, concurrency))
    tcp_timeout = min(0.8, timeout)
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    last_log = time.time()

    for i in range(0, len(domains), chunk_size):
        chunk = domains[i : i + chunk_size]
        workers = min(concurrency, len(chunk))
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        lock = asyncio.Lock()

        for d in chunk:
            queue.put_nowait(d)
        for _ in range(workers):
            queue.put_nowait(None)

        connector = aiohttp.TCPConnector(
            limit=workers,
            limit_per_host=4,
            ssl=ssl_ctx,
            ttl_dns_cache=600,
            use_dns_cache=True,
            force_close=True,
            enable_cleanup_closed=True,
        )
        client_timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=tcp_timeout,
            sock_connect=tcp_timeout,
            sock_read=timeout,
        )

        async def worker(session: aiohttp.ClientSession) -> None:
            while True:
                domain = await queue.get()
                if domain is None:
                    return
                port_open, alive = await _check_one(session, domain, tcp_timeout, status_max)
                async with lock:
                    stats.done += 1
                    if port_open:
                        stats.ports_open += 1
                    if alive:
                        out_fh.write(domain + "\n")
                        stats.alive += 1
                        if stats.alive % 100 == 0:
                            out_fh.flush()

        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
            tasks = [asyncio.create_task(worker(session)) for _ in range(workers)]
            while not all(t.done() for t in tasks):
                await asyncio.sleep(0.3)
                if time.time() - last_log >= log_interval:
                    _emit(stats)
                    last_log = time.time()
            await asyncio.gather(*tasks, return_exceptions=True)

        await asyncio.sleep(0.15)

    out_fh.flush()


async def _check_httpx(
    domains: list[str],
    out_fh: TextIO,
    concurrency: int,
    timeout: float,
    status_max: int,
    stats: CheckStats,
    log_interval: float,
) -> None:
    httpx = shutil.which("httpx")
    if not httpx:
        raise RuntimeError("httpx absent")

    import tempfile

    with tempfile.TemporaryDirectory(prefix="dg-check-") as tmp:
        inp = Path(tmp) / "in.txt"
        inp.write_text("\n".join(domains) + "\n", encoding="utf-8")
        cmd = [
            httpx,
            "-l",
            str(inp),
            "-threads",
            str(concurrency),
            "-timeout",
            str(max(1, int(timeout))),
            "-silent",
            "-json",
            "-status-code",
            "-follow-redirects",
            "-no-color",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        assert proc.stdout is not None
        last_log = time.time()
        seen: set[str] = set()
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            stats.done += 1
            try:
                row = json.loads(raw.decode(errors="replace"))
            except json.JSONDecodeError:
                continue
            code = int(row.get("status_code") or row.get("status-code") or 0)
            if code <= 0 or code > status_max:
                continue
            url = row.get("url", "")
            host = row.get("input") or ""
            if "://" in host:
                host = urlparse(host).hostname or host
            if not host and url:
                host = urlparse(url).hostname or ""
            if not host or host in seen:
                continue
            seen.add(host)
            out_fh.write(host + "\n")
            stats.alive += 1
            stats.ports_open += 1
            if stats.alive % 100 == 0:
                out_fh.flush()
            if time.time() - last_log >= log_interval:
                _emit(stats)
                last_log = time.time()
        await proc.wait()
        stats.done = max(stats.done, stats.total)
        out_fh.flush()


async def run_http_check(
    input_file: Path,
    output_file: Path,
    *,
    concurrency: int = 1500,
    timeout: float = 1.5,
    status_max: int = 499,
    log_interval: float = 3.0,
    prefer_httpx: bool = True,
) -> CheckStats:
    domains = _load_domains(input_file)
    stats = CheckStats(total=len(domains), start=time.time())
    if not domains:
        print("[CHECK] 0 domaines", flush=True)
        return stats

    httpx_bin = shutil.which("httpx")
    mode = "httpx" if (prefer_httpx and httpx_bin) else "async"
    if mode == "async":
        concurrency = min(concurrency, 600)

    print(
        f"[CHECK] {len(domains)} domaines | mode={mode} | "
        f"conc={concurrency} | timeout={timeout}s | ports=80,443",
        flush=True,
    )
    if mode == "async":
        print(
            "[CHECK] Tip: bash scripts/install-verify-tools.sh (httpx = max vitesse)",
            flush=True,
        )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as out_fh:
        if mode == "httpx":
            try:
                await _check_httpx(
                    domains, out_fh, concurrency, timeout, status_max, stats, log_interval
                )
            except Exception as exc:
                print(f"[CHECK] httpx fail ({exc}) → async", flush=True)
                stats.done = 0
                stats.alive = 0
                stats.ports_open = 0
                stats.start = time.time()
                await _check_async(
                    domains, out_fh, min(concurrency, 600), timeout, status_max, stats, log_interval
                )
        else:
            await _check_async(
                domains, out_fh, concurrency, timeout, status_max, stats, log_interval
            )

    _emit(stats)
    elapsed = max(time.time() - stats.start, 0.001)
    print(
        f"[DONE] {stats.alive}/{stats.total} ALIVE ({100 * stats.alive / max(stats.total, 1):.0f}%) | "
        f"{int(stats.alive / elapsed)} domain/s avg | → {output_file}",
        flush=True,
    )
    return stats
