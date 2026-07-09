"""Pipeline de vérification rapide : DNS → ports → HTTP.

Utilise massdns / masscan / httpx si disponibles (max perf sur serveur root),
sinon fallback asyncio haute concurrence.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp

DEFAULT_RESOLVERS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
]


@dataclass
class VerifyConfig:
    batch_size: int = 2000
    timeout: float = 2.0
    ports: tuple[int, ...] = (443, 80)
    require_http: bool = True
    http_status_max: int = 499
    dns_workers: int = 500
    tcp_concurrency: int = 1000
    http_concurrency: int = 400
    masscan_rate: int = 100_000
    resolvers: list[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    resolvers_file: str = ""
    prefer_tools: bool = True


@dataclass
class VerifiedDomain:
    domain: str
    ip: str = ""
    port: int = 0
    scheme: str = ""
    status: int = 0
    url: str = ""


@dataclass
class VerifyStats:
    input_domains: int = 0
    resolved: int = 0
    ports_open: int = 0
    http_alive: int = 0
    elapsed: float = 0.0

    @property
    def rate(self) -> float:
        return self.http_alive / max(self.elapsed, 0.001)


class Toolchain:
    def __init__(self) -> None:
        self.massdns = shutil.which("massdns")
        self.masscan = shutil.which("masscan")
        self.httpx = shutil.which("httpx")

    def describe(self) -> str:
        parts = []
        if self.massdns:
            parts.append("massdns")
        if self.masscan:
            parts.append("masscan")
        if self.httpx:
            parts.append("httpx")
        return "+".join(parts) if parts else "async-fallback"


def _unique_domains(domains: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


async def _run_subprocess(cmd: list[str], timeout: float = 120.0) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise
    return proc.returncode or 0, stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")


def _parse_massdns_output(text: str) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0].rstrip(".")
        if parts[1] != "A":
            continue
        ip = parts[2]
        mapping.setdefault(name, []).append(ip)
    return mapping


async def _resolve_massdns(
    domains: list[str],
    cfg: VerifyConfig,
    tools: Toolchain,
) -> dict[str, list[str]]:
    if not tools.massdns:
        return {}

    with tempfile.TemporaryDirectory(prefix="dg-verify-") as tmp:
        tmp_path = Path(tmp)
        domains_file = tmp_path / "domains.txt"
        resolvers_file = tmp_path / "resolvers.txt"
        out_file = tmp_path / "dns.out"

        domains_file.write_text("\n".join(domains) + "\n", encoding="utf-8")
        if cfg.resolvers_file and Path(cfg.resolvers_file).exists():
            resolvers_file.write_text(Path(cfg.resolvers_file).read_text(encoding="utf-8"))
        else:
            resolvers_file.write_text("\n".join(cfg.resolvers) + "\n", encoding="utf-8")

        cmd = [
            tools.massdns,
            "-r",
            str(resolvers_file),
            "-t",
            "A",
            "-o",
            "S",
            "-w",
            str(out_file),
            "-s",
            str(min(len(domains), 10000)),
            str(domains_file),
        ]
        rc, _, stderr = await _run_subprocess(cmd, timeout=max(30, len(domains) / 500))
        if rc != 0 and not out_file.exists():
            return {}
        text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
        if not text and stderr:
            return {}
        return _parse_massdns_output(text)


async def _resolve_async(domains: list[str], cfg: VerifyConfig) -> dict[str, list[str]]:
    try:
        return await _resolve_dnspython(domains, cfg)
    except ImportError:
        return await _resolve_getaddrinfo(domains, cfg)


async def _resolve_dnspython(domains: list[str], cfg: VerifyConfig) -> dict[str, list[str]]:
    import dns.asyncresolver
    import dns.exception

    resolvers = cfg.resolvers or DEFAULT_RESOLVERS
    sem = asyncio.Semaphore(min(cfg.dns_workers, len(domains), 2000))
    mapping: dict[str, list[str]] = {}

    async def resolve_one(domain: str) -> None:
        async with sem:
            for ns in resolvers:
                resolver = dns.asyncresolver.Resolver(configure=False)
                resolver.nameservers = [ns]
                resolver.timeout = cfg.timeout
                resolver.lifetime = cfg.timeout
                try:
                    answers = await resolver.resolve(domain, "A")
                    ips = list(dict.fromkeys(r.to_text() for r in answers))
                    if ips:
                        mapping[domain] = ips
                        return
                except (dns.exception.DNSException, OSError):
                    continue

    await asyncio.gather(*[resolve_one(d) for d in domains])
    return mapping


async def _resolve_getaddrinfo(domains: list[str], cfg: VerifyConfig) -> dict[str, list[str]]:
    import socket
    from concurrent.futures import ThreadPoolExecutor

    loop = asyncio.get_running_loop()
    mapping: dict[str, list[str]] = {}

    def resolve_one(domain: str) -> tuple[str, list[str]]:
        try:
            infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            ips = list(dict.fromkeys(info[4][0] for info in infos))
            return domain, ips
        except OSError:
            return domain, []

    workers = min(cfg.dns_workers, len(domains), 1000)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = await loop.run_in_executor(None, lambda: list(pool.map(resolve_one, domains)))

    for domain, ips in results:
        if ips:
            mapping[domain] = ips
    return mapping


async def resolve_domains(
    domains: list[str],
    cfg: VerifyConfig,
    tools: Toolchain,
) -> dict[str, list[str]]:
    domains = _unique_domains(domains)
    if not domains:
        return {}

    if tools.massdns and cfg.prefer_tools:
        result = await _resolve_massdns(domains, cfg, tools)
        if result:
            return result

    # Résolution par chunks pour éviter la saturation résolveur/OS
    chunk_size = min(800, max(200, cfg.dns_workers))
    mapping: dict[str, list[str]] = {}
    for i in range(0, len(domains), chunk_size):
        chunk = domains[i : i + chunk_size]
        part = await _resolve_async(chunk, cfg)
        mapping.update(part)
    return mapping


def _parse_masscan_json(text: str) -> set[tuple[str, int]]:
    open_pairs: set[tuple[str, int]] = set()
    stripped = text.strip()
    if stripped.startswith("["):
        try:
            entries = json.loads(stripped)
            for entry in entries:
                if isinstance(entry, dict) and entry.get("ip") and entry.get("ports"):
                    for p in entry["ports"]:
                        open_pairs.add((entry["ip"], int(p.get("port", 0))))
            return open_pairs
        except json.JSONDecodeError:
            pass
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and entry.get("ip") and entry.get("ports"):
            for p in entry["ports"]:
                open_pairs.add((entry["ip"], int(p.get("port", 0))))
    return open_pairs


async def _scan_masscan(
    ips: list[str],
    cfg: VerifyConfig,
    tools: Toolchain,
) -> set[tuple[str, int]]:
    if not tools.masscan or not ips:
        return set()

    ports = ",".join(str(p) for p in cfg.ports)
    with tempfile.TemporaryDirectory(prefix="dg-mscan-") as tmp:
        ips_file = Path(tmp) / "ips.txt"
        out_file = Path(tmp) / "scan.json"
        ips_file.write_text("\n".join(ips) + "\n", encoding="utf-8")

        cmd = [
            tools.masscan,
            "-iL",
            str(ips_file),
            "-p",
            ports,
            "--rate",
            str(cfg.masscan_rate),
            "-oJ",
            str(out_file),
            "--wait",
            "0",
        ]
        rc, _, _ = await _run_subprocess(cmd, timeout=max(15, len(ips) / 2000))
        if rc != 0 and not out_file.exists():
            return set()
        text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""
        return _parse_masscan_json(text)


async def _scan_tcp_async(
    domain_ips: dict[str, list[str]],
    cfg: VerifyConfig,
) -> dict[str, int]:
    """Retourne domain -> premier port ouvert."""
    sem = asyncio.Semaphore(cfg.tcp_concurrency)
    results: dict[str, int] = {}

    async def probe(domain: str, ip: str) -> tuple[str, int | None]:
        async with sem:
            for port in cfg.ports:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=cfg.timeout,
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return domain, port
                except Exception:
                    continue
            return domain, None

    tasks = []
    for domain, ips in domain_ips.items():
        tasks.append(probe(domain, ips[0]))

    for coro in asyncio.as_completed(tasks):
        domain, port = await coro
        if port is not None:
            results[domain] = port
    return results


async def filter_open_ports(
    domain_ips: dict[str, list[str]],
    cfg: VerifyConfig,
    tools: Toolchain,
) -> dict[str, int]:
    if not domain_ips:
        return {}

    unique_ips = list(dict.fromkeys(ip for ips in domain_ips.values() for ip in ips))

    if tools.masscan and cfg.prefer_tools:
        open_pairs = await _scan_masscan(unique_ips, cfg, tools)
        if open_pairs:
            domain_port: dict[str, int] = {}
            open_by_ip: dict[str, set[int]] = {}
            for ip, port in open_pairs:
                open_by_ip.setdefault(ip, set()).add(port)
            for domain, ips in domain_ips.items():
                for ip in ips:
                    ports = open_by_ip.get(ip)
                    if not ports:
                        continue
                    for preferred in cfg.ports:
                        if preferred in ports:
                            domain_port[domain] = preferred
                            break
                    if domain in domain_port:
                        break
            return domain_port

    return await _scan_tcp_async(domain_ips, cfg)


async def _probe_httpx(
    domains: list[str],
    cfg: VerifyConfig,
    tools: Toolchain,
) -> list[VerifiedDomain]:
    if not tools.httpx or not domains:
        return []

    with tempfile.TemporaryDirectory(prefix="dg-httpx-") as tmp:
        domains_file = Path(tmp) / "domains.txt"
        domains_file.write_text("\n".join(domains) + "\n", encoding="utf-8")

        cmd = [
            tools.httpx,
            "-l",
            str(domains_file),
            "-threads",
            str(cfg.http_concurrency),
            "-timeout",
            str(int(max(1, cfg.timeout))),
            "-silent",
            "-json",
            "-status-code",
            "-follow-redirects",
            "-no-color",
        ]
        rc, stdout, _ = await _run_subprocess(cmd, timeout=max(60, len(domains) / 200))
        if rc != 0 and not stdout.strip():
            return []

        alive: list[VerifiedDomain] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = row.get("url", "")
            status = int(row.get("status_code") or row.get("status-code") or 0)
            if status <= 0 or status > cfg.http_status_max:
                continue
            host = row.get("input") or row.get("host") or ""
            if "://" in host:
                from urllib.parse import urlparse

                host = urlparse(host).hostname or host
            if not host and url:
                from urllib.parse import urlparse

                host = urlparse(url).hostname or ""
            if not host:
                continue
            scheme = "https" if url.startswith("https") else "http" if url.startswith("http") else ""
            alive.append(
                VerifiedDomain(
                    domain=host,
                    ip=row.get("host") or row.get("a", [""])[0] if isinstance(row.get("a"), list) else "",
                    port=443 if scheme == "https" else 80,
                    scheme=scheme,
                    status=status,
                    url=url,
                )
            )
        return alive


async def _probe_http_async(
    domains: list[str],
    cfg: VerifyConfig,
) -> list[VerifiedDomain]:
    domains = _unique_domains(domains)
    if not domains:
        return []

    # Traiter par chunks pour garder un bon taux de succès à haute concurrence
    chunk_size = min(400, max(150, cfg.http_concurrency))
    alive: list[VerifiedDomain] = []
    for i in range(0, len(domains), chunk_size):
        chunk = domains[i : i + chunk_size]
        alive.extend(await _probe_http_chunk(chunk, cfg))
        if i + chunk_size < len(domains):
            await asyncio.sleep(0.2)
    return alive


async def _probe_http_chunk(
    domains: list[str],
    cfg: VerifyConfig,
) -> list[VerifiedDomain]:
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    for domain in domains:
        await queue.put(domain)
    workers = min(cfg.http_concurrency, len(domains), 2000)
    for _ in range(workers):
        await queue.put(None)

    alive: list[VerifiedDomain] = []
    lock = asyncio.Lock()
    connector = aiohttp.TCPConnector(
        limit=workers,
        ssl=False,
        ttl_dns_cache=300,
        force_close=True,
        enable_cleanup_closed=True,
    )

    async def worker(session: aiohttp.ClientSession) -> None:
        while True:
            domain = await queue.get()
            if domain is None:
                return
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}"
                try:
                    async with session.head(
                        url,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=cfg.timeout),
                        ssl=False,
                    ) as resp:
                        if 0 < resp.status <= cfg.http_status_max:
                            item = VerifiedDomain(
                                domain=domain,
                                port=443 if scheme == "https" else 80,
                                scheme=scheme,
                                status=resp.status,
                                url=str(resp.url),
                            )
                            async with lock:
                                alive.append(item)
                            break
                except Exception:
                    continue

    async with aiohttp.ClientSession(connector=connector) as session:
        await asyncio.gather(*[worker(session) for _ in range(workers)])
    return alive


async def probe_http(
    domains: list[str],
    cfg: VerifyConfig,
    tools: Toolchain,
) -> list[VerifiedDomain]:
    domains = _unique_domains(domains)
    if not domains:
        return []
    if tools.httpx and cfg.prefer_tools:
        result = await _probe_httpx(domains, cfg, tools)
        if result or not cfg.require_http:
            return result
    return await _probe_http_async(domains, cfg)


class FastVerifier:
    def __init__(self, cfg: VerifyConfig | None = None) -> None:
        self.cfg = cfg or VerifyConfig()
        self.tools = Toolchain()
        self.stats = VerifyStats()

    async def verify_batch(self, domains: list[str]) -> list[VerifiedDomain]:
        t0 = time.time()
        domains = _unique_domains(domains)
        self.stats.input_domains += len(domains)

        domain_ips = await resolve_domains(domains, self.cfg, self.tools)
        self.stats.resolved += len(domain_ips)

        if not domain_ips:
            self.stats.elapsed += time.time() - t0
            return []

        if self.cfg.require_http:
            candidates = list(domain_ips.keys())
            self.stats.ports_open += len(candidates)
            # massdns → httpx direct, ou DNS → HTTP (sans TCP intermédiaire)
            if self.tools.httpx and self.cfg.prefer_tools:
                alive = await _probe_httpx(candidates, self.cfg, self.tools)
                if not alive and self.tools.massdns:
                    alive = await _probe_http_async(candidates, self.cfg)
            else:
                alive = await _probe_http_async(candidates, self.cfg)
            for item in alive:
                if not item.ip:
                    item.ip = domain_ips.get(item.domain, [""])[0]
        else:
            domain_ports = await filter_open_ports(domain_ips, self.cfg, self.tools)
            self.stats.ports_open += len(domain_ports)
            alive = [
                VerifiedDomain(
                    domain=d,
                    ip=domain_ips[d][0],
                    port=domain_ports[d],
                    scheme="https" if domain_ports[d] == 443 else "http",
                )
                for d in domain_ports
            ]

        self.stats.http_alive += len(alive)
        self.stats.elapsed += time.time() - t0
        return alive
