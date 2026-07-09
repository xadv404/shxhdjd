"""Point d'entrée CLI du domain grabber."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.live import Live
from rich.table import Table

from domain_grabber.filters import FilterConfig
from domain_grabber.pipeline import DomainPipeline
from domain_grabber.scanner import (
    DEFAULT_CHECKS,
    DEFAULT_LFI_PARAMS,
    DEFAULT_PATHS,
    DEFAULT_SECRET_PATTERNS,
    ScanConfig,
    VulnScanner,
    findings_to_json,
)
from domain_grabber.sources.certstream import stream_certstream
from domain_grabber.sources.crtsh import stream_crtsh
from domain_grabber.sources.commoncrawl import stream_commoncrawl
from domain_grabber.sources.ct_logs import stream_ct_logs
from domain_grabber.sources.rapid7_fdns import stream_rapid7_fdns
from domain_grabber.sources.zone_files import stream_zone_files
from domain_grabber.storage import DomainStore
from domain_grabber.utils import normalize_domain

console = Console()


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build_filter_config(cfg: dict[str, Any]) -> FilterConfig:
    f = cfg.get("filters", {})
    return FilterConfig(
        punycode=f.get("punycode", False),
        ip_in_san=f.get("ip_in_san", False),
        suspicious_tlds=f.get("suspicious_tlds", []),
        min_domain_length=f.get("min_domain_length", 4),
        max_domain_length=f.get("max_domain_length", 253),
        require_match=f.get("require_match", False),
    )


def build_scan_config(cfg: dict[str, Any]) -> ScanConfig:
    s = cfg.get("scanner", {})
    checks = dict(DEFAULT_CHECKS)
    checks.update(s.get("checks", {}))
    return ScanConfig(
        concurrency=s.get("concurrency", 50),
        timeout=s.get("timeout", 10),
        aggressive=s.get("aggressive", False),
        callback_url=s.get("callback_url", ""),
        checks=checks,
        paths=s.get("paths") or list(DEFAULT_PATHS),
        lfi_params=s.get("lfi_params") or list(DEFAULT_LFI_PARAMS),
        secret_patterns=s.get("secret_patterns") or list(DEFAULT_SECRET_PATTERNS),
    )


def _write_findings(findings_file: Path, findings: list) -> int:
    if not findings:
        return 0
    with findings_file.open("a", encoding="utf-8") as fh:
        for f in findings:
            fh.write(
                json.dumps(
                    {
                        "domain": f.domain,
                        "check": f.check,
                        "severity": f.severity,
                        "url": f.url,
                        "evidence": f.evidence,
                        "metadata": f.metadata,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return len(findings)


async def _scan_batch(
    domains: list[str],
    scan_cfg: ScanConfig,
    store: DomainStore,
    findings_file: Path,
) -> int:
    if not domains:
        return 0

    scanner = VulnScanner(scan_cfg)
    by_domain: dict[str, list] = {d: [] for d in domains}
    total = 0

    async def on_result(batch: list) -> None:
        nonlocal total
        total += _write_findings(findings_file, batch)
        for f in batch:
            by_domain.setdefault(f.domain, []).append(f)

    await scanner.scan_many(domains, on_result=on_result)

    for domain in domains:
        await store.mark_scanned(domain, findings_to_json(by_domain.get(domain, [])))

    return total


async def run_grabber(cfg: dict[str, Any], target: int = 0, duration: int = 0) -> None:
    output = cfg.get("output", {})
    new_cfg = cfg.get("new_domains", {})
    sources_cfg = cfg.get("sources", {})
    scan_cfg_dict = cfg.get("scanner", {})

    output_dir = Path(output.get("directory", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    store = DomainStore(Path(new_cfg.get("database", "./data/domains.db")))
    await store.init()

    new_only = new_cfg.get("enabled", True)
    scan_enabled = scan_cfg_dict.get("enabled", True)
    scan_cfg = build_scan_config(cfg)
    scan_batch_size = max(1, min(scan_cfg.concurrency, 100))

    pipeline = DomainPipeline(
        output_dir=output_dir,
        output_format=output.get("format", "jsonl"),
        deduplicate=output.get("deduplicate", True),
        filter_config=build_filter_config(cfg),
        target_count=target,
    )

    findings_file = output_dir / f"findings_{int(time.time())}.jsonl"
    original_process = pipeline.process
    scan_queue: list[str] = []
    findings_total = 0
    new_count = 0
    start = time.time()

    async def flush_scan_queue() -> None:
        nonlocal findings_total
        if not scan_queue or not scan_enabled:
            return
        batch = scan_queue.copy()
        scan_queue.clear()
        findings_total += await _scan_batch(batch, scan_cfg, store, findings_file)

    async def async_process(domain: str, source: str, metadata: dict[str, Any] | None = None) -> bool:
        nonlocal new_count
        normalized = normalize_domain(domain)
        if not normalized:
            return False

        is_new_domain = await store.register(normalized, source)
        if new_only and not is_new_domain:
            pipeline.stats.duplicates += 1
            return False

        if is_new_domain:
            new_count += 1

        exported = original_process(domain, source, metadata)
        if exported and scan_enabled:
            scan_queue.append(normalized)
            if len(scan_queue) >= scan_batch_size:
                await flush_scan_queue()

        return exported

    sources = _build_sources(sources_cfg)
    if not sources:
        console.print("[red]Aucune source activée dans la config.[/red]")
        return

    async def consume(name: str, iterator: AsyncIterator[tuple[str, dict[str, Any]]]) -> None:
        async for domain, meta in iterator:
            await async_process(domain, name, meta)
            if target and pipeline.stats.exported >= target:
                return
            if duration and (time.time() - start) >= duration:
                return

    tasks = [asyncio.create_task(consume(name, src())) for name, src in sources]
    deadline = start + duration if duration else None

    try:
        with Live(_render_stats(pipeline, new_count, findings_total), refresh_per_second=2, console=console) as live:
            while tasks:
                if deadline and time.time() >= deadline:
                    for t in tasks:
                        t.cancel()
                    break
                _, pending = await asyncio.wait(tasks, timeout=1.0, return_when=asyncio.FIRST_COMPLETED)
                live.update(_render_stats(pipeline, new_count, findings_total))
                if target and pipeline.stats.exported >= target:
                    for t in pending:
                        t.cancel()
                    break
                tasks = list(pending)
                if not tasks:
                    break
    finally:
        await flush_scan_queue()
        pipeline.close()
        console.print(f"\n[green]Domaines exportés :[/green] {pipeline.output_file}")
        if scan_enabled and findings_file.exists():
            console.print(f"[green]Findings :[/green] {findings_file} ({findings_total:,} résultats)")
        console.print(f"[green]Nouveaux domaines :[/green] {new_count:,}")
        console.print(_render_stats(pipeline, new_count, findings_total))


def _build_sources(
    sources_cfg: dict[str, Any],
) -> list[tuple[str, Callable[[], AsyncIterator[tuple[str, dict[str, Any]]]]]]:
    sources: list[tuple[str, Callable[[], AsyncIterator[tuple[str, dict[str, Any]]]]]] = []

    if sources_cfg.get("crtsh", {}).get("enabled", True):
        cs = sources_cfg.get("crtsh", {})

        def crtsh_factory() -> AsyncIterator[tuple[str, dict[str, Any]]]:
            return stream_crtsh(
                percent=cs.get("query", "%"),
                poll_interval=cs.get("poll_interval", 120),
                max_age_hours=cs.get("max_age_hours", 24),
            )

        sources.append(("crtsh", crtsh_factory))

    if sources_cfg.get("certstream", {}).get("enabled", True):
        url = sources_cfg["certstream"].get("url", "wss://certstream.calidog.io/domains-only")

        def certstream_factory(u: str = url) -> Callable[[], AsyncIterator[tuple[str, dict[str, Any]]]]:
            return lambda: stream_certstream(u)

        sources.append(("certstream", certstream_factory()))

    if sources_cfg.get("ct_logs", {}).get("enabled", True):
        ct = sources_cfg["ct_logs"]

        def ct_factory() -> AsyncIterator[tuple[str, dict[str, Any]]]:
            return stream_ct_logs(
                ct.get("logs", []),
                batch_size=ct.get("batch_size", 512),
                workers=ct.get("workers", 8),
                tail=ct.get("tail", True),
            )

        sources.append(("ct_logs", ct_factory))

    if sources_cfg.get("commoncrawl", {}).get("enabled", False):
        cc = sources_cfg["commoncrawl"]

        def cc_factory() -> AsyncIterator[tuple[str, dict[str, Any]]]:
            return stream_commoncrawl(
                cc.get("tlds", ["com"]),
                workers=cc.get("workers", 4),
                max_per_tld=cc.get("max_per_tld", 0),
            )

        sources.append(("commoncrawl", cc_factory))

    if sources_cfg.get("zone_files", {}).get("enabled", False):
        zdir = Path(sources_cfg["zone_files"]["directory"])
        sources.append(("zone_files", lambda d=zdir: stream_zone_files(d)))

    if sources_cfg.get("rapid7_fdns", {}).get("enabled", False):
        rdir = Path(sources_cfg["rapid7_fdns"]["directory"])
        sources.append(("rapid7_fdns", lambda d=rdir: stream_rapid7_fdns(d)))

    return sources


def _render_stats(pipeline: DomainPipeline, new_count: int, findings: int) -> Table:
    table = Table(title="Domain Grabber — Nouveaux domaines + Scan vuln")
    table.add_column("Métrique")
    table.add_column("Valeur", justify="right")
    s = pipeline.stats
    table.add_row("Reçus", f"{s.received:,}")
    table.add_row("Nouveaux", f"{new_count:,}")
    table.add_row("Exportés", f"{s.exported:,}")
    table.add_row("Findings", f"{findings:,}")
    table.add_row("Débit", f"{s.rate:,.0f} dom/s")
    table.add_row("Durée", f"{s.elapsed:.0f}s")
    return table


async def run_scan_only(cfg: dict[str, Any], input_file: Path) -> None:
    scan_cfg = build_scan_config(cfg)
    output_dir = Path(cfg.get("output", {}).get("directory", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    domains: list[str] = []
    with input_file.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    d = data.get("domain", "")
                except json.JSONDecodeError:
                    continue
            else:
                d = line
            normalized = normalize_domain(d)
            if normalized:
                domains.append(normalized)

    console.print(f"[cyan]Scan de {len(domains):,} domaines...[/cyan]")
    findings_file = output_dir / f"findings_{int(time.time())}.jsonl"
    scanner = VulnScanner(scan_cfg)

    async def on_batch(batch: list) -> None:
        _write_findings(findings_file, batch)

    findings = await scanner.scan_many(domains, on_result=on_batch)
    console.print(f"[green]{len(findings)} findings → {findings_file}[/green]")


async def run_stats(cfg: dict[str, Any]) -> None:
    new_cfg = cfg.get("new_domains", {})
    store = DomainStore(Path(new_cfg.get("database", "./data/domains.db")))
    await store.init()
    max_age = float(new_cfg.get("max_age_hours", 24))
    count = await store.count_new(max_age)
    pending = await store.unscaned_new(max_age, limit=10)
    console.print(f"[cyan]Nouveaux domaines ({max_age}h) :[/cyan] {count:,}")
    console.print(f"[cyan]En attente de scan :[/cyan] {len(pending)} (aperçu)")
    for d in pending[:10]:
        console.print(f"  - {d}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Domain Grabber — nouveaux domaines (CT) + scan vuln gratuit",
    )
    parser.add_argument("-c", "--config", default="config.yaml", help="Fichier config YAML")
    sub = parser.add_subparsers(dest="command")

    for name, help_text in [("run", "Grab nouveaux domaines + scan auto"), ("grab", "Alias de run")]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("-n", "--count", type=int, default=0, help="Domaines à collecter (0=illimité)")
        p.add_argument("-t", "--time", type=int, default=0, help="Durée en secondes (0=illimité)")
        p.add_argument("--no-scan", action="store_true", help="Collecter sans scanner")

    scan_p = sub.add_parser("scan", help="Scanner un fichier de domaines")
    scan_p.add_argument("-i", "--input", required=True, help="Fichier domains (txt ou jsonl)")

    sub.add_parser("stats", help="Statistiques base nouveaux domaines")

    args = parser.parse_args(argv)
    cfg = load_config(Path(args.config))

    if not cfg:
        cfg_path = Path("config.example.yaml")
        if cfg_path.exists():
            console.print("[yellow]config.yaml absent, utilisation de config.example.yaml[/yellow]")
            cfg = load_config(cfg_path)

    cmd = args.command or "run"
    if cmd == "scan":
        asyncio.run(run_scan_only(cfg, Path(args.input)))
    elif cmd == "stats":
        asyncio.run(run_stats(cfg))
    else:
        if getattr(args, "no_scan", False):
            cfg.setdefault("scanner", {})["enabled"] = False
        asyncio.run(
            run_grabber(
                cfg,
                target=getattr(args, "count", 0) or 0,
                duration=getattr(args, "time", 0) or 0,
            )
        )


if __name__ == "__main__":
    main()
