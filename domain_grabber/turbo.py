"""Mode turbo — collecte 2-3k domaines/s + vérification rapide."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live

from domain_grabber.filters import FilterConfig
from domain_grabber.pipeline import DomainPipeline
from domain_grabber.sources.ct_logs import stream_ct_logs_batches
from domain_grabber.storage import DomainStore
from domain_grabber.verify import DEFAULT_RESOLVERS, FastVerifier, VerifyConfig, VerifiedDomain

console = Console()


def _build_verify_config(cfg: dict[str, Any]) -> VerifyConfig:
    v = cfg.get("verify", {})
    perf = cfg.get("performance", {})
    return VerifyConfig(
        batch_size=int(v.get("batch_size", perf.get("verify_batch_size", 5000))),
        timeout=float(v.get("timeout", 2.0)),
        ports=tuple(v.get("ports", [443, 80])),
        require_http=bool(v.get("require_http", True)),
        http_status_max=int(v.get("http_status_max", 499)),
        dns_workers=int(v.get("dns_workers", 500)),
        tcp_concurrency=int(v.get("tcp_concurrency", 1000)),
        http_concurrency=int(v.get("http_concurrency", perf.get("http_concurrency", 500))),
        masscan_rate=int(v.get("masscan_rate", 100_000)),
        resolvers=list(v.get("resolvers") or DEFAULT_RESOLVERS),
        resolvers_file=str(v.get("resolvers_file", "")),
        prefer_tools=bool(v.get("prefer_tools", True)),
    )


async def _collect_batch(
    stream: Any,
    batch_size: int,
    deadline: float,
    target_remaining: int,
) -> list[str]:
    batch: list[str] = []
    seen: set[str] = set()
    async for domains, _meta in stream:
        for d in domains:
            if d in seen:
                continue
            seen.add(d)
            batch.append(d)
            if len(batch) >= batch_size:
                return batch
            if target_remaining and len(batch) >= target_remaining:
                return batch
        if deadline and time.time() >= deadline:
            break
    return batch


async def run_turbo_grabber(
    cfg: dict[str, Any],
    target: int = 0,
    duration: int = 0,
    *,
    verify: bool = False,
) -> None:
    perf = cfg.get("performance", {})
    output = cfg.get("output", {})
    new_cfg = cfg.get("new_domains", {})
    ct = cfg.get("sources", {}).get("ct_logs", {})

    output_dir = Path(output.get("directory", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    store = DomainStore(Path(new_cfg.get("database", "./data/domains.db")))
    load_existing = new_cfg.get("enabled", True) and new_cfg.get("load_existing", True)
    await store.init(load_existing=load_existing)

    new_only = new_cfg.get("enabled", True)
    batch_write = int(perf.get("batch_write", 2000))
    flush_interval = float(perf.get("flush_interval", 0.25))
    db_commit_interval = int(perf.get("db_commit_interval", 4))
    db_flush_counter = 0

    pipeline = DomainPipeline(
        output_dir=output_dir,
        output_format=perf.get("format", output.get("format", "txt")),
        deduplicate=output.get("deduplicate", True),
        filter_config=FilterConfig(require_match=False),
        target_count=target,
    )

    log_urls = ct.get("logs") or None
    batch_size = int(ct.get("batch_size", 32))
    inflight = int(ct.get("inflight_per_log", perf.get("inflight_per_log", 24)))
    parse_workers = int(ct.get("parse_workers", perf.get("parse_workers", 32)))
    tail = bool(ct.get("tail", perf.get("tail", False)))
    start_offset = int(ct.get("start_offset", perf.get("start_offset", 500_000)))
    discover = bool(ct.get("discover", True))

    new_count = 0
    collected = 0
    verified_count = 0
    start = time.time()
    last_flush = start
    pending_domains: list[str] = []
    pending_source = "ct_logs"

    verifier = FastVerifier(_build_verify_config(cfg)) if verify else None
    verify_batch_size = verifier.cfg.batch_size if verifier else 0
    if verify and verifier:
        if verifier.tools.describe() == "async-fallback":
            verify_batch_size = min(verify_batch_size, 1200)
        if duration:
            verify_batch_size = min(verify_batch_size, max(400, int(duration * 50)))
    collect_task: asyncio.Task[list[str]] | None = None

    async def flush_export(domains: list[str], source: str, force: bool = False) -> None:
        nonlocal new_count, last_flush, db_flush_counter
        if not domains:
            return

        if new_only:
            pairs = [(d, source) for d in domains]
            db_flush_counter += 1
            commit_db = force or db_flush_counter >= db_commit_interval
            new_batch = await store.register_batch(pairs, commit=commit_db)
            if commit_db:
                db_flush_counter = 0
            pipeline.stats.duplicates += len(domains) - len(new_batch)
            export_list = new_batch
            new_count += len(new_batch)
        else:
            export_list = domains
            new_count += len(domains)

        if export_list:
            pipeline.process_batch(export_list, source, flush=False)

        now = time.time()
        if force or (now - last_flush) >= flush_interval:
            pipeline._fh.flush()
            last_flush = now

    async def flush_pending(force: bool = False) -> None:
        nonlocal pending_domains
        if not pending_domains:
            return
        chunk = pending_domains[:batch_write]
        del pending_domains[:batch_write]
        await flush_export(chunk, pending_source, force=force)

    async def export_verified(results: list[VerifiedDomain]) -> None:
        nonlocal verified_count
        names = [r.domain for r in results]
        verified_count += len(names)
        await flush_export(names, "ct_verify", force=False)

    stream = stream_ct_logs_batches(
        log_urls=log_urls,
        batch_size=batch_size,
        inflight_per_log=inflight,
        tail=tail,
        parse_workers=parse_workers,
        start_offset=start_offset,
        discover=discover,
    )

    deadline = start + duration if duration else 0.0

    def target_remaining() -> int:
        if not target:
            return 0
        return max(0, target - pipeline.stats.exported)

    def start_collect() -> asyncio.Task[list[str]]:
        remaining = target_remaining()
        size = verify_batch_size if verify else batch_write
        if remaining and remaining < size:
            size = remaining
        return asyncio.create_task(
            _collect_batch(stream, size, deadline, remaining)
        )

    try:
        if verify and verifier:
            tools_msg = verifier.tools.describe()
            if tools_msg == "async-fallback":
                console.print(
                    "[yellow]Astuce :[/yellow] installe massdns+httpx pour 5-10x plus rapide "
                    "→ bash scripts/install-verify-tools.sh"
                )
            console.print(
                f"[cyan]Pipeline verify :[/cyan] {tools_msg} "
                f"(batch={verify_batch_size}, timeout={verifier.cfg.timeout}s)"
            )
            collect_task = start_collect()

            with Live(console=console, refresh_per_second=4) as live:
                while True:
                    if duration and time.time() >= deadline:
                        break
                    if target and pipeline.stats.exported >= target:
                        break

                    batch = await collect_task
                    if not batch:
                        break
                    collected += len(batch)

                    remaining = (deadline - time.time()) if deadline else None
                    if remaining is not None and remaining <= 0:
                        break

                    next_collect = asyncio.create_task(
                        _collect_batch(stream, verify_batch_size, deadline, target_remaining())
                    )
                    alive = await verifier.verify_batch(batch)
                    await export_verified(alive)
                    collect_task = next_collect

                    elapsed = max(time.time() - start, 0.001)
                    export_rate = pipeline.stats.exported / elapsed
                    verify_rate = verified_count / max(verifier.stats.elapsed, 0.001)
                    live.update(
                        f"[bold cyan]TURBO+VERIFY[/] ({verifier.tools.describe()}) | "
                        f"collectés: {collected:,} | vivants: {verified_count:,} | "
                        f"exportés: {pipeline.stats.exported:,} | "
                        f"{export_rate:,.0f} exp/s | verify {verify_rate:,.0f}/s | {elapsed:.0f}s"
                    )
        else:
            async def consume() -> None:
                nonlocal collected
                async for domains, _meta in stream:
                    collected += len(domains)
                    pending_domains.extend(domains)
                    await flush_pending()
                    if target and pipeline.stats.exported >= target:
                        return
                    if duration and (time.time() - start) >= duration:
                        return

            task = asyncio.create_task(consume())
            with Live(console=console, refresh_per_second=4) as live:
                while not task.done():
                    await asyncio.sleep(0.25)
                    elapsed = max(time.time() - start, 0.001)
                    rate = pipeline.stats.exported / elapsed
                    live.update(
                        f"[bold cyan]TURBO[/] | exportés: {pipeline.stats.exported:,} | "
                        f"nouveaux: {new_count:,} | {rate:,.0f} dom/s | {elapsed:.0f}s"
                    )
                    if duration and (time.time() - start) >= duration:
                        break
                    if target and pipeline.stats.exported >= target:
                        break
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    finally:
        if collect_task and not collect_task.done():
            collect_task.cancel()
            try:
                await collect_task
            except asyncio.CancelledError:
                pass
        await flush_pending(force=True)
        await store.flush()
        await store.close()
        pipeline.close()
        elapsed = max(time.time() - start, 0.001)
        rate = pipeline.stats.exported / elapsed
        console.print(f"\n[green]Export :[/green] {pipeline.output_file}")
        if verify and verifier:
            console.print(
                f"[green]Collectés :[/green] {collected:,} | "
                f"[green]HTTP vivants :[/green] {verified_count:,} "
                f"({100 * verified_count / max(collected, 1):.1f}%)"
            )
            console.print(
                f"[green]Total exportés :[/green] {pipeline.stats.exported:,} "
                f"en {elapsed:.1f}s ({rate:,.0f} dom/s)"
            )
        else:
            console.print(
                f"[green]Total :[/green] {pipeline.stats.exported:,} domaines "
                f"en {elapsed:.1f}s ({rate:,.0f} dom/s)"
            )
