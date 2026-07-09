"""Mode turbo — collecte 2-3k domaines/s."""

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

console = Console()


async def run_turbo_grabber(
    cfg: dict[str, Any],
    target: int = 0,
    duration: int = 0,
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
    start = time.time()
    last_flush = start
    pending_domains: list[str] = []
    pending_source = "ct_logs"

    async def flush_pending(force: bool = False) -> None:
        nonlocal new_count, last_flush, pending_domains, db_flush_counter
        if not pending_domains:
            return
        now = time.time()
        if not force and len(pending_domains) < batch_write and (now - last_flush) < flush_interval:
            return

        chunk = pending_domains[:batch_write]
        del pending_domains[:batch_write]

        if new_only:
            pairs = [(d, pending_source) for d in chunk]
            db_flush_counter += 1
            commit_db = force or db_flush_counter >= db_commit_interval
            new_batch = await store.register_batch(pairs, commit=commit_db)
            if commit_db:
                db_flush_counter = 0
            pipeline.stats.duplicates += len(chunk) - len(new_batch)
            if new_batch:
                pipeline.process_batch(new_batch, pending_source, flush=False)
                new_count += len(new_batch)
        else:
            pipeline.process_batch(chunk, pending_source, flush=False)
            new_count += len(chunk)

        if force or (now - last_flush) >= flush_interval:
            pipeline._fh.flush()
        last_flush = time.time()

    async def consume() -> None:
        async for domains, meta in stream_ct_logs_batches(
            log_urls=log_urls,
            batch_size=batch_size,
            inflight_per_log=inflight,
            tail=tail,
            parse_workers=parse_workers,
            start_offset=start_offset,
            discover=discover,
        ):
            pending_domains.extend(domains)
            await flush_pending()
            if target and pipeline.stats.exported >= target:
                return
            if duration and (time.time() - start) >= duration:
                return

    task = asyncio.create_task(consume())
    stop = False

    try:
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
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await flush_pending(force=True)
        await store.flush()
        await store.close()
        pipeline.close()
        elapsed = max(time.time() - start, 0.001)
        rate = pipeline.stats.exported / elapsed
        console.print(f"\n[green]Export :[/green] {pipeline.output_file}")
        console.print(f"[green]Total :[/green] {pipeline.stats.exported:,} domaines en {elapsed:.1f}s ({rate:,.0f} dom/s)")
