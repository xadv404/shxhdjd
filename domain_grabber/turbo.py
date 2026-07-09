"""Pipeline unique : CT → vérification HTTP → export."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from domain_grabber.filters import FilterConfig
from domain_grabber.pipeline import DomainPipeline
from domain_grabber.sources.ct_logs import stream_ct_logs_batches
from domain_grabber.storage import DomainStore
from domain_grabber.verify import DEFAULT_RESOLVERS, FastVerifier, VerifyConfig, VerifiedDomain


def _build_verify_config(cfg: dict[str, Any]) -> VerifyConfig:
    v = cfg.get("verify", {})
    perf = cfg.get("performance", {})
    return VerifyConfig(
        batch_size=int(v.get("batch_size", 2000)),
        timeout=float(v.get("timeout", 2.0)),
        ports=tuple(v.get("ports", [443, 80])),
        require_http=bool(v.get("require_http", True)),
        http_status_max=int(v.get("http_status_max", 499)),
        dns_workers=int(v.get("dns_workers", 500)),
        tcp_concurrency=int(v.get("tcp_concurrency", 1000)),
        http_concurrency=int(v.get("http_concurrency", 400)),
        masscan_rate=int(v.get("masscan_rate", 100_000)),
        resolvers=list(v.get("resolvers") or DEFAULT_RESOLVERS),
        resolvers_file=str(v.get("resolvers_file", "")),
        prefer_tools=bool(v.get("prefer_tools", True)),
    )


class StatusLogger:
    """Log [INFO] DOMAINS | VALIDS | req/s toutes les N secondes."""

    def __init__(self, interval: float = 3.0) -> None:
        self.interval = interval
        self.domains = 0
        self.valids = 0
        self._prev_valids = 0
        self._prev_time = time.time()
        self._start = time.time()
        self._task: asyncio.Task | None = None

    def set(self, domains: int, valids: int) -> None:
        self.domains = domains
        self.valids = valids

    def emit(self) -> None:
        now = time.time()
        dt = max(now - self._prev_time, 0.001)
        instant = int((self.valids - self._prev_valids) / dt)
        avg = int(self.valids / max(now - self._start, 0.001))
        rate = instant if instant > 0 else avg
        print(
            f"[INFO] {self.domains} DOMAINS | {self.valids} VALIDS | {rate} req/s",
            flush=True,
        )
        self._prev_valids = self.valids
        self._prev_time = now

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            self.emit()

    def start(self) -> None:
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.emit()
        elapsed = max(time.time() - self._start, 0.001)
        avg = int(self.valids / elapsed)
        print(
            f"[INFO] DONE {self.domains} DOMAINS | {self.valids} VALIDS | {avg} req/s avg",
            flush=True,
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


async def run_pipeline(
    cfg: dict[str, Any],
    target: int = 0,
    duration: int = 0,
) -> None:
    perf = cfg.get("performance", {})
    output = cfg.get("output", {})
    new_cfg = cfg.get("new_domains", {})
    ct = cfg.get("sources", {}).get("ct_logs", {})
    log_interval = float(perf.get("log_interval", 3.0))

    output_dir = Path(output.get("directory", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    store = DomainStore(Path(new_cfg.get("database", "./data/domains.db")))
    load_existing = new_cfg.get("enabled", True) and new_cfg.get("load_existing", True)
    await store.init(load_existing=load_existing)

    new_only = new_cfg.get("enabled", True)
    db_commit_interval = int(perf.get("db_commit_interval", 4))
    db_flush_counter = 0

    pipeline = DomainPipeline(
        output_dir=output_dir,
        output_format=perf.get("format", output.get("format", "txt")),
        deduplicate=output.get("deduplicate", True),
        filter_config=FilterConfig(require_match=False),
        target_count=target,
    )

    verifier = FastVerifier(_build_verify_config(cfg))
    verify_batch_size = verifier.cfg.batch_size
    if verifier.tools.describe() == "async-fallback":
        verify_batch_size = min(verify_batch_size, 1200)
    if duration:
        verify_batch_size = min(verify_batch_size, max(300, int(duration * 12)))

    tools_msg = verifier.tools.describe()
    print(f"[INFO] Pipeline {tools_msg} | batch={verify_batch_size}", flush=True)
    if tools_msg == "async-fallback":
        print("[INFO] Tip: bash scripts/install-verify-tools.sh for massdns+httpx", flush=True)

    status = StatusLogger(interval=log_interval)
    collected = 0
    verified_count = 0
    start = time.time()
    deadline = start + duration if duration else 0.0
    collect_task: asyncio.Task[list[str]] | None = None
    logger_started = False

    stream = stream_ct_logs_batches(
        log_urls=ct.get("logs") or None,
        batch_size=int(ct.get("batch_size", 32)),
        inflight_per_log=int(ct.get("inflight_per_log", perf.get("inflight_per_log", 24))),
        tail=bool(ct.get("tail", perf.get("tail", False))),
        parse_workers=int(ct.get("parse_workers", perf.get("parse_workers", 32))),
        start_offset=int(ct.get("start_offset", perf.get("start_offset", 500_000))),
        discover=bool(ct.get("discover", True)),
    )

    def target_remaining() -> int:
        if not target:
            return 0
        return max(0, target - pipeline.stats.exported)

    def start_collect() -> asyncio.Task[list[str]]:
        remaining = target_remaining()
        size = verify_batch_size
        if remaining and remaining < size:
            size = remaining
        return asyncio.create_task(_collect_batch(stream, size, deadline, remaining))

    async def flush_export(domains: list[str], force: bool = False) -> None:
        nonlocal db_flush_counter, verified_count
        if not domains:
            return

        if new_only:
            pairs = [(d, "ct_verify") for d in domains]
            db_flush_counter += 1
            commit_db = force or db_flush_counter >= db_commit_interval
            export_list = await store.register_batch(pairs, commit=commit_db)
            if commit_db:
                db_flush_counter = 0
            pipeline.stats.duplicates += len(domains) - len(export_list)
        else:
            export_list = domains

        if export_list:
            pipeline.process_batch(export_list, "ct_verify", flush=False)
            verified_count += len(export_list)

        if force:
            pipeline._fh.flush()

        status.set(collected, verified_count)

    try:
        collect_task = start_collect()

        while True:
            if duration and time.time() >= deadline:
                break
            if target and pipeline.stats.exported >= target:
                break

            batch = await collect_task
            if not batch:
                break
            collected += len(batch)
            status.set(collected, verified_count)
            if not logger_started:
                status.start()
                logger_started = True

            if duration and time.time() >= deadline:
                break

            collect_task = start_collect()
            alive = await verifier.verify_batch(batch)
            await flush_export([r.domain for r in alive])
            status.set(collected, verified_count)

            if duration and time.time() >= deadline:
                break

    finally:
        if collect_task and not collect_task.done():
            collect_task.cancel()
            try:
                await collect_task
            except asyncio.CancelledError:
                pass
        await store.flush()
        await store.close()
        pipeline.close()
        if logger_started:
            await status.stop()
        else:
            print(f"[INFO] DONE 0 DOMAINS | 0 VALIDS | 0 req/s avg", flush=True)
        print(f"[INFO] Export → {pipeline.output_file}", flush=True)


# Alias rétrocompat
run_turbo_grabber = run_pipeline
