"""Pipeline unique : CT → export (sans check HTTP)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from domain_grabber.filters import FilterConfig
from domain_grabber.pipeline import DomainPipeline
from domain_grabber.sources.ct_logs import stream_ct_logs_batches
from domain_grabber.state import PanelState
from domain_grabber.storage import DomainStore


class StatusLogger:
    """Log [RECUP] DOMAINS | domain/s toutes les N secondes."""

    def __init__(self, interval: float = 3.0, panel: PanelState | None = None) -> None:
        self.interval = interval
        self.panel = panel
        self.domains = 0
        self._start = time.time()
        self._task: asyncio.Task | None = None

    def set(self, collected: int) -> None:
        self.domains = collected
        if self.panel:
            self.panel.set_phase("collect")
            self.panel.update_collect(collected)

    def _log(self, line: str) -> None:
        print(line, flush=True)
        if self.panel:
            self.panel.add_log(line)

    def _rate(self) -> int:
        if self.panel:
            return self.panel.collect_rate
        elapsed = max(time.time() - self._start, 0.001)
        return int(self.domains / elapsed)

    def emit(self) -> None:
        self._log(f"[RECUP] {self.domains} DOMAINS | {self._rate()} domain/s")

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
        avg = int(self.domains / elapsed)
        self._log(f"[DONE] {self.domains} DOMAINS | {avg} domain/s avg")


async def run_pipeline(
    cfg: dict[str, Any],
    target: int = 0,
    duration: int = 0,
    state: PanelState | None = None,
) -> None:
    panel = state
    perf = cfg.get("performance", {})
    output = cfg.get("output", {})
    new_cfg = cfg.get("new_domains", {})
    ct = cfg.get("sources", {}).get("ct_logs", {})
    log_interval = float(perf.get("log_interval", 3.0))
    batch_write = int(perf.get("batch_write", 2000))
    flush_interval = float(perf.get("flush_interval", 0.25))

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

    if panel:
        panel.begin("ct-only")
        panel.add_log("[INFO] Pipeline CT → export (sans check)")
    else:
        print("[INFO] Pipeline CT → export (sans check)", flush=True)

    status = StatusLogger(interval=log_interval, panel=panel)
    collected = 0
    exported = 0
    start = time.time()
    deadline = start + duration if duration else 0.0
    last_flush = start
    pending: list[str] = []
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

    async def flush_export(force: bool = False) -> None:
        nonlocal db_flush_counter, exported, last_flush, pending
        if not pending:
            return
        now = time.time()
        if not force and len(pending) < batch_write and (now - last_flush) < flush_interval:
            return

        chunk = pending[:batch_write]
        del pending[:batch_write]

        if new_only:
            pairs = [(d, "ct_logs") for d in chunk]
            db_flush_counter += 1
            commit_db = force or db_flush_counter >= db_commit_interval
            export_list = await store.register_batch(pairs, commit=commit_db)
            if commit_db:
                db_flush_counter = 0
            pipeline.stats.duplicates += len(chunk) - len(export_list)
        else:
            export_list = chunk

        if export_list:
            pipeline.process_batch(export_list, "ct_logs", flush=False)
            exported += len(export_list)

        if force or (now - last_flush) >= flush_interval:
            pipeline._fh.flush()
            last_flush = time.time()

        status.set(collected)

    try:
        async for domains, _meta in stream:
            if panel and panel.stop_event and panel.stop_event.is_set():
                break
            if duration and time.time() >= deadline:
                break
            if target and pipeline.stats.exported >= target:
                break

            collected += len(domains)
            pending.extend(domains)
            await flush_export()
            status.set(collected)
            if not logger_started:
                status.start()
                logger_started = True

            if target and pipeline.stats.exported >= target:
                break
            if duration and time.time() >= deadline:
                break

    finally:
        await flush_export(force=True)
        await store.flush()
        await store.close()
        pipeline.close()
        if logger_started:
            await status.stop()
        else:
            msg = "[DONE] 0 DOMAINS | 0 domain/s avg"
            if panel:
                panel.add_log(msg)
            else:
                print(msg, flush=True)
        export_path = str(pipeline.output_file)
        if panel:
            panel.finish(export_path)
            panel.add_log(f"[INFO] Export → {export_path}")
        else:
            print(f"[INFO] Export → {export_path}", flush=True)


run_turbo_grabber = run_pipeline
