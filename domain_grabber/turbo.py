"""Pipeline multi CT logs + dashboard live."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from domain_grabber.dashboard import LiveDashboard
from domain_grabber.filters import FilterConfig
from domain_grabber.pipeline import DomainPipeline
from domain_grabber.sources.ct_logs import stream_ct_logs_batches
from domain_grabber.spam import build_spam_filter
from domain_grabber.state import PanelState
from domain_grabber.storage import DomainStore


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
    filters_cfg = cfg.get("filters", {})
    zero_spam = filters_cfg.get("zero_spam", True)
    filtering_on = bool(zero_spam.get("enabled", True)) if isinstance(zero_spam, dict) else bool(zero_spam)

    batch_write = int(perf.get("batch_write", 5000))
    flush_interval = float(perf.get("flush_interval", 0.15))
    log_interval = float(perf.get("log_interval", 1.0))

    output_dir = Path(output.get("directory", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)
    export_name = output.get("file", "domains.txt")
    stable_path = output_dir / export_name

    store = DomainStore(Path(new_cfg.get("database", "./data/domains.db")))
    load_existing = new_cfg.get("enabled", True) and new_cfg.get("load_existing", True)
    await store.init(load_existing=load_existing)
    new_only = new_cfg.get("enabled", True)
    db_commit_interval = int(perf.get("db_commit_interval", 8))
    db_flush_counter = 0

    pipeline = DomainPipeline(
        output_dir=output_dir,
        output_format=perf.get("format", output.get("format", "txt")),
        deduplicate=output.get("deduplicate", True),
        filter_config=FilterConfig(require_match=False),
        target_count=target,
    )

    spam_filter = build_spam_filter(cfg)
    dash = LiveDashboard(
        interval=log_interval,
        output_file=str(stable_path),
        filtering=filtering_on,
        recent_size=5,
    )

    if panel:
        panel.begin("ct-multi")
        panel.add_log("[INFO] Multi CT logs — cible 10-15k domain/s")

    collected = 0
    clean_count = 0
    spam_count = 0
    exported = 0
    start = time.time()
    deadline = start + duration if duration else 0.0
    last_flush = start
    pending: list[str] = []
    logger_started = False

    inflight = int(ct.get("inflight_per_log", perf.get("inflight_per_log", 48)))
    parse_workers = int(ct.get("parse_workers", perf.get("parse_workers", 32)))
    start_offset = int(ct.get("start_offset", perf.get("start_offset", 500_000)))
    max_logs = int(ct.get("max_logs", perf.get("max_logs", 8)))
    log_urls = ct.get("logs") or None

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
            # Écriture directe unique vers domains.txt (max débit)
            with stable_path.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(export_list) + "\n")
            exported += len(export_list)
            pipeline.stats.exported += len(export_list)
            for d in export_list:
                pipeline._seen.add(d)

        dash.update(received=collected, filtered=clean_count, rejected=spam_count)
        if panel:
            panel.update_collect(clean_count)

    stable_path.write_text("", encoding="utf-8")

    try:
        dash.start()
        logger_started = True

        async for domains, meta in stream_ct_logs_batches(
            log_urls=log_urls,
            batch_size=int(ct.get("batch_size", 32)),
            inflight_per_log=inflight,
            parse_workers=parse_workers,
            start_offset=start_offset,
            discover=bool(ct.get("discover", True)),
            max_logs=max_logs,
        ):
            if meta.get("sources") and not domains:
                dash.set_sources(int(meta["sources"]))
                continue

            if panel and panel.stop_event and panel.stop_event.is_set():
                break
            if duration and time.time() >= deadline:
                break
            if target and clean_count >= target:
                break

            collected += len(domains)
            kept, rejected = spam_filter.filter_list(domains)
            spam_count += rejected
            clean_count += len(kept)
            pending.extend(kept)
            if kept:
                dash.update(
                    received=collected,
                    filtered=clean_count,
                    rejected=spam_count,
                    recent=kept[-5:],
                )
            await flush_export()

            if target and clean_count >= target:
                break
            if duration and time.time() >= deadline:
                break

    finally:
        await flush_export(force=True)
        await store.flush()
        await store.close()
        pipeline.close()
        if logger_started:
            await dash.stop()
        if panel:
            panel.finish(str(stable_path))


run_turbo_grabber = run_pipeline
