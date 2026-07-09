"""Pipeline central : collecte, déduplication, export."""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.table import Table

from domain_grabber.filters import FilterConfig, VulnerabilityFilter
from domain_grabber.utils import normalize_domain

console = Console()


@dataclass
class DomainRecord:
    domain: str
    source: str
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    collected_at: float = field(default_factory=time.time)


@dataclass
class PipelineStats:
    received: int = 0
    normalized: int = 0
    filtered: int = 0
    duplicates: int = 0
    exported: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return max(time.time() - self.start_time, 0.001)

    @property
    def rate(self) -> float:
        return self.exported / self.elapsed


class DomainPipeline:
    def __init__(
        self,
        output_dir: Path,
        output_format: str = "jsonl",
        deduplicate: bool = True,
        filter_config: FilterConfig | None = None,
        target_count: int = 0,
    ) -> None:
        self.output_dir = output_dir
        self.output_format = output_format
        self.deduplicate = deduplicate
        self.target_count = target_count
        self.vuln_filter = VulnerabilityFilter(filter_config)
        self.stats = PipelineStats()
        self._seen: set[str] = set()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        ext = "jsonl" if output_format == "jsonl" else "txt"
        self.output_file = self.output_dir / f"domains_{ts}.{ext}"
        self._fh = self.output_file.open("a", encoding="utf-8")

    def close(self) -> None:
        self._fh.close()

    def _export(self, record: DomainRecord) -> None:
        if self.output_format == "jsonl":
            line = json.dumps(
                {
                    "domain": record.domain,
                    "source": record.source,
                    "reasons": record.reasons,
                    "metadata": record.metadata,
                    "collected_at": record.collected_at,
                },
                ensure_ascii=False,
            )
            self._fh.write(line + "\n")
        else:
            self._fh.write(record.domain + "\n")
        self._fh.flush()
        self.stats.exported += 1

    def process_batch(
        self,
        domains: list[str],
        source: str,
        metadata: dict[str, Any] | None = None,
        flush: bool = True,
    ) -> list[str]:
        """Traite un lot de domaines. Retourne les domaines exportés."""
        exported: list[str] = []
        lines: list[str] = []
        meta = metadata or {}
        now = time.time()

        for domain in domains:
            self.stats.received += 1
            normalized = normalize_domain(domain)
            if not normalized:
                continue
            self.stats.normalized += 1

            if self.deduplicate:
                if normalized in self._seen:
                    self.stats.duplicates += 1
                    continue
                self._seen.add(normalized)

            ok, reasons = self.vuln_filter.accept(normalized)
            if not ok:
                self.stats.filtered += 1
                continue

            if self.output_format == "jsonl":
                lines.append(
                    json.dumps(
                        {
                            "domain": normalized,
                            "source": source,
                            "reasons": reasons,
                            "metadata": meta,
                            "collected_at": now,
                        },
                        ensure_ascii=False,
                    )
                )
            else:
                lines.append(normalized)
            exported.append(normalized)
            self.stats.exported += 1

        if lines:
            self._fh.write("\n".join(lines) + "\n")
            if flush:
                self._fh.flush()
        return exported

    def process(self, domain: str, source: str, metadata: dict[str, Any] | None = None) -> bool:
        return bool(self.process_batch([domain], source, metadata))

    def target_reached(self) -> bool:
        return self.target_count > 0 and self.stats.exported >= self.target_count

    async def run_sources(
        self,
        sources: list[tuple[str, Callable[[], AsyncIterator[tuple[str, dict[str, Any]]]]]],
    ) -> None:
        import asyncio

        async def consume(name: str, iterator: AsyncIterator[tuple[str, dict[str, Any]]]) -> None:
            async for domain, meta in iterator:
                self.process(domain, name, meta)
                if self.target_reached():
                    return

        tasks = [asyncio.create_task(consume(name, src())) for name, src in sources]
        try:
            with Live(self._render_table(), refresh_per_second=2, console=console) as live:
                while tasks:
                    done, pending = await asyncio.wait(tasks, timeout=1.0, return_when=asyncio.FIRST_COMPLETED)
                    live.update(self._render_table())
                    if self.target_reached():
                        for task in pending:
                            task.cancel()
                        break
                    tasks = list(pending)
        finally:
            self.close()
            console.print(f"\n[green]Export terminé :[/green] {self.output_file}")
            console.print(self._render_table())

    def _render_table(self) -> Table:
        table = Table(title="Domain Grabber — Sources gratuites")
        table.add_column("Métrique")
        table.add_column("Valeur", justify="right")
        table.add_row("Reçus", f"{self.stats.received:,}")
        table.add_row("Normalisés", f"{self.stats.normalized:,}")
        table.add_row("Filtrés", f"{self.stats.filtered:,}")
        table.add_row("Doublons", f"{self.stats.duplicates:,}")
        table.add_row("Exportés", f"{self.stats.exported:,}")
        table.add_row("Débit", f"{self.stats.rate:,.0f} dom/s")
        table.add_row("Durée", f"{self.stats.elapsed:.0f}s")
        if self.target_count:
            table.add_row("Objectif", f"{self.stats.exported:,}/{self.target_count:,}")
        return table
