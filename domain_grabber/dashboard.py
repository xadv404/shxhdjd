"""Dashboard live style terminal (présentation type scrap)."""

from __future__ import annotations

import asyncio
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path


class LiveDashboard:
    """Affichage plein écran actualisé toutes les N secondes."""

    def __init__(
        self,
        *,
        interval: float = 1.0,
        output_file: str = "domains.txt",
        filtering: bool = True,
        recent_size: int = 5,
    ) -> None:
        self.interval = interval
        self.output_file = output_file
        self.filtering = filtering
        self.received = 0
        self.filtered = 0
        self.rejected = 0
        self.sources = 0
        self.recent: deque[str] = deque(maxlen=recent_size)
        self._start = time.time()
        self._prev_filtered = 0
        self._prev_time = self._start
        self._rate = 0
        self._task: asyncio.Task | None = None
        self._lines = 0

    def set_sources(self, n: int) -> None:
        self.sources = n

    def update(
        self,
        *,
        received: int | None = None,
        filtered: int | None = None,
        rejected: int | None = None,
        recent: list[str] | None = None,
    ) -> None:
        if received is not None:
            self.received = received
        if filtered is not None:
            self.filtered = filtered
        if rejected is not None:
            self.rejected = rejected
        if recent:
            for d in recent:
                self.recent.append(d)
        elapsed = max(time.time() - self._start, 0.001)
        self._rate = int(self.filtered / elapsed)

    def _fmt(self, n: int) -> str:
        return f"{n:,}"

    def render(self) -> str:
        now = datetime.now().strftime("%H:%M:%S")
        uptime = int(time.time() - self._start)
        name = Path(self.output_file).name
        filtrage = "on" if self.filtering else "off"
        lines = [
            "-" * 40,
            f"Time:           {now}",
            f"Uptime:         {uptime}s",
            f"Domaines/s:     {self._rate}",
            f"Flux reçus:     {self._fmt(self.received)}",
            f"Sources:        {self.sources}",
            f"Filtrage:       {filtrage}",
            f"Filtrés:        {self._fmt(self.filtered)}",
            f"Rejetées:       {self._fmt(self.rejected)}",
            f"Fichier:        {name}",
            "Derniers:",
        ]
        if self.recent:
            for d in list(self.recent)[-5:]:
                lines.append(f"  {d}")
        else:
            lines.append("  —")
        lines.append("-" * 40)
        return "\n".join(lines)

    def emit(self) -> None:
        text = self.render()
        # Remonter le curseur pour écraser l'écran précédent
        if self._lines > 0:
            sys.stdout.write(f"\033[{self._lines}A")
        sys.stdout.write("\033[J")  # clear below
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        self._lines = text.count("\n") + 1

    async def run(self) -> None:
        while True:
            self.emit()
            await asyncio.sleep(self.interval)

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
        print(
            f"\n[DONE] {self._fmt(self.filtered)} filtrés / "
            f"{self._fmt(self.received)} reçus | "
            f"{self._rate} domaines/s | → {self.output_file}",
            flush=True,
        )
