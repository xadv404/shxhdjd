"""État partagé entre le pipeline et le panel web."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PanelState:
    running: bool = False
    status: str = "idle"
    phase: str = "idle"  # collect | check | idle | done
    pipeline: str = ""
    export_file: str = ""
    elapsed: float = 0.0
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=50))

    # Récupération (CT)
    collected: int = 0
    collect_rate: int = 0
    collect_avg: int = 0

    # Check (HTTP)
    checked: int = 0
    valids: int = 0
    check_rate: int = 0
    check_avg: int = 0
    hit_rate: float = 0.0

    _start: float = 0.0
    _prev_collected: int = 0
    _prev_valids: int = 0
    _prev_time: float = 0.0
    _listeners: list[asyncio.Queue] = field(default_factory=list)
    stop_event: asyncio.Event | None = None
    grab_task: asyncio.Task | None = None

    def begin(self, pipeline: str) -> None:
        self.running = True
        self.status = "running"
        self.phase = "collect"
        self.pipeline = pipeline
        self.collected = 0
        self.collect_rate = 0
        self.collect_avg = 0
        self.checked = 0
        self.valids = 0
        self.check_rate = 0
        self.check_avg = 0
        self.export_file = ""
        self.hit_rate = 0.0
        self._start = time.time()
        self._prev_collected = 0
        self._prev_valids = 0
        self._prev_time = self._start
        self.stop_event = asyncio.Event()
        self.logs.clear()
        self._tick()
        self._notify()

    def set_phase(self, phase: str) -> None:
        self.phase = phase
        self._notify()

    def update_collect(self, collected: int) -> None:
        self.collected = collected
        self._tick()
        self._notify()

    def update_check(self, checked: int, valids: int) -> None:
        self.checked = checked
        self.valids = valids
        self.hit_rate = (valids / checked * 100) if checked else 0.0
        self._tick()
        self._notify()

    def _tick(self) -> None:
        now = time.time()
        self.elapsed = now - self._start
        dt = max(now - self._prev_time, 0.001)

        d_col = self.collected - self._prev_collected
        d_val = self.valids - self._prev_valids
        inst_collect = int(d_col / dt) if d_col > 0 else 0
        inst_check = int(d_val / dt) if d_val > 0 else 0

        self.collect_rate = inst_collect if inst_collect > 0 else int(self.collected / max(self.elapsed, 0.001))
        self.check_rate = inst_check if inst_check > 0 else int(self.valids / max(self.elapsed, 0.001))
        self.collect_avg = int(self.collected / max(self.elapsed, 0.001))
        self.check_avg = int(self.valids / max(self.elapsed, 0.001))

        if d_col > 0 or d_val > 0:
            self._prev_collected = self.collected
            self._prev_valids = self.valids
            self._prev_time = now

    def finish(self, export_file: str = "") -> None:
        self.running = False
        self.status = "done"
        self.phase = "done"
        if export_file:
            self.export_file = export_file
        self.elapsed = max(time.time() - self._start, 0.001)
        self.collect_avg = int(self.collected / self.elapsed)
        self.check_avg = int(self.valids / self.elapsed)
        self.stop_event = None
        self.grab_task = None
        self._notify()

    def stop(self) -> None:
        self.running = False
        self.status = "stopping"
        if self.stop_event:
            self.stop_event.set()
        self._notify()

    def add_log(self, line: str) -> None:
        self.logs.append(line)
        self._notify()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=10)
        self._listeners.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._listeners:
            self._listeners.remove(q)

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "status": self.status,
            "phase": self.phase,
            "elapsed": int(self.elapsed),
            "pipeline": self.pipeline,
            "export_file": self.export_file,
            "logs": list(self.logs),
            "recup": {
                "collected": self.collected,
                "rate": self.collect_rate,
                "avg": self.collect_avg,
            },
            "check": {
                "checked": self.checked,
                "valids": self.valids,
                "rate": self.check_rate,
                "avg": self.check_avg,
                "hit_rate": round(self.hit_rate, 1),
            },
            # rétrocompat
            "domains": self.collected,
            "valids": self.valids,
            "rate": self.check_rate,
            "avg_rate": self.check_avg,
            "hit_rate": round(self.hit_rate, 1),
        }

    def _notify(self) -> None:
        data = self.to_dict()
        dead: list[asyncio.Queue] = []
        for q in self._listeners:
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(data)
                except Exception:
                    dead.append(q)
        for q in dead:
            self.unsubscribe(q)


STATE = PanelState()
