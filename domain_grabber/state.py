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
    domains: int = 0
    valids: int = 0
    rate: int = 0
    avg_rate: int = 0
    elapsed: float = 0.0
    status: str = "idle"
    pipeline: str = ""
    export_file: str = ""
    hit_rate: float = 0.0
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=50))
    _start: float = 0.0
    _prev_valids: int = 0
    _prev_time: float = 0.0
    _listeners: list[asyncio.Queue] = field(default_factory=list)
    stop_event: asyncio.Event | None = None
    grab_task: asyncio.Task | None = None

    def begin(self, pipeline: str) -> None:
        self.running = True
        self.status = "running"
        self.pipeline = pipeline
        self.domains = 0
        self.valids = 0
        self.rate = 0
        self.avg_rate = 0
        self.export_file = ""
        self.hit_rate = 0.0
        self._start = time.time()
        self._prev_valids = 0
        self._prev_time = self._start
        self.stop_event = asyncio.Event()
        self.logs.clear()
        self._notify()

    def update(self, domains: int, valids: int) -> None:
        now = time.time()
        self.domains = domains
        self.valids = valids
        self.elapsed = now - self._start
        dt = max(now - self._prev_time, 0.001)
        instant = int((valids - self._prev_valids) / dt)
        avg = int(valids / max(self.elapsed, 0.001))
        self.rate = instant if instant > 0 else avg
        self.avg_rate = avg
        self.hit_rate = (valids / domains * 100) if domains else 0.0
        self._prev_valids = valids
        self._prev_time = now
        self._notify()

    def finish(self, export_file: str = "") -> None:
        self.running = False
        self.status = "done"
        if export_file:
            self.export_file = export_file
        self.elapsed = max(time.time() - self._start, 0.001)
        self.avg_rate = int(self.valids / self.elapsed)
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
            "domains": self.domains,
            "valids": self.valids,
            "rate": self.rate,
            "avg_rate": self.avg_rate,
            "elapsed": int(self.elapsed),
            "status": self.status,
            "pipeline": self.pipeline,
            "export_file": self.export_file,
            "hit_rate": round(self.hit_rate, 1),
            "logs": list(self.logs),
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


# Singleton global
STATE = PanelState()
