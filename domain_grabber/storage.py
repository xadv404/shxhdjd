"""Stockage SQLite haute performance avec écritures batch."""

from __future__ import annotations

import time
from pathlib import Path

import aiosqlite


class DomainStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: aiosqlite.Connection | None = None
        self._memory_seen: set[str] = set()

    async def init(self, load_existing: bool = True) -> None:
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA cache_size=-64000")
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                source TEXT,
                scanned INTEGER DEFAULT 0,
                findings TEXT DEFAULT '[]'
            )
            """
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domains_first_seen ON domains(first_seen)"
        )
        await self._conn.commit()
        if load_existing:
            async with self._conn.execute("SELECT domain FROM domains") as cur:
                async for row in cur:
                    self._memory_seen.add(row[0])

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def register(self, domain: str, source: str) -> bool:
        new = await self.register_batch([(domain, source)])
        return domain in new

    async def register_batch(
        self,
        items: list[tuple[str, str]],
        *,
        commit: bool = True,
    ) -> list[str]:
        """Enregistre un lot. Retourne la liste des nouveaux domaines."""
        if not self._conn or not items:
            return []

        now = time.time()
        new_domains: list[str] = []
        inserts: list[tuple[str, float, float, str]] = []
        updates: list[tuple[float, str, str]] = []

        for domain, source in items:
            if domain in self._memory_seen:
                updates.append((now, source, domain))
            else:
                self._memory_seen.add(domain)
                new_domains.append(domain)
                inserts.append((domain, now, now, source))

        if inserts:
            await self._conn.executemany(
                "INSERT OR IGNORE INTO domains (domain, first_seen, last_seen, source) VALUES (?, ?, ?, ?)",
                inserts,
            )
        if updates:
            await self._conn.executemany(
                "UPDATE domains SET last_seen = ?, source = COALESCE(?, source) WHERE domain = ?",
                updates,
            )
        if commit and (inserts or updates):
            await self._conn.commit()

        return new_domains

    async def flush(self) -> None:
        if self._conn:
            await self._conn.commit()

    async def mark_scanned(self, domain: str, findings: str) -> None:
        if not self._conn:
            return
        await self._conn.execute(
            "UPDATE domains SET scanned = 1, findings = ? WHERE domain = ?",
            (findings, domain),
        )
        await self._conn.commit()

    async def unscaned_new(self, max_age_hours: float, limit: int = 1000) -> list[str]:
        cutoff = time.time() - max_age_hours * 3600
        if not self._conn:
            return []
        async with self._conn.execute(
            """
            SELECT domain FROM domains
            WHERE scanned = 0 AND first_seen >= ?
            ORDER BY first_seen DESC LIMIT ?
            """,
            (cutoff, limit),
        ) as cursor:
            rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def count_new(self, max_age_hours: float) -> int:
        cutoff = time.time() - max_age_hours * 3600
        if not self._conn:
            return 0
        async with self._conn.execute(
            "SELECT COUNT(*) FROM domains WHERE first_seen >= ?", (cutoff,)
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0
