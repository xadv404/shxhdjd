"""Stockage SQLite des domaines vus / nouveaux."""

from __future__ import annotations

import time
from pathlib import Path

import aiosqlite


class DomainStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def init(self) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
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
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_domains_first_seen ON domains(first_seen)"
            )
            await db.commit()

    async def register(self, domain: str, source: str) -> bool:
        """Enregistre un domaine. Retourne True si c'est un nouveau domaine."""
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT domain FROM domains WHERE domain = ?", (domain,)
            ) as cursor:
                row = await cursor.fetchone()
            if row:
                await db.execute(
                    "UPDATE domains SET last_seen = ?, source = COALESCE(?, source) WHERE domain = ?",
                    (now, source, domain),
                )
                await db.commit()
                return False

            await db.execute(
                "INSERT INTO domains (domain, first_seen, last_seen, source) VALUES (?, ?, ?, ?)",
                (domain, now, now, source),
            )
            await db.commit()
            return True

    async def is_new(self, domain: str, max_age_hours: float) -> bool:
        cutoff = time.time() - max_age_hours * 3600
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT first_seen FROM domains WHERE domain = ?", (domain,)
            ) as cursor:
                row = await cursor.fetchone()
        if not row:
            return True
        return row[0] >= cutoff

    async def mark_scanned(self, domain: str, findings: str) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE domains SET scanned = 1, findings = ? WHERE domain = ?",
                (findings, domain),
            )
            await db.commit()

    async def unscaned_new(self, max_age_hours: float, limit: int = 1000) -> list[str]:
        cutoff = time.time() - max_age_hours * 3600
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT domain FROM domains
                WHERE scanned = 0 AND first_seen >= ?
                ORDER BY first_seen DESC
                LIMIT ?
                """,
                (cutoff, limit),
            ) as cursor:
                rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def count_new(self, max_age_hours: float) -> int:
        cutoff = time.time() - max_age_hours * 3600
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT COUNT(*) FROM domains WHERE first_seen >= ?", (cutoff,)
            ) as cursor:
                row = await cursor.fetchone()
        return row[0] if row else 0
