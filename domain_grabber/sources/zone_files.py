"""Source gratuite : fichiers zone ICANN CZDS (téléchargement manuel)."""

from __future__ import annotations

import gzip
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from domain_grabber.utils import normalize_domain


def _parse_zone_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith(";"):
        return None
    parts = line.split()
    if len(parts) < 1:
        return None
    name = parts[0].rstrip(".")
    return normalize_domain(name)


async def stream_zone_files(directory: Path) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Parse les fichiers .txt ou .txt.gz du répertoire CZDS."""
    files = sorted(directory.glob("*.txt")) + sorted(directory.glob("*.txt.gz"))
    for path in files:
        tld = path.stem.replace(".txt", "").replace(".gz", "")
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                domain = _parse_zone_line(line)
                if domain:
                    yield domain, {"tld": tld, "file": path.name}
