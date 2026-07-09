"""Source gratuite : fichiers Rapid7 FDNS (téléchargement manuel depuis opendata.rapid7.com)."""

from __future__ import annotations

import gzip
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from domain_grabber.utils import normalize_domain


async def stream_rapid7_fdns(directory: Path) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Parse les fichiers JSON.gz Rapid7 FDNS."""
    for path in sorted(directory.glob("*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                name = record.get("name", "")
                domain = normalize_domain(name)
                if domain:
                    yield domain, {
                        "file": path.name,
                        "record_type": record.get("type"),
                        "value": record.get("value"),
                    }
