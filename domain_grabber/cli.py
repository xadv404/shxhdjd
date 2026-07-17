"""Point d'entrée CLI du domain grabber."""

from __future__ import annotations

import argparse
import asyncio
import time
from pathlib import Path
from typing import Any

import yaml

from domain_grabber.turbo import run_pipeline


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Domain Grabber — CLI")
    parser.add_argument("-c", "--config", default="config.yaml", help="Config YAML")
    sub = parser.add_subparsers(dest="command")

    grab = sub.add_parser("grab", help="Grab CT → domains.txt")
    grab.add_argument("-n", "--count", type=int, default=0, help="Objectif domaines (0=∞)")
    grab.add_argument("-t", "--time", type=int, default=0, help="Durée secondes (0=∞)")

    check = sub.add_parser("check", help="Check ports 80/443 (TCP)")
    check.add_argument("-i", "--input", required=True, help="Fichier domaines")
    check.add_argument("-o", "--output", default="", help="Output alive (défaut: output/alive_*.txt)")
    check.add_argument("--concurrency", type=int, default=2000, help="Workers")
    check.add_argument("--timeout", type=float, default=0.8, help="Timeout TCP (s)")

    args = parser.parse_args(argv)
    cfg = load_config(Path(args.config))
    if not cfg:
        example = Path("config.example.yaml")
        if example.exists():
            print("[INFO] config.yaml absent → config.example.yaml", flush=True)
            cfg = load_config(example)

    cmd = args.command or "grab"
    if cmd == "check":
        from domain_grabber.fast_check import run_fast_check

        inp = Path(args.input)
        out = Path(args.output) if args.output else Path("output") / f"alive_{int(time.time())}.txt"
        asyncio.run(
            run_fast_check(
                inp,
                out,
                concurrency=int(args.concurrency),
                timeout=float(args.timeout),
            )
        )
    else:
        asyncio.run(
            run_pipeline(
                cfg,
                target=getattr(args, "count", 0) or 0,
                duration=getattr(args, "time", 0) or 0,
            )
        )


if __name__ == "__main__":
    main()
