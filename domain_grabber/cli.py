"""Point d'entrée CLI du domain grabber."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console

from domain_grabber.scanner import (
    DEFAULT_CHECKS,
    DEFAULT_LFI_PARAMS,
    DEFAULT_PATHS,
    DEFAULT_SECRET_PATTERNS,
    ScanConfig,
    VulnScanner,
    findings_to_json,
)
from domain_grabber.storage import DomainStore
from domain_grabber.turbo import run_pipeline
from domain_grabber.utils import normalize_domain

console = Console()


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build_scan_config(cfg: dict[str, Any]) -> ScanConfig:
    s = cfg.get("scanner", {})
    checks = dict(DEFAULT_CHECKS)
    checks.update(s.get("checks", {}))
    return ScanConfig(
        concurrency=s.get("concurrency", 50),
        timeout=s.get("timeout", 10),
        aggressive=s.get("aggressive", False),
        callback_url=s.get("callback_url", ""),
        checks=checks,
        paths=s.get("paths") or list(DEFAULT_PATHS),
        lfi_params=s.get("lfi_params") or list(DEFAULT_LFI_PARAMS),
        secret_patterns=s.get("secret_patterns") or list(DEFAULT_SECRET_PATTERNS),
    )


def _write_findings(findings_file: Path, findings: list) -> int:
    if not findings:
        return 0
    with findings_file.open("a", encoding="utf-8") as fh:
        for f in findings:
            fh.write(
                json.dumps(
                    {
                        "domain": f.domain,
                        "check": f.check,
                        "severity": f.severity,
                        "url": f.url,
                        "evidence": f.evidence,
                        "metadata": f.metadata,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return len(findings)


async def run_grabber(cfg: dict[str, Any], target: int = 0, duration: int = 0) -> None:
    await run_pipeline(cfg, target=target, duration=duration)


async def run_scan_only(cfg: dict[str, Any], input_file: Path) -> None:
    scan_cfg = build_scan_config(cfg)
    output_dir = Path(cfg.get("output", {}).get("directory", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    domains: list[str] = []
    with input_file.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    d = data.get("domain", "")
                except json.JSONDecodeError:
                    continue
            else:
                d = line
            normalized = normalize_domain(d)
            if normalized:
                domains.append(normalized)

    print(f"[INFO] Scan {len(domains)} domaines...", flush=True)
    findings_file = output_dir / f"findings_{int(time.time())}.jsonl"

    def on_batch(batch: list) -> None:
        _write_findings(findings_file, batch)

    scanner = VulnScanner(scan_cfg)
    findings = await scanner.scan_many(domains, on_result=on_batch)
    print(f"[INFO] {len(findings)} findings → {findings_file}", flush=True)


async def run_stats(cfg: dict[str, Any]) -> None:
    new_cfg = cfg.get("new_domains", {})
    store = DomainStore(Path(new_cfg.get("database", "./data/domains.db")))
    await store.init()
    max_age = float(new_cfg.get("max_age_hours", 24))
    count = await store.count_new(max_age)
    pending = await store.unscaned_new(max_age, limit=10)
    console.print(f"[cyan]Nouveaux domaines ({max_age}h) :[/cyan] {count:,}")
    console.print(f"[cyan]En attente de scan :[/cyan] {len(pending)} (aperçu)")
    for d in pending[:10]:
        console.print(f"  - {d}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Domain Grabber — CT grab + checker HTTP rapide",
    )
    parser.add_argument("-c", "--config", default="config.yaml", help="Fichier config YAML")
    sub = parser.add_subparsers(dest="command")

    for name, help_text in [("run", "Grab CT → export"), ("grab", "Alias de run")]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("-n", "--count", type=int, default=0, help="Domaines à exporter (0=illimité)")
        p.add_argument("-t", "--time", type=int, default=0, help="Durée en secondes (0=illimité)")

    check_p = sub.add_parser("check", help="Checker HTTP externe ultra-rapide (massdns→masscan→httpx)")
    check_p.add_argument("-i", "--input", required=True, help="Fichier domaines (txt/jsonl)")
    check_p.add_argument("-o", "--output", default="", help="Fichier output (défaut: output/alive_*.txt)")
    check_p.add_argument("--rate", type=int, default=100000, help="Masscan packets/s")

    scan_p = sub.add_parser("scan", help="Scanner vuln un fichier de domaines")
    scan_p.add_argument("-i", "--input", required=True, help="Fichier domains (txt ou jsonl)")

    sub.add_parser("stats", help="Statistiques base domaines")

    panel_p = sub.add_parser("panel", help="Panel web mobile (stats live + start/stop)")
    panel_p.add_argument("--host", default="0.0.0.0", help="Adresse d'écoute")
    panel_p.add_argument("--port", type=int, default=8080, help="Port HTTP")

    args = parser.parse_args(argv)
    cfg = load_config(Path(args.config))

    if not cfg:
        cfg_path = Path("config.example.yaml")
        if cfg_path.exists():
            print("[INFO] config.yaml absent → config.example.yaml", flush=True)
            cfg = load_config(cfg_path)

    cmd = args.command or "run"
    if cmd == "check":
        import subprocess

        script = Path(__file__).resolve().parent.parent / "scripts" / "check.sh"
        inp = Path(args.input)
        out = Path(args.output) if args.output else Path("output") / f"alive_{int(time.time())}.txt"
        if not script.exists():
            print(f"[ERR] script introuvable: {script}", flush=True)
            raise SystemExit(1)
        rate = str(getattr(args, "rate", 100000) or 100000)
        raise SystemExit(subprocess.call(["bash", str(script), str(inp), str(out), rate]))
    elif cmd == "scan":
        asyncio.run(run_scan_only(cfg, Path(args.input)))
    elif cmd == "stats":
        asyncio.run(run_stats(cfg))
    elif cmd == "panel":
        from domain_grabber.panel import run_panel
        host = getattr(args, "host", "0.0.0.0")
        port = getattr(args, "port", 8080) or int(cfg.get("panel", {}).get("port", 8080))
        asyncio.run(run_panel(cfg, host=host, port=port))
    else:
        asyncio.run(
            run_grabber(
                cfg,
                target=getattr(args, "count", 0) or 0,
                duration=getattr(args, "time", 0) or 0,
            )
        )


if __name__ == "__main__":
    main()
