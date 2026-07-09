"""Panel web mobile — stats live + contrôle grab."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from aiohttp import web

from domain_grabber.cli import load_config
from domain_grabber.state import STATE

STATIC_DIR = Path(__file__).parent / "static"


async def handle_index(_request: web.Request) -> web.Response:
    return web.FileResponse(STATIC_DIR / "index.html")


async def handle_status(_request: web.Request) -> web.Response:
    return web.json_response(STATE.to_dict())


async def handle_start(request: web.Request) -> web.Response:
    if STATE.running:
        return web.json_response({"ok": False, "error": "Déjà en cours"}, status=409)

    cfg: dict[str, Any] = request.app["cfg"]
    try:
        body = await request.json()
    except Exception:
        body = {}

    duration = int(body.get("duration", 0))
    target = int(body.get("count", 0))

    from domain_grabber.turbo import run_pipeline

    async def _run() -> None:
        try:
            await run_pipeline(cfg, target=target, duration=duration, state=STATE)
        except asyncio.CancelledError:
            STATE.add_log("[INFO] Arrêté")
            STATE.finish()
            raise
        except Exception as exc:
            STATE.add_log(f"[ERROR] {exc}")
            STATE.finish()

    STATE.grab_task = asyncio.create_task(_run())
    return web.json_response({"ok": True})


async def handle_stop(_request: web.Request) -> web.Response:
    if not STATE.running:
        return web.json_response({"ok": False, "error": "Rien à arrêter"}, status=400)
    STATE.stop()
    if STATE.grab_task:
        STATE.grab_task.cancel()
    return web.json_response({"ok": True})


async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=15)
    await ws.prepare(request)
    queue = STATE.subscribe()
    try:
        await ws.send_json(STATE.to_dict())
        while True:
            try:
                data = await asyncio.wait_for(queue.get(), timeout=3.0)
                await ws.send_json(data)
            except asyncio.TimeoutError:
                await ws.send_json(STATE.to_dict())
            if ws.closed:
                break
    finally:
        STATE.unsubscribe(queue)
    return ws


def create_app(cfg: dict[str, Any]) -> web.Application:
    app = web.Application()
    app["cfg"] = cfg
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/status", handle_status)
    app.router.add_post("/api/start", handle_start)
    app.router.add_post("/api/stop", handle_stop)
    app.router.add_get("/ws", handle_ws)
    app.router.add_static("/static", STATIC_DIR, show_index=False)
    return app


async def run_panel(cfg: dict[str, Any], host: str = "0.0.0.0", port: int = 8080) -> None:
    app = create_app(cfg)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[INFO] Panel mobile → http://{host}:{port}", flush=True)
    print(f"[INFO] Depuis ton tel : http://<IP-SERVEUR>:{port}", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def start_panel(cfg_path: str = "config.yaml", host: str = "0.0.0.0", port: int = 8080) -> None:
    cfg = load_config(Path(cfg_path))
    if not cfg:
        example = Path("config.example.yaml")
        if example.exists():
            cfg = load_config(example)
    asyncio.run(run_panel(cfg, host=host, port=port))
