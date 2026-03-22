"""
api.py — FastAPI backend for the NIDS dashboard.

Endpoints
---------
GET  /             → serves dashboard.html
GET  /api/stats    → current pipeline stats
GET  /api/alerts   → recent alert history (last 500)
WS   /ws/alerts    → real-time alert stream (JSON per message)

Usage
-----
    # Live mode (requires root + network interface)
    uvicorn src.api:app --host 0.0.0.0 --port 8000

    # Demo mode (replays a pcap or generates synthetic traffic)
    NIDS_DEMO=1 uvicorn src.api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from pathlib import Path
from typing import Deque, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.flow_monitor import Alert, FlowMonitor
from src.predict import NIDSEngine

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="NIDS Dashboard", version="1.0.0")

DEMO_MODE  = os.getenv("NIDS_DEMO", "0") == "1"
INTERFACE  = os.getenv("NIDS_INTERFACE", "eth0")
THRESHOLD  = float(os.getenv("NIDS_THRESHOLD", "0.5"))
LOG_FILE   = os.getenv("NIDS_LOG", "alerts.ndjson")
PCAP_FILE  = os.getenv("NIDS_PCAP", "demo.pcap")

# In-memory alert ring buffer (last 500 alerts)
_alert_history: Deque[dict] = deque(maxlen=500)
_ws_clients: List[WebSocket] = []
_monitor: FlowMonitor | None = None

# ---------------------------------------------------------------------------
# Alert broadcast
# ---------------------------------------------------------------------------

async def _broadcast(alert_dict: dict) -> None:
    _alert_history.appendleft(alert_dict)
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_text(json.dumps(alert_dict))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


def _on_alert_sync(alert: Alert) -> None:
    """Called from the monitor thread — schedules broadcast on the event loop."""
    alert_dict = alert.to_dict()
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(_broadcast(alert_dict), loop)
    except RuntimeError:
        _alert_history.appendleft(alert_dict)


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    global _monitor

    engine = NIDSEngine()

    if DEMO_MODE:
        from src.demo import DemoMonitor
        _monitor = DemoMonitor(
            engine=engine,
            on_alert=_on_alert_sync,
            pcap_file=PCAP_FILE if Path(PCAP_FILE).exists() else None,
        )
    else:
        _monitor = FlowMonitor(
            interface=INTERFACE,
            engine=engine,
            on_alert=_on_alert_sync,
            alert_only=False,
            confidence_threshold=THRESHOLD,
            log_file=LOG_FILE,
        )

    _monitor.start()
    print(f"{'[DEMO]' if DEMO_MODE else '[LIVE]'} NIDS started")


@app.on_event("shutdown")
async def shutdown() -> None:
    if _monitor:
        _monitor.stop()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html_path = Path(__file__).parent.parent / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>dashboard.html not found</h1>", status_code=404)


@app.get("/api/stats")
async def get_stats() -> JSONResponse:
    if _monitor is None:
        return JSONResponse({"error": "monitor not started"}, status_code=503)
    stats = _monitor.get_stats()
    stats["demo_mode"] = DEMO_MODE
    stats["interface"] = INTERFACE if not DEMO_MODE else "demo"
    return JSONResponse(stats)


@app.get("/api/alerts")
async def get_alerts(limit: int = 100) -> JSONResponse:
    alerts = list(_alert_history)[:limit]
    return JSONResponse({"alerts": alerts, "total": len(_alert_history)})


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    await websocket.accept()
    _ws_clients.append(websocket)
    # Send recent history on connect so the dashboard isn't empty
    for alert in list(_alert_history)[:50]:
        await websocket.send_text(json.dumps(alert))
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)
