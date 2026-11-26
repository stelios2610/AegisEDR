"""
AegisEDR Console-side scanner management.
Handles scan job queuing, results collection, and real-time broadcasting.
"""
import asyncio
import json
from datetime import datetime, timezone

# WebSocket connections for the live scan console. Events are ephemeral UI
# state. Durable work (scans, quarantine) lives in SQLite.
_ws_connections: list = []

_scan_events: list = []
_MAX_EVENTS = 500


def add_scan_event(event: dict):
    """Add a scan event to the in-memory log and broadcast to WebSocket clients."""
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    _scan_events.append(event)
    if len(_scan_events) > _MAX_EVENTS:
        _scan_events.pop(0)
    # Broadcast to all connected WebSocket clients (non-blocking)
    asyncio.ensure_future(_broadcast(json.dumps(event)))


def get_scan_events(limit: int = 100) -> list:
    return list(reversed(_scan_events[-limit:]))


async def _broadcast(message: str):
    dead = []
    for ws in list(_ws_connections):
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _ws_connections:
            _ws_connections.remove(ws)


def register_ws(ws):
    _ws_connections.append(ws)


def unregister_ws(ws):
    if ws in _ws_connections:
        _ws_connections.remove(ws)
