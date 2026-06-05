"""
AegisEDR Console-side scanner management.
Handles scan job queuing, results collection, and real-time broadcasting.
"""
import asyncio
import hashlib
import json
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable

# ── Pending scan commands per endpoint ────────────────────────────────────────
# endpoint_id -> list of commands waiting to be picked up by agent
_pending_commands: dict[int, list] = defaultdict(list)

# ── WebSocket connections per client browser ──────────────────────────────────
_ws_connections: list = []

# ── In-memory scan event log (last 500 events) ────────────────────────────────
_scan_events: list = []
_MAX_EVENTS = 500


def queue_scan(endpoint_id: int, scan_type: str, target_path: str = "/") -> str:
    """Queue a scan command for an endpoint agent to pick up."""
    cmd_id = hashlib.md5(f"{endpoint_id}{scan_type}{time.time()}".encode()).hexdigest()[:12]
    _pending_commands[endpoint_id].append({
        "cmd_id": cmd_id,
        "type": "scan",
        "scan_type": scan_type,
        "target_path": target_path,
        "queued_at": datetime.utcnow().isoformat()
    })
    return cmd_id


def get_pending_commands(endpoint_id: int) -> list:
    """Agent polls this to get commands. Returns and clears the queue."""
    cmds = list(_pending_commands.get(endpoint_id, []))
    _pending_commands[endpoint_id] = []
    return cmds


def add_scan_event(event: dict):
    """Add a scan event to the in-memory log and broadcast to WebSocket clients."""
    event.setdefault("timestamp", datetime.utcnow().isoformat())
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
