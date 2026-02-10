"""WebSocket connection manager for real-time audit streaming."""

import asyncio
import json
from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections grouped by audit ID."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        # Buffer recent messages per audit so late-connecting clients get caught up
        self._history: dict[str, list[dict]] = {}
        self._max_history = 50

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, audit_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        if audit_id not in self._connections:
            self._connections[audit_id] = []
        self._connections[audit_id].append(websocket)

        # Replay buffered messages so the client catches up
        if audit_id in self._history:
            for msg in self._history[audit_id]:
                try:
                    await websocket.send_text(json.dumps(msg))
                except Exception:
                    pass

    def disconnect(self, audit_id: str, websocket: WebSocket) -> None:
        if audit_id in self._connections:
            self._connections[audit_id] = [
                ws for ws in self._connections[audit_id] if ws is not websocket
            ]
            if not self._connections[audit_id]:
                del self._connections[audit_id]

    async def broadcast(self, audit_id: str, message: dict) -> None:
        # Buffer the message for late-connecting clients
        if audit_id not in self._history:
            self._history[audit_id] = []
        self._history[audit_id].append(message)
        if len(self._history[audit_id]) > self._max_history:
            self._history[audit_id] = self._history[audit_id][-self._max_history:]

        if audit_id not in self._connections:
            return
        data = json.dumps(message)
        dead = []
        for ws in self._connections[audit_id]:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(audit_id, ws)

    def broadcast_sync(self, audit_id: str, message: dict) -> None:
        """Thread-safe broadcast — called from background threads."""
        if self._loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(audit_id, message), self._loop)

    def clear_history(self, audit_id: str) -> None:
        """Remove buffered messages for a completed/cleaned-up audit."""
        self._history.pop(audit_id, None)


ws_manager = ConnectionManager()
