"""Wire logging facility for capturing JSON-RPC frames over /mcp Streamable HTTP."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import threading
import time
from typing import Any, Mapping


@dataclass
class WireLogEntry:
    """A single JSON-RPC message captured on the /mcp wire."""

    entry_id: int
    timestamp: float
    iso_time: str
    direction: str  # 'REQUEST' (Client -> Server) or 'RESPONSE' (Server -> Client)
    method: str = ""
    tool_name: str = ""
    jsonrpc_id: str | int | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class WireLogger:
    """In-memory thread-safe ring buffer capturing live MCP JSON-RPC traffic."""

    def __init__(self, max_entries: int = 200) -> None:
        self.max_entries = max_entries
        self._entries: list[WireLogEntry] = []
        self._counter = 0
        self._lock = threading.Lock()

    def log_request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        jsonrpc_id: str | int | None = None,
        tool_name: str = "",
    ) -> WireLogEntry:
        """Record an outgoing JSON-RPC request to /mcp."""
        now = time.time()
        iso = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]

        if not tool_name and params and "name" in params:
            tool_name = params["name"]

        summary = f"JSON-RPC Request: {method}"
        if tool_name:
            summary += f" ({tool_name})"

        payload = {
            "jsonrpc": "2.0",
            "id": jsonrpc_id if jsonrpc_id is not None else 1,
            "method": method,
            "params": dict(params or {}),
        }

        with self._lock:
            self._counter += 1
            entry = WireLogEntry(
                entry_id=self._counter,
                timestamp=now,
                iso_time=iso,
                direction="REQUEST",
                method=method,
                tool_name=tool_name,
                jsonrpc_id=jsonrpc_id,
                payload=payload,
                summary=summary,
            )
            self._entries.append(entry)
            if len(self._entries) > self.max_entries:
                self._entries.pop(0)
            return entry

    def log_response(
        self,
        jsonrpc_id: str | int | None,
        result: Any = None,
        error: Any = None,
        method: str = "",
        tool_name: str = "",
    ) -> WireLogEntry:
        """Record an incoming JSON-RPC response from /mcp."""
        now = time.time()
        iso = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]

        summary = f"JSON-RPC Response"
        if tool_name:
            summary += f" for {tool_name}"
        if error:
            summary += " [ERROR]"

        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": jsonrpc_id if jsonrpc_id is not None else 1,
        }
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result

        with self._lock:
            self._counter += 1
            entry = WireLogEntry(
                entry_id=self._counter,
                timestamp=now,
                iso_time=iso,
                direction="RESPONSE",
                method=method,
                tool_name=tool_name,
                jsonrpc_id=jsonrpc_id,
                payload=payload,
                summary=summary,
            )
            self._entries.append(entry)
            if len(self._entries) > self.max_entries:
                self._entries.pop(0)
            return entry

    def get_entries(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the latest entries in chronological order."""
        with self._lock:
            subset = self._entries[-limit:] if limit else self._entries
            return [e.to_dict() for e in subset]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# Global singleton
_GLOBAL_WIRE_LOGGER = WireLogger()


def get_wire_logger() -> WireLogger:
    return _GLOBAL_WIRE_LOGGER
