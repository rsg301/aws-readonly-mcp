"""Append-only JSON Lines audit log of every tool call.

Each line records who/what/when/outcome, but never result contents: arguments are logged
(after redaction) so you can see what was asked, results are only summarised by size.
By default the log fails closed: if an entry cannot be written, the call returns nothing to
the agent (AuditError) and the server refuses to start if the log is not writable. Set
AWS_MCP_AUDIT_FAIL_CLOSED=0 to make logging best-effort (warn on stderr, keep serving).
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_ERROR_CHARS = 500


class AuditError(Exception):
    """Raised when the audit log cannot be written and the server is failing closed."""


class AuditLog:
    def __init__(self, path: str | os.PathLike | None, fail_closed: bool = False):
        self.path = Path(path).expanduser() if path else None
        self.fail_closed = fail_closed
        self._lock = threading.Lock()

    def check_writable(self) -> None:
        """Startup check: create the file if needed and prove we can append to it."""
        if not self.enabled:
            return
        try:
            self._append("")
        except OSError as exc:
            raise AuditError(f"audit log is not writable: {exc}") from exc

    def _append(self, line: str) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                if line:
                    f.write(line + "\n")

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def record(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        status: str,
        duration_ms: float,
        summary: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        if not self.enabled:
            return
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "tool": tool,
            "args": args,
            "status": status,  # ok | error | blocked
            "duration_ms": round(duration_ms, 1),
        }
        if summary:
            entry["summary"] = summary
        if error:
            entry["error"] = error[:MAX_ERROR_CHARS]
        try:
            self._append(json.dumps(entry, default=str, ensure_ascii=False))
        except OSError as exc:
            if self.fail_closed:
                raise AuditError(
                    "Audit log unavailable; refusing to return results."
                ) from exc
            print(f"aws-readonly-mcp: audit log write failed: {exc}", file=sys.stderr)


def summarize(result: Any, redactions: int) -> dict[str, Any]:
    """Size-only summary of a result. Never includes the data itself."""
    out: dict[str, Any] = {"redactions": redactions}
    if isinstance(result, dict):
        for k in ("count", "scanned_count", "size", "bytes_returned"):
            if isinstance(result.get(k), int):
                out[k] = result[k]
        for k in ("items", "objects", "prefixes", "tables", "buckets"):
            if isinstance(result.get(k), list):
                out[f"{k}_returned"] = len(result[k])
        if "truncated" in result:
            out["truncated"] = bool(result["truncated"])
        if result.get("next_token"):
            out["more_available"] = True
    return out
