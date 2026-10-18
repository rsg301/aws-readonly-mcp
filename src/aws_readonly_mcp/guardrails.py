"""Guardrails: read-only enforcement, result limits, and optional resource scoping.

Defence in depth. IAM should still be read-only; this layer makes sure the server
cannot write even if it is accidentally given broad credentials.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

# Every AWS API operation this server is allowed to call. Anything else is blocked
# before the request leaves the process.
ALLOWED_OPERATIONS: frozenset[str] = frozenset(
    {
        # DynamoDB
        "ListTables",
        "DescribeTable",
        "GetItem",
        "Query",
        "Scan",
        # S3
        "ListBuckets",
        "ListObjectsV2",
        "HeadObject",
        "GetObject",
    }
)


class GuardrailError(Exception):
    """Raised when a request violates a guardrail."""


def _csv(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def _json_list(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be a JSON list of regex strings: {exc}") from exc
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{name} must be a JSON list of regex strings")
    return tuple(value)


DEFAULT_AUDIT_PATH = "~/.aws-readonly-mcp/audit.jsonl"


def _audit_path_from_env() -> str | None:
    raw = os.environ.get("AWS_MCP_AUDIT_LOG", DEFAULT_AUDIT_PATH).strip()
    return None if raw.lower() in ("", "off", "none", "0") else raw


@dataclass(frozen=True)
class Config:
    max_items: int = 50
    max_bytes: int = 100_000
    allowed_tables: frozenset[str] = field(default_factory=frozenset)
    allowed_buckets: frozenset[str] = field(default_factory=frozenset)
    redact_names: frozenset[str] = field(default_factory=frozenset)
    redact_patterns: tuple[str, ...] = ()
    redact_defaults: bool = True
    audit_path: str | None = None  # None = audit logging off
    audit_fail_closed: bool = True  # only matters when audit_path is set

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            max_items=int(os.environ.get("AWS_MCP_MAX_ITEMS", "50")),
            max_bytes=int(os.environ.get("AWS_MCP_MAX_BYTES", "100000")),
            allowed_tables=_csv("AWS_MCP_ALLOWED_TABLES"),
            allowed_buckets=_csv("AWS_MCP_ALLOWED_BUCKETS"),
            redact_names=_csv("AWS_MCP_REDACT_ATTRIBUTES"),
            redact_patterns=_json_list("AWS_MCP_REDACT_PATTERNS"),
            redact_defaults=os.environ.get("AWS_MCP_REDACT_DEFAULTS", "1") != "0",
            audit_path=_audit_path_from_env(),
            audit_fail_closed=os.environ.get("AWS_MCP_AUDIT_FAIL_CLOSED", "1") != "0",
        )

    def clamp_items(self, requested: int | None) -> int:
        """Return a safe item limit: default to the cap, never exceed it, minimum 1."""
        if requested is None:
            return self.max_items
        return max(1, min(int(requested), self.max_items))

    def check_table(self, table: str) -> None:
        if self.allowed_tables and table not in self.allowed_tables:
            raise GuardrailError(
                f"Table '{table}' is not in the allowlist (AWS_MCP_ALLOWED_TABLES)."
            )

    def check_bucket(self, bucket: str) -> None:
        if self.allowed_buckets and bucket not in self.allowed_buckets:
            raise GuardrailError(
                f"Bucket '{bucket}' is not in the allowlist (AWS_MCP_ALLOWED_BUCKETS)."
            )


def enforce_read_only(client) -> None:
    """Attach a hook that blocks any operation not in ALLOWED_OPERATIONS."""

    def _block(model, **_kwargs):
        if model.name not in ALLOWED_OPERATIONS:
            raise GuardrailError(
                f"Operation '{model.name}' is blocked: this server is read-only."
            )

    client.meta.events.register("before-call.*.*", _block)
