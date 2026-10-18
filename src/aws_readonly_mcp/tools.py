"""Tool implementations. Plain functions so they are easy to test without MCP."""

from __future__ import annotations

import base64
import functools
import json
import time
from decimal import Decimal
from typing import Any

import boto3

from .audit import AuditError, AuditLog, summarize
from .guardrails import Config, GuardrailError, enforce_read_only
from .redact import Redactor


def _json_safe(value: Any) -> Any:
    """Make DynamoDB/S3 values JSON-serialisable (Decimal, bytes, sets)."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, (bytes, bytearray)):
        return {"_base64": base64.b64encode(bytes(value)).decode()}
    if isinstance(value, (set, frozenset)):
        return sorted((_json_safe(v) for v in value), key=str)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _encode_token(key: dict | None) -> str | None:
    if not key:
        return None
    return base64.urlsafe_b64encode(json.dumps(_json_safe(key)).encode()).decode()


def _decode_token(token: str | None) -> dict | None:
    if not token:
        return None
    key = json.loads(base64.urlsafe_b64decode(token.encode()))
    # Numbers came back as int/float; DynamoDB wants Decimal for N attributes.
    return {k: Decimal(str(v)) if isinstance(v, (int, float)) else v for k, v in key.items()}


class AwsReader:
    """Holds boto3 clients (with the read-only hook attached) plus the config."""

    def __init__(self, config: Config | None = None, session: boto3.Session | None = None):
        self.config = config or Config.from_env()
        session = session or boto3.Session()
        self._ddb = session.resource("dynamodb")
        self._ddb_client = self._ddb.meta.client
        self._s3 = session.client("s3")
        enforce_read_only(self._ddb_client)
        enforce_read_only(self._s3)
        self.redactor = Redactor(
            names=self.config.redact_names,
            patterns=self.config.redact_patterns,
            defaults=self.config.redact_defaults,
        )
        self.audit = AuditLog(self.config.audit_path, self.config.audit_fail_closed)
        if self.audit.fail_closed:
            self.audit.check_writable()  # refuse to start with a broken audit log
        # Wrap every public tool so results are redacted and every call is audited.
        for name in dir(self):
            if name.startswith(("dynamodb_", "s3_")):
                setattr(self, name, self._instrument(name, getattr(self, name)))

    def _instrument(self, tool: str, fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            call_args = _bind_args(fn, args, kwargs)
            logged_args, _ = self.redactor.redact(call_args)
            start = time.perf_counter()
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                status = "blocked" if isinstance(exc, GuardrailError) else "error"
                message, _ = self.redactor.redact(f"{type(exc).__name__}: {exc}")
                try:
                    self.audit.record(
                        tool=tool,
                        args=logged_args,
                        status=status,
                        duration_ms=(time.perf_counter() - start) * 1000,
                        error=message,
                    )
                except AuditError:
                    pass  # nothing is returned to the agent on this path anyway
                raise
            clean, count = self.redactor.redact(result)
            # If this raises AuditError (fail closed), the result is withheld.
            self.audit.record(
                tool=tool,
                args=logged_args,
                status="ok",
                duration_ms=(time.perf_counter() - start) * 1000,
                summary=summarize(clean, count),
            )
            return clean

        return wrapper

    # ---------------------------------------------------------------- DynamoDB

    def dynamodb_list_tables(self) -> dict:
        names: list[str] = []
        for page in self._ddb_client.get_paginator("list_tables").paginate():
            names.extend(page["TableNames"])
        if self.config.allowed_tables:
            names = [n for n in names if n in self.config.allowed_tables]
        return {"tables": names}

    def dynamodb_describe_table(self, table: str) -> dict:
        self.config.check_table(table)
        t = self._ddb_client.describe_table(TableName=table)["Table"]
        return _json_safe(
            {
                "name": t["TableName"],
                "status": t.get("TableStatus"),
                "key_schema": t["KeySchema"],
                "attribute_definitions": t["AttributeDefinitions"],
                "item_count": t.get("ItemCount"),
                "size_bytes": t.get("TableSizeBytes"),
                "billing_mode": t.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                "global_secondary_indexes": [
                    {"name": g["IndexName"], "key_schema": g["KeySchema"]}
                    for g in t.get("GlobalSecondaryIndexes", [])
                ],
                "local_secondary_indexes": [
                    {"name": g["IndexName"], "key_schema": g["KeySchema"]}
                    for g in t.get("LocalSecondaryIndexes", [])
                ],
            }
        )

    def dynamodb_get_item(self, table: str, key: dict[str, Any]) -> dict:
        self.config.check_table(table)
        resp = self._ddb.Table(table).get_item(Key=key)
        item = resp.get("Item")
        return {"found": item is not None, "item": _json_safe(item)}

    def _page(self, op: str, table: str, limit: int | None, next_token: str | None, **kw) -> dict:
        self.config.check_table(table)
        kw = {k: v for k, v in kw.items() if v is not None}
        kw["Limit"] = self.config.clamp_items(limit)
        start = _decode_token(next_token)
        if start:
            kw["ExclusiveStartKey"] = start
        resp = getattr(self._ddb.Table(table), op)(**kw)
        return {
            "items": _json_safe(resp.get("Items", [])),
            "count": resp.get("Count", 0),
            "scanned_count": resp.get("ScannedCount", 0),
            "next_token": _encode_token(resp.get("LastEvaluatedKey")),
        }

    def dynamodb_query(
        self,
        table: str,
        key_condition_expression: str,
        expression_attribute_values: dict[str, Any],
        expression_attribute_names: dict[str, str] | None = None,
        filter_expression: str | None = None,
        index_name: str | None = None,
        scan_index_forward: bool = True,
        limit: int | None = None,
        next_token: str | None = None,
    ) -> dict:
        return self._page(
            "query",
            table,
            limit,
            next_token,
            KeyConditionExpression=key_condition_expression,
            ExpressionAttributeValues=_to_decimals(expression_attribute_values),
            ExpressionAttributeNames=expression_attribute_names,
            FilterExpression=filter_expression,
            IndexName=index_name,
            ScanIndexForward=scan_index_forward,
        )

    def dynamodb_scan(
        self,
        table: str,
        filter_expression: str | None = None,
        expression_attribute_values: dict[str, Any] | None = None,
        expression_attribute_names: dict[str, str] | None = None,
        index_name: str | None = None,
        limit: int | None = None,
        next_token: str | None = None,
    ) -> dict:
        return self._page(
            "scan",
            table,
            limit,
            next_token,
            FilterExpression=filter_expression,
            ExpressionAttributeValues=_to_decimals(expression_attribute_values)
            if expression_attribute_values
            else None,
            ExpressionAttributeNames=expression_attribute_names,
            IndexName=index_name,
        )

    # --------------------------------------------------------------------- S3

    def s3_list_buckets(self) -> dict:
        names = [b["Name"] for b in self._s3.list_buckets().get("Buckets", [])]
        if self.config.allowed_buckets:
            names = [n for n in names if n in self.config.allowed_buckets]
        return {"buckets": names}

    def s3_list_objects(
        self,
        bucket: str,
        prefix: str = "",
        delimiter: str | None = "/",
        limit: int | None = None,
        next_token: str | None = None,
    ) -> dict:
        self.config.check_bucket(bucket)
        kw: dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "MaxKeys": self.config.clamp_items(limit),
        }
        if delimiter:
            kw["Delimiter"] = delimiter
        if next_token:
            kw["ContinuationToken"] = next_token
        resp = self._s3.list_objects_v2(**kw)
        return _json_safe(
            {
                "objects": [
                    {"key": o["Key"], "size": o["Size"], "last_modified": o["LastModified"]}
                    for o in resp.get("Contents", [])
                ],
                "prefixes": [p["Prefix"] for p in resp.get("CommonPrefixes", [])],
                "next_token": resp.get("NextContinuationToken"),
            }
        )

    def s3_head_object(self, bucket: str, key: str) -> dict:
        self.config.check_bucket(bucket)
        r = self._s3.head_object(Bucket=bucket, Key=key)
        return _json_safe(
            {
                "size": r["ContentLength"],
                "content_type": r.get("ContentType"),
                "last_modified": r["LastModified"],
                "etag": r.get("ETag"),
                "metadata": r.get("Metadata", {}),
            }
        )

    def s3_read_object(self, bucket: str, key: str, max_bytes: int | None = None) -> dict:
        """Read up to max_bytes (capped by config) from the start of an object as text."""
        self.config.check_bucket(bucket)
        cap = self.config.max_bytes
        want = cap if max_bytes is None else max(1, min(int(max_bytes), cap))
        r = self._s3.get_object(Bucket=bucket, Key=key, Range=f"bytes=0-{want - 1}")
        body = r["Body"].read()
        total = _total_size(r, len(body))
        if b"\x00" in body:
            return {"binary": True, "size": total, "note": "Binary content not shown."}
        return {
            "binary": False,
            "size": total,
            "bytes_returned": len(body),
            "truncated": total > len(body),
            "content": body.decode("utf-8", errors="replace"),
        }


def _bind_args(fn, args: tuple, kwargs: dict) -> dict:
    import inspect

    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        return dict(bound.arguments)
    except TypeError:
        return {"args": list(args), **kwargs}


def _total_size(resp: dict, fallback: int) -> int:
    # ContentRange looks like "bytes 0-99/1234"; absent when the object is empty.
    cr = resp.get("ContentRange")
    if cr and "/" in cr:
        try:
            return int(cr.rsplit("/", 1)[1])
        except ValueError:
            pass
    return resp.get("ContentLength", fallback)


def _to_decimals(values: dict[str, Any]) -> dict[str, Any]:
    """DynamoDB's resource API rejects float; convert numbers via Decimal(str(x))."""

    def conv(v: Any) -> Any:
        if isinstance(v, bool):
            return v
        if isinstance(v, float):
            return Decimal(str(v))
        if isinstance(v, dict):
            return {k: conv(x) for k, x in v.items()}
        if isinstance(v, list):
            return [conv(x) for x in v]
        return v

    return conv(values)
