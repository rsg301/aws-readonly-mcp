import json
import os
import stat

import boto3
import pytest
from moto import mock_aws

from aws_readonly_mcp.audit import AuditError
from aws_readonly_mcp.guardrails import Config, GuardrailError
from aws_readonly_mcp.redact import REDACTED, Redactor
from aws_readonly_mcp.tools import AwsReader


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ------------------------------------------------------------------ redactor


def test_default_sensitive_keys_redacted_at_any_depth_and_case():
    data = {
        "user": "bob",
        "Password": "hunter2",
        "profile": {"api_key": "k", "nested": [{"AuthToken": "t", "ok": 1}]},
        "db-secret": {"anything": "inside"},
    }
    out, n = Redactor().redact(data)
    assert out["user"] == "bob"
    assert out["Password"] == REDACTED
    assert out["profile"]["api_key"] == REDACTED
    assert out["profile"]["nested"][0] == {"AuthToken": REDACTED, "ok": 1}
    assert out["db-secret"] == REDACTED  # whole subtree hidden
    assert n == 4


def test_custom_names_match_exactly_not_by_substring():
    r = Redactor(names=frozenset({"ssn"}))
    out, n = r.redact({"SSN": "123-45-6789", "ssn_last4_label": "keep", "classname": "keep"})
    assert out == {"SSN": REDACTED, "ssn_last4_label": "keep", "classname": "keep"}
    assert n == 1


def test_defaults_can_be_disabled():
    out, n = Redactor(defaults=False).redact({"password": "x", "AKIAABCDEFGHIJKLMNOP": 1})
    assert out["password"] == "x" and n == 0


def test_next_token_is_never_redacted():
    out, _ = Redactor().redact({"next_token": "abc123", "items": []})
    assert out["next_token"] == "abc123"


def test_value_patterns_scrub_aws_keys_pem_and_jwt():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijk"
    text = f"id=AKIAABCDEFGHIJKLMNOP and {pem} and {jwt} done"
    out, n = Redactor().redact({"note": text})
    assert "AKIA" not in out["note"]
    assert "PRIVATE KEY" not in out["note"]
    assert "eyJ" not in out["note"]
    assert out["note"].endswith("done")
    assert n == 3


def test_custom_value_pattern():
    out, n = Redactor(patterns=(r"\b\d{3}-\d{2}-\d{4}\b",)).redact({"t": "ssn 123-45-6789 ok"})
    assert out["t"] == f"ssn {REDACTED} ok" and n == 1


def test_secrets_inside_free_text():
    text = 'db_password=hunter2\n{"api_key": "abc123", "region": "us-east-1"}\nlevel: info'
    out, n = Redactor().redact({"content": text})
    c = out["content"]
    assert "hunter2" not in c and "abc123" not in c
    assert "us-east-1" in c and "level: info" in c
    assert n == 2


def test_original_input_is_not_mutated():
    data = {"password": "x", "list": [{"token": "y"}]}
    Redactor().redact(data)
    assert data == {"password": "x", "list": [{"token": "y"}]}


# ---------------------------------------------------------------- integration


@pytest.fixture
def seeded():
    with mock_aws():
        t = boto3.resource("dynamodb").create_table(
            TableName="users",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        t.put_item(Item={"pk": "u1", "email": "a@b.c", "password_hash": "$2b$xyz", "ssn": "123"})
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="cfg")
        s3.put_object(
            Bucket="cfg",
            Key="app.env",
            Body=b"REGION=us-east-1\nAWS_KEY=AKIAABCDEFGHIJKLMNOP\nDB_PASSWORD=hunter2\n",
        )
        yield


def make(tmp_path, **kw):
    log = tmp_path / "audit.jsonl"
    cfg = Config(audit_path=str(log), redact_names=frozenset({"ssn"}), **kw)
    return AwsReader(cfg), log


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_dynamodb_results_are_redacted(seeded, tmp_path):
    r, _ = make(tmp_path)
    item = r.dynamodb_get_item("users", {"pk": "u1"})["item"]
    assert item["email"] == "a@b.c"
    assert item["password_hash"] == REDACTED
    assert item["ssn"] == REDACTED
    scan = r.dynamodb_scan("users")["items"][0]
    assert scan["password_hash"] == REDACTED


def test_s3_content_is_redacted(seeded, tmp_path):
    r, _ = make(tmp_path)
    c = r.s3_read_object("cfg", "app.env")["content"]
    assert "REGION=us-east-1" in c
    assert "AKIA" not in c and "hunter2" not in c


# ----------------------------------------------------------------------- audit


def test_audit_records_calls_without_result_contents(seeded, tmp_path):
    r, log = make(tmp_path)
    r.dynamodb_get_item("users", {"pk": "u1"})
    r.s3_read_object("cfg", "app.env")
    entries = lines(log)
    assert [e["tool"] for e in entries] == ["dynamodb_get_item", "s3_read_object"]
    assert all(e["status"] == "ok" and "ts" in e and e["duration_ms"] >= 0 for e in entries)
    assert entries[0]["args"] == {"table": "users", "key": {"pk": "u1"}}
    raw = log.read_text()
    assert "a@b.c" not in raw and "hunter2" not in raw and "$2b$xyz" not in raw
    assert entries[1]["summary"]["redactions"] >= 2
    assert entries[1]["summary"]["bytes_returned"] > 0


def test_audit_summary_for_listings(seeded, tmp_path):
    r, log = make(tmp_path)
    r.dynamodb_scan("users")
    s = lines(log)[0]["summary"]
    assert s["items_returned"] == 1 and s["count"] == 1


def test_audit_args_are_redacted(seeded, tmp_path):
    r, log = make(tmp_path)
    r.dynamodb_scan(
        "users",
        filter_expression="email = :e AND nick = :password",
        expression_attribute_values={":e": "x", ":password": "p4ss"},
    )
    assert "p4ss" not in log.read_text()


def test_audit_records_blocked_and_errors(seeded, tmp_path):
    r, log = make(tmp_path, allowed_tables=frozenset({"other"}))
    with pytest.raises(GuardrailError):
        r.dynamodb_get_item("users", {"pk": "u1"})
    with pytest.raises(Exception):
        r.s3_head_object("cfg", "does-not-exist")
    blocked, err = lines(log)
    assert blocked["status"] == "blocked" and "allowlist" in blocked["error"]
    assert err["status"] == "error" and err["tool"] == "s3_head_object"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_audit_file_is_private_and_append_only(seeded, tmp_path):
    r, log = make(tmp_path)
    r.dynamodb_list_tables()
    r.dynamodb_list_tables()
    assert len(lines(log)) == 2
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_audit_disabled_by_default_config(seeded, tmp_path):
    r = AwsReader(Config())
    r.dynamodb_list_tables()
    assert not r.audit.enabled


def test_audit_failure_does_not_break_the_call(seeded, tmp_path, capsys):
    # Path whose parent is a regular file, so it cannot be created.
    blocker = tmp_path / "file"
    blocker.write_text("x")
    bad = str(blocker / "sub" / "audit.jsonl")
    r = AwsReader(Config(audit_path=bad, audit_fail_closed=False))
    assert r.dynamodb_list_tables() == {"tables": ["users"]}
    assert "audit log write failed" in capsys.readouterr().err


def test_fail_closed_refuses_to_start_with_unwritable_log(seeded, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(AuditError, match="not writable"):
        AwsReader(Config(audit_path=str(blocker / "sub" / "audit.jsonl")))


def test_fail_closed_withholds_results_when_log_breaks_midway(seeded, tmp_path):
    r, log = make(tmp_path)
    assert r.dynamodb_get_item("users", {"pk": "u1"})["found"] is True
    log.unlink()
    log.mkdir()  # now the path is a directory, so appends fail
    with pytest.raises(AuditError, match="refusing to return results"):
        r.dynamodb_get_item("users", {"pk": "u1"})
    with pytest.raises(AuditError):
        r.s3_read_object("cfg", "app.env")


def test_fail_closed_still_raises_original_error_when_log_broken(seeded, tmp_path):
    r, log = make(tmp_path, allowed_tables=frozenset({"other"}))
    log.unlink()
    log.mkdir()
    with pytest.raises(GuardrailError):  # the real reason, not the audit failure
        r.dynamodb_get_item("users", {"pk": "u1"})


def test_fail_closed_env(monkeypatch):
    assert Config.from_env().audit_fail_closed is True
    monkeypatch.setenv("AWS_MCP_AUDIT_FAIL_CLOSED", "0")
    assert Config.from_env().audit_fail_closed is False


def test_env_config(monkeypatch):
    monkeypatch.setenv("AWS_MCP_REDACT_ATTRIBUTES", "ssn, dob")
    monkeypatch.setenv("AWS_MCP_REDACT_PATTERNS", '["\\\\d{16}"]')
    monkeypatch.setenv("AWS_MCP_REDACT_DEFAULTS", "0")
    monkeypatch.setenv("AWS_MCP_AUDIT_LOG", "off")
    c = Config.from_env()
    assert c.redact_names == {"ssn", "dob"}
    assert c.redact_patterns == ("\\d{16}",)
    assert c.redact_defaults is False and c.audit_path is None
    monkeypatch.setenv("AWS_MCP_REDACT_PATTERNS", "not json")
    with pytest.raises(ValueError):
        Config.from_env()
