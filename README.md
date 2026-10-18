# aws-readonly-mcp

A small [MCP](https://modelcontextprotocol.io) server that lets an AI agent **browse DynamoDB and S3 without being able to change anything**.

## Guardrails

- **Read-only at the SDK layer.** A botocore hook blocks every AWS operation that is not on an explicit allowlist (`ListTables`, `Query`, `GetObject`, ...). Writes fail before the request leaves your machine, even if the credentials could write. Keep IAM read-only too.
- **Capped results.** Item lists and object reads are limited (default 50 items, 100 KB). Large results come back with a `next_token` for paging.
- **Optional scoping.** Limit which tables and buckets the agent can see.
- **No binary dumps.** Binary S3 objects return metadata only.
- **Redaction.** Sensitive values are scrubbed before the agent sees them (see below).
- **Audit log.** Every call is recorded to an append-only JSONL file (see below).

## Tools

| Service | Tools |
|---|---|
| DynamoDB | `dynamodb_list_tables`, `dynamodb_describe_table`, `dynamodb_get_item`, `dynamodb_query`, `dynamodb_scan` |
| S3 | `s3_list_buckets`, `s3_list_objects`, `s3_head_object`, `s3_read_object` |

## Install and run

Once published: `uvx aws-readonly-mcp`. From source:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
aws-readonly-mcp          # speaks MCP over stdio
```

It uses the standard AWS credential chain (`AWS_PROFILE`, env vars, SSO, ...).

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `AWS_MCP_MAX_ITEMS` | `50` | Max items per DynamoDB page / S3 listing |
| `AWS_MCP_MAX_BYTES` | `100000` | Max bytes returned by `s3_read_object` |
| `AWS_MCP_ALLOWED_TABLES` | *(all)* | Comma-separated table allowlist |
| `AWS_MCP_ALLOWED_BUCKETS` | *(all)* | Comma-separated bucket allowlist |
| `AWS_MCP_REDACT_ATTRIBUTES` | *(none)* | Extra attribute/key names to redact, e.g. `ssn,dob` (exact match, case-insensitive) |
| `AWS_MCP_REDACT_PATTERNS` | *(none)* | JSON list of extra regexes to scrub from values, e.g. `["\\b\\d{16}\\b"]` |
| `AWS_MCP_REDACT_DEFAULTS` | `1` | Set `0` to turn off the built-in key names and patterns |
| `AWS_MCP_AUDIT_LOG` | `~/.aws-readonly-mcp/audit.jsonl` | Audit log path, or `off` |
| `AWS_MCP_AUDIT_FAIL_CLOSED` | `1` | `1`: no audit entry, no results. `0`: best-effort logging |

## Redaction

Applied to every result, recursively:

1. **Key names.** Any key containing `password`, `passwd`, `secret`, `token`, `apikey`, `privatekey`, `authorization` or `credential` has its whole value replaced with `[REDACTED]`. Names from `AWS_MCP_REDACT_ATTRIBUTES` are matched exactly.
2. **Value patterns.** AWS access key IDs, PEM private keys and JWTs are scrubbed from any string, plus your own regexes.
3. **Text secrets.** `DB_PASSWORD=hunter2` or `"api_key": "abc"` inside a text file (for example in S3) has its value scrubbed.

Limits: redaction hides values; it can't recognise a secret with no telltale name or shape, and an agent can still probe a hidden attribute through filter expressions. For anything truly off limits, use the table and bucket allowlists.

## Audit log

One JSON object per line, written to a file only you can read (mode `0600`):

```json
{"ts": "2026-10-17T22:10:03.512+00:00", "tool": "s3_read_object",
 "args": {"bucket": "cfg", "key": "app.env"}, "status": "ok", "duration_ms": 41.3,
 "summary": {"redactions": 2, "size": 71, "bytes_returned": 71, "truncated": false}}
```

- `status` is `ok`, `error` or `blocked` (guardrail refusal).
- Arguments are logged after redaction; **results are never logged**, only a size summary.
- **Fails closed by default.** The server refuses to start if the log isn't writable, and if an entry can't be written mid-session the call returns an error instead of data. Set `AWS_MCP_AUDIT_FAIL_CLOSED=0` for best-effort logging (warning on stderr, calls still succeed).
- Fail closed means a full disk or a broken path takes the tool offline. That is the point, but monitor it.

## Releasing to PyPI

One-time setup, then every GitHub Release publishes automatically:

1. On pypi.org, add a *pending publisher* for project `aws-readonly-mcp`: your GitHub user/repo, workflow `publish.yml`, environment `pypi`.
2. In the GitHub repo, create an environment named `pypi` (Settings > Environments).
3. Bump `version` in `pyproject.toml` and `src/aws_readonly_mcp/__init__.py`, then create a GitHub Release.

After that, anyone can run it with `uvx aws-readonly-mcp`.

## Use with Claude Desktop

```json
{
  "mcpServers": {
    "aws-readonly": {
      "command": "/absolute/path/to/.venv/bin/aws-readonly-mcp",
      "env": {
        "AWS_PROFILE": "my-readonly-profile",
        "AWS_MCP_ALLOWED_BUCKETS": "my-data-bucket"
      }
    }
  }
}
```

## Tests

```bash
pytest
```

Tests run against [moto](https://github.com/getmoto/moto), so no AWS account is needed.

## Ideas for next versions

Step Functions and CloudWatch Logs tools, a `--profile` flag, and log rotation.
