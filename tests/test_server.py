import json

import boto3
import pytest
from moto import mock_aws

from aws_readonly_mcp.guardrails import Config
from aws_readonly_mcp.server import build_server
from aws_readonly_mcp.tools import AwsReader

EXPECTED = {
    "dynamodb_list_tables",
    "dynamodb_describe_table",
    "dynamodb_get_item",
    "dynamodb_query",
    "dynamodb_scan",
    "s3_list_buckets",
    "s3_list_objects",
    "s3_head_object",
    "s3_read_object",
}


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


async def test_all_tools_registered_and_marked_read_only():
    with mock_aws():
        server = build_server(AwsReader(Config()))
        tools = await server.list_tools()
        assert {t.name for t in tools} == EXPECTED
        assert all(t.annotations and t.annotations.read_only_hint for t in tools)


async def test_call_tool_end_to_end():
    with mock_aws():
        boto3.client("s3").create_bucket(Bucket="demo")
        boto3.client("s3").put_object(Bucket="demo", Key="a.txt", Body=b"hi")
        server = build_server(AwsReader(Config()))
        result = await server.call_tool("s3_read_object", {"bucket": "demo", "key": "a.txt"})
        text = json.dumps(result, default=lambda o: getattr(o, "__dict__", str(o)))
        assert "hi" in text
