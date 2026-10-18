import boto3
import pytest
from moto import mock_aws

from aws_readonly_mcp.guardrails import Config, GuardrailError
from aws_readonly_mcp.tools import AwsReader


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def aws():
    with mock_aws():
        ddb = boto3.resource("dynamodb")
        table = ddb.create_table(
            TableName="orders",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        for i in range(5):
            table.put_item(Item={"pk": "user#1", "sk": f"order#{i}", "total": i * 10})
        table.put_item(Item={"pk": "user#2", "sk": "order#0", "total": 7})

        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="data")
        s3.put_object(Bucket="data", Key="logs/a.txt", Body=b"hello world")
        s3.put_object(Bucket="data", Key="logs/big.txt", Body=b"x" * 500)
        s3.put_object(Bucket="data", Key="img.bin", Body=b"\x00\x01\x02")
        s3.put_object(Bucket="data", Key="top.txt", Body=b"top")
        yield


def reader(**cfg):
    return AwsReader(Config(**cfg))


# ------------------------------------------------------------------ guardrails


def test_writes_are_blocked_on_s3_client(aws):
    r = reader()
    with pytest.raises(GuardrailError, match="PutObject"):
        r._s3.put_object(Bucket="data", Key="evil.txt", Body=b"x")
    with pytest.raises(GuardrailError, match="DeleteObject"):
        r._s3.delete_object(Bucket="data", Key="top.txt")


def test_writes_are_blocked_on_dynamodb_client(aws):
    r = reader()
    with pytest.raises(GuardrailError, match="PutItem"):
        r._ddb.Table("orders").put_item(Item={"pk": "x", "sk": "y"})
    with pytest.raises(GuardrailError, match="DeleteTable"):
        r._ddb_client.delete_table(TableName="orders")


def test_table_and_bucket_allowlists(aws):
    r = reader(allowed_tables=frozenset({"other"}), allowed_buckets=frozenset({"nope"}))
    with pytest.raises(GuardrailError):
        r.dynamodb_describe_table("orders")
    with pytest.raises(GuardrailError):
        r.s3_list_objects("data")
    assert r.dynamodb_list_tables() == {"tables": []}
    assert r.s3_list_buckets() == {"buckets": []}


def test_clamp_items():
    c = Config(max_items=10)
    assert c.clamp_items(None) == 10
    assert c.clamp_items(1000) == 10
    assert c.clamp_items(0) == 1
    assert c.clamp_items(3) == 3


# -------------------------------------------------------------------- dynamodb


def test_list_and_describe(aws):
    r = reader()
    assert r.dynamodb_list_tables() == {"tables": ["orders"]}
    d = r.dynamodb_describe_table("orders")
    assert d["name"] == "orders"
    assert [k["AttributeName"] for k in d["key_schema"]] == ["pk", "sk"]


def test_get_item(aws):
    r = reader()
    hit = r.dynamodb_get_item("orders", {"pk": "user#1", "sk": "order#2"})
    assert hit == {"found": True, "item": {"pk": "user#1", "sk": "order#2", "total": 20}}
    assert r.dynamodb_get_item("orders", {"pk": "nope", "sk": "nope"})["found"] is False


def test_query_with_pagination(aws):
    r = reader(max_items=2)
    args = dict(
        table="orders",
        key_condition_expression="pk = :pk AND begins_with(sk, :p)",
        expression_attribute_values={":pk": "user#1", ":p": "order#"},
    )
    seen, token = [], None
    for _ in range(5):
        page = r.dynamodb_query(**args, next_token=token)
        assert len(page["items"]) <= 2
        seen += [i["sk"] for i in page["items"]]
        token = page["next_token"]
        if not token:
            break
    assert seen == [f"order#{i}" for i in range(5)]


def test_query_numeric_filter_and_reverse(aws):
    r = reader()
    page = r.dynamodb_query(
        "orders",
        "pk = :pk",
        {":pk": "user#1", ":min": 20},
        expression_attribute_names={"#t": "total"},  # 'total' is a DynamoDB reserved word
        filter_expression="#t >= :min",
        scan_index_forward=False,
    )
    assert [i["total"] for i in page["items"]] == [40, 30, 20]


def test_scan_is_capped(aws):
    r = reader(max_items=3)
    page = r.dynamodb_scan("orders", limit=100)
    assert len(page["items"]) == 3
    assert page["next_token"]


def test_scan_with_filter(aws):
    r = reader()
    page = r.dynamodb_scan(
        "orders", "pk = :p", {":p": "user#2"}
    )
    assert [i["sk"] for i in page["items"]] == ["order#0"]


# -------------------------------------------------------------------------- s3


def test_s3_list_buckets_and_objects(aws):
    r = reader()
    assert r.s3_list_buckets() == {"buckets": ["data"]}
    top = r.s3_list_objects("data")
    assert [o["key"] for o in top["objects"]] == ["img.bin", "top.txt"]
    assert top["prefixes"] == ["logs/"]
    logs = r.s3_list_objects("data", prefix="logs/")
    assert [o["key"] for o in logs["objects"]] == ["logs/a.txt", "logs/big.txt"]


def test_s3_list_objects_paginates(aws):
    r = reader(max_items=1)
    first = r.s3_list_objects("data", prefix="logs/")
    assert len(first["objects"]) == 1 and first["next_token"]
    second = r.s3_list_objects("data", prefix="logs/", next_token=first["next_token"])
    assert second["objects"][0]["key"] == "logs/big.txt"


def test_s3_head_object(aws):
    r = reader()
    h = r.s3_head_object("data", "logs/a.txt")
    assert h["size"] == 11


def test_s3_read_object_full_and_truncated(aws):
    r = reader(max_bytes=100)
    full = r.s3_read_object("data", "logs/a.txt")
    assert full["content"] == "hello world" and full["truncated"] is False
    cut = r.s3_read_object("data", "logs/big.txt")
    assert cut["bytes_returned"] == 100
    assert cut["truncated"] is True
    assert cut["size"] == 500


def test_s3_read_object_binary(aws):
    r = reader()
    out = r.s3_read_object("data", "img.bin")
    assert out["binary"] is True and "content" not in out
