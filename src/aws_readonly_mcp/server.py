"""MCP server entry point. Registers the AwsReader methods as read-only tools."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .tools import AwsReader

INSTRUCTIONS = """\
Read-only access to AWS DynamoDB and S3. Nothing here can modify data.
Results are capped (items and bytes); when a result includes next_token, pass it back
to fetch the next page. Prefer query over scan, and describe a table before querying.
"""

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)


def build_server(reader: AwsReader | None = None) -> MCPServer:
    mcp = MCPServer("aws-readonly", instructions=INSTRUCTIONS)
    r = reader or AwsReader()

    @mcp.tool(annotations=READ_ONLY)
    def dynamodb_list_tables() -> dict:
        """List DynamoDB tables visible to this server."""
        return r.dynamodb_list_tables()

    @mcp.tool(annotations=READ_ONLY)
    def dynamodb_describe_table(table: str) -> dict:
        """Describe a table: key schema, indexes, approximate size and item count."""
        return r.dynamodb_describe_table(table)

    @mcp.tool(annotations=READ_ONLY)
    def dynamodb_get_item(table: str, key: dict[str, Any]) -> dict:
        """Fetch one item by its full primary key, e.g. {"pk": "user#1", "sk": "profile"}."""
        return r.dynamodb_get_item(table, key)

    @mcp.tool(annotations=READ_ONLY)
    def dynamodb_query(
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
        """Query a table or index by key condition, e.g. "pk = :pk AND begins_with(sk, :p)"
        with values {":pk": "user#1", ":p": "order#"}. Paginated and capped."""
        return r.dynamodb_query(
            table,
            key_condition_expression,
            expression_attribute_values,
            expression_attribute_names,
            filter_expression,
            index_name,
            scan_index_forward,
            limit,
            next_token,
        )

    @mcp.tool(annotations=READ_ONLY)
    def dynamodb_scan(
        table: str,
        filter_expression: str | None = None,
        expression_attribute_values: dict[str, Any] | None = None,
        expression_attribute_names: dict[str, str] | None = None,
        index_name: str | None = None,
        limit: int | None = None,
        next_token: str | None = None,
    ) -> dict:
        """Scan a table (reads every item it visits; prefer query). Paginated and capped."""
        return r.dynamodb_scan(
            table,
            filter_expression,
            expression_attribute_values,
            expression_attribute_names,
            index_name,
            limit,
            next_token,
        )

    @mcp.tool(annotations=READ_ONLY)
    def s3_list_buckets() -> dict:
        """List S3 buckets visible to this server."""
        return r.s3_list_buckets()

    @mcp.tool(annotations=READ_ONLY)
    def s3_list_objects(
        bucket: str,
        prefix: str = "",
        delimiter: str | None = "/",
        limit: int | None = None,
        next_token: str | None = None,
    ) -> dict:
        """List objects and 'folders' under a prefix. Paginated and capped."""
        return r.s3_list_objects(bucket, prefix, delimiter, limit, next_token)

    @mcp.tool(annotations=READ_ONLY)
    def s3_head_object(bucket: str, key: str) -> dict:
        """Get an object's size, type, modified time, ETag and user metadata."""
        return r.s3_head_object(bucket, key)

    @mcp.tool(annotations=READ_ONLY)
    def s3_read_object(bucket: str, key: str, max_bytes: int | None = None) -> dict:
        """Read the start of a text object (capped; binary content is not returned)."""
        return r.s3_read_object(bucket, key, max_bytes)

    return mcp


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
