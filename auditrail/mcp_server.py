"""AUDITRAIL MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from auditrail.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-auditrail[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-auditrail[mcp]'")
        return 1
    app = FastMCP("auditrail")

    @app.tool()
    def auditrail_scan(target: str) -> str:
        """Tamper-evident audit-log aggregator with hash-chained attestation. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
