"""AUDITRAIL MCP server — exposes audit operations as MCP tools for Cognis.Studio."""
from __future__ import annotations

import json

from auditrail.core import attest, build_chain, load_events_from_path, verify_chain


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
    def auditrail_attest(path: str) -> str:
        """Load events from a JSONL/JSON file and return an attestation manifest as JSON."""
        try:
            events = load_events_from_path(path)
        except (FileNotFoundError, ValueError, OSError) as exc:
            return json.dumps({"error": str(exc)})
        chain = build_chain(events)
        return json.dumps(attest(chain, source=path))

    @app.tool()
    def auditrail_verify(path: str) -> str:
        """Verify chain integrity for events in a file. Returns JSON with intact/breaks."""
        try:
            events = load_events_from_path(path)
        except (FileNotFoundError, ValueError, OSError) as exc:
            return json.dumps({"error": str(exc)})
        chain = build_chain(events)
        breaks = verify_chain(chain)
        return json.dumps(
            {
                "intact": not breaks,
                "event_count": len(chain),
                "break_count": len(breaks),
                "head": chain.head,
                "breaks": breaks,
            }
        )

    app.run()
    return 0
