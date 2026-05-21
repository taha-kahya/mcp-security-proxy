"""
Connects to MCP servers and fetches their tool manifests.
Supports stdio transport (spawn a local server process) and SSE transport (HTTP endpoint).
"""

import json
from pathlib import Path

# Corpus directory relative to the project root (two levels up from this file)
_CORPUS_DIR = Path(__file__).parent.parent.parent / "corpus" / "manifests"


async def collect_stdio(command: list[str]) -> list[dict]:
    """Spawn a server process via stdio transport and return its tool list."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command[0], args=command[1:])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [_tool_to_dict(t) for t in result.tools]


async def collect_sse(url: str) -> list[dict]:
    """Connect to a running MCP server via SSE transport and return its tool list."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [_tool_to_dict(t) for t in result.tools]


def load(path: Path) -> list[dict]:
    """Load a saved manifest from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    # Accept either a raw list or {"tools": [...]} wrapper
    if isinstance(data, list):
        return data
    return data.get("tools", data)


def save(tools: list[dict], name: str) -> Path:
    """Write tools to corpus/manifests/{name}.json and return the path."""
    _CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    path = _CORPUS_DIR / f"{name}.json"
    with open(path, "w") as f:
        json.dump({"server": name, "tools": tools}, f, indent=2)
    return path


def list_saved() -> list[Path]:
    """Return all saved manifest files in the corpus directory."""
    if not _CORPUS_DIR.exists():
        return []
    return sorted(_CORPUS_DIR.glob("*.json"))


def _tool_to_dict(tool) -> dict:
    """Convert an MCP Tool object to a plain dict."""
    try:
        return tool.model_dump()
    except AttributeError:
        return vars(tool)
