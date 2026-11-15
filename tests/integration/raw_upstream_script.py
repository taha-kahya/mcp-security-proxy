"""A raw JSON-RPC stdio server with a fixed tool listing.

It writes JSON text directly, so the key order of every tool definition is
exactly what is written here and no SDK server normalizes it. Tools are
deliberately not in alphabetical order, and one carries a top-level field the
MCP spec does not define.
"""

import json
import sys

# Written as JSON text, not built from dicts, to pin the key order on the wire.
TOOLS_JSON = (
    '[{"name":"zeta","description":"second letter last","inputSchema":{"type":"object",'
    '"properties":{"query":{"type":"string","description":"q"},'
    '"options":{"type":"object","properties":{"limit":{"type":"integer"},'
    '"cursor":{"type":"string"}},"additionalProperties":false}},'
    '"required":["query"],"additionalProperties":false},'
    '"annotations":{"readOnlyHint":true,"title":"Zeta"},'
    '"vendorField":{"z":1,"a":2},"_meta":{"b":1,"a":2}},'
    '{"name":"alpha","description":"listed after zeta","inputSchema":{"type":"object",'
    '"additionalProperties":false,"required":[],"properties":{}}}]'
)


def main() -> None:
    for line in sys.stdin:
        message = json.loads(line)
        if "id" not in message:
            continue
        method = message["method"]
        if method == "initialize":
            version = json.dumps(message["params"]["protocolVersion"])
            result = (
                f'{{"protocolVersion":{version},"capabilities":{{"tools":{{}}}},'
                '"serverInfo":{"name":"Raw","version":"1"}}'
            )
        elif method == "tools/list":
            result = f'{{"tools":{TOOLS_JSON}}}'
        elif method == "tools/call":
            text = json.dumps(message["params"]["name"])
            result = f'{{"content":[{{"type":"text","text":{text}}}]}}'
        else:
            result = "{}"
        request_id = json.dumps(message["id"])
        sys.stdout.write(f'{{"jsonrpc":"2.0","id":{request_id},"result":{result}}}\n')
        sys.stdout.flush()


if __name__ == "__main__":
    main()
