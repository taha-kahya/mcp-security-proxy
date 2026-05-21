"""
Poisoned web server for indirect prompt injection PoC.

Routes are generated automatically from payloads.py:
  /{payload_name}           visible technique
  /{payload_name}/hidden    CSS display:none
  /{payload_name}/comment   HTML comment
  /{payload_name}/script    <script type="text/plain">

Payloads with a custom "body" key only get a single route (/{name}).

Add new payloads in payloads.py — no changes needed here.

Usage:
    python tests/poc/server.py          # localhost:8888
    python tests/poc/server.py 9000     # custom port
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from payloads import PAYLOADS

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888

_SHARED_BODY = """
<h1>MCP Security Research — Sabanci University</h1>
<p>This page contains background reading for our ongoing study into AI agent
   security in tool-augmented LLM systems (supervisor: Prof. Cemal Yilmaz, 2026).</p>
<p>Topics covered: tool poisoning, rug pulls, prompt injection, credential leakage.</p>
"""

_HIDING_TECHNIQUES: dict[str, str] = {
    "visible": "<p>{text}</p>",
    "hidden":  '<div style="display:none; color:white; font-size:0px;">{text}</div>',
    "comment": "<!-- {text} -->",
    "script":  '<script type="text/plain">{text}</script>',
}


def _page(body: str) -> str:
    return (
        '<!DOCTYPE html><html><head><title>Sabanci AI Security Lab</title></head>'
        f'<body>{body}</body></html>'
    )


def _build_variants() -> dict[str, str]:
    variants: dict[str, str] = {}
    for name, payload in PAYLOADS.items():
        if "body" in payload:
            variants[f"/{name}"] = _page(payload["body"])
        else:
            text = payload["text"]
            for technique, template in _HIDING_TECHNIQUES.items():
                route = f"/{name}" if technique == "visible" else f"/{name}/{technique}"
                variants[route] = _page(_SHARED_BODY + template.format(text=text))
    return variants


VARIANTS = _build_variants()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = VARIANTS.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(f"Unknown route. Valid routes:\n{chr(10).join(VARIANTS)}".encode())
            return
        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        print(f"[server] {self.address_string()} — {fmt % args}")


if __name__ == "__main__":
    routes = "\n".join(f"  http://localhost:{PORT}{path}" for path in VARIANTS)
    print(f"Poisoned server running. Routes:\n{routes}\n")
    HTTPServer(("localhost", PORT), Handler).serve_forever()
