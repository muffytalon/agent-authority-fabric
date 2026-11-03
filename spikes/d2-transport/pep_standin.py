"""Test-only stand-in for the PEP's agent-facing MCP endpoint (WEEK2_PLAN M1 router) on a Unix socket.

Usage: pep_standin.py SOCKET LOGFILE [plain|cancelled|hold] [202|400]
  plain:     subscriptions/listen -> acknowledged (empty filter), then the completion result.
  hold:      acknowledged, then the completion result only after 5 s.
  cancelled: the same, with notifications/cancelled sent between the two (the spec's ambiguity).
  202|400:   the status for notification POSTs (the plan's U1 says 400).
The tool `slow` answers after 3 s, to provoke a client-side timeout.
It logs every request and the M1 header/_meta checks, but answers regardless, to observe client behaviour.
"""
import json, socketserver, sys, time
from http.server import BaseHTTPRequestHandler

SOCK, LOGFILE = sys.argv[1], sys.argv[2]
VARIANT = sys.argv[3] if len(sys.argv) > 3 else "plain"
NOTIFY_STATUS = int(sys.argv[4]) if len(sys.argv) > 4 else 202
LOG = open(LOGFILE, "a", buffering=1)
TOOL = {"name": "get_invoice", "description": "Look up an invoice.",
        "inputSchema": {"type": "object", "properties": {"invoice_id": {"type": "string"}},
                        "required": ["invoice_id"], "additionalProperties": False}}

def log(**kv):
    LOG.write(json.dumps(kv) + "\n")

def sse(obj):
    return b"event: message\ndata: " + json.dumps(obj).encode() + b"\n\n"

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def address_string(self):
        return "unix"

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body=b"", ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _legacy(self):
        log(kind="http", verb=self.command, headers={k.lower(): v for k, v in self.headers.items()})
        self._send(405)

    do_GET = do_DELETE = _legacy

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        msg = json.loads(raw)
        method, rid = msg.get("method"), msg.get("id")
        hdr = {k.lower(): v for k, v in self.headers.items()}
        log(kind="request", method=method, id=rid, headers=hdr, params=msg.get("params"))
        if "id" not in msg:                                   # a notification
            self._send(NOTIFY_STATUS)
            return
        params = msg.get("params") or {}
        meta = params.get("_meta") or {}
        problems = []
        if "mcp-protocol-version" not in hdr:
            problems.append("no MCP-Protocol-Version header")
        if hdr.get("mcp-method") != method:
            problems.append(f"Mcp-Method {hdr.get('mcp-method')!r} != body {method!r}")
        if method == "tools/call" and hdr.get("mcp-name") != params.get("name"):
            problems.append(f"Mcp-Name {hdr.get('mcp-name')!r} != body {params.get('name')!r}")
        accept = hdr.get("accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            problems.append(f"Accept {accept!r}")
        if meta.get("io.modelcontextprotocol/protocolVersion") != "2026-07-28":
            problems.append(f"_meta protocolVersion {meta.get('io.modelcontextprotocol/protocolVersion')!r}")
        if not isinstance(meta.get("io.modelcontextprotocol/clientCapabilities"), dict):
            problems.append("_meta clientCapabilities missing or not an object")
        if hdr.get("mcp-protocol-version") not in (None, meta.get("io.modelcontextprotocol/protocolVersion")):
            problems.append("MCP-Protocol-Version header differs from _meta")
        if problems:
            log(kind="m1-check", method=method, problems=problems)

        if method == "subscriptions/listen":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            sid = {"io.modelcontextprotocol/subscriptionId": rid}
            self.wfile.write(sse({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
                                  "params": {"_meta": sid, "notifications": {}}}))
            self.wfile.flush()
            time.sleep(5 if VARIANT == "hold" else 0.3)
            if VARIANT == "cancelled":
                self.wfile.write(sse({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                      "params": {"requestId": rid, "reason": "server closed the subscription"}}))
                self.wfile.flush()
            try:
                self.wfile.write(sse({"jsonrpc": "2.0", "id": rid,
                                      "result": {"resultType": "complete", "_meta": sid}}))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                log(kind="client-gone", method=method, id=rid)
            self.close_connection = True
            log(kind="listen-served", id=rid, variant=VARIANT)
            return

        if method == "server/discover":
            result = {"resultType": "complete", "supportedVersions": ["2026-07-28"],
                      "capabilities": {"tools": {}}, "ttlMs": 0, "cacheScope": "public"}
        elif method == "tools/list":
            result = {"resultType": "complete", "tools": [TOOL], "ttlMs": 0, "cacheScope": "private"}
        elif method == "tools/call" and params.get("name") == "slow":
            time.sleep(3)
            result = {"resultType": "complete", "isError": False, "content": [{"type": "text", "text": "slow done"}]}
        elif method == "tools/call":
            result = {"resultType": "complete", "isError": False,
                      "content": [{"type": "text", "text": f"invoice {params.get('arguments', {}).get('invoice_id')}"}]}
        else:
            self._send(404, json.dumps({"jsonrpc": "2.0", "id": rid,
                                        "error": {"code": -32601, "message": "Method not found"}}).encode())
            return
        try:
            self._send(200, json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode())
        except (BrokenPipeError, ConnectionResetError):
            log(kind="client-gone", method=method, id=rid)

class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

with Server(SOCK, Handler) as srv:
    print("LISTENING", flush=True)
    srv.serve_forever()
