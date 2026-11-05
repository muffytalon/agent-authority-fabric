"""MCP Python SDK v2 client over a Unix socket (httpx2 AsyncHTTPTransport(uds=...)).

Usage: py_client.py SOCKET [token|enforce-header|enforce-meta-only]
  token: attach a test Episode Token as the Pep-Episode header on every request (client-wide
         headers) and as _meta["dev.pep-sidecar/episode"] on tools/list and tools/call.
  enforce-header, enforce-meta-only (RV4 #11, against the stand-in's `enforce` variant): call
         tools without listing them first, from a client recreated mid-episode, and through the
         -32020 re-list path. enforce-header sends the token client-wide as Pep-Episode and in
         _meta on tools/call; enforce-meta-only sends it in _meta only.
"""
import sys
import anyio, httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

import os
# A placeholder the stand-in never verifies. Against the real PEP (real_pep.py) the harness
# writes a real Episode Token to stdin, as it would for an agent (E1); the environment only
# says where to read it.
TOKEN = sys.stdin.readline().strip() if os.environ.get("PEP_TOKEN_FROM_STDIN") == "1" else "eyJ.spike.token"
REAL = os.environ.get("PEP_REAL") == "1"   # the real PEP has no `stale` tool

async def main(sock: str, mode: str) -> None:
    transport = httpx2.AsyncHTTPTransport(uds=sock)
    headers = {"Pep-Episode": TOKEN} if mode == "token" else None
    meta = {"dev.pep-sidecar/episode": TOKEN} if mode == "token" else None
    async with httpx2.AsyncClient(transport=transport, trust_env=False, headers=headers,
                                  timeout=httpx2.Timeout(30.0, read=300.0)) as http:
        async with Client(streamable_http_client("http://pep.local/mcp", http_client=http)) as client:
            print("negotiated:", client.protocol_version)
            tools = await client.list_tools(meta=meta)
            print("tools/list:", [t.name for t in tools.tools])
            r = await client.call_tool("get_invoice", {"invoice_id": "INV-1"}, meta=meta)
            print("tools/call:", r.content[0].text, "isError:", r.is_error)
            async with client.listen(tools_list_changed=True) as sub:
                print("listen acknowledged, honored:", sub.honored.model_dump(exclude_none=True) if sub.honored else sub.honored)
                events = [e async for e in sub]
                print("listen ended gracefully; events:", events)
            await anyio.sleep(2)   # give any automatic re-listen a chance to show up in the server log
    print("client closed cleanly")

async def enforce(sock: str, mode: str) -> None:
    transport = httpx2.AsyncHTTPTransport(uds=sock)
    headers = {"Pep-Episode": TOKEN} if mode == "enforce-header" else None
    meta = {"dev.pep-sidecar/episode": TOKEN}
    async with httpx2.AsyncClient(transport=transport, trust_env=False, headers=headers,
                                  timeout=httpx2.Timeout(30.0, read=300.0)) as http:
        async def call(label: str, name: str, invoice: str) -> None:
            # A fresh Client each time: the first call of a session has never listed the tool.
            async with Client(streamable_http_client("http://pep.local/mcp", http_client=http)) as client:
                try:
                    r = await client.call_tool(name, {"invoice_id": invoice}, meta=meta)
                    print(f"{label}: {r.content[0].text} isError: {r.is_error}")
                except Exception as e:  # report what the agent would see
                    print(f"{label} raised: {type(e).__name__}: {str(e)[:120]}")
        await call("unlisted call", "get_invoice", "INV-1")
        await call("call from a recreated client", "get_invoice", "INV-2")
        if not REAL:
            await call("stale call (-32020, then re-list and resend)", "stale", "INV-3")
    print("client closed cleanly")

if len(sys.argv) > 2 and sys.argv[2].startswith("enforce"):
    anyio.run(enforce, sys.argv[1], sys.argv[2])
else:
    anyio.run(main, sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "plain")
