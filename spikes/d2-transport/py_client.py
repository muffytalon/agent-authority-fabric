"""MCP Python SDK v2 client over a Unix socket (httpx2 AsyncHTTPTransport(uds=...)).

Usage: py_client.py SOCKET [token]
  token: attach a test Episode Token as the Pep-Episode header on every request (client-wide
         headers) and as _meta["dev.pep-sidecar/episode"] on tools/list and tools/call.
"""
import sys
import anyio, httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

TOKEN = "eyJ.spike.token"   # a placeholder; the stand-in never verifies it

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

anyio.run(main, sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "plain")
