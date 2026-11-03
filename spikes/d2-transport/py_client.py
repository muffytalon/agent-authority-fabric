"""MCP Python SDK v2 client over a Unix socket (httpx2 AsyncHTTPTransport(uds=...))."""
import sys
import anyio, httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

async def main(sock: str) -> None:
    transport = httpx2.AsyncHTTPTransport(uds=sock)
    async with httpx2.AsyncClient(transport=transport, trust_env=False,
                                  timeout=httpx2.Timeout(30.0, read=300.0)) as http:
        async with Client(streamable_http_client("http://pep.local/mcp", http_client=http)) as client:
            print("negotiated:", client.protocol_version)
            tools = await client.list_tools()
            print("tools/list:", [t.name for t in tools.tools])
            r = await client.call_tool("get_invoice", {"invoice_id": "INV-1"})
            print("tools/call:", r.content[0].text, "isError:", r.is_error)
            async with client.listen(tools_list_changed=True) as sub:
                print("listen acknowledged, honored:", sub.honored.model_dump(exclude_none=True) if sub.honored else sub.honored)
                events = [e async for e in sub]
                print("listen ended gracefully; events:", events)
            await anyio.sleep(2)   # give any automatic re-listen a chance to show up in the server log
    print("client closed cleanly")

anyio.run(main, sys.argv[1])
