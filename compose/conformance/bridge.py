"""A test-only bridge from TCP to the PEP's agent socket, for the MCP conformance suite (step 9,
RV3 D5). The suite speaks HTTP to a URL and knows nothing of Episode Tokens, so this listens on a
port, and adds the token a pinned SDK would send to `tools/list` and `tools/call`. It also spaces
out those calls, because the suite sends them faster than the episode's rate limit (U1 step 15)
and would otherwise test only that. It changes nothing else, so the PEP answers the suite's
requests as it would any agent's.

The token arrives on stdin (E1), and this runs only in a throwaway container, as the agent's uid.
"""
import asyncio, json, sys

SOCKET = "/run/pep/agent.sock"
PORT = 8080
EPISODE_KEY = "dev.pep-sidecar/episode"
NEEDS_TOKEN = {"tools/list", "tools/call"}
SPACING_S = 0.15             # config/pep's limit is 10 a second, with a burst of 20


def with_token(body, token):
    """The body, and whether it took the token."""
    try:
        message = json.loads(body)
    except ValueError:
        return body, False
    if not isinstance(message, dict) or message.get("method") not in NEEDS_TOKEN:
        return body, False
    params = message.setdefault("params", {})
    params.setdefault("_meta", {})[EPISODE_KEY] = token
    return json.dumps(message, separators=(",", ":")).encode(), True


async def serve(reader, writer, token, spacing):
    try:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        request_line, fields = lines[0], [line for line in lines[1:] if line]
        length = next((int(field.split(":", 1)[1]) for field in fields if field.lower().startswith("content-length:")), 0)
        body, took = with_token(await reader.readexactly(length), token)
        kept = [field for field in fields if not field.lower().startswith(("content-length:", "connection:"))]
        if took:
            kept.append(f"Pep-Episode: {token}")
            async with spacing:
                await asyncio.sleep(SPACING_S)
        kept += [f"Content-Length: {len(body)}", "Connection: close"]
        upstream_reader, upstream_writer = await asyncio.open_unix_connection(SOCKET)
        upstream_writer.write(("\r\n".join([request_line, *kept]) + "\r\n\r\n").encode("latin-1") + body)
        await upstream_writer.drain()
        while chunk := await upstream_reader.read(65536):
            writer.write(chunk)
            await writer.drain()
        upstream_writer.close()
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        writer.close()


async def main():
    token = sys.stdin.readline().strip()
    spacing = asyncio.Lock()
    server = await asyncio.start_server(lambda r, w: serve(r, w, token, spacing), "0.0.0.0", PORT)
    print("bridge: serving", flush=True)
    async with server:
        await server.serve_forever()


asyncio.run(main())
