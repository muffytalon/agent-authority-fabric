// MCP TypeScript SDK v2 client over a Unix socket: a custom fetch with an undici Agent({ connect: { socketPath } }).
// Usage: node ts_client.mjs SOCKET SCENARIO   (run from a directory whose node_modules has the SDK and undici)
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { Agent, fetch as undiciFetch } from 'undici';

const [sock, scenario] = process.argv.slice(2);
const agent = new Agent({ connect: { socketPath: sock } });
const viaUndici = (url, init) => undiciFetch(url, { ...init, dispatcher: agent });
const viaGlobal = (url, init) => globalThis.fetch(url, { ...init, dispatcher: agent });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pin = { versionNegotiation: { mode: { pin: '2026-07-28' } } };

function makeClient(options, fetchFn) {
  const client = new Client({ name: 'pep-d2-spike', version: '0.0.1' }, options);
  client.onerror = (e) => console.log('  client.onerror:', e?.code ?? e?.name, String(e?.message ?? e).slice(0, 160));
  const transport = new StreamableHTTPClientTransport(new URL('http://pep.local/mcp'), { fetch: fetchFn });
  return { client, transport };
}

async function main() {
  if (scenario === 'default') {                       // no versionNegotiation option: the SDK default
    const { client, transport } = makeClient({}, viaUndici);
    try { await client.connect(transport); console.log('connected; version:', client.getNegotiatedProtocolVersion?.()); }
    catch (e) { console.log('connect failed:', e?.code ?? e?.name, String(e?.message).slice(0, 200)); }
    await client.close().catch(() => {});
    return;
  }
  if (scenario === 'global-fetch') {                  // Node's built-in fetch with the undici package's Agent
    const { client, transport } = makeClient(pin, viaGlobal);
    try { await client.connect(transport); const t = await client.listTools(); console.log('global fetch: tools', t.tools.map((x) => x.name)); }
    catch (e) { console.log('global fetch failed:', e?.code ?? e?.name, String(e?.message).slice(0, 200)); }
    await client.close().catch(() => {});
    return;
  }
  if (scenario === 'listchanged') {                   // listChanged configured: does connect auto-open a subscription?
    const { client, transport } = makeClient({ ...pin, listChanged: { tools: { onChanged: () => console.log('  onChanged fired') } } }, viaUndici);
    await client.connect(transport);
    await sleep(1000);
    console.log('autoOpenedSubscription:', client.autoOpenedSubscription === undefined ? 'none' : 'opened');
    await client.close();
    return;
  }
  if (scenario === 'clientclose') {                   // the client closes an open subscription itself
    const { client, transport } = makeClient(pin, viaUndici);
    await client.connect(transport);
    const sub = await client.listen({ toolsListChanged: true });
    console.log('listen acknowledged; closing it from the client');
    await sub.close().then(() => console.log('sub.close() resolved'), (e) => console.log('sub.close() rejected:', e?.code ?? e?.name, e?.message));
    console.log('closed:', await sub.closed);
    await sleep(500);
    const r = await client.callTool({ name: 'get_invoice', arguments: { invoice_id: 'INV-3' } });
    console.log('call after close:', r.content[0].text);
    await client.close();
    console.log('client closed cleanly');
    return;
  }
  // scenario 'main': the full flow
  const { client, transport } = makeClient(pin, viaUndici);
  await client.connect(transport);
  console.log('connected (pinned 2026-07-28)');
  const tools = await client.listTools();
  console.log('tools/list:', tools.tools.map((t) => t.name));
  const r = await client.callTool({ name: 'get_invoice', arguments: { invoice_id: 'INV-1' } });
  console.log('tools/call:', r.content[0].text, 'isError:', r.isError);
  const sub = await client.listen({ toolsListChanged: true });
  console.log('listen acknowledged, honoredFilter:', JSON.stringify(sub.honoredFilter));
  console.log('listen closed:', await Promise.race([sub.closed, sleep(5000).then(() => 'still open after 5 s')]));
  await sleep(2000);                                   // any automatic re-listen would show in the server log
  try { await client.callTool({ name: 'slow', arguments: {} }, { timeout: 1000 }); console.log('slow call returned'); }
  catch (e) { console.log('slow call (1 s timeout):', e?.code ?? e?.name, String(e?.message).slice(0, 120)); }
  await sleep(4000);                                   // let the server finish the slow call and log what arrived
  const after = await client.callTool({ name: 'get_invoice', arguments: { invoice_id: 'INV-2' } });
  console.log('call after the timeout:', after.content[0].text);
  await client.close();
  console.log('client closed cleanly');
}

main().catch((e) => { console.log('FAILED:', e?.code ?? e?.name, e?.message); process.exitCode = 1; }).finally(() => agent.close());
