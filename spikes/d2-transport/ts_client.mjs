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
import { readFileSync } from 'node:fs';
// A placeholder the stand-in never verifies. Against the real PEP (real_pep.py) the harness writes a
// real Episode Token to stdin, as it would for an agent (E1); the environment only says where to read it.
const TOKEN = process.env.PEP_TOKEN_FROM_STDIN === '1' ? readFileSync(0, 'utf8').split('\n')[0].trim() : 'eyJ.spike.token';
const REAL = process.env.PEP_REAL === '1';            // the real PEP has no `stale` tool

function makeClient(options, fetchFn, transportOptions = {}) {
  const client = new Client({ name: 'pep-d2-spike', version: '0.0.1' }, options);
  client.onerror = (e) => console.log('  client.onerror:', e?.code ?? e?.name, String(e?.message ?? e).slice(0, 160));
  const transport = new StreamableHTTPClientTransport(new URL('http://pep.local/mcp'), { fetch: fetchFn, ...transportOptions });
  return { client, transport };
}

// The error's cause chain, so a failure deep inside fetch is not reduced to "fetch failed".
function causes(e) {
  const out = [];
  for (let c = e?.cause, depth = 0; c && depth < 5; c = c.cause, depth += 1) out.push(`${c.code ?? c.name}: ${String(c.message).slice(0, 120)}`);
  return out.length ? out.join(' <- ') : 'none';
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
    catch (e) { console.log('global fetch failed:', e?.code ?? e?.name, String(e?.message).slice(0, 200)); console.log('  cause chain:', causes(e)); }
    await client.close().catch(() => {});
    return;
  }
  if (scenario === 'token') {                         // the Episode Token: Pep-Episode header everywhere, _meta where the API allows
    const { client, transport } = makeClient(pin, viaUndici, { requestInit: { headers: { 'Pep-Episode': TOKEN } } });
    const meta = { 'dev.pep-sidecar/episode': TOKEN };
    await client.connect(transport);
    const tools = await client.listTools({ _meta: meta });
    console.log('tools/list:', tools.tools.map((t) => t.name));
    const r = await client.callTool({ name: 'get_invoice', arguments: { invoice_id: 'INV-1' }, _meta: meta });
    console.log('tools/call:', r.content[0].text, 'isError:', r.isError);
    const sub = await client.listen({ toolsListChanged: true });
    console.log('listen closed:', await Promise.race([sub.closed, sleep(5000).then(() => 'still open after 5 s')]));
    await client.close();
    console.log('client closed cleanly');
    return;
  }
  if (scenario === 'enforce-header' || scenario === 'enforce-meta-only') {   // RV4 #11, against the stand-in's `enforce`
    const headers = scenario === 'enforce-header' ? { requestInit: { headers: { 'Pep-Episode': TOKEN } } } : {};
    const meta = { 'dev.pep-sidecar/episode': TOKEN };
    const call = async (label, name, invoice) => {      // a fresh client each time: nothing listed yet
      const { client, transport } = makeClient(pin, viaUndici, headers);
      await client.connect(transport);
      try { const r = await client.callTool({ name, arguments: { invoice_id: invoice }, _meta: meta }); console.log(`${label}: ${r.content[0].text} isError: ${r.isError}`); }
      catch (e) { console.log(`${label} failed:`, e?.code ?? e?.name, String(e?.message).slice(0, 120)); }
      await client.close();
    };
    await call('unlisted call', 'get_invoice', 'INV-1');
    await call('call from a recreated client', 'get_invoice', 'INV-2');
    if (!REAL) await call('stale call (-32020, then re-list and resend)', 'stale', 'INV-3');
    console.log('client closed cleanly');
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
