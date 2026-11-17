// tunnel-lt.mjs — proxy-aware localtunnel driver (no external dependencies).
// Maintains 2 tunnel slots to localtunnel.me:<port> through the sandbox egress
// proxy (HTTP CONNECT), each bridging raw bytes to the local agent server on
// localhost:8080. No localtunnel library: the data plane is a raw TCP pipe,
// which is all the lt server needs.
// Subdomain: agent-games-rezimx (stable URL). If that subdomain is taken the
// driver falls back to a random name and writes it to logs/public-url.txt.
// Proxy credentials are read from process.env at runtime, never printed.
// Launched by supervisor.sh; logs to stdout (logs/tunnel-lt.log).
process.env.NODE_USE_ENV_PROXY = '1';
import net from 'net';
import fs from 'node:fs';

const LOCAL_PORT = 8080;
const SUBDOMAIN = process.env.LT_SUBDOMAIN || 'agent-games-rezimx';
const SLOTS = 2;
const URL_FILE = new URL('./logs/public-url.txt', import.meta.url).pathname;

const proxyUrl = new URL(process.env.https_proxy || process.env.HTTPS_PROXY || '');
const proxyHost = proxyUrl.hostname;
const proxyPort = Number(proxyUrl.port || 3128);
const proxyAuth = Buffer.from(
  decodeURIComponent(proxyUrl.username) + ':' + decodeURIComponent(proxyUrl.password),
).toString('base64');

const ts = () => new Date().toISOString();
const log = (...a) => console.log(`[${ts()}]`, ...a);

async function getAssignment() {
  const uri = SUBDOMAIN ? `https://localtunnel.me/${SUBDOMAIN}` : 'https://localtunnel.me/?new';
  const res = await fetch(uri);
  if (!res.ok) throw new Error(`assignment HTTP ${res.status}`);
  return res.json(); // {id, port, url, max_conn_count}
}

let info = null;
let failCount = 0;
let refreshing = false;

function writeUrl() {
  try { fs.writeFileSync(URL_FILE, (info?.url || '') + '\n'); } catch (e) { log('cannot write url file:', e.message); }
}

async function refreshAssignment() {
  if (refreshing) return;
  refreshing = true;
  try {
    info = await getAssignment();
    log('assignment: ' + info.url + ' (port ' + info.port + ', id ' + info.id + ')');
    writeUrl();
    failCount = 0;
  } catch (e) {
    log('assignment failed: ' + e.message);
    failCount++;
  } finally { refreshing = false; }
}

function connectSlot(slotIdx) {
  if (!info) { setTimeout(() => connectSlot(slotIdx), 3000); return; }
  const port = info.port;
  const sock = net.connect({ host: proxyHost, port: proxyPort });
  let handshook = false;
  let buf = Buffer.alloc(0);
  let local = null;
  let localReady = false;
  let closed = false;
  const slog = (...a) => log(`[slot${slotIdx}]`, ...a);

  function ensureLocal() {
    if (local && !local.destroyed) return;
    local = net.connect({ host: '127.0.0.1', port: LOCAL_PORT });
    localReady = false;
    local.on('connect', () => { localReady = true; });
    local.on('data', (d) => { if (!sock.destroyed) sock.write(d); });
    local.on('error', (e) => slog('local error ' + e.message));
    local.on('close', () => { localReady = false; local = null; });
  }
  function onTunnelData(chunk) {
    ensureLocal();
    if (localReady) local.write(chunk);
    else if (local) local.once('connect', () => { if (!local.destroyed) local.write(chunk); });
  }
  function teardown(reason) {
    if (closed) return;
    closed = true;
    clearTimeout(hsTimer);
    slog('closed (' + reason + '), reopening in 2s');
    if (local) { try { local.destroy(); } catch {} local = null; }
    setTimeout(() => connectSlot(slotIdx), 2000);
  }

  // Handshake timeout (fix 2026-11-15): the egress proxy sometimes accepts
  // the TCP connection but never answers CONNECT (hangs forever). Without
  // this the slot sits dead with no log line and no retry. Kill it after 10s
  // so the normal 2s reopen loop retries; the watchdog refreshes the
  // assignment after 4 failures.
  const hsTimer = setTimeout(() => {
    if (closed || handshook) return;
    slog('CONNECT timeout (no response in 10s), retrying');
    failCount++;
    sock.destroy();
  }, 10000);

  sock.on('connect', () => {
    sock.write(
      `CONNECT localtunnel.me:${port} HTTP/1.1\r\nHost: localtunnel.me:${port}\r\nProxy-Authorization: Basic ${proxyAuth}\r\n\r\n`,
    );
  });
  sock.on('data', (chunk) => {
    if (!handshook) {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      const head = buf.slice(0, idx).toString();
      if (!/^HTTP\/1\.[01] 200/.test(head)) {
        slog('CONNECT failed: ' + head.split('\r\n')[0]);
        failCount++;
        sock.destroy();
        if (failCount >= 4) refreshAssignment();
        return;
      }
      handshook = true;
      failCount = 0;
      slog('slot OPEN -> ' + info.url);
      const rest = buf.slice(idx + 4);
      if (rest.length) onTunnelData(rest);
      return;
    }
    onTunnelData(chunk);
  });
  sock.on('error', (e) => { slog('socket error ' + e.message); teardown('error'); });
  sock.on('close', () => teardown('close'));
}

async function main() {
  log('tunnel-lt starting, subdomain=' + SUBDOMAIN);
  // Retry loop (fix 2026-11-15): localtunnel.me can 403 the assignment
  // endpoint (egress-proxy IP blocked / LT outage). The old code crashed
  // on the first 403 (res.json() on a "Forbidden" body) so every keepalive
  // restart died in ~1s. Stay alive and retry assignment every 60s so the
  // tunnel self-heals the moment the endpoint answers again.
  while (!info) {
    await refreshAssignment();
    if (!info && SUBDOMAIN) {
      log('requested subdomain unavailable, falling back to random');
      try {
        const res = await fetch('https://localtunnel.me/?new');
        if (!res.ok) { log('random assignment failed: assignment HTTP ' + res.status); }
        else {
          info = await res.json();
          log('assignment (random): ' + info.url + ' (port ' + info.port + ')');
          writeUrl();
        }
      } catch (e) { log('random assignment error: ' + e.message); }
    }
    if (!info) {
      log('no assignment yet, retrying in 60s');
      await new Promise((r) => setTimeout(r, 60000));
    }
  }
  for (let i = 0; i < SLOTS; i++) connectSlot(i);
  // watchdog: if the assignment goes stale (slots keep failing), refresh it
  setInterval(async () => {
    if (failCount >= 4) { await refreshAssignment(); failCount = 0; }
  }, 60000);
}
main();
process.on('SIGTERM', () => { log('SIGTERM, exiting'); process.exit(0); });
