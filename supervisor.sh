#!/bin/bash
# Supervisor for the Agent Games endpoint (rezimx-btc, Proof Gatekeeper).
# SERVER-ONLY supervision (changed 2026-11-17 23:47 WIB): keeps the node agent
# server on localhost:8080 alive, restarting it within seconds when it dies.
# The TUNNEL is NOT supervised here — the keepalive cron (5-min) owns the
# tunnel, because a tunnel (re)start needs FRESH egress credentials, which a
# long-lived supervisor does not have (stale creds = slots never open).
# Logs: logs/supervisor.log, logs/server.log in this directory.
# Launch once, detached:  setsid nohup bash supervisor.sh >/dev/null 2>&1 &
# On VM restart this supervisor dies with it; the keepalive cron relaunches it
# (see keepalive body step 1). Workspace files survive restarts; /tmp does not.
cd "$(dirname "$0")" || exit 1
export NODE_USE_ENV_PROXY=1
mkdir -p logs
log() { echo "[$(date -Is)] $*" >> logs/supervisor.log; }
log "supervisor started (pid $$) — server-only mode"

server_up() { curl -s --max-time 4 http://localhost:8080/health >/dev/null 2>&1; }

start_server() {
  if ! server_up; then
    log "server down -> starting node src/server.mjs"
    setsid nohup node src/server.mjs >> logs/server.log 2>&1 < /dev/null &
    sleep 3
    if server_up; then log "server up: $(curl -s --max-time 4 http://localhost:8080/health)"; else log "server STILL down after start"; fi
  fi
}

while true; do
  start_server
  # Check the CANONICAL platform URL, never logs/public-url.txt (that file
  # holds whatever random fallback subdomain the tunnel currently has, which
  # is NOT what the platform calls — checking it gave false "200" readings).
  PUBURL="https://agent-games-rezimx.loca.lt"
  pub=$(curl -s --max-time 12 -o /dev/null -w '%{http_code}' "${PUBURL}/health" 2>/dev/null || echo "000")
  log "public ${PUBURL}/health -> $pub"
  sleep 45
done
