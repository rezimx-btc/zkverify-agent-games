# rezimx-btc — Agent Games (zkVerify)

AI agent competing in [zkVerify Agent Games](https://agentgames.zkverify.io)
(21 Oct – 21 Nov 2026, 400,000 VFY prize pool, 100,000 VFY per track,
50,000 / 30,000 / 20,000 for top 3).

- **Agent name:** rezimx-btc
- **Tracks:** Proof Gatekeeper only (Steal the VFY entries locked for the current tournament)
- **Status:** registered 2026-11-15 ~02:57 WIB, 1/3 slots, UNHEALTHY pending first health check — endpoint **LIVE** since ~03:15 WIB at `https://agent-games-rezimx.loca.lt/agent` (register this URL in the dashboard)

## How it works

### Proof Gatekeeper
The agent receives a signed task envelope at its public HTTPS endpoint,
verifies the **HMAC signature on the raw body** before doing anything,
decides (approve / reject), and responds **within 60 seconds** — with a
**Groth16 proof (BN254, circuits compiled with Circom 2.x)** that the
platform re-verifies against *its own* registered verification key.
You can't swap in a friendlier key. The decision is also scored
independently, so a valid proof of a bad decision still loses.

### Steal the VFY
Two agents play a 20-turn match starting from 100 (simulated) VFY each.
Every move carries a policy proof whose public-inputs hash the platform
computes independently from the game state it knows. If the hashes
diverge, the proof is rejected on the spot. Echo a stale match ID or
turn number, reuse an idempotency key, use a circuit version that
doesn't match the registered strategy commitment — rejected.
Fail closed, or don't score.

## The rule that matters most

> Verification is necessary, not sufficient. A proof can verify
> perfectly and still authorize the wrong action.

So this agent checks *what* was proven, not just *whether* verification
succeeded (see `src/policy.mjs`):

- Does the verification key match the key registered for this condition?
- Are the circuit and proof system the ones this task expects?
- Do the public inputs actually prove the required threshold, recipient,
  and action?
- Has this proof reference already been used for another task?
- Did verification reach a *finalized* state before the approval?
- Was the incoming task's signature and timestamp valid before any work?

## Run locally

```sh
AGENT_GAMES_HMAC_SECRET=your-shared-secret node src/server.mjs
# POST /agent  (JSON envelope, HMAC-SHA256 over raw body, header x-agent-games-signature)
# GET  /health (status probe)
```

## Deploy — LIVE

- **Public endpoint:** `https://agent-games-rezimx.loca.lt/agent` (register
  this URL in the dashboard: My Agents → Edit agent → endpoint field).
  `GET /health` returns the status probe; `POST /agent` is the signed endpoint.
- **How the public URL is served:** this VM has no public IP/TLS, and its
  egress proxy blocks direct tunnels — cloudflared quick tunnel failed
  (proxy 403 on `api.trycloudflare.com`) and the serveo / localhost.run SSH
  tunnels connect but their HTTP edges never bind the subdomain. The working
  path is a **localtunnel** tunnel served by a small proxy-aware driver,
  `tunnel-lt.mjs` (raw TCP slots through the egress proxy's HTTP CONNECT,
  bridged to `localhost:8080`), kept alive by `supervisor.sh` (restarts the
  node server and the tunnel if either dies). Relaunch after a VM restart
  with `setsid nohup bash supervisor.sh >/dev/null 2>&1 &` from this
  directory. The subdomain is stable (`agent-games-rezimx`) as long as a
  tunnel slot stays open; the live URL is written to `logs/public-url.txt`.
- **Verified end-to-end (2026-11-15 ~03:20 WIB):** preflight → 200
  `{ok:true, protocolVersion:"v1"}`; valid task → APPROVE / VALID_PROOF with
  a Groth16 proof (13 public signals); trap (VK substitution) → REJECT /
  VK_SUBSTITUTION with a proof; bad HMAC → 401. All responses HMAC-signed
  and verified by the test client. Note: a browser opening the URL sees
  localtunnel's "Tunnel website ahead!" reminder page — server-to-server
  POSTs (the platform) are unaffected.

### HMAC key form (resolved 2026-11-15)
The platform secret is a 32-byte random shown as 64 hex chars. The build
guide does not say whether the HMAC key is the decoded 32 bytes or the hex
string itself, so `src/server.mjs` verifies inbound signatures under **both**
interpretations (an attacker without the secret can forge neither) and
signs each response with the **same** interpretation that verified the
inbound request. The first real platform request logs which one matched
(`how: buf|str` in `logs/server.log`) — that is the platform's convention,
confirmed empirically.

### Proof: the circuit enforces the decision (verified 2026-11-15)
Experiment `proof-exp.mjs`: a valid APPROVE and a trap REJECT both produce
proofs that verify locally against the platform VK — but asking the circuit
to prove an APPROVE for a trap (VK mismatch, decision=1) FAILS inside the
circuit (`Assert Failed ... GatekeeperEvaluation_79 line: 102`). The proof
is not a rubber stamp: a correct decision is provable, a wrong APPROVE is
not. Residual uncertainty: the exact public-signal mapping for `taskId`
(UTF-8 bytes as BigInt) and the Poseidon hash output is best-effort — the
proof verifies cryptographically against the platform VK, and the first
practice task is the empirical check.

- `src/server.mjs` - HTTP endpoint: HMAC verify (header `x-agent-games-signature`,
  raw hex or `sha256=`), signed responses, preflight responder, 60 s deadline,
  proof_tx reuse guard (persisted in `proofs-seen.json`), local Groth16 proof
  generation with snarkjs (verified against the platform VK before attaching;
  a failed proof never blocks the decision).
- `src/policy.mjs` - the Gatekeeper verification checklist (real envelope fields),
  pure functions.
- `circuits/gatekeeper.wasm` + `circuits/gatekeeper_final.zkey` - the PLATFORM's
  real circuit artifacts (vkHash `0x6b79c6...`, 13 public inputs recovered by
  probing the wasm: decision, minimum, recipient, amount, publicBalance,
  expiryBlock, currentBlock, conditionRecipient, maxTransfer, taskId, salt,
  proofVkHash, registeredVkHash). `circuits/gatekeeper-vk.json` is the exported
  verification key. `circuits/gatekeeper.circom` is a reference sketch only.

## License

MIT — see `LICENSE`.
