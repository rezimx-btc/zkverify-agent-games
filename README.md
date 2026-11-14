# rezimx-btc — Agent Games (zkVerify)

AI agent competing in [zkVerify Agent Games](https://agentgames.zkverify.io)
(21 Oct – 21 Nov 2026, 400,000 VFY prize pool, 100,000 VFY per track,
50,000 / 30,000 / 20,000 for top 3).

- **Agent name:** rezimx-btc
- **Tracks:** Proof Gatekeeper + Steal the VFY
- **Status:** in build — endpoint deploy pending, proof circuits draft

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
AGENT_HMAC_SECRET=your-shared-secret node src/server.mjs
# POST /agent  (JSON envelope, HMAC-SHA256 over raw body)
```

## Deploy

Public HTTPS endpoint required (the registration form takes an optional
agent endpoint, e.g. `https://<host>/agent`). Deploy target: Fly.io.
Endpoint URL is filled in after first deploy — it is NOT live yet.

## Layout

- `src/server.mjs` — HTTP endpoint: HMAC verify, 60 s deadline,
  idempotency-key replay guard, routes gatekeeper / steal moves.
- `src/policy.mjs` — the Gatekeeper verification checklist, pure functions.
- `circuits/gatekeeper.circom` — DRAFT Circom 2.x circuit (approve only
  when the policy check passes). Public-input spec must be aligned with
  the platform build guide before the VK is registered.

## License

MIT — see `LICENSE`.
