// rezimx-btc Agent Games endpoint — Node.js stdlib only.
// Proof Gatekeeper + Steal the VFY (zkVerify Agent Games).
//
// Contract with the platform (from the Agent Games build guide):
//  - The platform POSTs a signed task envelope to this public HTTPS endpoint.
//  - Verify the HMAC signature on the RAW body before doing anything.
//  - Decide and respond within 60 seconds.
//  - Every move/decision carries a Groth16 proof (BN254, Circom 2.x) that the
//    platform re-verifies against ITS OWN registered verification key.
//  - Fail closed: any mismatch -> reject, never guess.
//
// TODO before the arena goes live:
//  - Confirm the exact envelope field names + HMAC header name + signature
//    scheme from the platform build guide (currently read from the
//    registration dashboard after sign-in) and align ENVELOPE below.
//  - Wire real proof generation (snarkjs + circuits/gatekeeper.circom) and
//    attach { proof, publicSignals, vkHash } to every response.
//  - Deploy to a public HTTPS host and set the endpoint URL at registration.

import http from "node:http";
import crypto from "node:crypto";
import { checkGatekeeperTask } from "./policy.mjs";

const PORT = Number(process.env.PORT || 8080);
const HMAC_SECRET = process.env.AGENT_HMAC_SECRET || "";
const DEADLINE_MS = 60_000;

// Idempotency keys seen (in-memory; a match key must never be answered twice).
const seenKeys = new Set();

function hmacHex(rawBody) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(rawBody).digest("hex");
}

function verifySignature(rawBody, signature) {
  if (!HMAC_SECRET || !signature) return false;
  const expected = Buffer.from("sha256=" + hmacHex(rawBody));
  const given = Buffer.from(String(signature));
  return (
    expected.length === given.length && crypto.timingSafeEqual(expected, given)
  );
}

function decideGatekeeper(envelope) {
  // Returns { decision: "approve" | "reject", reason }.
  // The decision must ALSO be proven by the Groth16 circuit: approving a
  // task whose policy check fails is a loss even with a valid proof.
  const check = checkGatekeeperTask(envelope);
  if (!check.ok) return { decision: "reject", reason: check.reason };
  return { decision: "approve", reason: "policy-checks-passed" };
}

function decideSteal(envelope) {
  // 20-turn match, 100 VFY each at start. Policy: never steal on turn 1
  // against an unknown opponent (no read on them yet); steal when ahead on
  // expected value, hold when the opponent just defended (avoid a
  // steal-into-defense waste). Exact tuning lives in the strategy
  // commitment registered with the platform — this stub is the safe
  // default, not the final strategy.
  const { turn = 1, myBalance = 100, oppBalance = 100, oppLastMove = null } = envelope.state || {};
  if (turn === 1) return { decision: "hold", reason: "no-read-yet" };
  if (oppLastMove === "defend") return { decision: "hold", reason: "opp-defended" };
  if (myBalance <= oppBalance) return { decision: "steal", reason: "catch-up" };
  return { decision: "hold", reason: "protect-lead" };
}

const server = http.createServer((req, res) => {
  const started = Date.now();
  if (req.method !== "POST" || req.url !== "/agent") {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "not-found" }));
    return;
  }

  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const rawBody = Buffer.concat(chunks);

    // 1. Signature FIRST — before parsing, before any work.
    const signature =
      req.headers["x-agentgames-signature"] || req.headers["x-signature"] || "";
    if (!verifySignature(rawBody, signature)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "bad-signature" }));
      return;
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "bad-json" }));
      return;
    }

    // 2. Freshness + replay guard. Stale or reused => reject on the spot.
    const now = Math.floor(Date.now() / 1000);
    if (envelope.timestamp && Math.abs(now - envelope.timestamp) > 300) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "stale-envelope" }));
      return;
    }
    if (!envelope.idempotencyKey || seenKeys.has(envelope.idempotencyKey)) {
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "replay-or-missing-key" }));
      return;
    }
    seenKeys.add(envelope.idempotencyKey);

    // 3. Decide by track.
    let out;
    if (envelope.track === "gatekeeper") out = decideGatekeeper(envelope);
    else if (envelope.track === "steal") out = decideSteal(envelope);
    else {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "unknown-track" }));
      return;
    }

    // 4. Respond inside the 60 s deadline.
    const elapsed = Date.now() - started;
    if (elapsed > DEADLINE_MS) {
      res.writeHead(408, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "deadline-exceeded" }));
      return;
    }

    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        agent: "rezimx-btc",
        track: envelope.track,
        matchId: envelope.matchId ?? null,
        turn: envelope.turn ?? null,
        decision: out.decision,
        reason: out.reason,
        // TODO: attach Groth16 proof once circuits are registered:
        // proof: { pi_a, pi_b, pi_c, protocol: "groth16", curve: "bn128" },
        // publicSignals: [...], vkHash: "<registered-vk-hash>"
        proof: null,
        note: "proof pending circuit registration",
      })
    );
  });
});

server.listen(PORT, () =>
  console.log(`rezimx-btc agent listening on :${PORT} (POST /agent)`)
);
