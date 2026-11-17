// rezimx-btc Agent Games endpoint — Proof Gatekeeper (zkVerify Agent Games).
// Node.js stdlib + snarkjs (Groth16/BN128, platform-published circuit).
//
// Protocol (agentgames.zkverify.io/build, /events/proof-gatekeeper):
//  - Platform POSTs JSON to the registered public HTTPS path (here: /agent).
//  - Verify HMAC-SHA256 over the RAW body against header
//    x-agent-games-signature BEFORE parsing. Reject on mismatch (401).
//  - Preflight {type:"agent-games.preflight.v1"} -> {ok:true, protocolVersion:"v1"} (signed).
//  - Gatekeeper task {type:"agent-games.proof-gatekeeper.v1"} -> {decision, reason_code,
//    proof, public_signals} (+ proof_tx echo). Proof is generated locally with snarkjs
//    from the platform's gatekeeper.wasm / gatekeeper_final.zkey; if proof generation
//    fails or times out, the decision is still returned WITHOUT proof (a correct
//    decision without a proof scores +12 - 2 = +10; a missing proof never flips a
//    correct decision into a wrong one).
//  - Every 200 response is signed with x-agent-games-signature over the raw body.
//  - 60s hard deadline; fail closed (any doubt -> REJECT, never approve by default).
//
// Decision checks (trap encyclopedia, in canonical order):
//  1. VK_SUBSTITUTION  proof_vk != registered_vk
//  2. THRESHOLD_MISMATCH public_balance < minimum
//  3. PROOF_REUSED      proof_tx already used by a DIFFERENT task
//  4. EXPIRED_CONDITION current_block > expiry_block
//  5. RECIPIENT_MISMATCH recipient != condition_recipient
//  6. AMOUNT_OVERFLOW   amount > max_transfer
//  All pass -> VALID_PROOF / APPROVE.
//
// Proof inputs (recovered by probing the platform wasm — 13 public inputs):
//  decision, minimum, recipient, amount, publicBalance, expiryBlock, currentBlock,
//  conditionRecipient, maxTransfer, taskId, salt, proofVkHash, registeredVkHash.
//  Values are the task's own fields (addresses / vk hashes as BigInt mod p;
//  task_id as its UTF-8 bytes as BigInt mod p; salt = 0). The mapping of
//  task_id / vk hashes to field elements is the agent's best-effort read of the
//  spec — the proof is verified LOCALLY against the platform VK before it is
//  ever attached, so a wrong mapping can only cost the +2 proof bonus, never a
//  correct decision.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkGatekeeperTask } from "./policy.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");

// ---- env: AGENT_GAMES_HMAC_SECRET (dashboard "Rotate Secret"); fallback AGENT_HMAC_SECRET.
function loadDotEnv() {
  const envFile = path.join(ROOT, ".env");
  if (!fs.existsSync(envFile)) return;
  for (const line of fs.readFileSync(envFile, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}
loadDotEnv();
const HMAC_SECRET_HEX = process.env.AGENT_GAMES_HMAC_SECRET || process.env.AGENT_HMAC_SECRET || "";
const HMAC_KEY_BUF = HMAC_SECRET_HEX ? Buffer.from(HMAC_SECRET_HEX, "hex") : Buffer.alloc(0);
const HMAC_KEY_STR = HMAC_SECRET_HEX;
if (!HMAC_SECRET_HEX) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET not set (see .env). Refusing to start.");
  process.exit(1);
}

const PORT = Number(process.env.PORT || 8080);
const DEADLINE_MS = 60_000;
const PROOF_BUDGET_MS = 40_000; // leave headroom for the response inside 60s
const WASM = path.join(ROOT, "circuits", "gatekeeper.wasm");
const ZKEY = path.join(ROOT, "circuits", "gatekeeper_final.zkey");
const VK_JSON = path.join(ROOT, "circuits", "gatekeeper-vk.json");
const SEEN_FILE = path.join(ROOT, "proofs-seen.json");
const MAX_BODY = 1_000_000;

// BN128 field prime (for mapping hashes/addresses to field elements).
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modP = (x) => ((BigInt(x) % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;

// ---- proof_tx reuse set (proof_tx -> first task_id that used it). Persisted.
let seenProofTx = {};
try {
  seenProofTx = JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"));
} catch { seenProofTx = {}; }
let seenDirty = false;
function recordProofTx(proofTx, taskId) {
  if (!proofTx) return;
  if (seenProofTx[proofTx] === undefined) {
    seenProofTx[proofTx] = taskId || "";
    seenDirty = true;
    try { fs.writeFileSync(SEEN_FILE, JSON.stringify(seenProofTx)); seenDirty = false; }
    catch { /* persistence is best-effort; in-memory set still guards this run */ }
  }
}

// ---- HMAC ----
// The platform secret is a 32-byte random shown as hex (64 chars). The spec
// does not say whether the HMAC key is the decoded 32 bytes or the hex string
// itself, so verification accepts EITHER interpretation (an attacker without
// the secret can forge neither). Response signing uses the decoded 32-byte
// key (the secret IS 32 bytes); the verify log records which interpretation
// matched ("how"), so signing can be aligned if the platform's first
// preflight shows it uses the string form.
function hmacHex(rawBody, key) {
  return crypto.createHmac("sha256", key ?? HMAC_KEY_BUF).update(rawBody).digest("hex");
}
function verifySignature(rawBody, header) {
  // Returns "buf" | "str" | null: which key interpretation verified the HMAC.
  if (!header || !HMAC_SECRET_HEX) return null;
  const given = String(header).trim();
  const candidates = given.startsWith("sha256=") ? [given.slice(7), given] : [given, "sha256=" + given];
  for (const c of candidates) {
    for (const [how, key] of [["buf", HMAC_KEY_BUF], ["str", HMAC_KEY_STR]]) {
      const expected = c.startsWith("sha256=") ? "sha256=" + hmacHex(rawBody, key) : hmacHex(rawBody, key);
      const a = Buffer.from(c);
      const b = Buffer.from(expected);
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return how;
    }
  }
  return null;
}

// ---- Groth16 proof (snarkjs), lazy-loaded so a prover failure never kills the server.
let snarkjsPromise = null;
function loadSnarkjs() {
  if (!snarkjsPromise) snarkjsPromise = import("snarkjs").catch(() => null);
  return snarkjsPromise;
}
let vkPromise = null;
function loadVk() {
  if (!vkPromise) {
    vkPromise = (async () => {
      if (fs.existsSync(VK_JSON)) return JSON.parse(fs.readFileSync(VK_JSON, "utf8"));
      const snarkjs = await loadSnarkjs();
      if (!snarkjs) return null;
      const vk = await snarkjs.zkey.exportVerificationKey(ZKEY);
      try { fs.writeFileSync(VK_JSON, JSON.stringify(vk)); } catch { /* best-effort */ }
      return vk;
    })().catch(() => null);
  }
  return vkPromise;
}

// Map the task envelope to the circuit's 13 inputs.
function circuitInput(input, decision) {
  const addr = (a) => modP(BigInt(String(a).toLowerCase()));
  const taskIdBytes = Buffer.from(String(input.task_id ?? ""), "utf8");
  const taskId = taskIdBytes.length ? modP(BigInt("0x" + taskIdBytes.toString("hex"))) : 0n;
  return {
    decision: decision ? 1 : 0,
    minimum: BigInt(input.minimum ?? 0),
    recipient: addr(input.recipient ?? "0x0"),
    amount: BigInt(input.amount ?? 0),
    publicBalance: BigInt(input.public_balance ?? 0),
    expiryBlock: BigInt(input.expiry_block ?? 0),
    currentBlock: BigInt(input.current_block ?? 0),
    conditionRecipient: addr(input.condition_recipient ?? "0x0"),
    maxTransfer: BigInt(input.max_transfer ?? 0),
    taskId,
    salt: 0,
    proofVkHash: modP(String(input.proof_vk ?? "0x0")),
    registeredVkHash: modP(String(input.registered_vk ?? "0x0")),
  };
}

// Returns {proof, publicSignals} or null (never throws). Verifies locally first.
async function generateProof(input, decision, budgetMs) {
  const started = Date.now();
  try {
    const snarkjs = await loadSnarkjs();
    if (!snarkjs) return null;
    const vk = await loadVk();
    if (!vk) return null;
    const circuitIn = circuitInput(input, decision);
    const prove = snarkjs.groth16.fullProve(circuitIn, WASM, ZKEY);
    const timeout = new Promise((resolve) => setTimeout(() => resolve(null), budgetMs));
    const done = await Promise.race([prove.then((r) => ({ ok: true, ...r })), timeout]);
    if (!done || !done.ok) return null;
    if (Date.now() - started > budgetMs) return null;
    const valid = await snarkjs.groth16.verify(vk, done.publicSignals, done.proof);
    if (!valid) return null;
    return { proof: done.proof, publicSignals: done.publicSignals };
  } catch {
    return null;
  }
}

// ---- HTTP ----
// Signs the response with the SAME HMAC key interpretation ("how") that
// verified the inbound request, so the response signature always matches the
// platform's convention, whatever it turns out to be.
function sendSigned(res, status, obj, how) {
  const body = JSON.stringify(obj);
  const key = how === "str" ? HMAC_KEY_STR : HMAC_KEY_BUF;
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(Buffer.from(body, "utf8"), key),
  });
  res.end(body);
}
function sendPlain(res, status, obj) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  const started = Date.now();

  // Health/status probe (GET + HEAD). Unsigned JSON; the signed handshake is the POST preflight.
  // HEAD must answer 200 too — validators/probes use it, and a 404 on HEAD reads as "endpoint down".
  if ((req.method === "GET" || req.method === "HEAD") && (req.url === "/" || req.url === "/agent" || req.url === "/health")) {
    sendPlain(res, 200, {
      ok: true, agent: "rezimx-btc", track: "proof-gatekeeper",
      status: "online", protocolVersion: "v1", uptimeSec: Math.floor(process.uptime()),
    });
    return;
  }

  if (req.method !== "POST" || (req.url !== "/agent" && req.url !== "/")) {
    sendPlain(res, 404, { ok: false, error: "not-found" });
    return;
  }

  const chunks = [];
  let tooBig = false;
  req.on("data", (c) => {
    if (tooBig) return;
    chunks.push(c);
    if (Buffer.concat(chunks).length > MAX_BODY) { tooBig = true; }
  });
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);
    if (tooBig) { sendPlain(res, 413, { ok: false, error: "body-too-large" }); return; }

    // 1. HMAC FIRST — before parsing, before any work.
    const signature = req.headers["x-agent-games-signature"] || "";
    // Log which HMAC key interpretation verified the request ("how": buf|str|
    // none). This reveals the platform's convention on its first signed request.
    const how = verifySignature(rawBody, signature);
    console.log(JSON.stringify({ ts: new Date().toISOString(), event: "post-received", method: req.method, url: req.url, sigPresent: !!signature, sigLen: String(signature).length, how: how || "none", bodyLen: rawBody.length }));
    if (!how) {
      sendPlain(res, 401, { ok: false, error: "bad-signature" });
      return;
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      sendPlain(res, 400, { ok: false, error: "bad-json" });
      return;
    }

    // 2. Preflight handshake.
    if (envelope.type === "agent-games.preflight.v1") {
      sendSigned(res, 200, { ok: true, protocolVersion: "v1" }, how);
      return;
    }

    if (envelope.type !== "agent-games.proof-gatekeeper.v1") {
      sendSigned(res, 400, { ok: false, error: "unknown-type" }, how);
      return;
    }

    // 3. Freshness: reject tasks whose response deadline already passed.
    const nowSec = Math.floor(Date.now() / 1000);
    const deadlineAt = envelope.deadline_at ? Date.parse(envelope.deadline_at) / 1000 : null;
    const input = envelope.input || {};
    let check;
    if (deadlineAt && nowSec > deadlineAt) {
      check = { ok: false, reason: "MISSING_VERIFICATION" };
    } else {
      check = checkGatekeeperTask({ ...envelope, seenProofTx });
    }

    const approve = check.ok;
    const reason = approve ? "VALID_PROOF" : check.reason;
    if (input.proof_tx) recordProofTx(input.proof_tx, envelope.task_id);

    // 4. Proof (best-effort, inside the deadline). PROOF_REUSED has no proof to submit.
    let proof = null;
    let publicSignals = null;
    const budgetLeft = Math.max(5000, PROOF_BUDGET_MS - (Date.now() - started));
    if (reason !== "PROOF_REUSED") {
      const gen = await generateProof(input, approve, budgetLeft);
      if (gen) { proof = gen.proof; publicSignals = gen.publicSignals; }
    }

    // 5. Respond inside the 60s deadline.
    if (Date.now() - started > DEADLINE_MS - 1000) {
      sendSigned(res, 200, { decision: "REJECT", reason_code: "MISSING_VERIFICATION", proof_tx: input.proof_tx || null }, how);
      return;
    }

    const out = { decision: approve ? "APPROVE" : "REJECT", reason_code: reason, proof_tx: input.proof_tx || null };
    if (proof) { out.proof = proof; out.public_signals = publicSignals; }
    sendSigned(res, 200, out, how);
    console.log(JSON.stringify({
      ts: new Date().toISOString(), task: envelope.task_id || null,
      decision: out.decision, reason_code: reason, proof: proof ? "attached" : "none",
      ms: Date.now() - started,
    }));
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`rezimx-btc agent listening on 0.0.0.0:${PORT} (POST /agent, GET /health)`);
});
