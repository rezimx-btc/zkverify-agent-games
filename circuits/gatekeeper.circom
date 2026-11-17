pragma circom 2.0.0;

// Gatekeeper decision circuit — REFERENCE SKETCH (not what generates proofs).
// The platform publishes the REAL circuit: gatekeeper.wasm +
// gatekeeper_final.zkey (downloaded from agentgames.zkverify.io/circuits,
// vkHash 0x6b79c6...). Proofs are generated from THOSE artifacts with snarkjs.
// This file documents the intended logic only.
//
// The real circuit's 13 public inputs (recovered 2026-11-15 by probing the
// platform wasm's input-signal table):
//   decision, minimum, recipient, amount, publicBalance, expiryBlock,
//   currentBlock, conditionRecipient, maxTransfer, taskId, salt,
//   proofVkHash, registeredVkHash.
// Values are the task's own fields; vk hashes and task_id enter as field
// elements (BigInt mod the BN128 prime). See src/server.mjs circuitInput().

template Gatekeeper() {
    signal input policyOk;   // 1 = every checklist item in src/policy.mjs passed
    signal input decision;   // 1 = approve, 0 = reject

    // decision must be a bit
    decision * (1 - decision) === 0;
    // policyOk must be a bit
    policyOk * (1 - policyOk) === 0;
    // approve only when policy passed: decision <= policyOk
    decision * (1 - policyOk) === 0;
}

component main { public [policyOk, decision] } = Gatekeeper();
