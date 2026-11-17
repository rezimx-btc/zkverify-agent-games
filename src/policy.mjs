// Gatekeeper verification checklist — pure functions, no I/O.
// "Verification is necessary, not sufficient": a proof can verify perfectly
// and still authorize the wrong action. Every check below must pass before
// this agent approves anything.
//
// Operates on the REAL platform envelope (agentgames.zkverify.io/build):
//   envelope.input = { registered_vk, proof_vk, minimum, public_balance,
//                      expiry_block, current_block, recipient,
//                      condition_recipient, amount, max_transfer, proof_tx }
// Checks run in the platform's canonical trap order so the returned
// reason_code names the trap the platform injected.
// PROOF_REUSED needs the agent's seen set (proof_tx -> first task_id);
// a retry of the SAME task_id is not reuse.

export function checkGatekeeperTask(envelope) {
  const input = envelope.input || {};
  const seenProofTx = envelope.seenProofTx || {};

  const has = (...fields) => fields.every((f) => input[f] !== undefined && input[f] !== null && input[f] !== "");
  const toBig = (v) => {
    try { return BigInt(v); } catch { return null; }
  };

  // 0. Malformed envelope: cannot verify anything -> reject, fail closed.
  if (!has("registered_vk", "proof_vk", "minimum", "public_balance", "expiry_block",
           "current_block", "recipient", "condition_recipient", "amount", "max_transfer")) {
    return { ok: false, reason: "PROOF_INVALID" };
  }
  const minimum = toBig(input.minimum);
  const publicBalance = toBig(input.public_balance);
  const amount = toBig(input.amount);
  const maxTransfer = toBig(input.max_transfer);
  const expiryBlock = toBig(input.expiry_block);
  const currentBlock = toBig(input.current_block);
  if ([minimum, publicBalance, amount, maxTransfer, expiryBlock, currentBlock].some((v) => v === null)) {
    return { ok: false, reason: "PROOF_INVALID" };
  }

  // 1. Verification key must match the key registered for this condition.
  if (String(input.proof_vk).toLowerCase() !== String(input.registered_vk).toLowerCase()) {
    return { ok: false, reason: "VK_SUBSTITUTION" };
  }

  // 2. Public balance in the proof must meet the condition's minimum.
  if (publicBalance < minimum) {
    return { ok: false, reason: "THRESHOLD_MISMATCH" };
  }

  // 3. This proof reference must not have been used by a DIFFERENT task.
  if (input.proof_tx) {
    const firstTask = seenProofTx[input.proof_tx];
    if (firstTask !== undefined && firstTask !== "" && firstTask !== envelope.task_id) {
      return { ok: false, reason: "PROOF_REUSED" };
    }
  }

  // 4. The condition's block-height expiry must not have passed.
  if (currentBlock > expiryBlock) {
    return { ok: false, reason: "EXPIRED_CONDITION" };
  }

  // 5. The recipient committed in the proof must match the condition address.
  if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase()) {
    return { ok: false, reason: "RECIPIENT_MISMATCH" };
  }

  // 6. The requested amount must not exceed the single-transfer cap.
  if (amount > maxTransfer) {
    return { ok: false, reason: "AMOUNT_OVERFLOW" };
  }

  return { ok: true };
}
