// Gatekeeper verification checklist — pure functions, no I/O.
// "Verification is necessary, not sufficient": a proof can verify perfectly
// and still authorize the wrong action. Every check below must pass before
// this agent approves anything.
//
// Envelope fields are the platform's task envelope. Field names marked
// TODO must be aligned with the build guide once the exact spec is read
// from the registration dashboard.

export function checkGatekeeperTask(envelope) {
  const task = envelope.task || {};

  // 1. Verification key must match the key registered for this condition.
  if (!task.vkHash || task.vkHash !== task.expectedVkHash) {
    return { ok: false, reason: "vk-mismatch" };
  }

  // 2. Circuit + proof system must be the ones this task expects.
  //    Gatekeeper: Groth16, BN254, Circom 2.x.
  if (task.proofSystem !== "groth16" || task.curve !== "bn128") {
    return { ok: false, reason: "wrong-proof-system" };
  }
  if (task.circuitVersion !== task.expectedCircuitVersion) {
    return { ok: false, reason: "circuit-version-mismatch" };
  }

  // 3. Public inputs must prove the required threshold, recipient, action.
  const pi = task.publicInputs || {};
  if (typeof pi.thresholdMet !== "boolean" || !pi.thresholdMet) {
    return { ok: false, reason: "threshold-not-met" };
  }
  if (!pi.recipient || pi.recipient !== task.expectedRecipient) {
    return { ok: false, reason: "recipient-mismatch" };
  }
  if (!pi.action || pi.action !== task.expectedAction) {
    return { ok: false, reason: "action-mismatch" };
  }

  // 4. This proof reference must not have been used for another task.
  if (!task.proofRef || task.proofRefUsed === true) {
    return { ok: false, reason: "proof-ref-reused-or-missing" };
  }

  // 5. Verification must have reached a FINALIZED state first.
  if (task.verificationStatus !== "finalized") {
    return { ok: false, reason: "verification-not-finalized" };
  }

  // 6. Incoming signature + timestamp were already validated by the server
  //    (HMAC on raw body + freshness window) before this function runs.
  return { ok: true };
}
