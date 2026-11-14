pragma circom 2.0.0;

// Gatekeeper decision circuit — DRAFT.
// Proves: the agent approves (decision = 1) ONLY when the policy check
// passed (policyOk = 1), and rejects (decision = 0) otherwise.
// The platform re-verifies this proof against ITS OWN registered VK —
// the VK registered at sign-up must be generated from THIS circuit.
//
// !!! DO NOT register this VK yet. !!!
// The exact public-input layout (which fields, which order, how the
// public-inputs hash is computed) must be aligned with the platform build
// guide first. A proof with the wrong public-input spec is rejected even
// if the circuit is correct.

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
