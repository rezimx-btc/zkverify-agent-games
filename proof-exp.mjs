import * as snarkjs from "snarkjs";
import fs from "node:fs";
const WASM = process.env.HOME + "/workspace/agent-games-zkverify/circuits/gatekeeper.wasm";
const ZKEY = process.env.HOME + "/workspace/agent-games-zkverify/circuits/gatekeeper_final.zkey";
const VK = JSON.parse(fs.readFileSync("/tmp/gk-vk.json", "utf8"));
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modP = (x) => ((BigInt(x) % P) + P) % P;
const REG_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ALT_VK = "0xa4c11111111111111111111111111111111111111111111111111111111b8ff";
const RECIP = "0xDe42000000000000000000000000000000009f01";
function base(over = {}) {
  return {
    decision: 1, minimum: 1000, recipient: BigInt(RECIP), amount: 500,
    publicBalance: 1460, expiryBlock: 19842201, currentBlock: 19832000,
    conditionRecipient: BigInt(RECIP), maxTransfer: 1000, taskId: 24, salt: 0,
    proofVkHash: modP(REG_VK), registeredVkHash: modP(REG_VK), ...over,
  };
}
const scenarios = {
  "A valid APPROVE (vk match, decision=1)": base(),
  "B trap REJECT (vk differ, decision=0)": base({ decision: 0, proofVkHash: modP(ALT_VK) }),
  "C trap APPROVE (vk differ, decision=1)": base({ decision: 1, proofVkHash: modP(ALT_VK) }),
};
for (const [name, input] of Object.entries(scenarios)) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(`${name}: prove OK, verify=${ok}, publicSignals=[${publicSignals.join(", ")}]`);
  } catch (e) {
    console.log(`${name}: FAILED: ${String(e.message || e).split("\n")[0]}`);
  }
}
