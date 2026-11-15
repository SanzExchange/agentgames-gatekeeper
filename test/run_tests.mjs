import { spawn } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";
import * as snarkjs from "snarkjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "local-test-secret-do-not-use-in-production";
const VK = JSON.parse(
  fs.readFileSync(path.join(ROOT, "artifacts", "verification_key.json"), "utf8")
);
const WASM = path.join(ROOT, "artifacts", "gatekeeper.wasm");
const ZKEY = path.join(ROOT, "artifacts", "gatekeeper_final.zkey");

const seenPath = path.join(
  os.tmpdir(),
  `agentgames-seen-test-${process.pid}-${Date.now()}.json`
);

let failures = 0;
function check(name, cond, extra = "") {
  const mark = cond ? "PASS" : "FAIL";
  if (!cond) failures++;
  console.log(`[${mark}] ${name}${extra ? " — " + extra : ""}`);
}

function sign(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}

async function post(payload, { secret = SECRET, pathName = "/agent" } = {}) {
  const raw = Buffer.from(JSON.stringify(payload), "utf8");
  const res = await fetch(BASE + pathName, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": sign(secret, raw),
    },
    body: raw,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* ignore */ }
  const respSig = res.headers.get("x-agent-games-signature");
  const respSigValid = respSig === sign(SECRET, Buffer.from(text, "utf8"));
  return { status: res.status, json, respSigValid };
}

const VK_A = "0x" + "aa".repeat(32);
const VK_B = "0x" + "bb".repeat(32);
const ADDR = "0xDe42aBcDeF0123456789AbCdEf01234567" + "9f01";
const ADDR_OTHER = "0x" + "11".repeat(20);
let txCounter = 0;
function freshTx() {
  txCounter += 1;
  return "0x" + txCounter.toString(16).padStart(64, "0");
}
let taskCounter = 0;
function task(overrides = {}, inputOverrides = {}) {
  taskCounter += 1;
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: `gk_test_${taskCounter}`,
    mode: "practice",
    issued_at: new Date(now - 1000).toISOString(),
    deadline_at: new Date(now + 10 * 60 * 1000).toISOString(),
    input: {
      registered_vk: VK_A,
      proof_vk: VK_A,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: "500",
      max_transfer: "1000",
      proof_tx: freshTx(),
      ...inputOverrides,
    },
    ...overrides,
  };
}

async function verifyDecisionProof(json, expectedDecision) {
  if (!json.proof || !Array.isArray(json.public_signals)) return false;
  if (json.public_signals.length !== 13) return false;
  if (json.public_signals[11] !== expectedDecision) return false;
  return snarkjs.groth16.verify(VK, json.public_signals, json.proof);
}

// --- boot the service ---
const child = spawn("node", [path.join(ROOT, "src", "server.mjs")], {
  env: {
    ...process.env,
    AGENT_GAMES_HMAC_SECRET: SECRET,
    PORT: String(PORT),
    HOST: "127.0.0.1",
    SEEN_STORE_PATH: seenPath,
  },
  stdio: ["ignore", "pipe", "pipe"],
});
child.stderr.on("data", (d) => process.stderr.write(`[server] ${d}`));
await new Promise((resolve, reject) => {
  const to = setTimeout(() => reject(new Error("server did not start")), 15000);
  child.stdout.on("data", (d) => {
    if (String(d).includes("listening")) { clearTimeout(to); resolve(); }
  });
});

try {
  // 1. Preflight
  {
    const r = await post({
      type: "agent-games.preflight.v1",
      agent_id: "agt_test",
      issued_at: new Date().toISOString(),
      nonce: "abc123",
    });
    check("preflight ok", r.status === 200 && r.json?.ok === true && r.json?.protocolVersion === "v1");
    check("preflight response signed", r.respSigValid);
  }

  // 2. Bad HMAC is rejected before parsing
  {
    const r = await post(task(), { secret: "wrong-secret" });
    check("bad HMAC -> 401", r.status === 401 && r.json?.error === "SIGNATURE_MISMATCH");
  }

  // 3. Valid task -> APPROVE + verifiable decision proof
  {
    const t0 = Date.now();
    const r = await post(task());
    const ms = Date.now() - t0;
    check("valid task -> APPROVE/OK", r.json?.decision === "APPROVE" && r.json?.reason_code === "OK", JSON.stringify(r.json?.reason_code));
    check("valid task response signed", r.respSigValid);
    check("valid task proof verifies vs official VK", await verifyDecisionProof(r.json, "1"));
    check(`valid task answered fast (${ms}ms << 60000ms)`, ms < 60000);
  }

  // 4. VK substitution trap
  {
    const r = await post(task({}, { proof_vk: VK_B }));
    check("proof_vk != registered_vk -> REJECT/VK_SUBSTITUTION",
      r.json?.decision === "REJECT" && r.json?.reason_code === "VK_SUBSTITUTION");
    check("VK trap reject proof verifies (decision=0)", await verifyDecisionProof(r.json, "0"));
  }

  // 5. Recipient mismatch trap
  {
    const r = await post(task({}, { recipient: ADDR_OTHER }));
    check("recipient mismatch -> REJECT/RECIPIENT_MISMATCH",
      r.json?.decision === "REJECT" && r.json?.reason_code === "RECIPIENT_MISMATCH");
    check("recipient trap reject proof verifies", await verifyDecisionProof(r.json, "0"));
  }

  // 6. Expired traps: current > expiry, and the strict boundary current == expiry
  {
    const r1 = await post(task({}, { current_block: 8430001 }));
    check("current_block > expiry_block -> REJECT/EXPIRED_CONDITION",
      r1.json?.decision === "REJECT" && r1.json?.reason_code === "EXPIRED_CONDITION");
    const r2 = await post(task({}, { current_block: 8430000 }));
    check("current_block == expiry_block -> REJECT/EXPIRED_CONDITION (circuit is strict <)",
      r2.json?.decision === "REJECT" && r2.json?.reason_code === "EXPIRED_CONDITION");
  }

  // 7. Threshold trap
  {
    const r = await post(task({}, { public_balance: "999" }));
    check("public_balance < minimum -> REJECT/THRESHOLD_MISMATCH",
      r.json?.decision === "REJECT" && r.json?.reason_code === "THRESHOLD_MISMATCH");
    check("threshold trap reject proof verifies", await verifyDecisionProof(r.json, "0"));
  }

  // 8. Amount overflow trap (+ boundary amount == max_transfer approves)
  {
    const r = await post(task({}, { amount: "1001" }));
    check("amount > max_transfer -> REJECT/AMOUNT_OVERFLOW",
      r.json?.decision === "REJECT" && r.json?.reason_code === "AMOUNT_OVERFLOW");
    const r2 = await post(task({}, { amount: "1000" }));
    check("amount == max_transfer -> APPROVE",
      r2.json?.decision === "APPROVE" && r2.json?.reason_code === "OK");
  }

  // 9. Proof reuse: same proof_tx twice
  {
    const sharedTx = freshTx();
    const r1 = await post(task({}, { proof_tx: sharedTx }));
    check("first use of proof_tx -> APPROVE", r1.json?.decision === "APPROVE");
    const r2 = await post(task({}, { proof_tx: sharedTx }));
    check("reused proof_tx -> REJECT/PROOF_REUSED",
      r2.json?.decision === "REJECT" && r2.json?.reason_code === "PROOF_REUSED");
    // Reuse is an agent-side fact with no circuit input: the statement is
    // circuit-valid, so a decision=0 proof cannot exist. The response must
    // correctly carry NO proof (see README).
    check("reuse reject carries no proof (not circuit-provable)",
      r2.json?.proof === undefined && r2.json?.public_signals === undefined);
  }

  // 10. Embedded proof verification: genuine proof passes, tampered fails
  {
    const circuitInput = {
      taskId: "424242", registeredVkHash: "111", proofVkHash: "111",
      minimum: "1000", publicBalance: "1460", expiryBlock: "8430000",
      currentBlock: "8420000", recipient: "222", conditionRecipient: "222",
      amount: "500", maxTransfer: "1000", decision: "1", salt: "777",
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
    const okCase = await post(task({}, { proof, public_signals: publicSignals, vk: VK }));
    check("embedded genuine proof -> still APPROVE", okCase.json?.decision === "APPROVE");
    const tampered = [...publicSignals];
    tampered[9] = "501";
    const badCase = await post(task({}, { proof, public_signals: tampered, vk: VK }));
    check("embedded tampered proof -> REJECT/PROOF_INVALID",
      badCase.json?.decision === "REJECT" && badCase.json?.reason_code === "PROOF_INVALID");
  }

  // 11. Malformed task fails closed
  {
    const broken = task();
    delete broken.input.amount;
    const r = await post(broken);
    check("missing amount -> REJECT/MALFORMED_TASK",
      r.json?.decision === "REJECT" && r.json?.reason_code === "MALFORMED_TASK");
  }

  // 12. Unknown message type
  {
    const r = await post({ type: "agent-games.something-else.v9" });
    check("unknown type -> 400", r.status === 400 && r.json?.error === "UNKNOWN_TYPE");
  }
} finally {
  child.kill("SIGTERM");
  try { fs.unlinkSync(seenPath); } catch { /* ignore */ }
}

console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
