import http from "http";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Gatekeeper, REASON } from "./gatekeeper.mjs";
import { SeenProofStore } from "./seen.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "127.0.0.1";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const HARD_DEADLINE_MS = 55_000; // platform hard limit is 60s; keep margin

if (!SECRET) {
  console.error(
    "FATAL: AGENT_GAMES_HMAC_SECRET is not set. Copy the one-time plaintext from " +
      "the platform dashboard (Rotate Secret) into the environment. Refusing to start."
  );
  process.exit(1);
}

function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function signatureMatches(secret, rawBody, headerValue) {
  if (!headerValue || typeof headerValue !== "string") return false;
  let presented = headerValue.trim();
  if (presented.toLowerCase().startsWith("sha256=")) {
    presented = presented.slice("sha256=".length).trim();
  }
  const expectedHex = hmacHex(secret, rawBody);
  const candidates = [expectedHex];
  // Also accept the base64 spelling of the same digest, for robustness.
  candidates.push(Buffer.from(expectedHex, "hex").toString("base64"));
  return candidates.some((expected) => {
    const a = Buffer.from(expected);
    const b = Buffer.from(presented);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

const verificationKey = JSON.parse(
  fs.readFileSync(path.join(ROOT, "artifacts", "verification_key.json"), "utf8")
);
const seenStore = new SeenProofStore(
  process.env.SEEN_STORE_PATH || path.join(ROOT, "data", "seen_proof_tx.json")
);
const gatekeeper = new Gatekeeper({
  wasmPath: path.join(ROOT, "artifacts", "gatekeeper.wasm"),
  zkeyPath: path.join(ROOT, "artifacts", "gatekeeper_final.zkey"),
  verificationKey,
  seenStore,
});

function sendSigned(res, status, payload) {
  const raw = Buffer.from(JSON.stringify(payload), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(SECRET, raw),
  });
  res.end(raw);
}

function withDeadline(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("hard deadline exceeded")), ms)
    ),
  ]);
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/health" || req.url === "/healthz")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method !== "POST") {
    sendSigned(res, 404, { error: "NOT_FOUND" });
    return;
  }

  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("error", () => sendSigned(res, 400, { error: "REQUEST_ERROR" }));
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);

    // 1. Verify HMAC over the RAW body BEFORE parsing anything.
    if (!signatureMatches(SECRET, rawBody, req.headers["x-agent-games-signature"])) {
      sendSigned(res, 401, { error: "SIGNATURE_MISMATCH" });
      return;
    }

    // 2. Parse only after the signature checks out.
    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      sendSigned(res, 400, { error: "MALFORMED_BODY" });
      return;
    }

    try {
      if (envelope.type === "agent-games.preflight.v1") {
        sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
        return;
      }
      if (envelope.type === "agent-games.proof-gatekeeper.v1") {
        const result = await withDeadline(gatekeeper.evaluate(envelope), HARD_DEADLINE_MS);
        sendSigned(res, 200, result);
        return;
      }
      sendSigned(res, 400, { error: "UNKNOWN_TYPE" });
    } catch (err) {
      // Fail closed: never approve on an internal error or a blown deadline.
      console.error(`[agent] handler error: ${err.message}`);
      if (envelope && envelope.type === "agent-games.proof-gatekeeper.v1") {
        sendSigned(res, 200, { decision: "REJECT", reason_code: REASON.TIMEOUT });
      } else {
        sendSigned(res, 500, { error: "INTERNAL_ERROR" });
      }
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[agent] Proof Gatekeeper listening on http://${HOST}:${PORT} (POST /agent)`);
});
