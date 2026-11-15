/**
 * Minimal Kurier (zkVerify) REST client — OPTIONAL integration.
 *
 * The documented Gatekeeper envelope references the incoming transfer proof
 * only by `proof_tx` (a zkVerify/Kurier job reference) plus its VK hash; the
 * envelope carries no Groth16 proof bytes. The /build Security checklist item
 * "the verification reached a finalized state before approval" is therefore
 * checked against Kurier when KURIER_API_KEY is configured:
 *
 *   GET https://api.kurier.xyz/api/v1/job/{apiKey}/{jobId}
 *
 * Without a key the check is skipped (local/practice mode) — see README.
 * A mainnet API key is obtained from the zkVerify Kurier dashboard
 * (https://docs.zkverify.io/overview/getting-started/kurier); obtaining one
 * is a go-live step for the operator, never done by this service.
 */

const KURIER_BASE = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";

export function kurierEnabled() {
  return Boolean(process.env.KURIER_API_KEY);
}

async function kurierFetch(pathSuffix, options = {}) {
  const key = process.env.KURIER_API_KEY;
  if (!key) throw new Error("KURIER_API_KEY not set");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(`${KURIER_BASE}${pathSuffix}/${key}`, {
      ...options,
      signal: controller.signal,
      headers: { "content-type": "application/json", ...(options.headers || {}) },
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* keep null */ }
    return { status: res.status, json, text };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Check that a proof job referenced by proof_tx reached Finalized with a
 * valid result. Returns "finalized" | "not_finalized" | "unknown".
 * Callers must fail closed on anything other than "finalized".
 */
export async function checkProofFinalized(proofTx) {
  try {
    const { status, json } = await kurierFetch(`/job/${encodeURIComponent(proofTx)}`, {
      method: "GET",
    });
    if (status !== 200 || !json) return "unknown";
    const jobStatus = String(json.status || json.jobStatus || "").toLowerCase();
    if (jobStatus === "finalized") {
      // If the payload carries an explicit validity flag, honour it.
      if (json.valid === false || json.result === "invalid") return "not_finalized";
      return "finalized";
    }
    return "not_finalized";
  } catch {
    return "unknown";
  }
}

/**
 * Submit OUR decision proof to zkVerify via Kurier (optional audit pointer
 * for the response's proof_tx). Disabled by default: finalization polling can
 * take longer than the platform's 60s response deadline, and the scored
 * response already carries the proof + public_signals directly.
 */
export async function submitDecisionProof({ proof, publicSignals, vkHash }) {
  const { status, json } = await kurierFetch("/submit-proof", {
    method: "POST",
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk: vkHash },
    }),
  });
  if (status !== 200 && status !== 201) {
    throw new Error(`Kurier submit-proof failed with HTTP ${status}`);
  }
  return json;
}
