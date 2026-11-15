import crypto from "crypto";
import * as snarkjs from "snarkjs";
import {
  FIELD_PRIME,
  parseQuantity,
  fieldFromIdentifier,
  identifiersEqual,
} from "./field.mjs";
import { checkProofFinalized, kurierEnabled } from "./kurier.mjs";

export const REASON = {
  OK: "OK",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  PROOF_INVALID: "PROOF_INVALID",
  // Local extensions for structurally broken envelopes (never expected from
  // the platform's well-formed tasks; documented in README).
  MALFORMED_TASK: "MALFORMED_TASK",
  TIMEOUT: "TIMEOUT",
};

function randomSalt() {
  return BigInt("0x" + crypto.randomBytes(32).toString("hex")) % FIELD_PRIME;
}

/**
 * Proof Gatekeeper decision engine.
 *
 * Decision semantics were verified empirically against the official circuit
 * (artifacts/gatekeeper.wasm + gatekeeper_final.zkey): the circuit asserts
 * decision == verdict, where verdict is APPROVE iff ALL of:
 *   proofVkHash == registeredVkHash
 *   recipient == conditionRecipient
 *   currentBlock < expiryBlock        (strict — equality is already expired)
 *   publicBalance >= minimum
 *   amount <= maxTransfer
 * The off-chain checks below mirror those rules exactly so the reason_code we
 * report names the trap the circuit itself would enforce. Everything fails
 * closed: any parse problem, ambiguity, or verification failure is a REJECT.
 */
export class Gatekeeper {
  constructor({ wasmPath, zkeyPath, verificationKey, seenStore, logger = console }) {
    this.wasmPath = wasmPath;
    this.zkeyPath = zkeyPath;
    this.verificationKey = verificationKey;
    this.seenStore = seenStore;
    this.log = logger;
    this.selfVerify = process.env.SKIP_SELF_VERIFY !== "1";
  }

  /** Verify a Groth16 proof embedded in the task input, when one is present. */
  async verifyEmbeddedProof(input) {
    const proof = input.proof;
    const publicSignals = input.public_signals || input.publicSignals;
    const vk = input.vk || input.verification_key || input.verificationKey;
    if (proof === undefined && publicSignals === undefined && vk === undefined) {
      return "absent";
    }
    if (!proof || !Array.isArray(publicSignals) || !vk) return "invalid";
    try {
      const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
      return ok ? "valid" : "invalid";
    } catch {
      return "invalid";
    }
  }

  /** Generate our decision proof with the official gatekeeper circuit. */
  async proveDecision(circuitInput) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      this.wasmPath,
      this.zkeyPath
    );
    if (this.selfVerify) {
      const ok = await snarkjs.groth16.verify(
        this.verificationKey,
        publicSignals,
        proof
      );
      if (!ok) throw new Error("self-verification of decision proof failed");
    }
    return { proof, publicSignals };
  }

  /**
   * Evaluate one `agent-games.proof-gatekeeper.v1` envelope.
   * Always resolves to a response object; never throws.
   */
  async evaluate(envelope) {
    const input = envelope && typeof envelope === "object" ? envelope.input : null;
    if (!input || typeof input !== "object") {
      return { decision: "REJECT", reason_code: REASON.MALFORMED_TASK };
    }

    // --- Structural parse (fail closed on anything unparseable) ---
    const minimum = parseQuantity(input.minimum);
    const publicBalance = parseQuantity(input.public_balance);
    const amount = parseQuantity(input.amount);
    const maxTransfer = parseQuantity(input.max_transfer);
    const expiryBlock = parseQuantity(input.expiry_block);
    const currentBlock = parseQuantity(input.current_block);
    const registeredVk = fieldFromIdentifier(input.registered_vk);
    const proofVk = fieldFromIdentifier(input.proof_vk);
    const recipientF = fieldFromIdentifier(input.recipient);
    const conditionRecipientF = fieldFromIdentifier(input.condition_recipient);
    const taskIdF = fieldFromIdentifier(envelope.task_id);
    const proofTx =
      typeof input.proof_tx === "string" && input.proof_tx.trim().length > 0
        ? input.proof_tx.trim()
        : null;

    if (
      minimum === null || publicBalance === null || amount === null ||
      maxTransfer === null || expiryBlock === null || currentBlock === null ||
      registeredVk === null || proofVk === null ||
      recipientF === null || conditionRecipientF === null || taskIdF === null ||
      proofTx === null
    ) {
      const resp = { decision: "REJECT", reason_code: REASON.MALFORMED_TASK };
      if (proofTx) resp.proof_tx = proofTx;
      return resp;
    }

    // Consume the proof reference on first sight, whatever the outcome: a
    // proof_tx may never authorize (or be attached to) a second task.
    const alreadySeen = this.seenStore.has(proofTx);
    if (!alreadySeen) this.seenStore.add(proofTx);

    // --- Deterministic policy checks, in Security-checklist order ---
    let reason = REASON.OK;

    // Timestamp validity: an already-passed wall-clock deadline is expired.
    const deadlineMs = Date.parse(envelope.deadline_at || "");
    if (reason === REASON.OK && Number.isFinite(deadlineMs) && Date.now() > deadlineMs) {
      reason = REASON.EXPIRED_CONDITION;
    }
    if (reason === REASON.OK && !identifiersEqual(input.proof_vk, input.registered_vk)) {
      reason = REASON.VK_SUBSTITUTION;
    }
    if (reason === REASON.OK && !identifiersEqual(input.recipient, input.condition_recipient)) {
      reason = REASON.RECIPIENT_MISMATCH;
    }
    if (reason === REASON.OK && currentBlock >= expiryBlock) {
      reason = REASON.EXPIRED_CONDITION;
    }
    if (reason === REASON.OK && publicBalance < minimum) {
      reason = REASON.THRESHOLD_MISMATCH;
    }
    if (reason === REASON.OK && amount > maxTransfer) {
      reason = REASON.AMOUNT_OVERFLOW;
    }
    if (reason === REASON.OK && alreadySeen) {
      reason = REASON.PROOF_REUSED;
    }
    if (reason === REASON.OK) {
      const embedded = await this.verifyEmbeddedProof(input);
      if (embedded === "invalid") reason = REASON.PROOF_INVALID;
    }
    if (reason === REASON.OK && kurierEnabled()) {
      // The incoming proof must be Finalized on zkVerify before approval.
      const status = await checkProofFinalized(proofTx);
      if (status !== "finalized") reason = REASON.PROOF_INVALID;
    }

    const decision = reason === REASON.OK ? "APPROVE" : "REJECT";
    const response = { decision, reason_code: reason, proof_tx: proofTx };

    // --- Decision proof with the official circuit (every provable task) ---
    const circuitInput = {
      taskId: taskIdF.toString(),
      registeredVkHash: registeredVk.toString(),
      proofVkHash: proofVk.toString(),
      minimum: minimum.toString(),
      publicBalance: publicBalance.toString(),
      expiryBlock: expiryBlock.toString(),
      currentBlock: currentBlock.toString(),
      recipient: recipientF.toString(),
      conditionRecipient: conditionRecipientF.toString(),
      amount: amount.toString(),
      maxTransfer: maxTransfer.toString(),
      decision: decision === "APPROVE" ? "1" : "0",
      salt: randomSalt().toString(),
    };
    try {
      const { proof, publicSignals } = await this.proveDecision(circuitInput);
      response.proof = proof;
      response.public_signals = publicSignals;
    } catch (err) {
      if (decision === "APPROVE") {
        // Inconsistency between checks and circuit: fail closed, no proof.
        this.log.error(
          `[gatekeeper] APPROVE proof failed for task ${envelope.task_id}: ${err.message}`
        );
        return { decision: "REJECT", reason_code: REASON.PROOF_INVALID, proof_tx: proofTx };
      }
      // Agent-side rejections (PROOF_REUSED, PROOF_INVALID) concern facts the
      // circuit has no inputs for — the statement itself is circuit-valid, so
      // a decision=0 proof is impossible BY DESIGN and the response correctly
      // goes out without one. Any other REJECT reason failing to prove means
      // our checks and the circuit disagree: log loudly.
      if (reason === REASON.PROOF_REUSED || reason === REASON.PROOF_INVALID) {
        this.log.log(
          `[gatekeeper] task ${envelope.task_id}: ${reason} is not circuit-provable; responding without proof`
        );
      } else {
        this.log.error(
          `[gatekeeper] decision proof failed for task ${envelope.task_id}: ${err.message}`
        );
      }
      delete response.proof;
      delete response.public_signals;
    }
    return response;
  }
}
