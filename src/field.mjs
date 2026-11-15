import crypto from "crypto";

// BN128 (alt_bn128) scalar field prime — all circuit values live mod p.
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function sha256BigInt(text) {
  const digest = crypto.createHash("sha256").update(text, "utf8").digest();
  return BigInt("0x" + digest.toString("hex"));
}

/**
 * Parse a value that must be a faithful field-sized quantity (amounts, blocks,
 * balances). Accepts decimal strings, 0x-hex strings, numbers, bigints.
 * Returns a BigInt in [0, p) or null when unparseable / out of range.
 * Out-of-range quantities fail closed (null) rather than wrapping mod p,
 * because a wrapped amount could smuggle a trap past the comparisons.
 */
export function parseQuantity(value) {
  let v;
  try {
    if (typeof value === "bigint") v = value;
    else if (typeof value === "number") {
      if (!Number.isInteger(value) || value < 0) return null;
      v = BigInt(value);
    } else if (typeof value === "string") {
      const s = value.trim();
      if (/^0x[0-9a-fA-F]+$/.test(s)) v = BigInt(s);
      else if (/^[0-9]+$/.test(s)) v = BigInt(s);
      else return null;
    } else return null;
  } catch {
    return null;
  }
  if (v < 0n || v >= FIELD_PRIME) return null;
  return v;
}

/**
 * Encode an identifier-like value (vk hash, address, task id, proof ref) as a
 * field element. Hex/decimal values are taken mod p (a 256-bit hash does not
 * fit in the BN128 scalar field otherwise); arbitrary strings (e.g. task ids
 * like "gk_8d31_...") are hashed with SHA-256 and reduced mod p.
 *
 * NOTE: the /build docs show these envelope fields truncated and never specify
 * the field encoding. This is the only sane local choice, but the exact
 * encoding must be confirmed against an unscored practice task at go-live —
 * see README "Docs ambiguities".
 */
export function fieldFromIdentifier(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "bigint") return value % FIELD_PRIME;
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value) % FIELD_PRIME;
  }
  if (typeof value !== "string") return null;
  const s = value.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  if (/^[0-9]+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  if (s.length === 0) return null;
  return sha256BigInt(s) % FIELD_PRIME;
}

/** Case-insensitive identifier equality (hex addresses / hashes). */
export function identifiersEqual(a, b) {
  if (a === null || a === undefined || b === null || b === undefined) return false;
  const sa = String(a).trim().toLowerCase();
  const sb = String(b).trim().toLowerCase();
  if (sa === sb) return true;
  // Fall back to numeric equality for hex/decimal spellings of the same value.
  const fa = fieldFromIdentifier(a);
  const fb = fieldFromIdentifier(b);
  return fa !== null && fb !== null && fa === fb;
}
