import fs from "fs";
import path from "path";

/**
 * Persistent seen-set of proof_tx references. A proof reference may authorize
 * exactly one task; any repeat is PROOF_REUSED. Stored as a JSON array on
 * disk so the set survives restarts (an in-memory-only set would reopen the
 * replay hole every deploy).
 */
export class SeenProofStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.set = new Set();
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) for (const x of arr) this.set.add(String(x));
    } catch {
      // Missing/corrupt store starts empty; the file is (re)created on write.
    }
  }

  has(ref) {
    return this.set.has(String(ref));
  }

  /** Returns true when the ref was newly added, false when already present. */
  add(ref) {
    const key = String(ref);
    if (this.set.has(key)) return false;
    this.set.add(key);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify([...this.set], null, 2));
    return true;
  }
}
