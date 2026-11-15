# Proof Gatekeeper agent — zkVerify Agent Games

A Node.js HTTP service that plays **Proof Gatekeeper**
(https://agentgames.zkverify.io): the platform POSTs signed transfer tasks,
the agent answers APPROVE/REJECT with a reason code and a Groth16 proof of
its decision, generated locally with `snarkjs` against the official
gatekeeper circuit.

**Status: build phase complete, all local tests passing. Not yet registered
or exposed publicly — see "Go-live checklist" below.**

## How it works

```
POST /agent   (any POST path is accepted; register the full URL)
  1. HMAC-SHA256 over the RAW request body is compared (timing-safe) with the
     x-agent-games-signature header BEFORE any JSON parsing. Mismatch -> 401.
  2. agent-games.preflight.v1        -> { ok: true, protocolVersion: "v1" }
     agent-games.proof-gatekeeper.v1 -> decision evaluation (below)
  3. Every response body is signed the same way (hex digest in the
     x-agent-games-signature response header).
```

Decision rules (deterministic code only; fail closed — any doubt is a
REJECT). These mirror the official circuit exactly, verified empirically
against `artifacts/gatekeeper.wasm` (see "Circuit semantics" below):

| Check | Reject reason |
|---|---|
| wall-clock `deadline_at` already passed | `EXPIRED_CONDITION` |
| `proof_vk` != `registered_vk` | `VK_SUBSTITUTION` |
| `recipient` != `condition_recipient` | `RECIPIENT_MISMATCH` |
| `current_block` >= `expiry_block` (circuit requires strict `<`) | `EXPIRED_CONDITION` |
| `public_balance` < `minimum` | `THRESHOLD_MISMATCH` |
| `amount` > `max_transfer` | `AMOUNT_OVERFLOW` |
| `proof_tx` seen before (persistent store, `data/seen_proof_tx.json`) | `PROOF_REUSED` |
| embedded Groth16 proof present but fails `snarkjs` verification | `PROOF_INVALID` |
| Kurier enabled and `proof_tx` job not Finalized on zkVerify | `PROOF_INVALID` |

On every task whose verdict the circuit can attest, the response also
carries `proof` + `public_signals` from the official circuit (self-verified
against the official VK before sending). Agent-side rejections
(`PROOF_REUSED`, external `PROOF_INVALID`) have no circuit inputs, so no
decision proof can exist for them — those responses go out without a proof
(see "Docs ambiguities" #5). Typical end-to-end latency locally: ~1.5 s,
far inside the 60 s hard deadline; the server additionally races every task
against a 55 s internal deadline and fails closed.

## Circuit semantics (reverse-engineered from the official artifacts)

The docs never print the circuit's input list, so it was recovered by
probing the wasm's input table (FNV-1a name hashes) and by proving/
verifying test vectors (`test/probe*.mjs`):

- 13 inputs, all scalars: `taskId`, `registeredVkHash`, `proofVkHash`,
  `minimum`, `publicBalance`, `expiryBlock`, `currentBlock`, `recipient`,
  `conditionRecipient`, `amount`, `maxTransfer`, `decision` (all public),
  plus `salt` (private, agent-chosen; it blinds the statement hash).
- Public signals (13, in order): `[statementHash, registeredVkHash,
  proofVkHash, minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId]`.
- The circuit **asserts `decision` equals its own computed verdict**:
  an APPROVE proof for a trapped statement, or a REJECT proof for a valid
  statement, cannot be generated at all. The circuit really is the referee.
- Verdict = APPROVE iff `proofVkHash == registeredVkHash`,
  `recipient == conditionRecipient`, `currentBlock < expiryBlock`
  (strict), `publicBalance >= minimum`, `amount <= maxTransfer`.
  Notably: `amount` vs `publicBalance`, `amount` vs `minimum`, and
  `publicBalance - amount` vs `minimum` are **not** checked (all proven
  empirically); `amount == 0` and `amount == maxTransfer` are approvable;
  `decision` must be 0 or 1.
- `proof_tx` is **not** a circuit input — replay protection is the agent's
  own bookkeeping, hence the persistent seen-store.
- Official artifacts (downloaded from agentgames.zkverify.io only):
  `gatekeeper.wasm` sha256 `be00aefe…64f`, `gatekeeper_final.zkey`
  sha256 `adfe95a4…80d`; circuit `vk_hash` (registered on zkVerify
  mainnet) `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  per `/api/circuit-info`. The exported verification key is in
  `artifacts/verification_key.json`.

## Run it locally

```bash
cd ~/workspace/agentgames
npm install
AGENT_GAMES_HMAC_SECRET=local-test-secret npm start   # http://127.0.0.1:8787
npm test                                              # full local test suite
```

`npm test` boots the service on a throwaway port with a test secret and a
fresh seen-store, then replays signed envelopes: preflight, bad HMAC, one
valid task, every trap type (VK substitution, recipient mismatch, expired
incl. the `current == expiry` boundary, threshold, amount overflow, proof
reuse), an embedded-proof tamper case, malformed input, and unknown type —
asserting decisions, reason codes, response signatures, and that every
attached decision proof verifies against the official VK. **25/25 pass.**

Configuration (environment only — never hardcode secrets):

| Variable | Required | Purpose |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform secret from dashboard **Rotate Secret** (one-time plaintext). The service refuses to start without it. |
| `KURIER_API_KEY` | no | Enables the zkVerify finalization check for incoming `proof_tx` before approving. |
| `PORT` / `HOST` | no | Default `8787` / `127.0.0.1`. |
| `SEEN_STORE_PATH` | no | Default `data/seen_proof_tx.json`. |
| `SKIP_SELF_VERIFY=1` | no | Skip local verification of our own proofs (not recommended). |

## Go-live checklist (remaining steps, in order)

1. **Register** on https://agentgames.zkverify.io/register (X account or
   wallet; handle/country/bio). Create the agent and register the endpoint
   with its **full handler path** (e.g. `https://<host>/agent`) for the
   Proof Gatekeeper event. *(Operator step — not done in this build phase.)*
2. **Expose the service on public HTTPS.** The platform requires a public
   HTTPS endpoint; the service itself speaks plain HTTP on localhost.
   Evaluation for this VM:
   - **Recommended: cloudflared quick tunnel** (`cloudflared tunnel
     --url http://127.0.0.1:8787`). Zero inbound ports, free TLS, works
     behind NAT. Caveat: a *quick* tunnel URL is random per process start —
     if cloudflared restarts, the URL changes and the dashboard endpoint
     must be updated. For a stable hostname, use a **named tunnel** with a
     domain on Cloudflare (free) — preferred once past practice rounds.
     Run cloudflared as a second systemd user service with
     `Restart=always` alongside the agent.
   - Alternatives: a small VPS/reverse proxy with Caddy (automatic TLS), or
     ngrok (stable domain needs a paid plan). Plain port-forwarding is not
     available on this VM.
3. **Run it as a systemd user service** so it survives restarts:
   `deploy/agentgames.service` is ready — copy secrets to
   `~/.config/agentgames/agentgames.env` (mode 600, template in
   `deploy/agentgames.env.example`), then
   `systemctl --user enable --now agentgames` and once
   `loginctl enable-linger $USER` so it starts at boot without a login
   session. Do the same for cloudflared.
4. **Rotate the secret**: dashboard → Rotate Secret → copy the one-time
   plaintext into `AGENT_GAMES_HMAC_SECRET` → restart the service → run the
   platform preflight from the dashboard; it must pass before the agent is
   marked active. A placeholder secret fails preflight by design.
5. **Confirm the field encodings with unscored practice tasks** (see
   ambiguity #1) before the first scored round; adjust `src/field.mjs` if
   the platform's expected public signals differ.
6. **Kurier API key — is it required?** Not for the scored response itself:
   the response carries our Groth16 `proof` + `public_signals` directly,
   and `proof_tx` in the response is only an *optional* audit pointer.
   A key **is** required for the stronger approval path the /build Security
   checklist describes — confirming the *incoming* proof (referenced by
   the task's `proof_tx`) reached **Finalized** on zkVerify before
   approving. Without a key this service skips that check (the platform
   still re-verifies everything itself). To get one: sign up at the
   zkVerify Kurier dashboard and create a **mainnet** API key (docs:
   https://docs.zkverify.io/overview/getting-started/kurier), then set
   `KURIER_API_KEY`. Do **not** sign up from this build environment —
   it's an operator go-live step. If enabled, also verify the job-status
   endpoint shape in `src/kurier.mjs` against the live API (ambiguity #7).
7. **Practice first**: the docs advise passing practice traps before a
   scored round (8 rounds/day; +12 correct, −6 approving a trap, −3
   rejecting a valid request, −2 timeout/invalid proof).

## Docs ambiguities hit (and the choices made)

1. **Field-element encodings are unspecified.** The envelope shows
   `registered_vk` truncated (`"0x7d...91"`), and nothing states how
   `registered_vk`, `recipient`, or the string `task_id` (`"gk_8d31_..."`)
   map to circuit field elements. Choices in `src/field.mjs`: hex/decimal
   values → integer mod p (a 256-bit hash exceeds the BN128 scalar field);
   addresses → their 160-bit integer; other strings → SHA-256 of the UTF-8
   bytes, mod p. Equality checks are done on the raw values, so decisions
   are encoding-independent; only the proof's public signals depend on the
   encoding. **Must be confirmed against a practice task at go-live.**
2. **Expiry boundary**: the task brief's phrasing (`current_block <=
   expiry_block` approves) contradicts the circuit, which enforces
   `current_block < expiry_block` (equality cannot be proven as APPROVE —
   proven empirically). We follow the circuit.
3. **APPROVE reason code**: the docs only show `reason_code` on a REJECT
   example. We return `"OK"` on approvals.
4. **HMAC header encoding**: docs name the header but not the digest
   encoding. We emit lowercase hex; on verify we accept hex or base64, with
   or without a `sha256=` prefix.
5. **"Provable tasks"**: agent-side rejections (`PROOF_REUSED`,
   finalization-based `PROOF_INVALID`) cannot carry a decision proof —
   `proof_tx` and finalization are not circuit inputs, and the circuit
   asserts decision == statement verdict. This matches the /build wording
   ("on every provable task"); the platform itself issued the `proof_tx`,
   so reuse is independently visible to it.
6. **The incoming proof is not in the envelope.** The task input carries
   only `proof_tx` + `proof_vk` — no Groth16 proof/public signals to verify
   with snarkjs. So "verify the proof itself" is realized two ways:
   (a) if a task ever embeds `proof` / `public_signals` / `vk`, we verify
   them with snarkjs and reject `PROOF_INVALID` on failure (implemented,
   tested); (b) in production, the proof's zkVerify **finalization** is
   checked via Kurier (implemented, env-gated). The platform re-verifies
   proofs against its own registered VK regardless.
7. **Kurier job-status endpoint** is not shown on /build (only
   `submit-proof` is). `src/kurier.mjs` assumes
   `GET /api/v1/job/{apiKey}/{jobId}` per the Kurier docs pattern; verify
   against the live API when the key exists. Failure of the check fails
   closed (`PROOF_INVALID`) whenever the key is configured.
8. **Timestamps**: `issued_at` / `deadline_at` are placeholders in the docs
   (`"<issued-at>"`). We parse ISO 8601 and enforce only a passed
   `deadline_at` (→ `EXPIRED_CONDITION`); unparseable values are ignored
   rather than rejected.
9. **`salt`** is undocumented. It is a private circuit input with no
   envelope counterpart, so the agent picks a fresh random one per proof;
   any value works and it changes the statement-hash public signal.
10. **Response shape**: the /build REJECT example shows `{decision,
    reason_code, proof_tx}` while the starter prompt shows `{decision,
    reason_code, proof, public_signals}`. We send the union: decision,
    reason_code, echoed `proof_tx`, and proof + public_signals whenever
    the verdict is circuit-provable.

## Layout

```
src/server.mjs      HTTP transport: raw-body HMAC verify/sign, routing, deadline
src/gatekeeper.mjs  Decision engine + decision-proof generation (snarkjs)
src/field.mjs       Field-element parsing/encoding helpers
src/seen.mjs        Persistent proof_tx seen-store
src/kurier.mjs      Optional Kurier client (finalization check, proof submit)
artifacts/          Official gatekeeper.wasm / gatekeeper_final.zkey / VK
test/run_tests.mjs  End-to-end local test suite (npm test)
test/probe*.mjs     Circuit reverse-engineering probes (evidence trail)
deploy/             systemd user unit + env template
docs/               Snapshot of the /build page used as the spec source
```
