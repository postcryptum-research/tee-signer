# REQ — R7 DESIGN: no signature after a restart until the owner arms the enclave

**Date:** 2026-11-05 · **Asks:** DESIGN-PASS (hard rule 1: no `core/` or `enclave/` change before
it) · **Owner decision (2026-11-05):** "при рестарте просить подтвердить ключом запуск" — chosen
over the chain-anchored budget (control coin) for its simplicity; the control coin stays on
record as the no-liveness-cost alternative (`THREAT-MODEL.md §5`, auditor first-look 2026-11-05).

## 1. The problem, as the attacker states it

Root on the server (T2 included; cannot read the seed, cannot alter the owner-signed mandate)
copies the sealed-state file, has the enclave pay the window's unlisted budget to addresses of
their choice, restores the copy, restarts `signerd`, and the enclave — holding the same seed and
the same signed mandate — pays the same window again. Confirmed by the auditor on 2026-11-05: the
rollback is repeatable, the header feed can be pinned, no persistence survives it, SGX has no
monotonic counter or clock the host cannot reset. The sealed state proves *authorship* (the seal
MAC), never *recency*; "no history", "old history" and "full history" are indistinguishable to a
freshly started enclave.

What survives a rollback: the enclave's own process memory does not (a restart is the only way to
load an older blob: within a process the session high-water mark refuses one, `rcore/session.rs`).
So **every rollback is a restart**, and the enclave always knows it has just started.

## 2. The rule

**After every load, the enclave signs nothing until the owner, with the owner key, approves this
particular start.** Nobody has to be awake for the system to be safe: a rollback at 3 a.m. yields
an enclave that is up and silent; the owner looks in the morning.

1. **Boot challenge.** At first use after load, the enclave draws 32 bytes from in-enclave RDRAND
   (`session::ensure`, next to the session id) and keeps them in enclave memory only — never in the
   sealed state (a sealed "armed" would roll back and forward with the blob). `STATUS` reports
   `boot_challenge` and `armed: false`.
2. **Unarmed = no signatures.** `SIGN` refuses with a new reason `NOT_ARMED` while the session is
   unarmed. Owner messages (policy update, cancel, freeze/unfreeze, rotate, recover) are accepted
   as today — they are owner-signed and nonce-bound, and a tightening or a cancel must not need an
   extra signature in an emergency. Headers are accepted (the block clock keeps running).
3. **Arm.** A new owner message `Arm { enclave_id, nonce, boot_challenge[32], seq_seen: u64 }`,
   P-256-signed by the owner key like every other owner message (`DESIGN.md §6` domain tag
   `tee-signer/policy/v1`, canonical encoding in `signer-core`). The enclave accepts it only if:
   (a) the signature verifies under the sealed `owner_pk`; (b) `nonce` is the next owner nonce
   (consumed on success, as for every owner message); (c) `boot_challenge` equals **this
   process's** challenge, else `ARM_CHALLENGE`; (d) `seq_seen ≤ s.seq`, else `ARM_SEQ_BEHIND`
   (the owner says "the last signature I saw was #Y"; an enclave that remembers less than Y has
   been rolled back). On success the session is armed until the next load.
4. **`init` arms the process it runs in.** Init is an attended owner operation on a fresh enclave;
   there is nothing to roll back yet. Every later load — reboot, update, crash, or an attacker's
   restart — is unarmed.
5. **owner-cli `arm`.** Fetches `status`; compares the enclave's `seq` with `last_seen_seq`
   recorded in `wallet.json` (owner-cli updates that record at every interaction that returns a
   `seq`: `status`, `sign`, `policy-*`, `arm`); **refuses to build the message if `seq <
   last_seen_seq`** and says so ("the enclave remembers #X, you last saw #Y: rolled back"), with an
   explicit `--i-have-investigated` override; otherwise shows the boot challenge, the enclave's
   seq and the time since the owner last looked, signs with the owner device (PIN + touch on a
   YubiKey) and submits. The enclave's check (d) is the second line behind owner-cli's.

## 3. Attacker scenarios against the rule

| Who, what | Outcome |
|---|---|
| Root restores an old state and restarts (the drain of §1) | the new process is unarmed: no signature until the owner arms. A rollback while the owner sleeps steals nothing |
| Root replays a captured `Arm` from an earlier boot | `ARM_CHALLENGE`: 32 random bytes per boot; a rolled-back nonce does not help because the challenge is not in the state |
| Root shows the owner a different challenge through `signerd` | the owner signs the wrong value; the enclave refuses; DoS only, visible |
| Root restarts repeatedly without rolling back | DoS; every restart is an event the owner sees and must sign for; the owner pulls the host |
| Root rolls back and the owner arms **without looking** | owner-cli refuses when `seq < last_seen_seq`; if the owner overrides, the attacker gets one window's budget **per owner-approved arm** — attended, visible, bounded; the residual of this design |
| Root rolls back to a point after the owner's last look (`seq_rolled ≥ last_seen_seq`) | owner-cli cannot tell; the enclave's check (d) cannot either. The owner is shown the restart and the enclave's seq; the loss, if they arm, is one window's budget, once, with the owner present |
| Owner-key thief | arms freely — they are the owner for every purpose; unchanged (timelock + recovery key) |
| Root on T1 | moot: reads the seed |
| A legitimate reboot at night | payouts pause until the owner's morning `arm`; nothing is lost; the operator guide says so |

## 4. What this is not

- Not a clock, not a counter, not a monitor: the enclave still cannot tell old memory from new.
  It only refuses to *act* on memory it has just loaded until someone outside the server, who
  cannot be rolled back, says "go". The two such parties are the owner (this REQ) and the chain
  (the control coin, on record); there is no third.
- Not a replacement for the mandate: inside an armed session the mandate is the bound exactly as
  today.
- The freshness witness and the receipts/monitor are untouched by this REQ (developer and audit
  tooling, out of the product path by the owner's decision); `Message::Rearm` and the sealed
  `s.armed` flag keep their current meaning for the witness. The new session-level arm is a
  different thing and is named apart in code (`session::armed()`), so the two never alias.

## 5. Changes (for the IMPL REQ; each a line here so the auditor can gate it)

| Where | Change |
|---|---|
| `core/src/proto.rs` | `Message::Arm { enclave_id, nonce, boot_challenge: [u8; 32], seq_seen: u64, sig }`: canonical encoding, digest under the policy domain tag, `verify` like the other owner messages |
| `core/src/state.rs` | `apply_message` takes a `SessionView { boot_challenge: [u8; 32] }` (pure: a value in, a verdict out); for `Arm`: signature, nonce, (c), (d); on success consumes the nonce and returns `arm: true` in the result — the core never holds the volatile flag |
| `core/src/reason.rs` | `NotArmed`, `ArmChallenge`, `ArmSeqBehind` (stable identifiers, `POLICY.md §6`) |
| `enclave/rcore/src/session.rs` | `CHALLENGE: [u8; 32]` drawn with the session id; `ARMED: AtomicBool`; `challenge()`, `armed()`, `arm()`; the `test-init` `reset()` clears both (simulates a reload) |
| `enclave/rcore/src/ops.rs` | `SIGN`: refuse `NOT_ARMED` unless `session::armed()`; `STATUS`: add `armed`, `boot_challenge`; `APPLY_MESSAGE` with `Arm`: pass the session view, arm on success; `INIT`: `session::arm()` |
| `host/signerd` | status fields passed through; nothing else (the daemon cannot arm) |
| `owner/owner-cli` | `arm` command (§2.5); `last_seen_seq` in `wallet.json` updated on every `seq`-returning call; `status` prints `armed` and the challenge |
| vectors | `NOT_ARMED` on sign after reload; replayed `Arm` → `ARM_CHALLENGE`; `seq_seen > seq` → `ARM_SEQ_BEHIND`; wrong key → `POLICY_SIG`; wrong nonce → `POLICY_NONCE`; T0 e2e: sign → reload → sign refused → arm → sign accepted; rollback drill on T0: spend, snapshot, spend, restore, reload → unarmed; owner-cli refuses to arm (`seq < last_seen_seq`) |
| docs | `HOW_IT_WORKS`/`FAQ` (both languages): the one new sentence for the operator — "after any restart of the signer, approve the start with your key; until then it signs nothing"; scenario 3 rewritten; `THREAT-MODEL.md §5` rollback row; `CONTINUITY.md` (a reboot is a pause, not a loss) |

TCB: no new crate; one message type, three reasons, one 32-byte volatile value. Enclave builds
stay reproducible (no new dependency, `MRENCLAVE` changes as for any code change; the T2 record is
re-pinned by the fused `init`/`attest` path as before).

## 6. Honest label after this round (what the docs will say)

Against anyone who comes in through BTCPay: the mandate is the bound, no one awake (as today).
Against root on a T2 server while the owner is absent: **no loss from a rollback** — a restarted
signer waits for the owner's key; the residual is one window's budget per start the owner
approves after a rollback they did not notice, with owner-cli warning on a sequence regression.
Against root on T1: unchanged (the seed is readable). Cost for the operator: one signed `arm`
after every restart, in their own time; payouts wait until then.

## 7. Questions for the auditor

1. Is the attended-override (`--i-have-investigated`) acceptable, or must owner-cli refuse hard on
   `seq < last_seen_seq` with no override (the owner would then re-initialise)?
2. Should owner messages other than `Arm` be refused while unarmed (stricter, one more signature
   in an emergency), or accepted as proposed?
3. Does the pure-core shape (`SessionView` in, `arm: bool` out) satisfy hard rule 8 in your
   reading, or do you want the challenge comparison in `rcore` only?
4. Anything that lets root obtain a signature from a freshly loaded, rolled-back state without
   the owner's `Arm` over this boot's challenge?
