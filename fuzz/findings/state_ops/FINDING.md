# Open findings — `state_ops`

A finding is a committed reproducer that fires an agreed oracle (REQ-r10 §3 "findings path"). It stays here, and
the replay test asserts it **still fires**, until the fix or the auditor's ruling lands; then the file moves to
`regressions/state_ops/` and the entry below gets its RESP reference. Nothing is fixed quietly.

## F-2026-11-21-01 — `apply_arm` / `apply_anchor` verify the owner's signature against the owner **before** a due rotation activates (F4)

**Status:** RESOLVED on branch `r10-f02-owner-at-activation` (`REQ-r10-f02-owner-at-activation-timelock-cap-2026-11-21.md`;
IMPL-PASS pending, merge after it, a new MRENCLAVE with the next ceremony build). The reproducer now lives in
`regressions/state_ops/` and passes. Originally: OPEN — **ruled a DEFECT by the auditor, 2026-11-21, severity LOW** (`RESP-r10-fuzzing-p2i-impl-2026-11-21.md` §2:
`Anchor` re-pins the rollback-protection root — AK, NV name, expected counter — so one more `Anchor` for the key being
retired is a one-shot re-rooting of rollback trust, bounded by the new owner's next `Anchor`; the direction is backwards
for what rotation is for). Fix authorized as drafted (activate first, verify against `s.owner_pk`), break-tested both
ways, in the next core round (`REQ-r10-f02-owner-at-activation-timelock-cap-2026-11-21.md`); the reproducer moves to
`regressions/` when that fix lands with its IMPL-PASS. Found by the `state_ops` target in the post-fix shakeout of phase 2
pass (i) (2026-11-21, two workers, within ten minutes). **Reproducer:**
`F-2026-11-21-01-arm-anchor-pre-activation-owner` — four scripted steps: `RotateOwner` to the witness key (pending
owner at `best + timelock`), the chain advanced 561 blocks (the rotation is due), then an `Anchor` signed by the
**new** owner ⇒ `POLICY_SIG`. `cargo run --no-default-features --example explain -- state_ops <file>` is not wired
for this target; the records decode as `[kind, flags, a, b, e, …]` per `src/structured.rs` (`4 0 0 bb`, `9 bb 46 …`,
`7 0 0 07`, `0 …`).

**What fires.** The harness's rule "the owner who may sign an operation is the owner at that operation" — i.e. after
a due pending rotation has activated — holds for every `apply_message` arm (`state.rs:401–408`: `s =
self.clone(); s.activate_pending(); … msg.verify(&s.owner_pk)`) but **not** for `apply_arm` (`state.rs:557`) and
`apply_anchor` (`state.rs:611`), which verify `msg.verify(&self.owner_pk)` — the owner **before** `activate_pending`
runs on the clone three lines later.

**Effect, as the dev reads it (for the auditor's ruling, not a verdict).** During the window between a rotation's
activation height and the next accepted operation (activation is lazy, by design):
1. the **new** owner's `Arm` or `Anchor` is refused `POLICY_SIG` — a liveness nit; any other owner message (even a
   harmless `Cancel`, verified against the post-activation owner) activates the rotation, after which the new
   owner's `Arm`/`Anchor` is accepted;
2. the **old** owner key still signs one accepted `Arm` or `Anchor` past the activation height — the operation that
   itself activates the rotation. `Arm` makes this load operational within the installed mandate; `Anchor` (first
   anchor, or re-anchor on the same objects) pins the TPM counter. Neither changes what may be signed (judge's
   boundary is the installed mandate), so this is an inconsistency in **who** may perform two liveness operations
   at the rotation boundary, not a signing-boundary change. The rotation itself is owner-signed and timelocked; the
   old key was the owner's own until the activation height.

**Against the design of record.** `POLICY.md` / REQ-r7: `Arm` and `Anchor` are "verified like every owner message —
signature, enclave id, next nonce" — "like every owner message" is exactly what differs here: every other owner
message is verified against the owner after activation.

**Possible fix (a proposal, not a change — hard rule 1):** in `apply_arm` and `apply_anchor`, clone and
`activate_pending()` first, then verify against `s.owner_pk` (two lines moved in each); vectors: the new owner's
`Arm`/`Anchor` accepted right after the activation height, the old owner's refused `POLICY_SIG`. One
`signer-core` change ⇒ an impl REQ, IMPL-PASS, a new MRENCLAVE with the next ceremony build — a candidate to ride
the same core round as the O01 deploy and the `timelock_blocks` cap question (REQ-r10 pass (i) §4).
