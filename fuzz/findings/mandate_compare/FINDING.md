# Open findings — `mandate_compare`

A finding is a committed reproducer that fires an agreed oracle (REQ-r10 §3 "findings path"). It
stays here, and the replay test asserts it **still fires**, until the fix or the auditor's ruling
lands; then the file moves to `regressions/mandate_compare/` and the entry below gets its RESP
reference. Nothing is fixed quietly.

## F-2026-11-20-01 — `compare` treats a changed checkpoint at the same height as tightening (C-R10-5)

**Status:** RESOLVED on branch `r10-f01-checkpoint` (fix REQ `docs/audit/REQ-r10-f01-checkpoint-impl-2026-11-20.md`,
DESIGN-PASS CONDITIONAL `docs/audit/RESP-r10-f01-checkpoint-design-2026-11-21.md`; **IMPL-PASS**
`docs/audit/RESP-r10-f01-checkpoint-impl-2026-11-21.md`, clean at `10f6770`, merged via PR #2; **deployed on T2 2026-11-21** as MRENCLAVE `2ae88422…`). The four reproducers now live in `regressions/mandate_compare/`
and pass C-R10-5 in both directions; the entry below is kept as the record. Note the auditor's re-ruling of the
frozen path: a re-pin while the chain is frozen applies at once (never through the timelock, which cannot run
while frozen) and is checkpoint-only — see the RESP. Originally: OPEN — **ruled a DEFECT by the auditor, 2026-11-20, two legs** (reported the same day; phase 1, first
45-second run of the target; the oracle fired after 82 executions). Leg 1: `compare`'s checkpoint rule — the
proposed one-line fix below is approved as correct. Leg 2 (the auditor's, confirmed firsthand in
`state.rs`): the install path's `known` check matches hash + height only and must also require the new
checkpoint's `time`, `bits`, `period_start_time`, `period_bits` to equal the matched recent header's — a real
hash with attacker-chosen parameters is an internally inconsistent forgery that install accepts today.
Severity: medium (a weakening of the V5 timelock control scoped to checkpoint content; chain-view impact
gated on a frozen chain). The oracle is NOT weakened. Fix: one impl REQ on a branch, both legs, with the
break-tests the auditor named; IMPL-PASS firsthand; new MRENCLAVE with the next ceremony build; nothing
deploys without the owner's GO. The same fix REQ carries the auditor's constructor-side requirement from the
reflexivity observation (`regressions/mandate_decode/REG-2026-11-20-01-*`): `State::new_at_init` must refuse (or at
least `debug_assert!`) an invalid mandate, so "the installed mandate is always validated" is enforced at the write
site and `compare`'s validity precondition rests on an invariant, not on caller vigilance. `compare` itself stays
as is (auditor: no duplicate-label defence in compare — `validate` owns it). **Reproducers:** `F-2026-11-20-01-checkpoint-{time,bits-a,bits-b,hash}`
(input layout: `u16 LE len(a)` ‖ `a` ‖ `b_bytes`; `b` is produced from `a` by `targets::mutate_mandate`
driven by `b_bytes` — `cargo run --no-default-features --example explain -- mandate_compare <file>` prints both
mandates and the differing field).

**What fires.** Two mandates that differ **only** in `checkpoint.time`, `checkpoint.bits`, one byte of
`checkpoint.hash`, `checkpoint.period_start_time` or `checkpoint.period_bits` — same `checkpoint.height`,
everything else equal — classify as `Tightening` in **both** directions. (The four reproducers cover time, bits
and hash; the one-hour run of 2026-11-21 past this finding — fork mode, `-ignore_crashes=1` — produced 560
crashes, every one of them this class: by the differing field of the firing pair, hash 244, bits 95,
period_start_time 82, period_bits 78, time 59, two with two fields; classified with `explain`, log
`.local/fuzz-runs/hour-classify-mandate_compare.log` on the laptop. No other class appeared.) `mandate::compare` (`core/src/mandate.rs`, the checkpoint line) tests only
`new.checkpoint.height >= installed.checkpoint.height`; the hash, time, bits and period fields do not take
part in the classification.

**Against the design of record.** `POLICY.md §5`: `chain.checkpoint` is tightening when **moved forward**;
"a field … not *provably* tightening by the table … makes the whole update loosening"; "the classifier
fails toward loosening (auditor R6, load-bearing)". A checkpoint with the same height and different
content is not moved forward and is not equal, so by the text it is loosening. The code says tightening.
Under hard rule 4 that is a defect against the doc or the code — the auditor rules which.

**Install path (read, not fuzzed — `core/src/state.rs`, `apply_message`, the `PolicyUpdate` arm).** A new
mandate whose checkpoint differs from the installed one is accepted when a header in `chain.recent` has the
same **hash and height** (`known`), or unconditionally while the chain is frozen (`repin`). The checkpoint's
`time`, `bits`, `period_start_time`, `period_bits` are **not** compared with the known header record. With
the chain unfrozen nothing consumes them at install; they sit in `state.mandate.checkpoint` and are read by
`ChainState::from_checkpoint` on two frozen-chain paths: the re-pin branch of the same arm (a tightening
re-pin restarts the chain from the new checkpoint at once) and `activate_pending` when a pending mandate
activates while frozen.

**Impact as understood by the dev (for the auditor's ruling, not a verdict).** (1) A checkpoint-content-only
change applies **at once** instead of waiting the installed mandate's timelock — the timelock is the control
against V5 (owner-key thief; `THREAT-MODEL.md`), who can thus plant attacker-chosen difficulty parameters into
the installed mandate without the recovery key's cancel window. (2) Those parameters become the chain's
view only on a frozen-chain path, which on signet needs a reorg deeper than `max_reorg` — hard for an
attacker without the signet key; easier on testnet4. (3) Separately, the `known` check at install compares
hash and height but not the other checkpoint fields — worth the auditor's look whether that is intended.

**Possible fix (a proposal, not a change — hard rule 1):** in `compare`, the checkpoint is tightening iff
`new.checkpoint == installed.checkpoint || new.checkpoint.height > installed.checkpoint.height` (equal is
fine, forward is forward, anything else is loosening). One line in `signer-core` → an impl REQ, an IMPL-PASS,
a new MRENCLAVE with the next ceremony build. With it the four reproducers pass C-R10-5 (forward ⇒ the reverse
direction is a loosening) and move to `regressions/`.
