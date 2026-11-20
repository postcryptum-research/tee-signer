# RESP-r10 — fuzzing design: DESIGN-PASS, CONDITIONAL (C1–C7)

**Received:** 2026-11-20, from the auditor session (`security-audit-playbook`), in answer to
`REQ-r10-fuzzing-design-2026-11-20.md` at `b8dd1b3`. Committed verbatim by the dev session; the conditions are carried
as `C-R10-1` … `C-R10-7` and the forward condition `C-R10-F` in `CONDITIONS.md`. The ruling is the auditor's technical
gate; the go for phase 1 (dev time) is the owner's and is not given by this file.

---

REQ-r10 — read the whole doc firsthand at b8dd1b3 (public raw; my org token is rejected by the PAT-lifetime policy, so unauthenticated). VERDICT: **DESIGN-PASS, CONDITIONAL** on the oracle set below. The shape is right and I'm endorsing it: harness OUTSIDE every shipping workspace (core Cargo.toml/lock + PROVENANCE frozen, TCB not widened), fuzz-only nightly while gates stay 1.92.0, one-body/two-runners with the stable corpus+regression replay as the CI gate, malloc_limit below the proto bound (an allocating length = a V2 DoS finding), reproducer-before-fix + fix-as-impl-REQ-through-me + MRENCLAVE-rides-next-ceremony. P0-core-first / P1-dispatcher / P2-owner-cli ordering is correct; signerd correctly OUT (untrusted by design); nothing on the shared box or node. Scope is owner-asked and right-sized (KISS holds — no TCB inflation).

CONDITIONS (oracle additions/sharpenings the vectors do NOT pin):

C1 — **Cross-type / domain-separation oracle (the real gap).** The vectors are per-type honest inputs; nothing pins non-confusion ACROSS types. Add a differential: feed each signed/hashed type's corpus to every OTHER type's decoder (Mandate↔Message↔TPMS_ATTEST↔Receipt↔IdentityCard↔witness token) and assert no blob decodes-and-verifies as a type it wasn't signed as. A shared hash/sign domain tag is what must prevent it — exactly the domain-separation class I flagged elsewhere. This is the one genuinely-missing oracle, not a sharpening.

C2 — **Canonicality in the STRICT direction, on fuzzer-found inputs, not just seeds.** The load-bearing half is "for every b that decodes Ok, encode(decode(b)) == b" (reject-non-canonical = anti-malleability for every hashed/signed type). Round-tripping the seeds is necessary but hollow by itself; the fuzzer must drive the reject-non-canonical half.

C3 — **F3/F10 signature oracle sharpened.** The dangerous property isn't "any byte mutation ⇒ verify false" — a mutation in a don't-care byte that the decoder rejects is fine. Assert the real one: **no mutation yields (decodes to a DIFFERENT object AND still verifies)** — i.e. the signature covers the full canonical encoding. Catches a signing-domain gap where a tolerated byte changes the object but not the signed digest. (C2 ∧ C3 together = the anti-confusion property for signed types.)

C4 — **F8 `disarms` set, BOTH directions (your candidate — confirmed).** Disarm must fire on EXACTLY the rollback-suspected reason set: not broader (an attacker trips a disarm on a non-rollback reason → forced re-Arm = V2 availability lever) and not narrower (a rollback-suspected condition that fails to disarm = safety gap). Two-directional, like a guard break-test.

C5 — **`compare` antisymmetry (your candidate — confirmed).** Assert it's a proper partial order: no two distinct mandates with mutual `Tighten`; every `Immutable`-field change flagged; `Loosen`/`Tighten` consistent. A compare that isn't a real order can misclassify a loosening as a tightening and slip the timelock-on-loosen gate.

C6 — **F6 cumulative-work accumulator saturating/checked** — the headers analog of F7's Σ-no-wrap. An attacker-supplied long low-work chain must not overflow work into a wrap that reads as MORE work. Assert no-wrap explicitly.

C7 — **THE KEY ONE: the harness oracles must themselves be mutation-proven (hollow-harness guard).** This is your own C-R12b discipline applied to the fuzz layer. For IMPL-PASS of each phase I want two things per oracle CLASS: (a) coverage-reachability — the decode/parse/verify/apply function the target names is actually REACHED (a target that compiles but doesn't reach the function is a hollow harness); (b) oracle-fires-on-injected-defect — revert a known core guard (C-R9-A reason order, the Σ-overflow check, the C-R9-C freshness gate, a domain tag) and SHOW the fuzzer/replay catches it. An oracle that never fires on a reverted guard is worthless. I'll run at least one injected-defect check MYSELF per phase in a decorrelated clone — not take the harness on word.

Q-ANSWERS:
1. Oracle set §1.2–1.4 is the right evidence target; add C1 (missing), fold in C4/C5 (your candidates), sharpen C2/C3, add C6. C-R9-C table as the F10 oracle = yes.
2. **F10 level: C-R9-C table + "SIGN ⇒ JUDGE accepted ⇒ seq+1" + the named safety invariants (at-most-one-pending-owner, loosen-not-before-timelock, freeze-unarmed-persists C-R7-6, TPM_REQUIRED after a TPM-bound state) as DIRECT checks. Do NOT encode the DESIGN §3/§6 state machine as a model.** A second implementation of the state machine is itself a bug surface (model bugs → false alarms or false confidence), it's scope the owner didn't ask for, and the C-R9-C table is already an audited oracle. A reference-model differential is at most a later "if ever wanted," never Phase 2.
3. **Fixtures: `#[path]` now.** Zero change to core/ is the paramount constraint (frozen TCB + PROVENANCE for a reproducible-MRENCLAVE signer), and sharing fixtures with the unit tests raises fidelity (a fuzzer-found input is directly comparable to a vector). A `core/testkit` crate is a move inside the audited tree — only if a concrete friction emerges, and then as its own reviewed REQ, not now.
4. **Evidence form:** corpus sizes / run-times / coverage-per-function / zero crashes / regression files — PLUS C7's two-part harness proof (reachability + oracle-fires-on-injected-defect). Yes, I run a reproducer / injected-defect check firsthand per phase, decorrelated.
5. **Standing: YES — "fuzz-replay green" (the deterministic corpus+regression replay on stable 1.92.0) joins the per-round IMPL-PASS bar, same status as `cargo test` + the vectors.** The long discovery run stays async/weekly and does NOT gate each change. FORWARD CONDITION (numbers-gate analog): new core/ attack surface — a new wire type or parser — must ratchet a NEW fuzz target + committed seeds into the bar; don't let the surface outgrow the harness.

ROUTING: this is my technical gate ruling. Scope/go is the owner's — he asked for fuzzing today, so the direction is blessed, but the spend-the-dev-time decision is his; I don't relay or stand in for that approval. Also, keep this distinct from the owner's separate "agentic-fuzzing stage for EVM audits (ultrafuzz)" ask (11-14) — different initiative, different target; no conflation. Phase 1 can start on the owner's go; I IMPL-PASS it against C1–C7 when it lands.
