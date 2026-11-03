# RESP-r2-enclave-shell-2026-11-03 (auditor's text, verbatim)

**Auditor:** `security-audit-playbook-13`, 2026-11-03. Bound to `r2-enclave-shell` @ `fd64e1e`.
Recorded verbatim per `PROTOCOL.md`; the dev's disposition follows.

---

RESP-r2-enclave-shell-2026-11-03 (commit verbatim before merge; English). Bound to r2-enclave-shell @fd64e1e.

# VERDICT: IMPL-PASS (merge enclave/, host/signerd, owner/owner-cli, core headers/proto/bip39, vectors/headers/ to main)
I read the two load-bearing new TCB pieces firsthand — the header verifier and the two-phase JUDGE/SIGN + session-HWM (the seq-fork I flagged). Both correct. The rest (seal envelope, init/install, gate-1) I accept on the hardware smoke + the LIVE signet first-signature + 51 vectors through the real ecalls + the design. No FAIL; the enforce/custody prerequisites are correctly carried to R4/R5.

**Firsthand confirmations:**
- **Header verifier (headers.rs, C-R3a–c) ✅** — the `bitcoin` crate's own `CompactTarget::from_next_work_required`/`Target`/`Work` (not hand-rolled); EXACT required nBits (:166, not just ≤target); `validate_pow`; median-time-past over header timestamps only (no wall-clock); checked 256-bit work add (overflow→refuse); adopt ONLY if strictly more work (:192); reorg deeper than maxReorg FREEZES + seals (:134). Labeled edge: the testnet4 fork-crossing-boundary `period_bits` approximation is exact on signet/mainnet — fine for the signet target.
- **Two-phase JUDGE/SIGN + HWM (ops.rs/session.rs, C-R13/§4a) ✅** — JUDGE raises the HWM (:448), records `last_judged{sha256(PSBT bytes),txid,seq,receipt}`, seals the charged blob; SIGN refuses unless `psbt_hash==sha256(exact bytes) && lj.seq==s.seq` (:488, D-R2-3 byte-exact); `check_seq` (seq≥HWM) on BOTH (:428/:483) ⇒ second-judge-from-base → SEQ_BEHIND_SESSION; `reset()` is `#[cfg(test-init)]` only (release can't reset — only a restart, which rotates the per-load `session_id` carried in every SignResponse). The sign-time re-classify with bounds widened by `own_index_gap` is safe (identical bytes⇒identical own-set; wider never admits foreign). Commit-before-sign enforced IN-ENCLAVE.
- **Identity key separate from seed (C-R1-2) ✅** — init draws `identity_sk` separately from `sgx_read_rand`, `enclave_id=SHA-256(identity_pk)`; envelope holds it apart from `seed`.
- **LIVE signet first signature ✅** — txid f8b12c1a…, 5000 unlisted + 1000 fee, `window_outflow 6000` = fee INSIDE net outflow exactly as I ruled R5; FEE_ABS refusal charged nothing; receipt seq 1.

# Deviations ruled (§5)
- **D-R2-1 (gate-1 = "our-code 0 + exactly the pinned SDK 8-set", not whole-.so zero) ✅ ACCEPTED, honest.** Zero-cpuid in the whole .so is impossible: `sgx_trts`→`sgx_init_crypto_lib`→`libsgx_tcrypto`(IPP) carries emulated cpuid. The residual (the SDK's 8 host-emulated cpuid sites) is **DoS-only** — a lying host can crash the enclave (which it can do anyway by not launching it); it does NOT break confidentiality/integrity (sealing is MRENCLAVE-bound and crypto correct on any path). ⛔CONDITION: the build must assert EXACTLY the pinned set (count + site-list diff) on the FINAL .so — the 12-extra catch (aes/polyval autodetect, removed by force-soft cfg) proves the assert works; keep it so a future dep adding cpuid is caught. Our-code-0 (the unreferenced compiler_builtins libm member the link drops) is fine.
- **D-R2-2 two-step init ✅** — binding the owner at INIT (before the wallet fingerprint exists for a mandate) is sound; a keys-only blob can only become full under a mandate the bound owner signed.
- **D-R2-3 PSBT-hash binding ✅** — confirmed firsthand (above).
- **D-R2-4 TCSPolicy=1 ✅** (OUT_OF_TCS found live; single runtime thread — acceptable, the daemon serializes).
- **D-R2-5 Recover voids pending + RotateOwner refuses recovery-key + INIT refuses owner==recovery (C-D3b(1)) ✅.**
- **D-R2-6/7 checkpoint/feed ✅** — trust root moves only forward to verified work; daemon transports, enclave judges forks.
- **D-R2-8 atomic persist, charged blob BEFORE sign, refusal-payload persisted ✅** — the shell's half of the ordering.
- **D-R2-9 owner-cli keyfile scrypt 2^18 + AES-GCM, refuses <2^18, policy-show --json diff + classification + policy-sign prints fields+hash (C-R14 WYSIWYS) ✅** (D3 floor, no-blind-sign).
- **D-R2-10 real signet retarget vectors ✅.**

# Carried to R4/R5 — ENFORCE/CUSTODY prerequisites (not testnet-dev blockers), each correctly stated
1. ⛔**The R4 monitor (chain-observation) is the cross-restart seq-fork detection** — the HWM prevents the within-load fork and the session_id makes a restart visible, but the automated detection (on-chain spend with no matching receipt + duplicate-seq across sessions, per my R2-preview ruling) is R4, specified-not-built. It MUST exist before enforce on real value (the seq-fork bound rests on it). Receipts carry session_id so it is detectable post-hoc now; the automated monitor is the gate for enforce.
2. ⛔**Reproducible build (gate-5/C-R1-3)** carried to R5 (method agreed: MRENCLAVE + SIGSTRUCT minus header.date). Until it lands, the identity-card MRENCLAVE can't be tied to audited source by the owner — so the TOFU/identity claim is not yet owner-verifiable. Fine for T1-debug testnet; required before any custody/TRUST claim.
3. ⛔**RELEASE=1 + DisableDebug=1 (T2/FLC)** — the deployed enclave is a `test-init`/debug build (TEST_INIT/TEST_RESET_SESSION present, reset() reachable). gate-2 asserts test symbols absent for RELEASE=1. The enforce/custody deployment must be the RELEASE=1 build on FLC/DCAP with DEBUG pinned 0; current T1-debug is correct for dev. (R5.)
4. D-11 descriptor-matching cost: unmeasured (no trusted descriptor in the live mandate yet); carried.

Merge R2. Send R4 (the monitor — chain-observation primary) and R5 (repro-build, RELEASE=1, T2-DCAP) REQs at their commits; I rule each firsthand, with the monitor's duplicate-seq + on-chain-spend-without-receipt detection as the named gate for any move toward enforce. Strong round — the LIVE signet signature with the fee-in-outflow accounting and the executed SEQ_BEHIND_SESSION are exactly the bar.

---

**Dev's disposition (2026-11-03):** merged to `main`. R2 gates discharged in `CONDITIONS.md`; carried:
C-R2-2 (the R4 monitor — chain observation primary — is the gate for any enforce on value),
C-R2-3 (reproducible build before any custody/TRUST claim, R5), C-R2-4 (RELEASE=1 + DisableDebug=1
on FLC/DCAP for enforce, R5), C-R2-5 (gate 1 keeps asserting the exact pinned set), C-R1-1 (D-11
cost, still open).
