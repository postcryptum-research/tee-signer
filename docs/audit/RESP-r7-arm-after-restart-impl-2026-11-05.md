# RESP — R7 IMPL: no signature after a restart until the owner arms the enclave — SOURCE IMPL-PASS

**Date:** 2026-11-05 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r7-arm-after-restart-impl-2026-11-05.md` on `r7-arm`
(checkout clean @ `bd80e48`, code `6022ce9`). Recorded verbatim by the dev session.

---

Verdict: SOURCE IMPL-PASS. Read at the pinned commit (checkout clean @bd80e48, code 6022ce9, pause MRENCLAVE ca5c1a6…). All of C-R7-0..10 hold in code, and the two blocking checks pass:

- C-R7-1 (RDRAND): session.rs ensure() → sgx::read_rand; the enclave branch is ffi::sgx_read_rand with `if rc != SGX_SUCCESS { abort() }` — in-enclave, no OCALL, and fail-closed so a failed RNG can never leave a predictable/zeroed challenge. The nosgx SHA-stream is unmistakably sim-only. PASS (with the obvious build-flag note: prod must not be built with nosgx — I confirm that when I reproduce ca5c1a6).
- C-R7-4 (completeness): I enumerated dispatch() myself. The only spend signature is sign_own_inputs(account_xpriv) at ops.rs:593, inside sign_op after the armed() gate (569, and it checks the boot-arm itself, not only via judge). The other two sign_digest_secp calls sign the card (218) and receipt (598) with id_sk — attestations, no spend. No ungated signer. PASS.
- C-R7-0: the gate reads the distinct volatile session::armed(); the sealed s.armed (the witness's) is untouched and only surfaced in STATUS. Good.
- C-R7-3: apply_message runs check_seq first, and on Arm calls session::raise(ns.seq) BEFORE session::arm() — HWM ratchets to the arm-blob's seq before arming, so arm-high-then-sign-low is closed exactly as asked.
- apply_arm (state.rs:510): owner-sig + enclave_id, nonce==next, c != boot_challenge → ArmChallenge, seq_seen > s.seq → ArmSeqBehind, pure with the challenge passed as data. Every check I wanted is there.
- C-R7-8: enclave/Makefile has AUTO_ARM build-time only with $(error) on AUTO_ARM+CEREMONY and --features auto-arm compiling the pause out (armed() becomes const true). The auto_arm flag in the card/report is cfg!(feature=...) — compile-time, so it can't be runtime-forged. 9/10 good.

SOURCE IMPL-PASS clears merge to main. What stays as the deployment-facet, standing and not merge-blocking:
1. My reproducible build of ca5c1a6 — confirms the deployed enclave is the reviewed source and wasn't built with nosgx. This is my gate before I'll call it deployed-trusted; same as every other MRENCLAVE in the stack.
2. The T1 hardware restart drill (real reload → NOT_ARMED, then a real owner Arm over a real in-enclave challenge).
3. T2 deploy after the YubiKey part-2 evidence at 329586 — a new MRENCLAVE means a live re-init, so sequence it after part-2 lands.
4. C-R7-8's different-MRENCLAVE artifact is OWED before the opt-out is ever offered. The Makefile logic is correct; your gap is that docker/build-enclave.sh doesn't forward AUTO_ARM into the container, so the first auto-arm build measured identical to pause. That's the safe direction (an inert opt-out = you get pause), so it doesn't block this PASS — but until you can show me pause-MRENCLAVE ≠ auto-arm-MRENCLAVE and the auto-arm one dev-signed, the opt-out must not be offered. Carried as open.

One honest scope note on my side: I verified the CODE supports C-R7-6 (freeze persists, the pending loosening keeps its height across restart+arm) — the sealed blob carries those forward and apply_arm calls activate_pending — but I did not re-run your e2e; your drill is the evidence for the runtime behaviour.

Clean work. Go ahead and start R8 on its own branch; I'll pick it up when it's pushed. And ping me when the repro build and the T1 drill are ready — those plus the 329586 re-init are what turn this from source-pass into deployed-trusted.

---

**Dev's reading:** IMPL-PASS for merging `r7-arm` to `main`. Carried as the deployment facet:
C-R7-11 (the auditor's reproduction of `ca5c1a6a…`), C-R7-12 (the T1 hardware restart drill),
C-R7-13 (T2 deployment after the YubiKey part-2 evidence at 329586: a live re-init), and C-R7-8's
artefact (the opt-out's own, dev-signed MRENCLAVE) before any operator is offered the opt-out.
