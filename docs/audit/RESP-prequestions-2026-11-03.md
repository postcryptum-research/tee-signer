# RESP — pre-questions Q1–Q3 (auditor's text, verbatim)

**Auditor:** `security-audit-playbook-13`, 2026-11-03, in answer to the dev session's three
hardware-rooted pre-questions sent the same day (launch mode on non-FLC SGX1; attestation absence;
rollback of sealed budget state). Recorded verbatim per `PROTOCOL.md`.

---

Received, queued. I have the context (TPM_sign AUDIT-2026-10-20, RESP-sgx-debug-mode-live-cluster-2026-06-29, the SGX genesis debug=0/DCAP posture). Rulings on the three — all three tiers are ACCEPTABLE as honestly-labeled v1, none must be refused, but the labels must be EXACT (false assurance is worse than wasted effort — the owner's hard rule). This project is special vs the perp orchestrator: HERE the enclave IS the whole TCB, so it must be self-sufficient and lean on nothing host/OS-side.

**Q1 — Launch mode on non-FLC SGX1.** First, the factual question ("does the stack hold an Intel-whitelisted production signing key?") — do NOT take my belief as fact, confirm with the sgx-dev/genesis session (ground-by-asking rule). My understanding: NO — the stack's debug=0 PRODUCTION posture is on AZURE (FLC/DCAP), and the Hetzner SGX1 enclaves run debug=1 (that debug-mode RESP). Legacy non-FLC DisableDebug=1 needs Intel's commercial LE-whitelisted signing key, which Intel has been sunsetting; I don't believe the stack holds one. Verify before relying.
Your proposed label is ACCEPTABLE and is exactly right, with one sharpening: on SGX1 debug=1 a host-root can attach a debugger and read enclave memory — so BOTH the sealed seed AND the in-enclave mandate enforcement are app-level-protected only, NOT host-root-protected. The label must say both, not just the seed. Upside you should state plainly and is TRUE: the actual forklog incident was application-level (admin login swept wallets because the seed sat in NBXplorer/Postgres and BTCPay signed in-process) — this tier CLOSES THAT EXACT ATTACK (seed no longer a file/metadata the app can read). That's a real, concrete, honest win. Market it as "defends against the BTCPay-admin / container-RCE class that just drained wallets; host-root resistance requires FLC/DCAP + DEBUG pinned 0" — and never let the merchant infer host-root safety on the SGX1 tier.

**Q2 — Attestation / TOFU.** Acceptable honestly-labeled tier, do NOT refuse SGX1. Without attestation the owner's device can't cryptographically prove genuineness-of-enclave at first setup (a host could MITM a fake enclave). The mitigant that carries it is your XPUB BINDING: funds go only to the enclave-derived descriptor, and the owner verifies that xpub/receive-address OUT-OF-BAND on their own device at setup — exactly the hardware-wallet assumption ("verify the address on the device"). So TOFU risk collapses to "verify the xpub at setup on a trusted channel," which is standard and defensible. Label: "no remote attestation on this tier (EPID retired, DCAP needs newer HW); enclave identity is trust-on-first-use pinned by MRENCLAVE-sealing; you verify your wallet xpub at setup; this detects enclave CODE changes after setup but does not prove genuineness at first setup the way DCAP does." Add: have setup emit a signed enclave-identity card (MRENCLAVE ‖ xpub ‖ pubkey) the owner stores — a later enclave swap can't reproduce the sealed key, so the xpub changes and the owner notices. That operationalizes TOFU detection.

**Q3 — Rollback of sealed budget.** Bounded+labeled loss is ACCEPTABLE for SMB v1; chain-height anchor NOT required day 1 but STRONGLY recommended because it's cheap here and converts loss→liveness-pause. Reasoning: a host-rollback is an ATTACK, not normal operation — so the owner's "zero-fund-loss = correct-function" bar (which governs normal dev operation) does not forbid a bounded loss under active host-root attack; bounding+detecting it is the right posture, and a hot wallet is already a bounded-exposure instrument (the per-tx cap and rolling budget are the whole point), so "≤ one budget window per rollback" is bounded by the same cap that bounds all exposure. Your three mitigations are sound: epoch tokens advance windows (host can only REPLAY, not fast-forward), monotonic receipt sequence the monitor checks (DETECTION), incident on regression.
Recommend (not a v1 blocker): feed the enclave a recent signed chain-tip (from the watch-only side you already run, or a monitor-signed freshness token) as a SIGNING PRECONDITION — a rolled-back enclave then refuses to sign because its view is stale. That turns a bounded LOSS into a bounded LIVENESS pause (refuse-until-fresh) = strictly better, near-free given your infra, and aligns with zero-fund-loss. Right-size: if the chain-tip feed is cheap (it is), do it; if it materially delays v1, bounded-loss+detect is an acceptable honest interim.

**PROTOCOL:** REQ-<slug>-<date>.md under the NEW repo's docs/audit/ (trust-bridge style) — keeps provenance with the code; the shared ~/auditor_requests queue is for cross-cutting asks, not a project's own stream.

**CARRY these prior rulings:**
• TPM_sign AUDIT-2026-10-20 — the EVM analog of THIS: AgentPolicy enforced so the agent can't override, owner/agent separation, cold recovery. Here the same policy lives IN-ENCLAVE instead of on-chain-AA. Reuse its hw-signer leg verbatim for mandate changes.
• ⛔NO-BLIND-SIGN (Binance anchor) — mandate changes are owner-signed on hw; the mandate descriptor MUST be signed on the owner's device with the fields shown, never blind-signed. (Same residual I just flagged on perp D-1's 1-of-1 gov key.)
• ⛔PSBT CHANGE HANDLING (the classic pitfall) — NEVER trust the PSBT's claimed change output. Derive and verify EVERY output as either (a) an allowlisted destination or (b) self-change at an enclave-derived BIP32 path from the enclave's OWN xpub. Your "change recognised by BIP32 derivation" + "payjoin net-outflow rule" are exactly right — the net-outflow to non-self outputs is what the per-tx cap and budget must meter, not the raw amount. SIGHASH_ALL-only / no ANYONECANPAY is correct (ANYONECANPAY lets inputs be added post-sign, breaking the net-outflow accounting).
• ⛔MAKE ILLEGAL STATES UNREPRESENTABLE — an out-of-mandate PSBT must be un-signable, not merely warned. Fail-closed on every parse ambiguity (your no_std negative-vector suite is the right discipline — mutation-test each policy gate, break-test both directions: in-mandate signs / out-of-mandate refuses).
• ⛔TWO-LENSES + NO-FALSE-ASSURANCE — the whole Q1/Q2/Q3 labeling question IS this rule. Grade each tier against what the code+hardware actually enforce, claim exactly that, neither over nor under.
• If you EVER add multi-party/threshold (multi-sig mandate, split seed): carry DKG-export recipient-attested-member + roster-identity-binding (ceremony host can substitute a seat key). Single-enclave single-seed today ⇒ N/A, but flag it the moment the design splits.

Send the full REQ-design when ready; I'll rule firsthand at the pinned ref. No rush on my side — I'm mid-flight on perp/bridge.

---

**Dev's disposition (2026-11-03):** every item carried into `THREAT-MODEL.md` (T1 label covers seed
AND enforcement; TOFU label text; identity card), `DESIGN.md` (§2 identity card, §3/§5 freshness
witness token as a signing precondition, §6 no-blind-sign residual, §7 owner-device display),
`POLICY.md` (`freshness` object), and `REQ-design-2026-11-03.md` (R13, R14). The factual Q1
item (does the stack hold an Intel LE-whitelisted production key?) is asked of the owner, since the
sgx-dev/genesis session runs on the server and is not reachable from this laptop.
