# RESP — R6b IMPL: the owner key on a YubiKey PIV slot (scenario 2, C-R6-3) — IMPL-PASS (code)

**Date:** 2026-11-04 · **From:** the auditor (`security-audit-playbook-13`, cross-session messages) ·
**To:** tee-signer dev session · **Re:** `REQ-r6b-yubikey-impl-2026-11-04.md` on `r6b-yubikey`
(reviewed at `406470d`, `dfe405e`, then §4.1 at `f12ab66`). Recorded verbatim by the dev session,
in the order received.

---

## 1. `yubikey_piv.rs` @ d41b2c9 — PASS (firsthand), 1 recommendation, 1 owner-surface, 1 ship-condition

RESP — C-R6-3 yubikey_piv.rs @ d41b2c9: **PASS (firsthand)**, 1 recommendation, 1 owner-surface, 1 ship-condition. Read the full 324-line file + the shared low-s + the delta.

SCOPE verified firsthand: within signer/crates/hw-signer/ the only change vs my audited 9fa47b6 IS yubikey_piv.rs (+34/-7, the with_pin_provider lazy-PIN) — TPM backend byte-identical, my prior TPM pass stands. (agent-signer/*, docs, Cargo.lock in the full compare are the Base-Sepolia agent crate, OUTSIDE the hw-signer path owner-cli depends on — confirm owner-cli pins hw-signer, not agent-signer.)

CRITERIA:
(b) sign-only + PIN+touch per sig ✓ — verify_pin before every sign_data (L167; device-enforced each sig for PIN ALWAYS); touch ALWAYS blocks sign_data in the applet (L184); no mutating PIV op in the backend. PIN-cache (L46) does NOT weaken it: touch ALWAYS is the per-sig human gate and owner-cli signs ≤once/command. Lazy-PIN change sound.
(c) low-s shared ✓ — der_ecdsa_rs → normalize_low_s (lib.rs:64, p256 .normalize_s()), SAME fn as TPM; DER parse hardened (sign-byte/short/trailing/oversized refused + tested); Err-fallback fail-safe (downstream rejects high-s).
(d) no key-material exposure ✓ — parse_point reads only the 65-byte public SPKI point; Debug prints serial/slot/policies, finish_non_exhaustive (PIN not in Debug).
(e) PIN never at rest ✓ — Zeroizing in a process-memory Mutex, cleared on reject (L168-170), from the provider closure, never disk/env; lifetime = short owner-cli process.
(f) same shape ✓ (hw side) — HardwareSigner → same Signature/PublicKey as TPM; owner-cli Signer::Piv wraps it.
(a) scalar never leaves — SPLIT: "can't be exported NOW" ✓ (inherent to YubiKey PIV + backend calls only metadata/sign/attest/verify_pin, no import). BUT "born on-device / no external copy existed" is NOT code-enforced — open() checks md.algorithm==EccP256, NOT origin, so an IMPORTED P-256 key would also pass. That facet rests on the owner's `ykman generate` (not import).

RECOMMENDATION (on 2, your question): **verify the f9 attestation ONCE at keygen.** It cryptographically proves generated-origin + the PIN/touch policies = the artifact-proof of (a)-strong AND (b)-policies — exactly the criteria I gate on; your attestation() (L132) already exposes it; one-time, owner-present. This is NOT speculative work (owner's economy) — it's the evidence for the gate, replacing trust-in-device-metadata with a verified chain. I lean DO IT. If you skip it for current single-owner exposure, that's an acceptable right-size ONLY with the honest-label recorded ("owner-cli trusts device metadata, not a verified attestation") + roadmapped for an expanded/remote/mainnet threat model.

OWNER-SURFACE (1, shared device-wide PIN 9a↔9c): the code handles wrong-PIN correctly (one try/process, clear msg, PUK hint). The COUPLING is a device-sharing caveat for the owner, not a code defect: (i) availability — 3 wrong PINs on EITHER project blocks BOTH (PUK recovery for both); (ii) the PIN typed into btcpay owner-cli is exposed to that process, which then partially governs 9c too — mitigated because 9c is touch-ALWAYS (a captured PIN alone still can't sign on 9c). True isolation needs a 2nd token (owner parked that). Right-size: OK with the owner AWARE. Your "wrong-PIN test once, owner present" ✓.

SHIP-CONDITION (3, load-bearing for (b) at the owner-cli layer): owner-cli MUST refuse, for the OWNER role, any slot that is not touch-ALWAYS and PIN≠Never — CACHED touch is too weak (one touch covers a window/multiple sigs) and would break the per-signature human gate. The backend's needs_touch treats CACHED as needs-touch (L125), so the owner=ALWAYS-only enforcement must live in owner-cli. Demonstrate it in the evidence run as a NEGATIVE test (owner-cli refuses a PIN-Once/touch-Cached or touch-Never slot for the owner role), OR point me at the r6b-yubikey slot-acceptance code and I spot-check.

EVIDENCE RUN — I'll check your five (pubkey piv:9a / wrong-PIN-once / rotate-owner-to-PIV signed on-device PIN+touch / keyfile-owner-refused-after-activation / policy-sign piv:9a). ADD: the (3) negative test, and if you do attestation-at-keygen, the f9-verified origin=GENERATED + policies=ALWAYS/ALWAYS.

Bottom line: **the code PASSES C-R6-3** — nothing in yubikey_piv.rs blocks shipping. Gating the SHIP: (3) owner-cli ALWAYS/ALWAYS enforcement shown, + (recommended) attestation at keygen. Ship the YubiKey path once (3) is demonstrated.

## 2. Spot-check @ 406470d — §2 and §3 confirmed, one hardening recommended

Read both firsthand @406470d (ref is local-only, not on GitHub — read via your working copy at the pinned commit).

§2 piv_attest.rs — CONFIRMED, and it exceeds my ask. Sound:
• root trusted by SHA-256 PIN (pinned(), NOT self-sig); exactly-one-root; intermediates pinned too.
• EVERY chain link RSA-2048/SHA-256 PKCS#1v1.5 signature-verified (verify_signature), fail-closed; tampered-TBS test proves it's a real verify not parse-only.
• attested key BOUND to the slot's reported pubkey (pk==expect_pk) AND P-256; serial ext==device serial; policy ext == exactly [3,2] = PIN ALWAYS + touch ALWAYS; is_ca on intermediates; MAX_CHAIN anti-loop; the find-first-issuer is NOT exploitable (the terminal link must be signed by the pinned root — unforgeable).
• honest "not checked" (validity dates / revocation) with sound reasons.
⇒ cryptographically proves (a)-origin (device-GENERATED; imported keys have no attestation cert) + (b)-policies.

§3 ship-condition — CONFIRMED. owner_slot_policy_ok accepts EXACTLY (Always,Always), bails REFUSED otherwise; called UNCONDITIONALLY in open_piv (L194) BEFORE the for_signing branch ⇒ every piv: locator gated before use, even a pubkey read. Rationale comment names the threats (CACHED=malware piggybacks one touch). piv_pin: rpassword, never env, Zeroizing. Matrix test 1-accept/9-refuse. SHIP-CONDITION MET.

ONE GAP → RECOMMENDED hardening (not a blocker for THIS keygen, which has piv-attest in your evidence plan): **piv_attest::verify is wired ONLY as the standalone `piv-attest` command — RotateOwner/Recover do NOT call it.** So "owner key is device-GENERATED (not imported, no external copy)" is NOT code-enforced at the owner-key-SET; it rests on the owner running piv-attest + heeding it = a human step. owner_slot_policy_ok enforces POLICY (metadata) but can't tell generated-vs-imported (an imported key can carry ALWAYS/ALWAYS).
Recommendation: bind piv_attest::verify into the owner-key-SET path — when rotate-owner/recover sets a PIV slot as owner, open it, run owner_slot_policy_ok AND piv_attest::verify, match the attested pubkey to new_owner_pk, REFUSE on failure. Makes (2) a GUARANTEE (make-illegal-states: can't set a non-attested PIV key as owner) and removes the human-remembers-to-attest link (⛔no-human-last-link). The fn exists; cheap. If you keep it standalone for now, the runbook MUST make piv-attest MANDATORY at every PIV-owner-set (not optional) — but I lean wire it.

Nice catch on the .pem gitignore (Intel R5 CA excluded → fresh clone couldn't build; now committed as gitignore exceptions, DER sha256 re-checked vs the compiled-in pin; pinned() also hash-gates the Yubico PEMs at runtime). Good supply-chain hygiene.

SEQUENCING: §2 is confirmed ⇒ you're clear to run the THROWAWAY evidence (T0/T2, not live). I'll glance the evidence: your five + the (3) negative test (owner-cli refuses a ONCE/CACHED slot for owner role) + the piv-attest output (chain→Yubico Root 1, policy ALWAYS/ALWAYS, serial match). Before the LIVE T2 PIV rotation (block 329441): either wire the attest-gate, OR show piv-attest run + passed in the evidence AND the runbook marks it mandatory. Good work.

## 3. @ dfe405e — the hardening confirmed; C-R6-3 code side complete

Confirmed firsthand @dfe405e. The wiring is exactly right:
• owner_pk_of_locator (L278) is the SOLE owner-key resolver; init/rotate-owner/recover all route through it (L1204/1408/1417).
• piv: branch (L283-297): open_piv (→ owner_slot_policy_ok, L285) + piv_certs + piv_attest::verify (L288) + binds the ATTESTED pk (verify confirms slot-pk==attestation-pk, so the pk placed into the message is the attested one); ANY failure → "{locator} cannot become the owner" → nothing built/sent.
• raw-hex owner input gone (new_owner is a locator; pk65 removed; the L816/L1243 owner_pk are the stored WalletRecord field, not CLI input).
⇒ **make-illegal-states achieved**: a non-attested OR wrong-policy PIV key has NO constructor as owner; the human-remembers-to-attest link is GONE. piv-attest stays as the standalone evidence/export command. Fully closes my hardening rec.

C-R6-3 code side = COMPLETE: yubikey_piv.rs (a-f PASS) + owner_slot_policy_ok (ALWAYS/ALWAYS, ship-cond MET) + piv_attest.rs (sound pinned-chain, policy-ext, key/serial bound) + WIRED on the owner-key-SET (a gate, not a procedure). 13/13 + clippy + e2e noted.

Sequencing good: throwaway T0 evidence as soon as the owner generates 9a; the live T2 rotation after 329441 carries the in-line ATTESTED output (L289-296 + the "(attested, firmware)" label) — nice. I'll glance REQ §4 evidence: your five + the (3) negative test + the in-line ATTESTED line on the rotation. Nothing else gates it from my side. This is the clean form — good work.

## 4. §4.1 evidence — CODE IMPL-PASS; §4.5 is the deployment facet

§4.1 reviewed — clean, thorough. **r6b C-R6-3: CODE IMPL-PASS** (my firsthand code review + §4.1 mechanics). §4.1 + the code is ENOUGH for the verdict now — I do NOT need to withhold until §4.5.

§4.1 confirms end-to-end:
• attestation gate fired on the real init path (in-line ATTESTED, chain→pinned Yubico Root 1 9271d914…, serial 39252737/policy ALWAYS-ALWAYS/pk all bound);
• pubkey no-PIN == ykman PEM;
• PIN+touch per owner signature (two sigs = two touches);
• negatives all correct — non-owner INSTALL→POLICY_SIG (nonce unchanged); wrong-PIN→one try burned, clear msg, nothing sent, 3/3 restored on correct; loosening→PENDING 144 (timelocked as designed); concurrent tighten→POLICY_PENDING (one-pending invariant). Policy-in-TEE timelock + one-pending look right.

(3) ship-condition MET without the live weak-key test: the refuse-side is the SAME code path as the live-proven ACCEPT side (open_piv→device-metadata→owner_slot_policy_ok, called unconditionally), and the unit matrix exhaustively covers all 10 policy combos (1 accept / 9 refuse) against the real function — which I confirmed firsthand. The on-device ONCE/CACHED ceremony would be confirmatory, not revealing; the owner's decline is fine, the committed matrix suffices.

§4.5 (live T2 rotation after 329441) = the DEPLOYMENT / custody-transition facet — the one thing §4.1 (nosgx) does NOT prove: the actual tpm→piv owner MOVE on a real T2 wallet + the TPM-owner RETIREMENT (post-144-timelock: TPM unfreeze REFUSED, YubiKey ACCEPTED). That's inherently your live owner-op (owner-gated custody). I verify it when it runs: the in-line ATTESTED line on the rotation + the post-timelock TPM-refused/YubiKey-accepted.

⇒ r6b code verdict STANDS now; §4.5 completes the deployment-facet. Proceed as planned. Good work — this closes C-R6-3 on the code side.

---

**Dev's reading:** IMPL-PASS for merging `r6b-yubikey` to `main`. C-R6-3 DISCHARGED on the code side;
the live T2 custody transition (REQ-r6b §4.5) is carried as C-R6b-1 and reported when it runs.
