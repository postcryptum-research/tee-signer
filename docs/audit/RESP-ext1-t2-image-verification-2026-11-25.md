# RESP-ext1 — the T2 sidecar image `ext1-a4b6e4d-t2`: the auditor's verification (2026-11-25)

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message, in answer to
the dev's image report (the image built on the build box from `main` @ `a4b6e4d`: the new `signerd`, the identical
`dcap-quote-helper`, the deployed ceremony-signed `enclave.signed.so` reused; image id `c353ac9e6650`, tarball sha256
`fab9928358addee1…`, staged on the node in `~/tee-signer/images/ext1-a4b6e4d/` and NOT loaded). **Recorded verbatim by
the dev; nothing edited.** The load is the owner's direct decision — the auditor says so below, and the dev waits for it.

---

T2 image `ext1-a4b6e4d-t2` — audit verification complete, **CLEAN from an audit standpoint**. What I verified firsthand (not from your hashes):

- **MRENCLAVE `9a18d5a8` unchanged.** `git diff 9139e49 a4b6e4d -- core/ enclave/` is empty (rc=0, and I confirmed `9139e49` resolves locally so it's a real empty diff, not a masked error). So the enclave source is byte-for-byte unchanged since the deployed ceremony build → the reused `enclave.signed.so` (no re-sign, no ceremony, MRENCLAVE/MRSIGNER unchanged) is valid.
- **All six host commits in the signerd binary are reviewed and clean.** I had no firsthand record of PR B (#25, SafeMath `d7f3364`), so I reviewed its signerd part just now — clean (`json_height` refuse-not-0 on the node tip, saturating/checked conversions that fail-loud, `pad32` a correct refactor; overflow-checks on in release). The other five are IMPL-PASS'd: PR C #16/#17 + the h_quote lock `8e48c88`, PR D #27 `b3b269b`, PR E #28 `466e116`/`3189dc5`.
- **Image == current main for binaries** (only `fuzz`/`docs`/`.github` changed between `a4b6e4d` and main). Compose fragment unchanged, `SIGNERD_ENCLAVE_DEBUG=false` before and after.

One honest boundary: I verified the *source* invariants that make your build hashes trustworthy (enclave source unchanged, host = reviewed PRs); I did not independently reproduce the binary hashes — a full repro-build is the mainnet bar, not demanded for this testnet/signet reuse of the ceremony binary.

**But I am not the load authority.** Per the standing rule the deploy/load is the owner's DIRECT decision, and I don't relay or grant that. So: **do not load on my word.** I've routed this verification to the owner; wait for the owner's own direct go to you. (Also noted for the owner: node at 78% disk, and the come-up-NOT-ARMED → vTPM auto-arm on first fresh call is unchanged behavior.)
