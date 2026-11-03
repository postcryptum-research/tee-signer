# REQ — tee-signer design round (R0)

**Date:** 2026-11-03 · **From:** tee-signer dev session (`llm-btcpay-tee-e6`) · **To:** the auditor
(`security-audit-playbook`) · **Status:** SENT 2026-11-03 (lab result in §8; file hashes in §9).
**Pre-rulings already received and carried:** `RESP-prequestions-2026-11-03.md` (Q1 label covers
seed and enforcement; Q2 TOFU label + identity card; Q3 bounded loss acceptable, freshness witness
recommended; carried: no-blind-sign, PSBT change handling, illegal states unrepresentable,
two-lenses, threshold N/A).
**Design of record:** `README.md`, `docs/THREAT-MODEL.md`, `docs/DESIGN.md`, `docs/POLICY.md`,
`docs/studies/BTCPAY-SIGNING-SEAMS-2026-11-03.md` at the working tree of this date (no commit yet:
the owner is creating the repo). **Requested verdict:** DESIGN-PASS / CONDITIONAL / FAIL for the
verification model below, before any `signer-core` policy logic or `enclave/` code is written.

## 0. What this is

A policy-enforcing SGX signer for BTCPay Server hot wallets — the SMB sibling of TRUST. The seed is
generated and sealed inside an enclave; BTCPay holds a cold (xpub-only) wallet; a plugin routes
PSBTs to the enclave; the enclave signs only inside an owner-signed, timelocked, rarely-changed
mandate. The motivating attack (2026-11-01) was an application-level admin compromise that swept
hot wallets whose seeds sat in NBXplorer's Postgres.

## 1. The model under review (summary; full text in the docs)

- **Adversaries** V1 (BTCPay admin / plugin RCE / container), V2 (non-root host user), V3 (host
  root), V4 (host clock and chain feed), V5 (owner-key thief), V6 (physical/Intel) —
  `THREAT-MODEL.md §2`. Tiers: T1 = SGX1 non-FLC **debug** enclave, no attestation; T2 = FLC/DCAP,
  `DisableDebug=1`, attested. T1 claims V1/V2/V4/V5; T2 adds V3.
- **Invariants** I1–I12, `THREAT-MODEL.md §4`: own-input by in-enclave derivation; amounts only
  from the full previous transaction (`non_witness_utxo` mandatory, txid recomputed); own outputs
  by derivation within an index bound; trusted destinations by address or descriptor derivation
  within a gap; net outflow = Σ own in − Σ own out judged against per-tx and per-window caps per
  class; fee ≤ abs and ≤ rate × upper-bound vsize; `SIGHASH_ALL` only; foreign inputs never signed;
  mandate by owner P-256 signature + strictly increasing nonce + activation height; windows advance
  only on verified headers; commit-seal-then-sign; the seed leaves the enclave only inside the
  recovery blob, once, at init.
- **Block clock** (`DESIGN.md §5`): header chain verified in-enclave from an owner-pinned
  checkpoint; every window, validity and timelock is a height. No wall-clock input to any decision.
- **Mandate** (`POLICY.md`): field semantics, the tightening/loosening partition (§5), refusal
  identifiers (§6).
- **Updates** (`DESIGN.md §6`): tightening applies at once; loosening waits `timelockBlocks` of the
  installed mandate; cancel by owner **or** recovery key; freeze by anyone, unfreeze by owner;
  owner rotation is loosening (timelocked); recovery-key rotation is immediate.
- **State** (`DESIGN.md §3`): one sealed blob (MRENCLAVE policy on T1), receipt sequence,
  rollback bounded by one window and detectable.
- **Integration** (`DESIGN.md §9`): plugin, no fork; wallet cold in BTCPay; four in-process
  signing sites structurally disabled; PayJoin out of v1.

## 2. Rulings requested

| # | Question | Dev's position |
|---|---|---|
| R1 | **Tier labels** — ruled in the pre-round (Q1/Q2): T1 acceptable with the label covering seed AND enforcement; identity card at setup. Please confirm the label text now in `THREAT-MODEL.md §3 (V3)` and `§5` matches the ruling. Open factual item: whether the stack holds an Intel LE-whitelisted production key is asked of the owner | carried |
| R2 | **Rollback** — ruled in the pre-round (Q3): bounded + detected acceptable; freshness witness recommended → R13 | carried |
| R3 | **PoW time as the window clock.** Is a header-chain clock from an owner-pinned checkpoint sound as the only clock, given that withholding is DoS-only and that signet/testnet work is cheap (labeled)? Is `maxReorg`-freeze the right reorg rule? | yes; the alternative (host time + monotonic + owner epochs) is weaker |
| R4 | **Classification rules.** `non_witness_utxo` mandatory for own inputs (refuse `witness_utxo`-only); own output = derivation match on branch 0/1 within `bound + gap`; trusted = address or descriptor within gap; everything else unlisted. Any gap in I1–I4? In particular: is the own-index bound (raised by use) a loosening vector? | the bound only widens which outputs count as *own*, i.e. as non-outflow — all are the wallet's own keys, so no value leaves |
| R5 | **Net outflow and fee.** Net outflow = Σ own in − Σ own out; fee = Σ all in − Σ all out; vsize upper-bound estimate in-enclave. Is "RBF charged twice" the right conservative default? Should `maxFeeRate` be bounded relative to the outflow too (dust-attack: many tiny outflows with max fee)? | fee abs bound covers the dust case; charge replacements twice |
| R6 | **Update protocol.** The tightening/loosening partition of `POLICY.md §5`; cancel by either key; freeze unauthenticated; recovery-key rotation immediate; `network`/`wallet` immutable. Anything that lets V1 or V5 widen the mandate without waiting the timelock? | none found; the timelock of the *installed* mandate governs, so shortening it is itself timelocked |
| R7 | **State machine order.** Commit → seal → hand blob out → sign → receipt. Crash between seal and sign = budget charged, no signature. Acceptable? Should the receipt be produced before the signature instead? | acceptable; receipt after signature so it can carry the txid |
| R8 | **Recovery blob.** Ephemeral P-256 ECDH + HKDF-SHA256 + AES-256-GCM, AAD = fingerprint ‖ xpub, produced once at init to the installed recovery public key; verified by the owner offline before funds. Is "once, at init, no other path" the right shape, or must there be a re-export under the recovery key for key rotation? | once; a new recovery key means a new wallet (sweep) |
| R9 | **Owner key.** P-256 verified in-enclave (TPM_sign `hw-signer` backends); the enclave holds public keys only; a software owner key refused outside a test-only build (TPM_sign F1/F8 carried). Agree? | yes |
| R10 | **TCB plan** (`DESIGN.md §8`): Intel SDK C shell + `no_std` Rust core; crate closure `bitcoin`, `secp256k1(-sys)`, `sha2` (force-soft), `hmac`, `pbkdf2`, `p256`, `aes-gcm`, `hkdf`. Each a provenance line. Objections to any crate, or to avoiding Teaclave's `sgx_tstd`? Lab result: §8 | decided; proven on T1 hardware |
| R11 | **Integration claim.** "The `signerd` bearer token is not a secret in the threat model" and "the four BTCPay signing sites are structurally disabled by `IsHotWallet=false`" — do these hold against the study's file:line evidence? | yes |
| R13 | **Freshness witness** (`DESIGN.md §3`, auditor Q3 recommendation): token `{tip_hash, tip_height, last_seen_seq, nonce}` signed by a low-privilege off-box P-256 key; precondition = tip within `maxTipLag` of the enclave's best **and** `last_seen_seq ≤ own seq`; rollback ⇒ refuse until an owner-signed `Rearm`. Is the two-check precondition sufficient against replay-after-rollback, and is "witness compromise = pause or hidden rollback only" the right privilege statement? | yes; v1 ships it behind `freshness.required` |
| R14 | **Owner-device display.** v1 owner key = YubiKey P-256 (no display; WYSIWYS rests on the owner's machine running `owner-cli policy diff`). Labeled residual acceptable for v1, with phone / hardware-wallet (secp256k1 message signing) as later rounds? | yes, labeled |
| R12 | **Negative-vector matrix.** Proposed minimum: one refusal vector per identifier in `POLICY.md §6`, plus boundary vectors (cap − 1 / cap / cap + 1 per class and window), a rolled-back-state vector, a replayed-update vector, a lying-`witness_utxo` fee-overpayment vector, a change-to-foreign-key vector, a foreign-input-signed vector, a reorg-beyond-`maxReorg` vector, built from real signet data. Sufficient as the IMPL-PASS bar? | yes |

## 3. Out of scope for this round

PSBTv2, P2TR, PayJoin (fork path), the phone owner app, DCAP attestation details (a T2 REQ),
the BTCPay plugin's own code (untrusted; reviewed at IMPL for the "cannot authorise" property only),
`signerd` internals (untrusted).

## 4. Carried from prior rounds

TPM_sign `AUDIT-2026-10-20` F1/F2/F4/F8 as mapped in `docs/audit/PROTOCOL.md`; SGX_project
`RESP-sgx-debug-mode-live-cluster-2026-06-29` (debug launch = no confidentiality against root,
`DisableDebug=1` pinned in signed config for production); trust-bridge rules: fail-closed,
time-stable claims, findings in the queue.

## 5. Deliverable

`RESP-design-2026-11-03.md` here, verdict + named conditions, committed verbatim.

## 8. Lab result (`docs/studies/NOSTD-ENCLAVE-LAB-2026-11-03.md`)

All three steps PASS on the SGX1 box (HW mode, debug launch): Intel SDK 2.25 sample; a `no_std`
Rust staticlib (sha2 over `alloc`) linked into the C enclave with SHA-256 matching `sha256sum`;
`bitcoin` 0.32 + `secp256k1` 0.29 no_std inside the enclave — `Psbt::deserialize`, BIP143 P2WPKH
sighash, RFC6979 ECDSA, DER byte-identical to a host signature and verified host-side. Gotchas
turned into build rules (`DESIGN.md §8`): no runtime CPU detection (`cpuid` crashed the enclave;
`force-soft`), LTO + one codegen unit for `rust_eh_personality`, no multiple-definition flag, no
TEXTREL, edger8r prerequisites, context randomization owed, fixed heap sizing. Unproven and
labeled: release launch (impossible here), sealing, attestation, multi-threaded ecalls, peak heap.

## 9. Pinned content (no git yet — the owner is creating the repo; SHA-256 per file)


| File | SHA-256 |
|---|---|
| `README.md` | `40f1daa2cac10bb88792a8d7d35fc936fd06a1b358166b808df6b3ae583e2dad` |
| `CLAUDE.md` | `df0e77c026c260ff14d3f863c84cda69213668695c109928d869b219ea57c039` |
| `deploy/README.md` | `f14c8f7b315dde6a269a464007ae983c0a05340219463a72cc079e0cb765e9bf` |
| `docs/THREAT-MODEL.md` | `15f55519445de28339b408aaaaa96ef1334cb3192f07fb0527f4fe946c430640` |
| `docs/DESIGN.md` | `0f2faaa1650176a6f87103debf98b9d70475cd6200a5775b728788c6510cbf77` |
| `docs/POLICY.md` | `52c709be82b8e0bbda05544388251cb142653cba497ceff171c9814b1bc4fae3` |
| `docs/audit/PROTOCOL.md` | `ca992f72ff1359e2b54dc808e130d4395c8a1ef7528d7d1d5ab0152448e55492` (re-pinned: the Rounds table row for this REQ changed from DRAFT to SENT after the first pin; the carried-rulings map is untouched) |
| `docs/audit/RESP-prequestions-2026-11-03.md` | `862fe2dc3a6518f668ce113ab421f055348c5b8cd1c3bf37d14eacf51b56d09f` |
| `docs/studies/BTCPAY-SIGNING-SEAMS-2026-11-03.md` | `a4b4bdfb440ec0ffed6c7c69dcab3865dda037bf5c4d6a843d57108b4497f47a` |
| `docs/studies/NOSTD-ENCLAVE-LAB-2026-11-03.md` | `76360e6cdf7c1ff93487cb0da2fee0a11921b89dd091481edb569fa41d642ea2` |

**Committed as `4fb7512d20f6d70eebaa3ab71e2954c80605890f` on `main` of `github.com/77ph/BTCPayTEE` (2026-11-03). The per-file hashes above are the pins; the commit carries the same bytes plus `LICENSE`, `.gitignore` and `docs/DECISIONS.md`.**
