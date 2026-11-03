# REQ — R5 IMPL: T2 on Azure DCsv3 — non-debug launch, reproducible pinned build, DCAP-attested identity card

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r5-t2-azure` of `github.com/77ph/BTCPayTEE` (commit named in the sending message). **Design of
record:** `REQ-r5-t2-azure-design-2026-11-03.md` + `RESP-r5-t2-azure-design-2026-11-03.md`
(DESIGN-PASS CONDITIONAL, C-R5-1..5). **Requested verdict:** IMPL-PASS / CONDITIONAL / FAIL for
merging to `main`: the `REPORT` op (TCB), the pinned build recipe with gates 5 and 6, `signerd`'s
quote endpoint, `owner-cli attest`, the T2 sidecar and fragment. **Gates this round discharges
or advances:** C-R2-3 / C-R10d / C-R1-3 (reproducible build, executed), C-R2-4 (RELEASE=1 on
FLC/DCAP, executed), C-R3-2 (verified non-debug launch on the chosen target, executed), C-R1-1
(D-11 cost, measured on T2), C-R5-1..5.

## 1. TCB diff — one op, nothing else

| Where | Change | Lines |
|---|---|---|
| `core/src/proto.rs` | `op::REPORT = 10`, `quote::{DOMAIN, TARGET_INFO_LEN, NONCE_LEN, INPUT_LEN, REPORT_LEN, REPORT_DATA_OFFSET, preimage()}`, `ReportResponse {report[432], card}` | +55 |
| `enclave/rcore/src/sgx.rs` | `report_for(target_info, report_data)` — `sgx_create_report` against the quoting enclave's target; `nosgx` stand-in writes `report_data` at its offset and attests nothing | +24 |
| `enclave/rcore/src/ops.rs` | `report()`: `SealedWith{sealed, data = target_info ‖ nonce}` (exactly 544 bytes, no `extra`, else `ENCODING`); opens the envelope (keys-only or installed), recomputes the card, `report_data = SHA-256(DOMAIN ‖ nonce ‖ card bytes) ‖ 0[32]`; **no state change, nothing secret out** | +40 |
| `enclave/Makefile` | `MITIGATION-CVE-2020-0551=LOAD` honoured (SDK flags + mitigated trusted libs) and mirrored on the Rust side (`+lvi-cfi,+lvi-load-hardening`); **gate 6** asserts the mitigation is in the artifact (`lfence` count ≥ 2000, recorded); cpuid baseline per SDK (`sdk-cpuid-baseline-2.28.txt`, 8 IPP sites, one instruction each — C-R5-5); `Enclave_Test_Key`, `SDK_CPUID_LIST`, `CARGO_FLAGS` overridable for the container | |
| `enclave/rcore/tests/replay.rs` | `report_binds_card_and_nonce`: binding equals the recomputed hash; a different nonce changes it; 543/545 bytes and a stray `extra` ⇒ `ENCODING`; an unsealable blob ⇒ `STATE_UNSEALABLE`; status unchanged after | +45 |

No new crate in the TCB. `core` 15 tests + 51 vectors and `rcore` tests pass (`cargo test`, the
pinned 1.92 toolchain is clippy-clean; a newer 1.95 clippy flags a pre-existing shift in
`bip39.rs:32` — left untouched, noted).

## 2. The build — gate 5 executed (C-R2-3 / C-R10d / C-R1-3 / C-R5-5)

`docker/Dockerfile.enclave-build`: `ubuntu:22.04`, every `libsgx-*` pinned to the node's measured
versions (PSW 2.28.100.1-jammy1, DCAP 1.25.100.1-jammy1), SDK 2.28, rustup 1.92.0, `cargo fetch
--locked` at image build, `make RELEASE=1 MITIGATION-CVE-2020-0551=LOAD --offline`,
`SOURCE_DATE_EPOCH` fixed; the image holds the **unsigned** `enclave.so`; signing, the gates and
the SIGSTRUCT dump run in `docker run` with the key mounted read-only
(`~/tee-signer-keys/enclave-dev-2.28.pem` on the Hetzner box, **dev key, labeled**, C-R5-4).
Built **only on the Hetzner box**; the node receives binaries (owner's rule).

| Build | MRENCLAVE | Gates |
|---|---|---|
| `build-2` | `51dee44db7d11c0fa0216ae1b4732f2db20f04ce619217cd32d515f5058c1fa6` | 1–4, 6 (lfence 38 424) ✓ |
| `build-3` (independent container run) | `51dee44db7d11c0fa0216ae1b4732f2db20f04ce619217cd32d515f5058c1fa6` | 1–4, 6 (lfence 38 424) ✓ |
| `docker/compare-builds.sh build-2 build-3` | **REPRODUCIBLE**: SIGSTRUCT minus `header.date`/signature identical, `enclave.so` byte-identical | |
| `build-debug` (RELEASE=0, the negative vector only) | `ea6b8be7a0b729f1bface1439a86c9c18b26b5e5874fddb27177fd06e5bdf6be` | never deployed |

MRSIGNER of the dev key: `73f20c7bd231e7017f7ba5b7c2239ddcde48ae3c927167bf7dca29d480f99660`, ProdID 1,
SVN 1. rustc prints that the LVI target features are "unstable… passed through to the codegen
backend"; the artifact gate (6) is what we rely on, not the flag.

**C-R5-1 ledger.** The platform (Ice Lake-SP, `sgx-node-3`) reports `SWHardeningNeeded` with
exactly one advisory, **INTEL-SA-00615** (MMIO stale data, CVE-2022-21123/21125/21127/21166).
Intel's advisory: the mitigation for enclaves is in the updated SGX SDK (reads outside ELRANGE at
8-byte size/alignment in the trusted runtime; SDK 2.16.100.3+), plus the microcode on the
platform. Our build: SDK 2.28; the enclave performs no MMIO and copies no secret into untrusted
memory (every output is public). The ledger entry used (dated, reasoned) is in the wallet record
(`attested.accepted_exceptions`). LVI (INTEL-SA-00334) is **not** reported by this platform (not
affected); the build carries the LVI mitigation anyway (gate 6), so the same artifact attests on
an affected platform with the same honesty.

## 3. The target and the launch (C-R2-4, C-R3-2)

`sgx-node-3` (52.236.130.102): Xeon Platinum 8370C, `sgx_lc`, in-kernel driver, PSW 2.28, aesmd
with ecdsa/pce/quote-ex plugins, `az-dcap-client`. Docker 29.1.3 installed (owner-approved). The
R3 stack shape (`stack.sh gen` with `TEE_FRAGMENT=opt-add-tee-signer-t2.custom`), **plus the
stock `opt-save-storage-xxs` fragment: the node's 29 GB disk hit 95 % during signet IBD, our
`bitcoind` was stopped at once and restarted pruned (5 GB); now 60–70 %** — the co-tenancy
condition C-R5-3 made that a hard stop, not a wait. Everything of ours: `~/tee-signer/`,
`~/tee-signer-btcpay/`, loopback 7390/7392; nothing of the siblings touched; shared only
`/dev/sgx_enclave` and the aesmd socket.

Sidecar `tee-signer/signerd:t2` (`btcpay/docker/Dockerfile.signerd-t2`: Intel's apt packages at
the node's versions, `signerd` + `dcap-quote-helper` + `enclave.signed.so` from `build-3`,
`SGX_AESM_ADDR=1`, `SIGNERD_ENCLAVE_DEBUG=false`, uid 999). **Launch:** `enclave="sgx"` (the host
side's label for debug=0; T1 said `sgx (debug launch)`), `status.tier = "T2-release"` — derived
by the enclave from its own report's DEBUG attribute, not from a flag.

## 4. The identity card, attested — `owner-cli attest` (C-R5-2, C-R5-4)

Owner's machine → SSH tunnel chain (laptop → Hetzner box → node loopback 7390). Fresh wallet
`INIT` on T2: xpub `tpubDCSDiHr…heEPV`, fingerprint `fae69580`, enclave id `f742311c…`, tier
`T2-release`, MRENCLAVE = the reproducible build's; recovery blob verified offline with the
recovery key; mandate (the T1 caps, wallet `fae69580`) installed, hash `802cee97…`.

`attest` (verifier `dcap-qvl 0.7.1`, pure Rust; Intel SGX Root CA **compiled in** with its SHA-256
`44a0196b…74d3` asserted, and the crate's own embedded copy must agree — two pins of one CA;
collateral from **Intel PCS v4** only, Azure THIM refused by construction):

```
quote: 4734 bytes via dcap-quote-helper (libsgx_dcap_ql) through the node's aesmd
step 1 ok: quote chain verifies to the pinned Intel SGX Root CA (sha256 44a0196b…); collateral from https://api.trustedservices.intel.com
step 2 ok: ATTRIBUTES.DEBUG = 0 (flags 0x5)
step 3 ok: MRENCLAVE 51dee44db7d11c0fa0216ae1b4732f2db20f04ce619217cd32d515f5058c1fa6
step 4 ok: MRSIGNER 73f20c7b…9660 (dev key enclave-dev-2.28.pem on the Hetzner build host; NOT a ceremony key (C-R5-4)), ProdID 1, SVN 1
step 5 ok: card signed by identity 033f5faf…efdb, tier T2-release
step 6 ok: report_data = SHA-256(domain ‖ nonce 69a2de07… ‖ card)
step 7 ok: TCB status SWHardeningNeeded — attested WITH RECORDED EXCEPTIONS: INTEL-SA-00615 (2026-11-03: MMIO stale data … SDK 2.28 … no MMIO … build 51dee44d)
ATTESTED: MRENCLAVE 51dee44d…, MRSIGNER 73f20c7b…, TCB SWHardeningNeeded with recorded exceptions ; quote sha256 d1749192…
wallet record updated (pinned MRSIGNER, ProdID, SVN; attestation recorded)
```

**Negative vectors, each refusing at the named step:**

| Vector | Result |
|---|---|
| debug-launched enclave (`build-debug`, `SIGNERD_ENCLAVE_DEBUG=true`, a second container on 7391, removed after) | `step 1 refused: quote chain/collateral: Debug mode is enabled` — before any measurement is believed (the explicit step-2 check stands behind it) |
| replay: a saved genuine quote against a fresh nonce (`attest --replay`) | `step 6 refused: report_data does not equal SHA-256(domain ‖ our nonce ‖ card) ‖ 0` |
| wrong expected MRENCLAVE | `step 3 refused: MRENCLAVE quote 51de… / card 51de… / expected 0000…` |
| record with a swapped card (xpub bytes altered) | `step 5 refused: the enclave's card differs from the wallet record's` |
| collateral unreachable (`…intel.com.invalid`) | `step 1 refused: collateral from …: error sending request` — a refusal, not a warning |
| no exception ledger | `step 7 refused: TCB status SWHardeningNeeded with advisory INTEL-SA-00615 not in the dated exception ledger` |

## 5. Live on T2 (signet)

- T1 → T2 funding, signed by the **T1** enclave under its mandate (an unlisted 40 000-sat spend
  within caps, R3 in live use): txid `79be1a98e46e4980d009e79d8ab97d2535439b9c6fd3f36d41858cc971a887df`, T1 receipt seq 8.
- First **T2** signature (non-debug enclave, loopback on the node): `POST /v1/sign` → HTTP 200 in
  **0.031 s** (JUDGE + SIGN ecalls + atomic persist, one P2WPKH input, two outputs) — the D-11
  number on T2 (C-R1-1); receipt seq 1, txid
  `de3c3b34ab771fded28f94b36778b1a48eb35a72a0db506f0781243c02d464bd`, window after: outflow 5500,
  unlisted 5000, fees 500. Finalised and broadcast from the owner's machine.
- **The four R3 gates on the node, against the T2 enclave** (`gates.sh setup` then `run`, signet
  fully synced, pruned node, NBXplorer UTXO scan found the T2 change coin): **ALL PASS** —

```
== gate (a): PASS store wallet is cold · == 3. plugin: settings [200], enclave tier T2-release, xpubMatches True, processor [200]
== gate (b): PASS nbxv1_metadata key rows = 0
== gate (c): PASS S2 signWithSeed → 503 · PASS S4 no payjoin · PASS S3 stock processor absent · PASS S1 follows from (a)
== gate (d.1): payout EPqB5TrGouC7bbUX2gR63ncddRw (2000 sat) → InProgress, proof txid 2c230c0607720ecef4b1ddf992fd4f98417a54188ad1b8e4de09131fa6333551
  enclave seq 1 → 2 · PASS the tx BTCPay broadcast is the one the enclave signed · PASS node holds it in its mempool
== gate (d.2): payout LW1t1Zbq9pWRULiQn2dJrTdEMEd created while frozen → PASS stays AwaitingPayment, seq unchanged (2) · PASS BTCPay logged FROZEN
== gate (d.3): PASS xpubMatches=false with a foreign wallet · PASS refused by name before any PSBT · PASS xpubMatches=true again
== gate (a) again after a BTCPay restart: PASS still cold · PASS key rows still 0
R3 gates: ALL PASS
```

  The run used the `build-3` host binary with the `build-3` enclave; the sidecar was then
  recreated on the `build-4` image (cookie fix, same MRENCLAVE) and unfrozen by the owner through
  the tunnel. Non-debug launch, enclave-bound payout, freeze and the xpub gate all hold on T2
  exactly as on T1 — the plugin and the gates did not know which tier they were on.

### 5a. Two host-side findings from the T2 run (untrusted; fixed on the branch)

- **Cookie rotation stalled the feed.** `bitcoind` regenerates its RPC cookie at every restart; the
  daemon read it once at start, so after the node's pruning restart every feed round failed with
  "error decoding response body" (a 401 body) while the enclave sat at its checkpoint. `signerd`
  now re-reads the cookie every round (`Bitcoind::refresh_auth`). After the fix the T2 enclave went
  checkpoint 329261 → tip in one round (`headers accepted=27`). The enclave was never wrong — it
  simply did not move, which is the fail-closed shape — but a stalled feed is a liveness defect the
  R4 monitor must also see (tip lag).
- **Rebuild after a host-only change does not move the measurement:** `build-4` (daemon changed,
  enclave sources untouched) compares REPRODUCIBLE against `build-3` — the measurement is the
  enclave's alone, as the design claims.

## 6. Decisions to rule / things to know

- **D-R5-7** The host label for a production launch is `enclave: "sgx"`; the trusted label is the
  card's `tier`. Fine, or should the host say `sgx (production launch)` for symmetry?
- **D-R5-8** `attest --pin` writes MRSIGNER/ProdID/SVN and the attestation into the wallet record
  only on an explicit flag; `init` does not attest by itself yet (the owner runs `attest` right
  after `init` — two commands). Acceptable for R5, or must `init` refuse to write the record on T2
  without a passing attestation?
- The LVI Rust target features are LLVM-unstable per rustc's note; gate 6 is the assertion.
- The node's small disk: pruned signet node (5 GB) — NBXplorer and BTCPay work on a pruned node;
  the sidecar's header feed uses headers only.

## 7. Carried / labeled

C-R2-2 / C-R3-1 (R4 monitor) unchanged. Ceremony signing key + two-step signing = R6 (C-R5-4
keeps "production-safe" off the table until then). `init --attest` fusion (D-R5-8) if ruled.
