# REQ — R5 design: T2 on Azure DCsv3 — non-debug launch, reproducible pinned build, DCAP-attested identity card

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r5-t2-azure` of `github.com/77ph/BTCPayTEE` (this file + the build recipe; **no enclave code
yet** — hard rule 1). **Requested verdict:** DESIGN-PASS / CONDITIONAL / FAIL for the one enclave
addition (§3), the verifier (§4), the build (§5) and the deployment shape (§6). Carried gates this
round discharges or advances: C-R2-3 / C-R10d / C-R1-3 (reproducible build), C-R2-4 (RELEASE=1 on
FLC/DCAP), C-R3-2 (verified non-debug launch on the chosen target), C-R1-1 (D-11 cost, measured on
T2). The owner chose the target today: **Azure DCsv3, `sgx-node-3` (52.236.130.102)**, no cluster;
the enclave is **built on the Hetzner box in Docker** (as the sibling projects do) and only
binaries go to Azure; Docker **is** installed on the node (owner-approved) because BTCPay runs
there in containers, as on the dev stack.

## 1. Facts on the target (read-only, 2026-11-03)

| | `sgx-node-3` |
|---|---|
| CPU / driver | Xeon Platinum 8370C (Ice Lake-SP), `sgx_lc` present, in-kernel `/dev/sgx_enclave` + `/dev/sgx_provision`, Ubuntu 22.04.5, kernel 6.8-azure |
| PSW / DCAP | `libsgx-urts 2.28.100.1-jammy1`, `libsgx-dcap-ql 1.25.100.1-jammy1`, `libsgx-quote-ex 2.28`, `sgx-aesm-service 2.28` active with ecdsa/pce/quote-ex plugins, `az-dcap-client 1.13.0` (Azure THIM collateral) |
| Ours | `~/tee-signer/`, loopback ports 7390 (signerd) and 7392 (BTCPay), free (in use: 22 53 3000 4002 5432 7195 7777 8086 9089 9191 9199–9202); Docker 29.1.3 installed today |
| Not ours | trust-bridge seats `c2/c5/c8/c12`, perp, phoenix, Postgres — never touched |

## 2. What T2 changes, in one table

| Property | T1 (Hetzner, today) | T2 (this round) |
|---|---|---|
| Launch | debug only (`0x4004` otherwise) | `DisableDebug=1`, `sgx_create_enclave(debug=0)`; `status.tier = "T2-release"` (derived from the self-report's DEBUG attribute, already in `rcore::sgx::tier`) |
| Identity card | signed by the identity key; MRENCLAVE from the self-report; **TOFU** | the same card **plus a DCAP quote** whose `report_data` binds the card and a verifier nonce (§3) |
| MRENCLAVE provenance | the box's SDK 2.25 build | pinned container (SDK 2.28 = the node's PSW), two builds equal (§5) |
| Sealing | `sgx_seal_data_ex` MRENCLAVE policy | **unchanged** (MRSIGNER+ISVSVN upgrade path stays the later REQ named in `ENCLAVE.md §2`) |
| Threat model | app-level (V1/V2) | + host root up to the SGX model (`THREAT-MODEL.md` T2 row), **only after** the verifier in §4 says so for a running instance |

## 3. The one enclave addition: `REPORT` (op 10) — TCB, hence this REQ

```
REPORT in:  SealedWith { sealed, data: target_info[512] ‖ nonce[32] }
       out: report[432]           (sgx_report_t, created against target_info)
report_data[64] = SHA-256("tee-signer/quote/v1" ‖ nonce ‖ IdentityCard::encode()) ‖ 0[32]
```

- Allowed on a keys-only blob and on an installed one (the card exists from `INIT`); **no state
  change, no secret in the output** — `target_info` and `nonce` are untrusted input; a malformed
  length refuses `ENCODING`. The card is recomputed from the envelope at every call, never cached.
- Why the card hash and not just `identity_pk`: the card carries MRENCLAVE, network, xpub,
  fingerprint, identity_pk and tier under the identity signature; binding its hash makes the quote
  speak for **all** of them at once, and a card with a swapped xpub fails §4 step 6.
- Why a verifier nonce (trust-bridge `RESP-dcap` Q-ATT-1): a quote taken once could be replayed
  forever; the owner generates 32 bytes from the OS at verification time and a quote whose
  `report_data` lacks it is refused. The identity signature over the card stays as the long-term
  binding; the quote is the fresh proof that *this* enclave, non-debug, holds that identity now.
- No new crate; `sgx_create_report` is already declared in `rcore::sgx` (used for the self-report).

Host side (untrusted, no REQ needed, listed for completeness): `GET /v1/quote?nonce=<hex32>` on
`signerd` forks `dcap-quote-helper` (one process for `sgx_qe_get_target_info` → `REPORT` ecall →
`sgx_qe_get_quote`, the DCsv3 lesson from the sibling projects: the quoting library cannot share a
process with the loaded enclave, and the attestation key is lost between processes), quoting
**through the node's `aesmd`** (`SGX_AESM_ADDR=1` inside the sidecar container, the socket mounted)
so the container carries no quote-provider configuration of its own. Response:
`{ card_hex, card_sig_hex, nonce, quote_hex, quoted_via: "aesmd/az-dcap-client" }`.

## 4. The verifier — `owner-cli attest`, on the owner's machine, in this order

1. **Quote chain and collateral**: ECDSA-P256 quote (v3), QE identity, PCK chain to Intel's root,
   TCB info and CRLs fetched from **Intel PCS v4** (the PCK chain is in the quote; TCB info and QE
   identity by FMSPC), expiry checked, the collateral source **named in the output**. Pure-Rust
   `dcap-qvl` (one crate, owner's machine only — not TCB) rather than Intel's QVL, so the owner
   needs no SGX libraries; a provider/collateral failure is a **hard refusal**.
2. **`ATTRIBUTES.DEBUG == 0`** — a debug enclave's quote is refused *here*, before MRENCLAVE.
3. **MRENCLAVE == card.mrenclave == the owner's expected measurement** (from the reproducible build
   §5; the owner-cli wallet record pins it).
4. **MRSIGNER == expected**, ProdID/ISVSVN as pinned (for this round a **dev signing key**, labeled
   in the record; a ceremony key is R6+).
5. **The card's identity signature** verifies and `card.tier == "T2-release"`.
6. **`report_data == SHA-256(prefix ‖ nonce ‖ card)`** with the verifier's own nonce.
7. **TCB status policy** (trust-bridge Q-ATT-3, adopted): accept `OK`; accept
   `SW_HARDENING_NEEDED` **only** with an explicit, dated, advisory-ID'd exception in the owner's
   config (Ice Lake DCsv3 is expected to return it); refuse `CONFIG_NEEDED`, `OUT_OF_DATE`,
   `OUT_OF_DATE_CONFIG_NEEDED`, `REVOKED`, anything else. The output says
   "attested with recorded exception [advisory]" when the exception is used, never bare "attested".

A failure at any step refuses; the tool prints which. `owner-cli init` on T2 runs this verifier
before writing the wallet record (TOFU ends); `owner-cli status` can re-run it on demand.

**Negative vectors (deliverable):** debug-built enclave's quote refused at step 2; wrong nonce
refused; card with a swapped xpub refused at 6; MRENCLAVE differing from the pinned one refused at
3; collateral unreachable ⇒ refusal, not a warning.

## 5. Build — gate 5 becomes executable

`docker/Dockerfile.enclave-build` (on the branch): `ubuntu:22.04`, every `libsgx-*` package pinned
to the node's measured versions (PSW 2.28.100.1-jammy1, DCAP 1.25.100.1-jammy1), SDK 2.28,
rustup 1.92.0 minimal, `cargo fetch --locked` at image build, then `make RELEASE=1 --offline`,
`SOURCE_DATE_EPOCH` fixed. The image produces the **unsigned** `enclave.so`; signing, the gates
and the SIGSTRUCT dump run in a `docker run` with the key mounted read-only
(`docker/build-enclave.sh`), so no key ever enters an image. `docker/compare-builds.sh` diffs two
builds' SIGSTRUCT minus `header.date` and the signature material and asserts MRENCLAVE equality.
Gate 1 gets a second pinned cpuid list for SDK 2.28 (`sdk-cpuid-baseline-2.28.txt`, pinned from
the first build after I confirm every site is an SDK IPP symbol, as with 2.25 — D-R2-1). The
daemon and `dcap-quote-helper` are built in the same image so their `libsgx_urts`/`dcap_ql` match
the node.

## 6. Deployment shape on the node

The dev stack from R3, unchanged in shape: btcpayserver-docker generated in a container,
`REVERSEPROXY=none`, HTTP on `127.0.0.1:7392`; signet `bitcoind` + NBXplorer + Postgres in the
stack (header feed from the stack's own node, as on Hetzner); the `tee-signer` sidecar image for
T2 built from the same pinned image (PSW 2.28 libs, `dcap-quote-helper`), devices
`/dev/sgx_enclave` + `/dev/sgx_provision`, `/var/run/aesmd` mounted, `SGX_AESM_ADDR=1`,
`SIGNERD_ENCLAVE_DEBUG=false`. Nothing is published beyond loopback; the owner reaches the node
through an SSH tunnel chained via the Hetzner box (the Azure key lives there). A **fresh** T2
wallet is initialised (new seed, new identity); it is funded from the T1 signet wallet under its
mandate (an unlisted spend within caps), which is itself a live use of R3.

## 7. Decisions to rule

- **D-R5-1** `report_data` = SHA-256(prefix ‖ nonce ‖ card bytes) ‖ zeros (§3) — versus binding
  `identity_pk` alone.
- **D-R5-2** sealing stays MRENCLAVE in R5; the MRSIGNER+ISVSVN upgrade path is its own REQ.
- **D-R5-3** verifier = pure-Rust `dcap-qvl` in `owner-cli` with Intel PCS collateral, on the
  owner's machine — versus Intel's QVL on the host (which would put the verifier next to the
  adversary).
- **D-R5-4** TCB policy as §4.7, the `SW_HARDENING_NEEDED` exception ledgered per advisory.
- **D-R5-5** quoting through the node's `aesmd` from inside the container (`SGX_AESM_ADDR=1`).
- **D-R5-6** a dev signing key for the T2 demo (MRSIGNER labeled dev in the wallet record and in
  every status line); the ceremony key and the two-step signing are a later round.

## 8. Evidence the IMPL REQ will carry

Non-debug launch on the node (`status.tier = "T2-release"`, quote attributes DEBUG=0); two builds
with equal MRENCLAVE and the SIGSTRUCT diff; `owner-cli attest` output naming collateral source and
TCB status; signet INIT/INSTALL/sign on T2 with receipts; the four R3 gates on the node; the §4
negative vectors; D-11 cost on T2 (ecall latency for JUDGE/SIGN at 1, 8, 16 inputs).
