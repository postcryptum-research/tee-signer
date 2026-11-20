# Reproducible build — rebuild the enclave and match the published MRENCLAVE

The point of publishing this repository is that **anyone can rebuild the enclave and get the same
measurement** the project's node attests. `MRENCLAVE` is a hash of the enclave's pages and its
launch configuration; it does not depend on who signs the enclave or when. So a build on your machine
with a throwaway signing key must produce the **same 64-hex value** as the ceremony-signed enclave that
runs on the node. If it does not, something in the recipe or in this document is wrong — report it
(`SECURITY.md`).

## Published measurements

| `MRENCLAVE` | Source | Signer of the deployed enclave | Where it runs |
|---|---|---|---|
| `2073c234229af3986b9b5a8cd3abc844d1e808a97db14ffb46846a13257410cc` | `main` at `4dd6285` (2026-11-19) | the ceremony key, `MRSIGNER 56b25ccb4c1e446df1be4b308cd305b2d43e3f44745c10118bd7bad7bb2c0d41` (`enclave/ceremony/`) | the project's signet T2 node since 2026-11-19 (Azure DCsv3, DCAP-attested) |

Independent agreement on record for this value: the dev's build from the synced tree, the dev's build
from a clean `git archive` of `4dd6285`, the ceremony build, and the auditor's build on an unrelated
machine with a throwaway key — all `2073c234…` (`docs/audit/RESP-r9a-anchor-live-counter-impl-2026-11-19.md`,
addendum 2). Earlier measurements and the commits they came from are in the `docs/audit/` round files.

## What you need

- an x86-64 Linux machine with Docker (BuildKit enabled), about 10 GB of disk and network access
  for the image build (Intel's apt repository and SDK installer, rustup, crates.io). **No SGX
  hardware is needed**: compiling, signing and measuring are offline operations of Intel's `sgx_sign`.
- a fresh clone of this repository at the commit you want to verify (build from a fresh clone:
  the Docker context is the repository root, and a working tree full of `target/` directories only
  slows the build).

## Build

```bash
git clone <repository> tee-signer && cd tee-signer
git checkout 4dd6285                      # the commit of the measurement you are verifying
SIGN=dev ENCLAVE_KEY=$PWD/out/dev-key.pem OUT=$PWD/out/build-1 docker/build-enclave.sh
```

What happens:

1. `docker build -f docker/Dockerfile.enclave-build` creates the pinned build image: Ubuntu 22.04,
   the Intel SGX SDK and PSW packages at `2.28.100.1` / DCAP `1.25.100.1`, Rust `1.92.0`, the crate
   closure fetched once with `--locked` so the build itself runs offline, `SOURCE_DATE_EPOCH` fixed.
   The image compiles the unsigned `enclave.so` and the daemon.
2. A container signs the enclave with the key at `ENCLAVE_KEY` (generated on the spot if the file
   does not exist — a dev key, labeled as such; it never matters for the measurement) and runs every
   build gate (`docs/ENCLAVE.md` §7): no `cpuid` outside the pinned SDK baseline, no test symbols,
   `--locked` build without `--allow-multiple-definition` or `TEXTREL`, `DisableDebug=1`, the LVI
   `lfence` count above its floor.
3. The outputs land in `OUT`: `enclave.signed.so`, `enclave.so`, `sigstruct.dump`, `MANIFEST`
   (toolchain and package versions), `lfence-count.txt`, `cpuid-sites.txt`, `build.log`.

The last lines of the run are the verdict:

```
build+gates: OK
MRENCLAVE: 2073c234229af3986b9b5a8cd3abc844d1e808a97db14ffb46846a13257410cc
outputs: /…/out/build-1
```

`build+gates: FAILED` means a gate refused the build — read `build.log`; a reproduction of that is a
report in itself.

## Compare

Against the published value: the `MRENCLAVE:` line must equal the table above for the commit you
checked out. Against a second build (yours again, or someone else's `OUT` directory):

```bash
SIGN=dev ENCLAVE_KEY=$PWD/out/dev-key.pem OUT=$PWD/out/build-2 docker/build-enclave.sh
docker/compare-builds.sh out/build-1 out/build-2
```

`compare-builds.sh` is the project's gate 5: it compares `MRENCLAVE`, `ATTRIBUTES` and mask,
`MISCSELECT` and mask, `ISVPRODID` and `ISVSVN` from the two `sigstruct.dump`s and reports
`REPRODUCIBLE` or the diff. It deliberately does **not** compare the signing date, the signer's
modulus (`MRSIGNER`) or the signature — those differ between your dev key and the ceremony key by
design. `enclave.so byte-identical` is the usual outcome as well, but only the SIGSTRUCT fields are
the claim.

## Verify a running node against the measurement

A build on your machine proves what the source measures to. Whether a **node** runs that enclave is
a separate question, answered by DCAP attestation: the owner's `owner-cli` asks the node for a quote
over a fresh nonce and verifies seven things — the certificate chain to the pinned Intel SGX Root CA,
`ATTRIBUTES.DEBUG = 0`, the expected `MRENCLAVE`, the pinned `MRSIGNER`, the identity card signed by
the enclave's identity key, `report_data` bound to the nonce and the card, and the TCB status against
the recorded exceptions (`owner-cli init --expect-mrenclave …` at wallet creation, `owner-cli attest`
afterwards; `docs/FAQ.md`, "verify the enclave"). The verifier refuses a debug enclave, a wrong
measurement, a wrong signer and an unbound quote — those refusals are part of the test suite.

## What the measurement covers, and what it does not

- **Covers:** every page of the enclave image (code and initial data of `rcore` + `signer-core` +
  the SDK trusted runtime) and the launch configuration (`Enclave.config.xml`: heap, stack, TCS
  number, `DisableDebug`, ProdID, SVN, `MiscSelect`). A one-byte source change in the enclave, a
  dependency bump in `enclave/rcore/Cargo.lock`, or a different toolchain changes it. So does a
  **line shift** in a file whose panic locations the binary embeds — checked on the deployed build
  2026-11-19: `core/src/{classify,headers,judge,sign}.rs` and `rcore/src/session.rs` appear as
  `file:line` data in `enclave.so`, which is why even a comment or license header added to those
  files is a new measurement (and why such headers are batched into the next ceremony build).
- **Does not cover:** the signer (`MRSIGNER` is a separate field), the signing date, the host daemon
  `signerd`, the owner tool, the BTCPay plugin, this documentation. A host-side change ships without a
  new measurement; an enclave change cannot.

## Caveats, stated

- The base image is `ubuntu:22.04` by tag, not by digest. The compilers that decide the enclave's
  bytes come from pinned Intel and Rust versions, but a future Ubuntu point release could in theory
  move `binutils`/`gcc` and change the measurement of a *new* build. Agreement on record so far
  (four builds, two machines, 2026-11-19) says it does not today; pinning the base image by digest is
  an open item for the owner.
- Intel's apt repository and SDK installer are fetched by version at image-build time. If Intel
  removes a version, the build **fails** (nothing is silently substituted); the pinned versions are in
  `docker/Dockerfile.enclave-build` and in every `MANIFEST`.
- The crate closure is pinned by the lockfiles and fetched with `--locked`; a yanked crate also fails
  the build rather than changing it.
