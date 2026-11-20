# Contributing

Thank you for looking. This project guards money with a small trusted computing base, so the rules
below are about *where* a change may land, not about style.

## Read first

`README.md`, `docs/THREAT-MODEL.md`, `docs/DESIGN.md`, `docs/POLICY.md`, and the working rules in
`CLAUDE.md` (they bind every contributor, human or not). The one invariant: **the host never decides
what gets signed.**

## Two kinds of change

| Where | What it is | How it lands |
|---|---|---|
| `core/`, `enclave/` | the TCB: policy, classification, sealing, the ecall surface, every crate inside the enclave | **REQ → DESIGN-PASS → branch → IMPL-PASS → merge** (`docs/audit/PROTOCOL.md`). No enclave or `core/` code is written before its REQ has a DESIGN-PASS in `docs/audit/`; nothing merges without an IMPL-PASS at the delivered commit. A merged enclave change reaches a node only as a new ceremony-signed build with a new published `MRENCLAVE` (`docs/REPRODUCIBLE-BUILD.md`). |
| `host/signerd`, `owner/owner-cli`, `btcpay/`, `scripts/`, `docker/`, `docs/`, `vectors/` | the untrusted side, tooling, documentation | an ordinary pull request. CI must be green (`cargo fmt`, `clippy -D warnings`, tests, the gitleaks gate). Changes to the attestation verifier in `owner-cli` and to the build recipe in `docker/` are reviewed as if they were TCB: they decide what the owner trusts. |

A refusal vector is the most welcome contribution of all: a PSBT or owner message the enclave must
refuse, with the expected verdict, in the `vectors/` layout. Each check in this project ships with the
negative vectors that prove it refuses (`CLAUDE.md`, rule 5).

## Hard rules, briefly

- fail-closed everywhere — no permissive default, not in tests either;
- `signer-core` stays `no_std`; every crate inside the enclave is a REQ, not a commit;
- pure modules: bytes in, verdict out, no I/O in policy code;
- signet/testnet only; no mainnet key, address or fund is touched by anything in this repository;
- **no secrets in git** — no seed, sealed blob, owner key, recovery blob, `.env`, RPC credential;
  test vectors use throwaway signet keys and say so;
- honest labeling: every claim states what the code enforces today and in which tier (T0/T1/T2).

## Local checks

```bash
cd core           && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cd enclave/rcore  && cargo fmt --check && cargo clippy --features nosgx,test-init --all-targets -- -D warnings && cargo test --features nosgx,test-init
cd host/signerd   && cargo test --features nosgx
cd owner/owner-cli && cargo test        # needs libtss2-dev, libpcsclite-dev, clang, pkg-config
cd fuzz  && cargo test --no-default-features   # the fuzz replay gate (REQ-r10); discovery runs: fuzz/run.sh <target>, laptop only
```

The enclave itself is built only through the pinned Docker recipe (`docs/REPRODUCIBLE-BUILD.md`);
it needs no SGX hardware to build and measure, and SGX hardware with FLC/DCAP to run attested.

## Security reports

Not as issues or pull requests — see `SECURITY.md`.

## License

Apache-2.0 (`LICENSE`). By contributing you agree that your contribution is licensed under the same
terms (inbound = outbound).
