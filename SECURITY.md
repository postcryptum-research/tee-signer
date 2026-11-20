# Security policy

## Status

This project runs on **signet**, a Bitcoin test network, and holds no real funds. Nothing in this
repository touches mainnet (`CLAUDE.md`, rule 3). Every round of the design and the code has been
through the project's internal review discipline — a REQ answered by a DESIGN-PASS / IMPL-PASS from an
independent reviewer, recorded verbatim in [`docs/audit/`](docs/audit/) — not a third-party audit.
A third-party audit comes before any mainnet funds.

## Reporting a vulnerability

Report it privately through GitHub: the **Report a vulnerability** button on the repository's
Security tab. Only the maintainers see the report. Please do not open a public issue for it.
<!-- owner: enable "Private vulnerability reporting" in the repository settings; once the public name is
     fixed, the direct link is https://github.com/<org>/<repo>/security/advisories/new -->

We aim to acknowledge a report within 5 business days.

Include the commit you looked at, the `MRENCLAVE` if a built enclave is involved, and a reproduction.
A refusal vector in the [`vectors/`](vectors/) layout — a PSBT or an owner message plus the verdict the
enclave should have given — is the ideal report; it becomes the regression test.

## Scope

- The trusted core in `core/` and the enclave in `enclave/` (`rcore`, the SDK shell, the build gates).
- The host daemon `host/signerd` and the BTCPay Server plugin in `btcpay/` — untrusted by design,
  in scope where they can make the enclave do something the mandate forbids.
- The owner tool `owner/owner-cli`, above all its attestation verifier: what it accepts, the owner trusts.
- The build recipe in `docker/` and the reproducibility claim in
  [`docs/REPRODUCIBLE-BUILD.md`](docs/REPRODUCIBLE-BUILD.md): a build from the pinned recipe that does not
  reproduce the published `MRENCLAVE` is a report.

The machine the signer runs on is **untrusted by design**: every byte from BTCPay, the plugin, `signerd`,
the host OS, the clock and the header feed is input the enclave verifies against its sealed state and the
owner's public key. What a compromised host can and cannot do is the subject of
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). A report that shows it can do more than the owner-signed
mandate allows — sign a foreign input, pay change to a foreign key, pass a cap or a window budget, accept a
rolled-back state, bypass the owner's signature or the attestation check — is in scope.

Out of scope, as stated residuals rather than bugs: SGX microarchitectural side channels and platform-TCB
advisories (`docs/THREAT-MODEL.md`, row V6 and the platform-TCB row), and denial of service against the
operator's own payouts — a pause is the designed fail-closed outcome.
