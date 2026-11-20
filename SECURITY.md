# Security policy

**Status:** signet only. No mainnet deployment exists or is supported today (`CLAUDE.md`, rule 3).
There is no bug bounty. The project is small; reports are read by the owner and the dev and, where
they touch the enclave or `core/`, by the independent auditor (`docs/audit/PROTOCOL.md`).

## What counts as a vulnerability here

The one invariant of this project: **the host never decides what gets signed.** Every byte from
BTCPay, the plugin, `signerd`, the host OS, the clock or the header feed is untrusted input; the
enclave verifies it against sealed state and the owner's public key and refuses on any doubt.
Report anything that breaks that, in particular:

- a PSBT the enclave signs **outside the owner-signed mandate** — a foreign input, change to a
  foreign key, a per-transaction cap or window budget passed at the boundary, a fee bound bypassed
  through a lying `witness_utxo`, a sighash other than `ALL`, payjoin as a net outflow;
- a mandate or owner message accepted **without a valid owner signature, nonce or timelock**, or a
  replayed update;
- a **stale or rolled-back sealed state** the enclave accepts as current (sequence, TPM counter,
  header chain, boot-arm after a restart);
- an attestation the owner's verifier (`owner-cli`) **accepts although it should refuse** — a debug
  enclave, a wrong `MRENCLAVE`/`MRSIGNER`, `report_data` not bound to the nonce and the identity card,
  a chain that does not end at the pinned Intel root;
- a build from the pinned recipe that **does not reproduce** the published measurement
  (`docs/REPRODUCIBLE-BUILD.md`), or a measurement that changes without a corresponding source change;
- the seed, the enclave's identity key or the recovery blob **in clear outside the enclave**, in any
  log, file, receipt or error message;
- the owner key, the ceremony key or a recovery passphrase **handled by anything but the owner's own
  device or terminal** (the tools must never ask a passphrase into an environment variable, log it,
  or send it anywhere).

**Out of scope** (stated residuals, not bugs — see `docs/THREAT-MODEL.md`): SGX microarchitectural
side channels and platform-TCB advisories (row V6 and the platform-TCB row), denial of service against
the operator's own payouts (a pause is the designed fail-closed outcome), anything that requires a
compromised owner device, and findings against the T0 software signer or the T1 debug tier beyond what
their rows claim.

## How to report

Privately, please — not as a public issue.

- **GitHub private vulnerability reporting** on this repository (Security → *Report a vulnerability*).
  <!-- owner: enable "Private vulnerability reporting" in the repository settings before the repo goes public -->
- **Email:** `<security contact — owner to fill in>` <!-- owner: address, and a PGP key if you want encrypted reports -->

Include the commit you looked at, the `MRENCLAVE` if a built enclave is involved, and a reproduction.
A refusal vector in the `vectors/` layout (a PSBT or an owner message plus the expected verdict) is
the ideal report; it becomes the regression test.

## What to expect

<!-- owner: confirm or change the two numbers -->
- an acknowledgement within **3 business days**;
- a fix or a stated decision within **30 days** for anything that touches the invariant above.

A fix to the enclave or to `core/` follows the project's audit discipline
(`docs/audit/PROTOCOL.md`): REQ → DESIGN-PASS → implementation on a branch → IMPL-PASS →
ceremony-signed build → a **new published measurement**. An enclave fix therefore reaches a node only
as a new `MRENCLAVE`, and the fix is recorded in `docs/audit/` with credit to the reporter unless you
prefer none.

## Deployed measurement

The measurement currently live on the project's signet node, and the one-command recipe to rebuild
and match it, are in `docs/REPRODUCIBLE-BUILD.md`.
