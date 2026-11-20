# CLAUDE.md — working rules for this repo

**Project:** tee-signer — a policy-enforcing SGX signer for BTCPay Server hot wallets (SMB sibling
of TRUST). **Read first:** `README.md`, `docs/THREAT-MODEL.md`, `docs/DESIGN.md`, `docs/POLICY.md`.

## Roles

| Role | Where | Does |
|---|---|---|
| **Owner** | the user | approves design, scope, spend, infra, every public claim; answers general questions |
| **Dev (this repo's sessions)** | here | design drafts, code, deployment, e2e. **Never merges enclave design or impl to `main` without a PASS from the auditor.** |
| **Auditor** | the `security-audit-playbook` session (one auditor, star topology) | answers `REQ-*.md` with `RESP-*.md` (DESIGN-PASS / IMPL-PASS / CONDITIONAL / FAIL). Never merges. Specific security questions go there, not to the owner. |

## The one non-negotiable

**The host never decides what gets signed.** Every byte from BTCPay, the plugin, `signerd` or the
host OS is untrusted input: the PSBT, the previous transactions, the headers, the clock, the policy
bytes, the owner's signature. The enclave verifies all of it against sealed state and the owner's
public key, and refuses on any doubt. If a code path lets a host-asserted value (an amount, an
address class, a timestamp, a "this is change" flag) decide a signature, that is the defect this
project exists to remove — stop and escalate.

## Hard rules (a violation is a defect, not a style choice)

1. **REQ/RESP before enclave code.** No `core/` policy logic or `enclave/` module is written before
   its REQ has a DESIGN-PASS in `docs/audit/`. Impl lands on a branch, gets an IMPL-PASS, then merges.
2. **Fail-closed everywhere.** Missing `non_witness_utxo`, unknown script type, unknown sighash,
   unparseable field, policy expired, header chain stale, state unsealable ⇒ refuse. No permissive
   default, not in tests either.
3. **Testnet/signet only.** No mainnet key, address, node or fund is touched by anything in this
   repo without explicit owner sign-off.
4. **Honest labeling, time-stable in both directions.** Every claim states what the code enforces
   today and which tier (T0/T1/T2) it holds in. A claim that outruns the code, or a caveat the code
   has outgrown, is a bug against the doc.
5. **Negative vectors are the deliverable.** Each check ships with the refusal vectors that prove it
   refuses: fee overpayment via lying `witness_utxo`, foreign input signed, change to a foreign key,
   budget overrun at the boundary, stale policy, rolled-back state, replayed policy update.
6. **TCB discipline.** `signer-core` is `no_std`; every crate inside the enclave is a REQ, not a
   commit. Prefer verifying a proof over building one. The host-side (`signerd`, `owner-cli`,
   plugin) may use anything; it is not trusted.
7. **No secrets in git.** No seed, sealed blob, owner key, recovery blob, `.env`, RPC credential —
   ever. Vectors use throwaway signet keys that are labeled as such.
8. **Pure modules.** Policy and classification logic takes bytes in and gives a verdict out — no
   I/O, no ocalls, no global mutable state, hash/verify functions injected — so it runs on the host
   under test exactly as it runs in the enclave.

## Infrastructure isolation (shared SGX host — do not break other projects)

Build/dev host: `<build-box>` (`TEE_BUILD_HOST` in the gitignored `.local/hosts.env`; Hetzner; SGX1, no FLC, legacy `/dev/isgx`; debug
enclaves only; no attestation). It carries the perp DEX, Phoenix, trust-bridge, ethsigner, rippled,
two `bitcoind`s, PostgreSQL, nginx — all other projects' processes, ports, sealed state, systemd
units, wallets and repositories are **never touched**. Rules inherited from trust-bridge
`deploy/README.md`:

- own directories only (`~/tee-signer*`, the lab `~/btcpay-tee-lab`); own ports, listed in
  `deploy/README.md` before use; own systemd units (`tee-signer-*`); own chain daemons with own
  datadirs if a configuration is needed — never another project's wallet.
- delete by **enumerated paths**, never by a glob in a shared directory; verify by the same list.
- `sudo` exists; treat every use as a production change and avoid it.
- never `kill`, `systemctl`, `docker rm/stop` anything not ours.

## Commands (once code exists)

```bash
cd core  && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cd host  && cargo test
cd owner && cargo test
# enclave builds are SERVER-SIDE (SGX SDK + hardware): make SGX_MODE=HW SGX_DEBUG=1 on T1 hardware
```

## Parking routine (owner's rule, 2026-11-03)

At the end of every working session run `scripts/park.sh --remote`: it deletes this project's
own debug build profiles on the laptop (release binaries and all state stay), reports the sizes
that matter, and checks the shared machines read-only — no throwaway `tee-*-test` containers or
state dirs left on the Azure node, no stray SSH forwards on the Hetzner box beyond the owner's
access ports, disk usage on both. Shared scratch (`/tmp`, `/tmp/claude-1000`) is reported, never
swept by the script. Anything the session created outside the project tree is removed by its
enumerated path during the session, not left for the routine.
