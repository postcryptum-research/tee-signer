# tee-signer — a policy-enforcing TEE signer for BTCPay Server hot wallets

**Working name.** Product name to be chosen by the owner.
**Status (2026-11-04):** every round so far has an IMPL-PASS from the auditor and is merged
(`docs/audit/`): R1 `signer-core`, R2 enclave shell + daemon + owner tool, R3 BTCPay plugin with
the four executable gates, R5 **T2 on Azure DCsv3** (reproducible pinned build, non-debug launch,
DCAP-attested identity card verified on the owner's machine), R6 the owner key inside the
operator's **TPM 2.0** and the enclave signed with an offline **ceremony key** (two-step signing,
gate 7), R4 the owner's **monitor** (receipt authenticity, seq-fork, chain observation first,
feed stall, freeze reflex), R6b the owner key on a **YubiKey 5 PIV** slot (PIN + touch per
signature; a slot becomes owner only through its attestation verified to Yubico's pinned root). The T1 box (SGX1, no FLC) runs the same enclave in debug launch for
development; the T2 node runs it non-debug. Signet only. The production code gate is met; what
remains is the operator's key custody (where the ceremony and TPM keys live) and the carried
items in `docs/audit/CONDITIONS.md`. Two models, kept apart: `THREAT-MODEL.md` (compromise) and
`docs/CONTINUITY.md` (accidents).

## The problem

On 2026-11-01 BTCPay Server instances running 2.4.1 or older had their
**hot wallets swept**. The attacker logged in as a BTCPay *admin*; the
mechanism is still under investigation (BTCPay's statement, forklog). A
BTCPay hot wallet is a BIP39 seed stored in NBXplorer's database and used by
the BTCPay process itself to sign PSBTs — so anyone who can act as BTCPay
can (a) read the seed and (b) sign any transaction. Both halves are needed
for the attack, and today both are one login away.

This is the small-business face of the problem TRUST solves for
enterprises with multi-operator thresholds, enclaves and ceremonies. A
merchant running BTCPay on one box has no operators, no ceremony budget and
no security team. They need a drop-in.

BTCPay's own statement on the incident (2026-11-02): *"Funds in wallets whose spending keys
are held off the server, including hardware wallets, were unaffected by these thefts."* A
hardware wallet needs a human per transaction; a merchant's payouts and sweeps do not have one.
tee-signer is that recommendation made automatic.

## What tee-signer does

1. **The seed never exists as a file.** It is generated inside an SGX enclave
   from hardware randomness, sealed to that enclave, and never leaves it in
   clear. BTCPay gets a watch-only account xpub. A cold **recovery blob**,
   encrypted to the merchant's offline recovery key, is the only other copy.
2. **The enclave signs only inside a mandate.** Every PSBT is parsed and
   judged *inside the enclave* before any input is signed: inputs must be
   the wallet's own (verified by derivation and the full previous
   transaction), change is recognised by derivation, destinations are
   classed as *trusted* (the merchant's cold storage descriptor, an
   exchange address) or *unlisted* (customer payouts), each class has a
   per-transaction cap and a per-window budget, fees are bounded,
   `SIGHASH_ALL` only, payjoin only as net inflow. Anything else is refused.
3. **The mandate changes rarely and never from the host.** It is signed by
   the merchant's **owner key** on a separate device (YubiKey, TPM, Apple
   Secure Enclave or a phone — through the `hw-signer` backends of
   [TPM_sign](https://github.com/77ph/TPM_sign)), with a nonce, and a
   loosening change takes effect only after a **timelock**, during which
   the owner can cancel. Routine signing inside the mandate needs nobody.
4. **Budget windows run on Bitcoin time.** The enclave follows the block
   header chain from an owner-pinned checkpoint; a budget window is 144
   blocks, not 24 host-clock hours, so a compromised host cannot reset the
   budget by moving the clock.
5. **Every signature leaves a receipt** with a monotonic sequence number,
   signed by the enclave's identity key, so the owner's monitor detects a
   host that rolled the enclave's state back.

The idea of the mandate — allow-list, per-operation cap, budget, validity
window, owner/agent separation, rotate / revoke / recover — is TPM_sign's
`AgentPolicy`. There it is enforced on-chain by a smart account; here there
is no chain to enforce it, so it is enforced inside the TEE. The code is
not shared; the model is.

## What it protects against — honest tiers

| Tier | Hardware | Protects against | Does NOT protect against |
|---|---|---|---|
| **T1** | SGX1 without Flexible Launch Control (cheap bare metal of the Hetzner class, e.g. Xeon E3 v5/v6). The enclave is **built** either way (`make` / `make RELEASE=1`, Makefile gates), but on this hardware only a **debug launch** succeeds: a non-debug launch asks Intel's Launch Enclave for a launch token, which it issues only for an Intel-whitelisted signing key (measured 2026-11-03 on the box: `DisableDebug=1` enclave, debug=0 ⇒ `sgx_create_enclave` 0x4004 `SERVICE_INVALID_PRIVILEGE`; debug=1 ⇒ 0x2004 `INVALID_ATTRIBUTE`). FLC hardware removes that dependency (the platform sets its own launch policy). The whitelist path itself is closed going forward: Intel's SDK/PSW 2.28 release notes remove the legacy Launch Enclave and whitelist management (the launch-token APIs return `SGX_ERROR_FEATURE_NOT_SUPPORTED`) and keep FLC through the in-kernel driver as the only launch mechanism. **No remote attestation exists** for this hardware (EPID retired 2025-04). | the observed attack class: BTCPay admin, a malicious plugin, RCE inside the BTCPay container, any **non-root** compromise of the host (with `ptrace_scope ≥ 2`) | host **root**: a root user can read a debug enclave's memory, so on T1 **neither the seed nor the mandate enforcement** is protected from root; a hardware or Intel-level attacker |
| **T2** | SGX with FLC + DCAP (Azure DCsv3, Xeon E-2200+, Ice Lake+). `DisableDebug=1`, attested. | everything in T1, **plus the seed stays out of root's reach** (up to the SGX threat model; side channels and microcode TCB excluded). Root can still repeat a window's payouts by restoring an old sealed state, so the hot wallet's balance is the exposure (`docs/HOW_IT_WORKS.md`, scenario 3) | physical / Intel-level attackers; SGX side channels |
| **T0** | software signer, no TEE | nothing — dev and CI only | everything |

Both T1 and T2 close the November 2026 attack. T1 is the merchant tier the
project exists for; T2 is the same binary on better silicon.

## Layout (planned)

```
docs/            THREAT-MODEL.md, DESIGN.md, POLICY.md, audit/ (REQ/RESP cycle)
core/            signer-core — no_std Rust: PSBT parse, classification, policy
                 engine, canonical encodings, receipts. Host-testable, negative
                 vector suite is the deliverable.
enclave/         Intel SGX SDK shell (C): ecalls, sealing, RDRAND, links core
host/            signerd — Rust daemon: loads the enclave, HTTP API for BTCPay,
                 header feed, receipt log
owner/           owner-cli — builds, diffs and signs mandates with hw-signer
                 (YubiKey / TPM / Secure Enclave / software for tests)
btcpay/          BTCPayServer.Plugins.TeeSigner (C#): TEE payout processor, "Sign with
                 TEE signer" on the Send page, status page — wallet stays cold in BTCPay
vectors/         golden vectors, positive and the refusal suite, from signet
deploy/          docker fragment for btcpayserver-docker, systemd, isolation table
```

## Reading order

Start with [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md) (one page) and
[`docs/FAQ.md`](docs/FAQ.md) (two worked setups, what gets refused and why, what to do when
things break; Russian: [`HOW_IT_WORKS_ru.md`](docs/HOW_IT_WORKS_ru.md),
[`FAQ_ru.md`](docs/FAQ_ru.md)). Then `docs/THREAT-MODEL.md` → `docs/DESIGN.md` →
`docs/POLICY.md` → `docs/CONTINUITY.md` → `docs/audit/PROTOCOL.md`. Working rules for
sessions: `CLAUDE.md`.
