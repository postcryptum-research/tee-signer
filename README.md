# tee-signer — a policy-enforcing TEE signer for BTCPay Server hot wallets

**Working name.** Product name to be chosen by the owner.
**Status (2026-11-03):** DESIGN-PASS; R1 `signer-core` and R2 (enclave shell, header verifier,
daemon, owner tool) both IMPL-PASS and merged (`docs/audit/`). The enclave runs on SGX1 hardware
in **debug launch** (tier T1-debug) and has signed its first signet transaction under a mandate.
Not yet: the owner's monitor (R4, the gate for any use on real value), reproducible builds and a
release launch on FLC/DCAP hardware (R5), the BTCPay plugin (R3). Testnet/signet only.

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
| **T1** | SGX1 without Flexible Launch Control (cheap bare metal of the Hetzner class, e.g. Xeon E3 v5/v6). Enclave runs in **debug** mode because production launch needs Intel's launch-enclave whitelist. **No remote attestation exists** for this hardware (EPID retired 2025-04). | the observed attack class: BTCPay admin, a malicious plugin, RCE inside the BTCPay container, any **non-root** compromise of the host (with `ptrace_scope ≥ 2`) | host **root**: a root user can read a debug enclave's memory, so on T1 **neither the seed nor the mandate enforcement** is protected from root; a hardware or Intel-level attacker |
| **T2** | SGX with FLC + DCAP (Azure DCsv3, Xeon E-2200+, Ice Lake+). `DisableDebug=1`, attested. | everything in T1 **plus** host root, up to the SGX threat model (side channels and microcode TCB excluded) | physical / Intel-level attackers; SGX side channels |
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

`docs/THREAT-MODEL.md` → `docs/DESIGN.md` → `docs/POLICY.md` →
`docs/audit/PROTOCOL.md`. Working rules for sessions: `CLAUDE.md`.
