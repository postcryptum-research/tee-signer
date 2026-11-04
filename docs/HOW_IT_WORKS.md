# How it works — on one page

Russian version: [`HOW_IT_WORKS_ru.md`](HOW_IT_WORKS_ru.md). Questions and worked setups: [`FAQ.md`](FAQ.md).

## The short version

**Before.** A BTCPay Server hot wallet is a BIP39 seed that lives in NBXplorer's database and
is used by the BTCPay process itself to sign. Whoever can act as BTCPay — an admin login, a
malicious plugin, a bug in the web app — can read the seed *and* sign any transaction. In
November 2026 that is exactly how hot wallets were swept. The key is a file, and the file can
sign anything, forever.

**After.** With tee-signer there is no seed file. The seed is generated **inside an SGX enclave**
on the merchant's own server and never leaves it in clear. An enclave is a protected region of
the CPU's memory, walled off from the operating system (Intel SGX; AMD has an equivalent), where
a special program runs: think of a hardware wallet like a Ledger Nano, built into the server's
CPU. The key lives in it; a transaction goes in, a signed transaction — or a refusal — comes out.
BTCPay gets a watch-only account xpub and keeps working as it does with any cold wallet. When BTCPay needs a
signature — a customer payout, a sweep to cold storage — it hands the enclave a PSBT, and the
enclave **judges the transaction itself** against a **mandate** the merchant signed on a separate
device: which destinations are trusted, how much per transaction, how much per budget window, fee
bounds, no foreign inputs. Inside the mandate the enclave signs without anyone present. Outside
it, the enclave refuses — whatever BTCPay, the plugin, the daemon or the host asked for.

The mandate is TPM_sign's `AgentPolicy` idea (allow-list, caps, budget, validity, owner / agent
separation, rotate / revoke / recover). There a chain enforces it; here there is no chain, so the
enclave does.

## How one payout goes

1. **BTCPay** (through the plugin) builds the payout PSBT as it would for a hardware wallet, with
   the full previous transactions and the derivation hints the enclave needs.
2. **`signerd`**, an untrusted daemon next to BTCPay, passes the bytes into the enclave. It cannot
   authorise anything; it is a pipe and a disk.
3. **The enclave** parses the PSBT, proves every input is the wallet's own by re-deriving it,
   takes the amounts from the previous transactions (never from what the host asserts), recognises
   change by derivation, classes every other output as *trusted* or *unlisted*, and checks the
   caps, the window budget, the fee bounds and the structural rules of the installed mandate.
4. **It refuses, or it commits and signs.** On refusal, a machine-readable reason list comes back
   (`CAP_UNLISTED_TX`, `FEE_RATE`, `INPUT_NOT_OWN`, …) and nothing is charged. On success the
   enclave first records the spend in its sealed state, *then* signs, and returns the signed PSBT.
5. **BTCPay** finalises and broadcasts, as for any externally signed PSBT.

Budget windows are counted in **blocks** (144 ≈ a day), not in host-clock hours: the enclave
follows the block-header chain from an owner-pinned checkpoint, so a compromised host cannot reset
the budget by moving the clock.

## If the worst happens

| What happens | A BTCPay hot wallet | tee-signer |
|---|---|---|
| The admin login is stolen (the November 2026 attack) | the whole wallet is swept | at most what the mandate allows for the current window — to unlisted destinations capped per transaction and per window; the merchant freezes and the budget rolls back nothing |
| A malicious plugin, or code execution inside the BTCPay container | same | same: the plugin can only *ask* the enclave |
| Malware with the merchant's user rights on the server | same | same, plus the sealed state can be read but not opened |
| **Root** on the server | same — root reads everything BTCPay reads | **T1** (SGX1 without Flexible Launch Control): root can read the enclave's memory, as it can read today's seed — no worse than today, and no better on this one front. **T2** (FLC + DCAP): the seed stays out of root's reach; the balance does not (scenario 3 below) |
| The host's clock or block feed is manipulated | the wallet does not care | windows run on verified block headers; a withheld feed only stops windows from rolling (the current window's remaining budget is the cap) |
| The merchant's owner device is stolen | — | the thief can only submit a *loosening*, which waits a **timelock** (one day by default) during which the merchant cancels with the recovery key; a tightening would only hurt the thief |
| The server dies, the disk is lost | the seed is in the database backup — or gone | the seed also exists in the **recovery blob**, encrypted to the merchant's offline recovery key: restore into any BIP84 wallet ([`CONTINUITY.md`](CONTINUITY.md)) |

## What an attacker can still steal

Written the way an attacker thinks: who they are, what they do, what they get. The amounts use
the example mandate in [`POLICY.md`](POLICY.md): unlisted payouts capped at 0.01 BTC per
transaction and 0.05 BTC per window of 144 blocks.

1. **Logged in as your BTCPay admin, or running a plugin they planted** (the November 2026
   attack). They make the enclave pay to their own addresses: 0.01 BTC per transaction, 0.05 BTC
   per window, then nothing until the next window or until you freeze. They cannot take the rest
   and cannot take the seed. *Closed down to the window budget, on both tiers.*
2. **Root on your T1 server** (the hosting provider, a full compromise). They read the seed out
   of the enclave's memory and own the whole hot wallet — what is in it now and what arrives
   later — exactly as with today's BTCPay. *Not closed on T1.* On T2 the seed is unreadable.
3. **Root on your T2 server.** They cannot read the seed and cannot make the enclave sign a
   transaction outside the mandate's shape. What they can do: let the enclave pay a window's
   budget to them, restore an older copy of the enclave's state file, restart it, and collect the
   same window again — a restart takes seconds. Assume root drains the hot wallet's balance, a
   window at a time. *Not closed by the mandate.* What bounds it is what sits in the hot wallet:
   keep a day or two of payouts there and let the rest go to cold storage — a trusted
   destination the enclave pays on schedule with nobody present — and root gets the float, not
   the business. The freshness witness (expert mode) narrows the trick to about one token's
   lifetime (`maxTipLag` blocks) and the monitor raises an alarm; neither stops a fast attacker.
4. **Your laptop stolen or controlled.** Routine payouts need no laptop, so nothing changes
   there. With your owner key in hand — the keyfile and its passphrase, or the YubiKey and its PIN
   while you are not there — they can submit a *loosening* (a bigger budget, their address as
   trusted), which waits the timelock and which you cancel with the recovery key. A controlled
   laptop can also show you one mandate and have the device sign another; a device with its own
   display is a later round.
5. **The recovery key and the recovery blob, stolen together.** That is the seed: the whole hot
   wallet. Keep them on different media in different places.
6. **Physical access to the CPU, Intel-level attacks** (side channels, microcode). Out of scope on
   every tier.

Everything else an attacker on the server can do — ask for signatures, delete files, stop the
daemon, withhold block headers, set the clock — ends in a refusal or a pause.

## The owner stays in charge

Two keys, kept apart, neither ever on the BTCPay box:

- the **owner key** signs mandate changes, freezes / unfreezes, hands the role to another key. It
  lives in a TPM 2.0 (`tpm:`), on a YubiKey 5 PIV slot with PIN + touch per signature (`piv:`),
  or — the permitted floor — in an encrypted keyfile on a USB drive. It is used rarely.
  Routine signing inside the mandate needs nobody.
- the **recovery key** is a cold encrypted keyfile on two media in two places. It can cancel a
  pending change, replace a lost owner key at once, and decrypt the recovery blob. It is the
  backstop that makes the owner key's compromise bounded.

A mandate **tightening** applies at once. A **loosening** — a higher cap, a new trusted
destination, a new owner — waits the mandate's timelock, visible at `status`, cancellable by
either key. One change in flight at a time. Anyone may **freeze** (no signature needed); only the
owner unfreezes.

## Expert mode, optional

The main path is two keys, one mandate, three commands and the plugin page; nothing in this
section is needed for it. For an operator who wants scenario 3 above *watched* rather than accepted: the enclave signs a **receipt** for every signature (sequence number, txid, amounts,
height) with a second key, its **stamp**; `owner-cli monitor`, run off the server, verifies those
receipts, watches your addresses on the chain from your own node for spends without a receipt,
notices a sequence that went backwards (a rollback) or a feed that stopped, and sends a freeze.
With `freshness.required` in the mandate the monitor also issues short-lived witness tokens, and a
rolled-back enclave pauses instead of re-spending a window. All of it is off unless you run it;
[`FAQ.md`](FAQ.md) describes it.

## Honest tiers

| Tier | Hardware | Closes the November 2026 attack | Protects from root on the server |
|---|---|---|---|
| **T1** | SGX1 without FLC (cheap bare metal, e.g. Xeon E3 v5/v6); the enclave can only be launched in debug mode; no remote attestation | yes | **no** — labeled, by the hardware |
| **T2** | SGX with FLC + DCAP (Azure DCsv3, Xeon E-2200+, Ice Lake+); non-debug launch; the enclave's identity is attested and verified on the owner's machine | yes | the seed: yes; the balance: no — root can repeat a window's payouts by restoring an old state file (scenario 3), so what you keep in the hot wallet is the exposure |
| **T0** | software, no TEE | dev and CI only | no |

In practice: today's BTCPay seed is readable by the BTCPay service user (not root), by the admin,
by a plugin — and by root. T1 takes it away from everyone below root and leaves root where it
was. T2 takes it away from root as well. Pick T1 for the attack that happened, on the hardware
you already rent; pick T2 when your threat includes the hosting provider or a root compromise.
Both tiers run the same enclave binary, reproducibly built and signed with an offline ceremony
key. Today the project runs on **signet** only.

## Where to go next

- [`FAQ.md`](FAQ.md) — two worked setups (a cheap SGX1 box; Azure DCsv3 with a YubiKey) and the
  questions people ask: what gets refused and why, what a day in the life looks like, what to do
  when things break.
- [`POLICY.md`](POLICY.md) — the mandate, field by field, and the refusal reasons.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — adversaries, invariants, residual risks (compromise).
- [`CONTINUITY.md`](CONTINUITY.md) — accidents: what can be lost and how it is recovered.
- [`DESIGN.md`](DESIGN.md) — components, key lifecycle, signing flow, the block clock.
- [`audit/`](audit/) — every round's request and the auditor's verdict; [`audit/CONDITIONS.md`](audit/CONDITIONS.md) is the worked queue of what is still open.
