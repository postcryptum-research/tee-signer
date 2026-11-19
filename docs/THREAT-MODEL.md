# Threat model

**Status:** draft for the first audit round (2026-11-03). Nothing here is enforced by code yet.

## 1. Assets

| Asset | Where it lives | Loss means |
|---|---|---|
| **A1 — the wallet seed** (BIP39 → BIP32 master) | inside the enclave, sealed at rest | total loss of the hot wallet, forever |
| **A2 — signing authority** (the ability to obtain a valid signature) | the enclave's ecall surface, reachable through `signerd` | loss bounded by the mandate |
| **A3 — the mandate** (policy + the owner's public key + nonce) | sealed state, installed by owner signature | an attacker who can change it owns A2 |
| **A4 — the owner key** | the merchant's separate device (YubiKey / TPM / Secure Enclave / phone) | attacker can rewrite the mandate (after the timelock) |
| **A5 — the recovery blob** (seed encrypted to the recovery key) and **the recovery key** | offline, merchant's custody | blob + key together = A1 |
| **A6 — budget/sequence state** (window usage, sequence, last header) | sealed state | rollback = one extra budget window |

## 2. Adversaries

| Id | Adversary | Capabilities | Tier that excludes them |
|---|---|---|---|
| **V1 — BTCPay admin** | the November 2026 attacker: valid admin credentials, full BTCPay UI/API, can upload plugins (= code execution inside the BTCPay process/container) | T1, T2 |
| **V2 — non-root host user / container escapee** | arbitrary code on the host as an unprivileged user; can talk to `signerd`; can read any file that user can read; **cannot** `ptrace` `signerd` (`kernel.yama.ptrace_scope ≥ 2`) | T1, T2 |
| **V3 — host root** | everything on the host: can read a *debug* enclave's memory through the SGX debug interface, can roll sealed state back, can replace binaries, can withhold or replay anything | **T2 only** |
| **V4 — the host's time and chain view** | V2 or V3 can set the host clock arbitrarily and feed any block headers they can obtain or mine | T1, T2 (windows run on PoW time) |
| **V5 — owner-key thief** | holds the owner device or extracted its key, not the recovery key | partially: the timelock + the owner's cancel; fully only by the owner rotating to the recovery key in time |
| **V7 — the cloud provider itself** (Azure, for T2 on DCsv3) **and anyone with control-plane rights over the VM's virtual hardware** — a subscription Contributor or a service principal with disk rights: the OS disk *and the vTPM's state (VMGS) can be snapshotted, exported and restored together* (widened 2026-11-17 after a reviewer's point, confirmed by the auditor the same day; the provider is not the only party in this class — the subscription's operator service principal has Contributor) | hypervisor, storage snapshots, the vTPM and its state | **accepted as a residual by the owner (2026-11-05)**: the posture every provider-hosted TEE has (AWS Nitro rests entirely on the provider); consequence: the adversary of "root on a T2 server" is root *inside* the VM, and a hypervisor-owned vTPM counts as a trustworthy freshness source (`docs/studies/FRESHNESS-SOURCES-2026-11-05.md`, source 3) **against that adversary only**: a disk+VMGS restore rolls the sealed blob and the counter back *consistently*, the R9 comparison passes, and the bound is the hot float (one mandate window per cycle, repeatable) — R7's attended `arm` bounds this adversary better than R9's auto-arm does. The SGX seal breaking when the restored VM lands on another CPU is luck of host allocation, not a guarantee |
| **V6 — physical / Intel-level** | CPU vulnerabilities, microcode TCB, side channels, decapping | out of scope at every tier; stated, not mitigated |

The attack that motivates the project is **V1**. V1 is excluded at every TEE tier. V3 is the
classic SGX adversary and is excluded only at T2, and that is said on every label.

## 3. What each adversary can and cannot do

### V1 / V2 — application-level compromise (the November 2026 class)

Can: request any signature through the API, as many times as they like; read everything
BTCPay can read (invoices, the watch-only xpub, the policy as installed — it is public); freeze the
signer (harmless, fail-closed); submit a policy update with an **invalid** owner signature
(refused); submit a **replayed** owner-signed policy (refused: nonce); submit a replayed valid
*loosening* policy from the past (refused: nonce strictly increases).

Cannot: read the seed; sign to an unlisted destination above `unlisted.maxPerTx` or beyond
`unlisted.maxPerWindow`; sign to any destination above `limits.maxPerTx`; move more than
`limits.window.maxOutflow` per 144 blocks in total; sign a fee above the bounds; sign with any
sighash but `ALL`; make the enclave sign a *foreign* input; make change go to a key that is not
the wallet's; reset the window by moving the clock (windows are block-counted); change the
mandate.

**Bound:** the loss an application-level attacker can cause between the compromise and the owner's
freeze is ≤ `limits.window.maxOutflow` per 144 blocks, of which unlisted destinations get at most
`unlisted.maxPerWindow`; trusted destinations are the merchant's own cold storage, so outflow
there is not a loss. With a typical merchant mandate (unlisted: 0.01 BTC/tx, 0.05 BTC/day;
trusted: cold descriptor only) the attacker's take is 0.05 BTC/day instead of the whole wallet.

### V3 — host root

T1: can attach a debugger to the debug enclave (`EDBGRD`/`EDBGWR`) and so read the seed **and**
alter the mandate enforcement in memory — **T1 claims nothing against root, neither for the seed
nor for the policy** (auditor, RESP-prequestions Q1). What T1 does claim, and what the November
2026 incident needed: the seed is no longer a file or a database row the application can read,
and the application cannot sign outside the mandate.
T2: cannot read the seed or the state; can still: roll sealed state back (bound: one extra budget
window per rollback, and the receipt sequence exposes it); withhold headers (DoS: windows never
advance, so the current window's remaining budget is all that can ever be spent); withhold or
delay owner updates (DoS); replace `signerd` (changes nothing the enclave trusts); kill the service
(DoS). DoS is a loss of availability, never of funds — the merchant's funds sit in a watch-only
wallet that can be recovered from the recovery blob.

### V4 — clock and chain

The enclave has **no trusted time** (SGX1 has no trusted-time service; SGX2 platforms' is
deprecated). Therefore:
- **budget windows are measured in blocks** on a header chain the enclave verifies from an
  owner-pinned checkpoint (SHA256d, prev-hash linkage, target/retarget rule, cumulative work). To
  reset a window the attacker must present 144 blocks of valid proof-of-work. On mainnet that is
  the network's hash rate; on signet/testnet it is cheap, and the testnet label says so.
- **validity dates** (`validity.notAfter`, the timelock's activation height) are also in block
  height, not wall time.
- Host wall time is used for **nothing** that affects a signature. It may be logged.
- The header feed can be **withheld** (DoS) but not **forged**; a fork with less work than the
  known best is ignored; a reorg deeper than `limits.maxReorg` freezes the signer until the owner
  re-pins.

### V5 — owner-key thief

Can: submit a valid loosening policy. It becomes **pending** for `timelock` blocks (owner-chosen,
e.g. 144); `signerd` and the receipts announce it; the legitimate owner cancels it with the
recovery key or the owner key (either suffices to cancel — cancel is fail-closed), and rotates
the owner key to a new device with the recovery key. A tightening policy applies immediately —
a thief tightening the mandate is a DoS, not a theft.

Cannot: shorten the timelock without waiting the current timelock; apply a loosening change
before the timelock; sign transactions (the owner key never signs transactions).

### V6 — out of scope

Side channels against the enclave's secp256k1 (constant-time implementation is required and
stated; it is not a proof of side-channel freedom), microcode, physical attacks, Intel. Listed so
that no label implies otherwise.

## 4. Invariants the enclave enforces (the "backing question")

For every signature the enclave produces there is an enclave-enforced chain of facts tying it to
the mandate. "`signerd` checked it" or "BTCPay only sends valid PSBTs" is never backing.

| # | Invariant | Enforced by |
|---|---|---|
| I1 | Every signed input is the wallet's own: its `scriptPubKey` equals the one derived in-enclave from the sealed master key at the PSBT's claimed path, and the path is under the wallet's account | derivation in-enclave, match, refuse otherwise |
| I2 | Every input's amount is the one in the **full previous transaction** whose txid equals the outpoint's txid | `non_witness_utxo` required for **every** input, own and foreign; txid recomputed in-enclave; `witness_utxo` alone, or one that disagrees, is refused |
| I3 | An output is *own* only if its `scriptPubKey` equals an in-enclave derivation under the wallet's account on branch 0 or 1 at an index within the sealed bound + gap | derivation + match; host `bip32_derivation` on outputs is a hint, never a decision — a hint that does not reproduce the script refuses, a missing hint makes the output unlisted |
| I4 | An output is *trusted* only if it matches an address or descriptor-derived address of the installed mandate within that descriptor's gap limit | derivation from the mandate's xpub in-enclave |
| I5 | Net outflow = Σ own inputs − Σ own outputs; it is ≤ `limits.maxPerTx` and, added to the current window's usage, ≤ `limits.window.maxOutflow`; per-class caps likewise | arithmetic in-enclave, checked overflow, state updated **before** the signature is released (sign-then-commit is refused by construction: commit, seal, then sign) |
| I6 | Fee = Σ all inputs − Σ all outputs ≤ `limits.maxFeeAbs` and ≤ `limits.maxFeeRate` × vsize, where the vsize is a **lower-bound** estimate (so the computed rate is never below the real one) | arithmetic in-enclave |
| I7 | Only `SIGHASH_ALL`; transaction version 1 or 2; no unknown PSBT fields that change meaning; script types limited to those the mandate names | parser refuses the rest |
| I8 | Payjoin: foreign inputs are never signed, and the transaction is accepted only if net outflow ≤ 0 (the merchant receives) or the foreign-input case is explicitly allowed by the mandate with the same outflow rules | classification + rule |
| I9 | The mandate in force is the latest one whose owner signature verified against the sealed owner public key with nonce = previous + 1 and whose activation height has passed | signature verify in-enclave (P-256 ECDSA), sealed nonce |
| I10 | Budget windows advance only with verified headers; no header, no window | header chain verifier in-enclave |
| I11 | Every signature is preceded by sealing the updated state and followed by a receipt carrying a strictly increasing sequence number | state machine order |
| I12 | The seed is generated from in-enclave RDRAND and leaves the enclave only inside the recovery blob encrypted to the installed recovery public key at initialisation | no ecall returns it or a function of it except the blob, once |

## 5. Residual risks, stated

| Risk | Tier | Bound / mitigation | Status |
|---|---|---|---|
| Debug enclave readable by root | T1 | none — labeled | by design of the hardware |
| No attestation on T1 | T1 | label (auditor Q2): *"no remote attestation on this tier (EPID retired, DCAP needs newer hardware); enclave identity is trust-on-first-use pinned by MRENCLAVE sealing; you verify your wallet xpub at setup on your own device; this detects enclave code changes after setup but does not prove genuineness at first setup the way DCAP does."* Setup emits a signed **identity card** (MRENCLAVE ‖ xpub ‖ fingerprint ‖ identity pubkey) the owner stores; a swapped enclave cannot unseal the seed, so the xpub changes and the owner notices | labeled |
| State rollback (root restores an older sealed state and restarts) | T1, T2 | **no loss bound** (re-read 2026-11-05, confirmed by the auditor): the rollback is repeatable — each cycle re-spends the window's budget to the attacker's addresses, and the attacker also pins the header feed so no token ever goes stale. The sealed state is the only persistence and it rolls back; SGX has no monotonic counter the host cannot reset. The receipt sequence and the freshness witness are **detection and bar-raising** (an unsophisticated rollback trips `FRESHNESS_SEQ_BEHIND`; the monitor alarms on `SEQ_REGRESSION`), not a bound. What bounds the loss today: the hot wallet's balance (sweep to a trusted cold destination). What would bound it: an external monotonic reference the host cannot roll back — the owner — **R7** (`REQ-r7-arm-after-restart-design-2026-11-05.md`, DESIGN-PASS 2026-11-05, implemented on `r7-arm`): after every load the enclave judges and signs nothing until the owner's `Arm` over that load's in-enclave challenge, so a rollback while the owner is absent yields a silent enclave, not a drain; residual = one window's budget per start the owner approves over an unnoticed rollback (owner-cli refuses on a sequence regression unless overridden, logged). Alternatives on record: a chain-anchored budget (a control coin every signed transaction spends and recreates; zero liveness cost, serialized payouts) or a TPM-NV counter. Build-time opt-out `AUTO_ARM` forfeits the bound (own MRENCLAVE, labeled). On T1 the question is moot: root reads the seed | R7 on branch, 2026-11-05 |
| Header withholding / stale chain | all | DoS only; the current window's remaining budget is the cap | by design |
| Signet/testnet PoW is cheap | testnet | the block clock is only as strong as the chain's work; mainnet label differs | labeled |
| Owner device lost | all | recovery key rotates the owner; recovery blob restores funds elsewhere | design |
| Owner signs blind | all | a YubiKey has no display: what it signs is what `owner-cli` on the owner's machine shows (WYSIWYS rests on that machine). Residual carried from the perp gov-key ruling; a device with its own display (phone owner app, hardware wallet message signing) removes it | labeled |
| Freshness witness key compromised | all | the witness can only pause signing or hide a rollback; it cannot loosen the mandate or sign | labeled |
| Recovery key + blob stolen together | all | = seed theft; custody guidance | labeled |
| RBF counted twice toward the budget | all | conservative (over-counts); v2 may recognise replacements | labeled |
| Fee burn and budget exhaustion by V1 | all | fee ∈ net outflow and every class counts toward `window.maxOutflow`, so the burn is bounded by the window budget (not by `maxFeeAbs`); `maxFeePerWindow` lowers it; exhaustion delays legitimate payouts to the next window (auditor R5) | labeled |
| Seq-fork of a sealed blob (two judges from one base) | T1; T2 by replay | needs control of `signerd`'s process or storage (not V1); in-enclave session high-water mark forces an enclave restart; `session_id` in status and receipts; the monitor alarms on seq duplication and on chain spends without receipts; bound = k forked txs × remaining window until detection (`ENCLAVE.md §4a`) | labeled |
| Rollback with a replayed witness token | all | a token whose `last_seen_seq` equals the rolled-back sequence passes on **every** cycle, not once (`judge.rs` disarms only on a token *ahead* of the enclave), and a pinned header feed keeps its tip fresh indefinitely; the R13 wording "passes once" was wrong and is withdrawn (auditor, 2026-11-05) | re-labeled 2026-11-05 |
| Owner key as an encrypted file (D3) | all | permitted floor, only off the BTCPay box. Label (auditor): a file-based owner key is extractable on a compromised owner signing machine, so a persistent compromise there can forge future owner signatures silently; hardware with touch requires per-use presence. Bounded by the timelock + the cold recovery key either way | labeled |
| Owner key and recovery key on the same medium or machine | all | one compromise would take both and the timelock backstop collapses (a thief loosens and cancels the cancel). Two things, kept apart (auditor): **(1) code-enforced** — `owner-cli init` refuses `owner_pk == recovery_pk`, which catches only the trivial collapse; **(2) operational, NOT code-enforced** — the two keys are held on separate media and separate machines. The equal-key refusal does not and cannot verify (2); (2) is a stated custody assumption the merchant carries (C-D3b) | rule + labeled custody assumption |
| secp256k1 side channels | T2 | constant-time library; no claim beyond that | labeled |
| Enclave bugs (parser, arithmetic) | all | pure-module tests + negative vectors + audit | the project's own job |
| Passphrase hints on owner secrets (2026-11-12) | all | a keyfile's `hint`, the wallet record's `owner_pin_hint` and the ceremony key's `Hint:` line are **at-rest plaintext**: whoever exfiltrates the file reads the hint too, and a hint's purpose is to narrow the passphrase space — so a hint that says *what* the passphrase is or looks like ("4 digits", "same as the PIN", "my usual pattern") shrinks the offline search the scrypt N=2^18 / AES-256 bound relies on (10⁴ candidates ≈ one hour), while a pure *where* hint ("password manager, entry tee-recovery") adds nothing an attacker can use. **WHERE-not-WHAT is therefore a security control, not hygiene** (auditor). The tools refuse a hint that contains the passphrase (or vice versa, case-insensitive) — necessary, not sufficient: semantic narrowing is the owner's responsibility (FAQ "I forget passphrases", C-SEC-1). The hint is unauthenticated: a file-writer can alter it, which can only confuse or lock out the owner, never reveal anything. **Owner's weighting (2026-11-12):** a forgotten passphrase is the more real loss — the recovery key is the backstop for a lost owner key, and a lost ceremony passphrase means a new MRSIGNER and every verifier's record changes — so the owner may write a hint as descriptive as they need, in plaintext, and carries the stated residual (an exfiltrated file's offline search narrows by whatever the hint gives away); the tools refuse only the literal passphrase | labeled; owner's call |
| TPM identity at anchor time (2026-11-17) | T2 with a TPM (R9) | the enclave pins the AK's public key and the counter's Name (`core/src/tpm_attest.rs`) and never parses a certificate; **which TPM holds that AK is trust-on-first-use at `tpm-setup`/`anchor`**: a VM-root who substitutes a software TPM behind `/dev/tpmrm0` *before* setup gets their AK pinned and can then certify any counter value; one who substitutes *after* is caught (REQ-r9 scenario 3: `TPM_SIG` → `STATE_STALE`). The documented manual check (read the EK certificate's issuer on the node) does not bind *our* AK to that TPM, and on an Azure Trusted Launch vTPM there is reportedly no EK certificate at all (Azure's own AK certificate sits at NV `0x01C101D0`, key `0x81000003`, under Microsoft's "Azure Virtual TPM Root CA 2023" — to confirm on a throwaway TL VM, never an SGX node). Remedy on the product path: `TPM2_Certify` of our AK by the provider-certified key, verified on the owner's laptop against the provider's root, before the AK is pinned; `tpm-anchor-prepare` (REQ-r9 step 9) was never implemented. Against the provider class (V7) this changes nothing | **labeled residual** (auditor, 2026-11-17: the counter is defense-in-depth against rollback, not the custody root — the seed stays SGX-sealed and signs only under an owner-signed mandate, so a substituted TPM buys the rollback-within-a-window residual already tracked, bounded by R7's attended `arm`, the mandate window and sweep-to-cold); **hardening SHOULD**: `TPM2_Certify` of our AK by the provider-certified key before pinning — cheap, closes the last TOFU, never a precondition custody leans on and never a mainnet gate (REQ-r9 impl §10) |
| Anchor-window race with the daemon's own header feed (2026-11-18) | T2 with a TPM (R9) | the Anchor pins `expected` = the counter the owner saw certified (+1 by the seal); every persisted blob increments the counter, and the daemon persists on its own at every new block (header feed). All of it is serialised under the daemon lock **except the owner's `tpm-certify → submit` round trip** (≈35–60 s): a block fed inside it leaves the TPM one ahead of what a *legitimate* anchor pins → `STATE_STALE` right after the anchor (sgx-node-3 2026-11-18, two signet blocks 26 s apart). Fail-closed, 0 funds at risk; the cost is a pause and a second anchor. Only a **live** state is exposed (a wallet's first anchor, a re-pin while payouts run); from `STATE_STALE` the re-anchor is race-free because the feed's refusal persists nothing. Not caught by the T0/T1 e2e (no live feed during their anchors) nor by the R9 IMPL-PASS (the auditor's own note) | **fixed — REQ-r9a (DESIGN-PASS 2026-11-18, IMPL-PASS 2026-11-19), on T2 since 2026-11-19** (ceremony-signed build `2073c234…`, wallet `735e6acd`; its first anchor pinned `expected` = the live counter + 1 and read clean, 140 → 141; the unattended restart re-armed on the next block) — the Anchor takes `expected` from the proof the daemon deposits at `submit`, verified in-enclave against the **sealed** TPM identity (AK, Name, live nonce; a host-supplied identity ≠ sealed → `ANCHOR_TPM_MISMATCH`), the owner's attested value as the lower bound (`ANCHOR_COUNTER_BEHIND`), refuse on any verification failure or a missing proof (`TPM_REQUIRED`). It is an enclave change: T2 reaches it with the next ceremony-signed build (new MRENCLAVE → new wallet, owner-run); until then `sgx-node-3` runs the pre-fix measurement and the worked example re-anchors on a repeat. A host-side guard was not adopted (never a boundary) |
| Platform TCB `SW_HARDENING_NEEDED` with the recorded INTEL-SA-00615 exception (auditor's forward note, 2026-11-19) | T2 (Azure DCsv3, `sgx-node-3`) | every T2 quote so far — the 11-19 quote of wallet `735e6acd` included — verifies to the pinned Intel root with TCB status `SWHardeningNeeded` and the one recorded exception (C-R5-1; 2026-11-10: reviewed, MMIO stale data, SDK 2.28, no MMIO in the enclave; the in-build lfence/LVI hardening, gate 6, is the mitigation). The platform TCB is a hardware-class fact about the host Intel will not patch away; it is not something the code fixes | labeled; the recorded posture for signet. **Mainnet gate item:** at the mainnet decision the exception stays an explicit, owner-acknowledged hardware/TCB exception — never silently inherited from the signet record (auditor 2026-11-19; owner's call, rule 3) |
