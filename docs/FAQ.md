# FAQ

Practical questions about running a BTCPay Server store on a tee-signer wallet. Each answer says
what the code does today and on which tier it holds; the project runs on **signet** only, and an
internal review cycle (an AI auditor answering every round's `REQ` with a `RESP`,
[`audit/`](audit/)), not a professional audit, is all the code has had (see the last section).
Russian version: [`FAQ_ru.md`](FAQ_ru.md). The one-page picture: [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md).

The words used below:

- **enclave** — the SGX program that holds the seed and judges every transaction; the only
  trusted code on the merchant's box;
- **`signerd`** — the untrusted daemon next to BTCPay that loads the enclave, stores its sealed
  state on disk, feeds it block headers and exposes a small HTTP API; it cannot authorise anything;
- **the plugin** — `BTCPayServer.Plugins.TeeSigner`: a payout processor and a "send through the
  enclave" page; untrusted glue;
- **mandate** — what the enclave may sign, enforced inside the enclave
  ([`POLICY.md`](POLICY.md)): trusted destinations, caps per transaction and per window, fee
  bounds, structural rules, a validity height, the timelock for loosening changes;
- **owner key** — signs mandate changes, unfreezes, rotates; on the merchant's separate device,
  never on the box;
- **recovery key** — a cold encrypted keyfile that can cancel a pending change, replace a lost
  owner key, and decrypt the **recovery blob** (the seed, encrypted at init to this key);
- **receipt** — the enclave's signed record of every signature (sequence number, txid, amounts);
- **monitor** — `owner-cli monitor`, run off the box: verifies receipts and watches the chain
  from the merchant's own node;
- **tiers** — T1: SGX1 without Flexible Launch Control (debug launch, no attestation); T2: FLC +
  DCAP (non-debug, attested); T0: software, tests only ([`HOW_IT_WORKS.md`](HOW_IT_WORKS.md)).

---

## 1. "I run BTCPay on one rented box. It has SGX (an older Xeon E3). Customer payouts are small, I sweep to cold storage weekly. What do I do, and what do I get?"

That is tier **T1**, the merchant tier the project exists for. Plan: the enclave and `signerd` as
a sidecar of your btcpayserver-docker stack; the owner key in your laptop's TPM 2.0 or on a
YubiKey (an encrypted keyfile on a USB drive is the permitted floor); the recovery key as an
encrypted keyfile on two USB drives in two places.

**1. Check the hardware.** `cpuid` must show SGX; the legacy driver gives `/dev/isgx`; `aesmd`
runs. On this class of hardware the enclave launches only in **debug** mode (Intel's launch
whitelist was retired with SDK 2.28; FLC hardware does not need it). That is the T1 label: the
November 2026 attack is closed, but **root on the box can read the enclave** — see "What does
root see?" below.

**2. Build and run the sidecar** (the dev stack's own scripts; an operator guide is a carried
item):

```sh
# on the SGX box: the enclave + signerd are built in a pinned container (reproducible MRENCLAVE)
docker/build-enclave.sh                     # TAG=…, RELEASE=1, SIGN=dev|ceremony → ~/tee-signer-out/<name>/
btcpay/docker/build-signerd-image.sh        # the sidecar image for btcpayserver-docker
TEE_FRAGMENT=opt-add-tee-signer.custom btcpay/docker/stack.sh gen && btcpay/docker/stack.sh up
btcpay/docker/stack.sh install-plugin       # the plugin DLL, built in a dotnet SDK container
```

`signerd` listens on `127.0.0.1:7390` only; you reach it from your laptop through an SSH tunnel.
Its bearer token sits in the sidecar's state volume (`token`); it rate-limits, it is not a secret
in the threat model (an attacker with it is still bound by the mandate).

**3. Create the keys — on your laptop, never on the box.** `owner-cli` is built with
`cd owner/owner-cli && cargo build` (Linux needs `libtss2-dev` for the TPM backend and `pcscd` +
`libpcsclite-dev` for the YubiKey one).

```sh
B=owner/owner-cli/target/debug/owner-cli
$B keygen --role recovery --out /media/$USER/USB1/recovery.key     # asks a passphrase; copy the file to USB2 too
# the owner key, one of:
$B keygen --role owner --backend tpm --handle 0x81000100            # inside the laptop's TPM; refuses an occupied handle
ykman piv keys generate -a ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 9a 9a.pub.pem   # on a YubiKey 5
$B keygen --role owner --out /media/$USER/USB3/owner.key            # the floor: an encrypted keyfile, off the box
$B pubkey --key tpm:0x81000100        # or piv:9a, or the keyfile path — prints the public key
```

Write the passphrases down somewhere safe: nothing can recover them. The owner key and the
recovery key go on **different media**; that separation is what makes an owner-key theft bounded.

**4. Initialise the wallet** (once, through the tunnel). The owner is given as a *locator*; a
YubiKey slot is attested to Yubico's root before it is accepted:

```sh
export SIGNERD_URL=http://127.0.0.1:7390 SIGNERD_TOKEN_FILE=./token
$B init --network signet --owner tpm:0x81000100 --recovery-pk $($B pubkey --key /media/$USER/USB1/recovery.key) --out wallet.json
$B recovery-verify --wallet wallet.json --recovery-key /media/$USER/USB1/recovery.key   # offline machine, ideally
```

`init` prints the tier (`T1-debug` here, labeled TOFU: no attestation exists on this hardware),
the account xpub, the master fingerprint, the enclave identity and writes `wallet.json` (the
identity card) — keep it, the monitor needs it. `recovery-verify` proves the recovery blob
decrypts to a mnemonic that derives the same xpub, **without** printing the words. Do it before
funding anything.

**5. Import the wallet into BTCPay as cold.** In the store's wallet setup, import
`[<fingerprint>/84'/1'/0']<xpub>` (signet) as a watch-only wallet. The plugin's settings page
shows whether the signer's xpub matches the store wallet; both signing paths refuse by name if it
does not. "View seed", PayJoin and the stock payout processor switch themselves off on a cold
wallet — that is gate (a) of the e2e suite, and gate (b) checks that NBXplorer's database holds
no key material.

**6. Write and install the mandate.** Start from the example in [`POLICY.md`](POLICY.md) §2:
your cold-storage descriptor as a *trusted* destination with its own caps, `unlisted` caps for
customer payouts (e.g. `maxPerTx` 1 000 000 sat, `maxPerWindow` 5 000 000 sat), `limits.window`
of 144 blocks, fee bounds, `validity.notAfterHeight` about a year ahead, `timelockBlocks` 144.

```sh
$B policy-build --json mandate.json --node-rpc http://127.0.0.1:7398 --node-cookie node.cookie --write   # fills chain.checkpoint, prints the hash
$B policy-show  --json mandate.json                                   # the diff against what is installed (nothing yet)
$B policy-sign  --json mandate.json --key tpm:0x81000100              # nonce 0 = install; shows every field, then signs
$B status                                                             # installed: true, nonce 0, best_height follows the chain
```

**7. Point BTCPay at the signer.** Plugin settings page: signerd URL `http://tee-signer:7390`
(the sidecar's name in the stack), the token, minimum confirmations, a fallback fee rate. Enable
the **TEE signer** payout processor for the store's on-chain payouts; use **Send through the
enclave** for manual sends. Create a small pull payment and a payout: the processor builds the
PSBT, the enclave signs it, the receipt sequence at `status` advances by one.

**8. Run the monitor** on your laptop (or any machine that is not the box), against your own
node if you have one:

```sh
$B monitor --wallet wallet.json --mandate mandate.json --node-rpc http://127.0.0.1:7398 --node-cookie node.cookie --interval 300
```

It verifies every receipt under the enclave's identity key, scans your addresses on the chain for
spends that have no receipt, cross-checks the window cap, watches the header feed, and on an
ALARM sends an unsigned **freeze** before telling you.

**What you get:** the seed is never a file; a stolen admin login, a bad plugin or a hacked BTCPay
container can at most spend the current window's unlisted budget, to destinations capped per
transaction — and the monitor tells you. You unfreeze, cancel or tighten from your laptop with
the owner key; nobody has to be present for routine payouts.

**What to know:** on T1 the enclave runs in debug mode, so **root on the box** can read its
memory (the seed included) — the tier protects against the application-level attack, not against
a root compromise. The enclave's identity is trust-on-first-use (pinned in `wallet.json`); there
is no remote attestation on this hardware. Signet only, today.

---

## 2. "I want the real thing: a node where even root cannot reach the seed, a YubiKey for the owner key, and proof that the enclave is the audited code. What do I do?"

That is tier **T2** — SGX with Flexible Launch Control and DCAP attestation: Azure DCsv3 (what
the project runs), or Xeon E-2200+/Ice Lake+ bare metal with FLC enabled in the firmware. It is
the same enclave binary, launched non-debug, and its identity is **attested** and verified on
your machine. Here is the sequence; the parts that are not done yet are named at the end.

**1. The enclave is built reproducibly and signed offline, never on the node.** The build runs
in a pinned container on a build box (`docker/build-enclave.sh` with `RELEASE=1`); two
independent builds give the same MRENCLAVE. Signing is a two-step ceremony: the build produces
the enclave hash, the ceremony key (RSA-3072, offline, passphrase-protected) signs it on the
owner's machine (`scripts/ceremony-sign.sh`), and the build box assembles the signed enclave. The
Makefile refuses a build whose MRSIGNER is not the pinned ceremony key (gate 7), whose code
contains a runtime CPU probe, or whose LVI mitigation count is below the floor.

**2. The sidecar on the node** uses the T2 fragment (`/dev/sgx_enclave` + `/dev/sgx_provision`,
the AESM socket, `SIGNERD_ENCLAVE_DEBUG=false`); on a small disk, the stack's pruned-node
fragment:

```sh
TEE_FRAGMENT=opt-add-tee-signer-t2.custom TEE_EXTRA_FRAGMENTS=opt-save-storage-xxs btcpay/docker/stack.sh gen && btcpay/docker/stack.sh up
```

**3. The owner key on a YubiKey 5.** Generate it on the device with PIN ALWAYS and touch ALWAYS
(the only policies `owner-cli` accepts for the owner role), then verify the slot's attestation:

```sh
ykman piv access change-pin; ykman piv access change-puk; ykman piv access change-management-key --protect --touch
ykman piv keys generate -a ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 9a 9a.pub.pem
$B piv-attest --key piv:9a --out ./9a-attest     # chain to Yubico Attestation Root 1 (pinned), policy ALWAYS/ALWAYS, serial, key == slot
```

Every owner signature then asks the PIN and waits for a touch. `init` and `rotate-owner` take the
owner as `piv:9a` and refuse the slot unless its attestation verifies — an imported key, or one
with a weaker policy, cannot become the owner.

**4. `init` with the verifier in front of the record.** On T2, `init` fetches a DCAP quote for a
fresh nonce and verifies it on your machine *before* writing `wallet.json`: certificate chain to
the Intel SGX Root CA compiled into `owner-cli`, DEBUG bit clear, MRENCLAVE equal to the pinned
value you pass, MRSIGNER equal to the ceremony key, the identity card's signature, the nonce, and
Intel's TCB status. A platform advisory you have reviewed is accepted by name with a date and a
reason, and that acceptance is part of the record:

```sh
$B init --network signet --owner piv:9a --recovery-pk … --out wallet.json \
   --expect-mrenclave <the reproducible build's MRENCLAVE> --accept-advisory INTEL-SA-00615:2026-11-03:reviewed
$B attest --wallet wallet.json            # the same seven checks, any time later; --pin re-records
```

A failure at any step refuses and names the step; no record is written, and you do not fund the
wallet.

**5. Then as in setup 1:** cold import into BTCPay, the mandate, the plugin settings, the monitor
against your own node. Consider `freshness.required = true` in the mandate: the monitor then
issues short-lived witness tokens, and a rolled-back enclave *pauses* instead of overspending.

**What you get on T2:** everything from T1, plus host root is outside the enclave (up to the SGX
threat model: side channels and Intel's microcode TCB are excluded), and a cryptographic answer
to "is the enclave I am talking to the code that was audited?".

**What is not done yet, honestly:** mainnet needs explicit owner sign-off and has not been
touched by anything in this repo; the auditor's *own* reproduction of the pinned MRENCLAVE is a
carried item (deployment trust rests on it); the operator deployment guide is a carried item; and
the project's dev T2 node is a shared Azure VM — a production deployment wants a node of its own.
If the YubiKey is shared with other uses, its PIN is device-wide: three wrong PINs block every
slot (the PUK unblocks), and the PIN typed for one key is typed into the same applet as the others.

---

## 3. More questions

### My BTCPay was hacked — the attacker is admin. What can they actually do?

Assume they can do whatever BTCPay can do, including uploading a plugin (code execution inside
the BTCPay container) and talking to `signerd` with the token. Then they can:

- **ask the enclave to sign** — exactly as the plugin does, as often as they like. They get *as
  much as the mandate allows*: unlisted outputs up to `unlisted.maxPerTx` per transaction and
  `unlisted.maxPerWindow` per 144-block window, trusted outputs only to *your* trusted
  destinations, fees inside the bounds, and the window's total `maxOutflow` over everything. When
  the window is spent, the enclave refuses until the next one. They cannot sign a transaction
  that spends a coin that is not the wallet's, pays an unlisted address beyond the cap, uses
  another sighash, or burns more fee than the window budget allows;
- **read every file BTCPay can read** — the sealed state file included. It is sealed to the
  enclave; without that enclave on that CPU it does not open. On **T1**, if they also get **root**,
  the debug enclave's memory is readable and the seed with it — that is the T1 label;
- **break things** — stop the feed, delete the receipt log, restart `signerd` with an older sealed
  state. None of that loosens the mandate. A withheld feed stops the windows from rolling (the
  current window's remaining budget is all there is); an older state is a **rollback** — one
  extra window's budget at most, and the monitor sees the sequence go backwards
  (`SEQ_REGRESSION`) and freezes. With `freshness.required`, a rolled-back enclave refuses to sign
  at all until you re-arm it.

What they cannot do: change the mandate (it needs your owner key's signature with the next
nonce), unfreeze, rotate the owner, or get the seed out of a T2 enclave. What you do: the monitor
has probably already sent a **freeze**; review the receipts and the chain, clean the box, then
`unfreeze` with the owner key — or tighten the mandate first (a tightening applies at once).

### What exactly does the enclave refuse?

Anything it cannot prove. The reasons are stable identifiers ([`POLICY.md`](POLICY.md) §6), and
every one of them has a refusal vector in the test suite. The classes:

| Class | Reasons | Typical cause |
|---|---|---|
| the PSBT itself | `PSBT_PARSE`, `UNKNOWN_FIELD`, `TX_VERSION`, `SIGHASH`, `TOO_MANY_INPUTS`, `TOO_MANY_OUTPUTS`, `OVERFLOW` | a malformed or exotic PSBT; a sighash other than `ALL` |
| inputs | `INPUT_NO_PREVTX`, `INPUT_PREVTX_MISMATCH`, `INPUT_NOT_OWN`, `INPUT_FOREIGN_FORBIDDEN`, `INPUT_SCRIPT_TYPE` | a missing full previous transaction (the enclave never trusts a host-asserted amount); a coin that is not the wallet's; a PayJoin input (`rules.payjoin = none`) |
| outputs | `OUTPUT_SCRIPT_TYPE`, `CHANGE_INDEX_BEYOND_GAP`, `OPRETURN_FORBIDDEN` | change to an index far beyond the sealed bound; an `OP_RETURN` the mandate does not allow |
| caps | `CAP_TX`, `CAP_WINDOW`, `CAP_UNLISTED_TX`, `CAP_UNLISTED_WINDOW`, `CAP_TRUSTED_TX(label)`, `CAP_TRUSTED_WINDOW(label)` | the payout, or the window's running total, is above the mandate |
| fees | `FEE_ABS`, `FEE_RATE` | BTCPay's fee estimate is above the bounds (the rate is checked against a lower-bound size, so a fair fee on a large transaction can be over-refused — `maxFeeAbs` is the hard backstop) |
| state | `FROZEN`, `MANDATE_EXPIRED`, `CHAIN_STALE`, `CHAIN_REORG`, `STATE_UNSEALABLE` | someone froze the signer; `validity.notAfterHeight` passed; the header feed stopped or a reorg deeper than `maxReorg` happened; the sealed state does not open |
| freshness | `FRESHNESS_MISSING`, `FRESHNESS_SIG`, `FRESHNESS_TIP`, `FRESHNESS_SEQ_BEHIND` | the monitor's witness token is absent, stale, or says the enclave is behind what the monitor has seen (a rollback) — needs the owner's `rearm` |
| owner messages | `POLICY_SIG`, `POLICY_NONCE`, `POLICY_NETWORK`, `POLICY_WALLET`, `POLICY_PENDING` | signed by a key that is not the owner (a retired key, a pending one), a wrong nonce, a mandate for another wallet, or a second change while one is pending |

A refusal charges nothing to the budget. The reasons come back to the plugin (BTCPay logs them
as `tee-signer: enclave refused …`), to `owner-cli sign`, and to `signerd`'s log.

### Why was my payout refused? What do I do?

Look at the reason. `CAP_UNLISTED_TX`: the payout is above the per-transaction cap for unlisted
destinations — split it, or raise the cap (a loosening: it waits the timelock). `CAP_WINDOW` /
`CAP_UNLISTED_WINDOW`: the window's budget is spent — wait for the next window (144 blocks from
the window's start height, shown at `status`), or raise the budget (timelocked). `FEE_RATE`: lower
the fee target in BTCPay, or the plugin's fallback fee rate. `FROZEN`: find out who froze and why
(the monitor's journal says) before you `unfreeze`. `MANDATE_EXPIRED`: install a new mandate with
a later `notAfterHeight`. `CHAIN_STALE`: the sidecar's header feed from `bitcoind` is down — the
enclave will not roll a window it cannot see. `INPUT_NO_PREVTX`: the PSBT lacks full previous
transactions — the plugin always includes them; a PSBT built elsewhere must too.

BTCPay's payout processor retries on its schedule; after ten refusals it disables itself for that
payout, as the stock processor does.

### Why does a mandate change wait a day? Which changes apply at once?

A **tightening** — every field moving in the restrictive direction (lower caps, removed trusted
entries, a shorter validity, a longer timelock, `payjoin` toward `none` …) — applies the moment
the enclave verifies your signature. A **loosening** — anything else, including a new trusted
destination, a higher cap, a changed witness key, a new owner — becomes *pending* and activates
only at `best_height + timelockBlocks` of the mandate that is installed. The classifier fails
toward loosening: a field it cannot prove tighter makes the whole update wait.

The point: a thief with your owner key can only submit a loosening, and during the timelock you
(or the recovery key) **cancel** it. One change in flight at a time: while one is pending, every
further update is refused (`POLICY_PENDING`), tightening included — your answer to a change you
did not make is `freeze` + `cancel`, never a tightening over it. `status` shows the pending hash
and height; so does every receipt.

### How do I change the mandate, day to day?

```sh
$B policy-show --json mandate-v2.json                          # field by field, DIFF marked; the hash you will sign
$B policy-sign --json mandate-v2.json --key piv:9a              # nonce = installed + 1; PIN + touch on a YubiKey
$B status                                                        # applied (tightening) or pending with its activation height
```

The file is intent; the sealed state is law. Editing a JSON file changes nothing until it is
signed with the next nonce and accepted. Keep the installed mandate's JSON next to `wallet.json`:
the monitor reads the caps from it.

### What is a receipt, and why run a monitor at all?

Every signature returns a receipt `{seq, txid, net outflow, amounts per class, fee, height,
mandate hash}` signed by the enclave's identity key (bound at init). The sequence number is
strictly increasing and lives inside the sealed state. The monitor, off the box:

- verifies every receipt under the identity key from `wallet.json` (a forged or edited log line
  is refused by name);
- keeps a high-water mark `(session, seq)`; the same `seq` with a different txid is a **fork**
  (two enclaves run from one sealed state), a lower `seq` is a **regression** (rollback);
- scans your addresses on the chain from an independent source — your own node, or an Esplora
  for signet — for **spends without a receipt** (the one thing an enclave bypass would show),
  and cross-checks the window cap against what actually confirmed;
- watches the enclave's `best_height` against the chain (a stalled feed becomes an ALARM after a
  few passes) and issues witness tokens when the mandate requires freshness;
- on any ALARM sends an unsigned **freeze** first, then reports; `--once` exits 0 / 1 / 2 for
  OK / WARN / ALARM so a cron can page you.

A spend you have reviewed and accept (`--acknowledge <txid>`) stops re-alarming. The monitor's key,
if it has one, can only pause signing or hide a rollback — never loosen or sign.

### The server died / the disk is gone / the provider deleted the VM. Are the coins lost?

No. The seed exists in two places: inside the enclave, and in the **recovery blob** encrypted at
init to your recovery key. Decrypt the blob on an offline machine (`recovery-verify` checks it
without printing; `--print-mnemonic` prints, with a warning and a typed confirmation) and restore
the 24 words into any BIP84 wallet; then sweep to a **new** enclave wallet, and treat the old
one as retired. A new enclave is always a new wallet: by design there is no way to put an old
seed into a new enclave. The whole table of what can be lost and what follows is
[`CONTINUITY.md`](CONTINUITY.md); the drills that have actually been executed are listed there
too (restore has; enclave-loss and owner-loss on a live wallet have not).

### I lost the owner key (the YubiKey, the laptop with the TPM). And the recovery key?

**Owner key lost:** signing inside the mandate continues; what stops is mandate changes.
`recover --recovery-key recovery.key --new-owner <locator>` hands the owner role to a new key
**at once** (the recovery key is the stronger factor). **Recovery key lost while the enclave
lives:** the coins are safe but the backstop is gone — `rotate-owner` cannot change the recovery
key, so initialise a new wallet with a new recovery key and sweep to it under the mandate. **Both
lost:** the coins are gone. That is the two-of-two the design rests on; hence two media, two places.

### Which owner devices work, and which should I use?

Today, through TPM_sign's `hw-signer`: a **Linux TPM 2.0** (`tpm:<handle>`; the key is created
inside the TPM under a passphrase, never exportable; the laptop is the operator machine) and a
**YubiKey 5 PIV** slot (`piv:<slot>`; generated on the device, PIN + touch per signature, the slot
attested to Yubico's root before it can become the owner). The **encrypted keyfile**
(scrypt + AES-GCM) is the permitted floor, only ever off the box. Secure Enclave, Windows TPM,
TROPIC01 and a phone owner app exist in TPM_sign and are later rounds here.

Which to use: a YubiKey for anything that holds value — the touch is physical presence per
signature, and a compromised laptop cannot sign without you. A TPM key is bound to the laptop
and sealed only by its passphrase (not to the boot state, labeled): malware with your rights on
that laptop could use it while plugged in — bounded, as always, by the timelock and the recovery
key. The owner key is never a theft-capable key by itself.

### What does root on the box see? What is the real difference between T1 and T2?

**T1** (SGX1 without FLC): the enclave can only be launched in debug mode, and a debug enclave's
memory is readable through the SGX debug interface by root. So on T1 root can read the seed and
could, in principle, sign outside the mandate. T1 protects against everything *below* root: the
BTCPay admin, a plugin, the container, a non-root user. That is the attack that happened, and it
is what a merchant on cheap hardware buys. **T2** (FLC + DCAP): non-debug launch, memory
encrypted and inaccessible to root, identity attested. Root can still delete files, stop the
daemon, withhold headers or replay an old sealed state — all of which the enclave and the monitor
turn into refusals, pauses or alarms, never into a signature outside the mandate.

`status` says which one you have (`tier: T1-debug` / `T2-release`); nothing can mistake one for
the other, and the identity card carries the tier too.

### Does it run on mainnet? Lightning? PayJoin?

**Mainnet:** not yet — signet only; mainnet needs explicit owner sign-off and the deployment
items above. **Lightning:** out of scope; this is the on-chain hot wallet. **PayJoin:** not in
v1 — the enclave refuses foreign inputs (`rules.payjoin = none`), and BTCPay's PayJoin receiver is
off on a cold wallet; the mandate already has the `inflow-only` rule for a later round through an
upstream signer interface. P2TR (`m/86'`) and PSBT v2 are later rounds too.

### How long does a signature take, and what does it cost?

Signing is a single ecall: parse, judge, seal, sign — a fraction of a second in the signet runs on
both tiers; the payout processor's own schedule dominates. There is no per-signature fee of any kind. The
hardware is the cost: a T1 box is cheap bare metal you likely already rent; T2 is an Azure DCsv3
VM or FLC-capable bare metal. The project has not published a benchmark table; the carried
measurement item is in [`audit/CONDITIONS.md`](audit/CONDITIONS.md).

### Is it audited?

Every round — the design, the core, the enclave shell, the plugin, T2, the owner-key backends,
the monitor — has an `IMPL-PASS` from an internal AI auditor working from written requests
([`audit/`](audit/)), with conditions tracked to discharge in
[`audit/CONDITIONS.md`](audit/CONDITIONS.md). Each check ships with the negative vectors that
prove it refuses. It is **not** a professional audit, and the auditor's own independent
reproduction of the enclave build is still open. The bigger the amount, the more review it
deserves. And no audit replaces the limits: a small unlisted budget per window, tight trusted
destinations, the owner key on a device with a button, the recovery key cold and backed up.
Those bounds hold even if a bug slips through.
