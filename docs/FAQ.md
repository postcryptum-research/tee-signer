# FAQ

Practical questions about running a BTCPay Server store on a tee-signer wallet. Each answer says
what the code does today and on which tier it holds; the project runs on **signet** only, and an
internal review cycle (an AI auditor answering every round's `REQ` with a `RESP`,
[`audit/`](audit/)), not a professional audit, is all the code has had (see the last section).
Russian version: [`FAQ_ru.md`](FAQ_ru.md). The one-page picture: [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md).

The words used below:

- **enclave** — a protected region of the CPU's memory, walled off from the operating system
  (Intel SGX; AMD has an equivalent), in which a special program runs. Here that program holds
  the seed phrase and the private key derived from it: a transaction goes in, a signed
  transaction — or a refusal — comes out, and the key never leaves. The nearest familiar thing
  is a hardware wallet like a Ledger Nano, except built into the server's CPU and signing
  without a button, by the rules you set;
- **wallet key** — the Bitcoin private key derived from the seed inside the enclave; the one
  that actually signs transactions. It is what replaces the hot-wallet key that sits on the
  BTCPay server today, and it never leaves the enclave;
- **the enclave's stamp** — a second, small key the enclave creates at init to sign its *own
  statements*: the identity card and every receipt. It signs no transactions; it exists so the
  owner's monitor can tell the enclave's word from the host's (`identity_pk` in the code and the
  audit documents);
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
- **tiers** — T2: SGX with FLC + DCAP (non-debug, attested) — the product; T1: SGX1 without
  Flexible Launch Control (debug launch, no attestation) — the project's build-and-test tier,
  runs but not for money; T0: software, tests only ([`HOW_IT_WORKS.md`](HOW_IT_WORKS.md)).

---

## 1. "I run BTCPay on one server. Which server do I need, what do I do, and what do I get?"

The product runs on tier **T2**: SGX with Flexible Launch Control and DCAP attestation — Azure
DCsv3 (what the project runs), or Xeon E-2200+/Ice Lake+ bare metal with FLC enabled in the
firmware. (Cheap SGX1 servers without FLC are the project's **build-and-test tier T1**: the
enclave runs there, but not for money — root reads a debug enclave.)

Three things, kept apart, and nothing passes between them but files:

- **your laptop** holds the owner key and the recovery key and runs `owner-cli`;
- **the server** runs BTCPay, the enclave sidecar and `signerd`;
- **a directory on each side** holds what is carried: `~/tee-owner/exchange/` on the laptop,
  `~/tee-signer-exchange/` on the server (the sidecar sees it as `/exchange`).

Every block below says where it runs. There is no tunnel: `owner-cli` never talks to the server,
the server never talks to the laptop, and a file moves with `scp` in either direction. Each
side finishes its step and hands over a file; that is where one party's work ends and the
other's begins.

**1. The server: hardware and the sidecar.** The in-kernel SGX driver gives `/dev/sgx_enclave`
and `/dev/sgx_provision`; `aesmd` runs with a DCAP quote provider (on Azure, `az-dcap-client`);
`cpuid` leaf 7 reports FLC. On this hardware the enclave launches **non-debug** and its
identity can be attested — that is what makes the seed unreadable to root. The enclave is built
reproducibly and signed with the project's offline ceremony key on a build box, never on the
server (setup 2 says how to reproduce it yourself); what reaches the server is the sidecar image.

```sh
mkdir -p -m 1777 ~/tee-signer-exchange
docker load -i signerd-t2-image.tar.gz
TEE_FRAGMENT=opt-add-tee-signer-t2.custom TEE_EXTRA_FRAGMENTS=opt-save-storage-xxs btcpay/docker/stack.sh gen
btcpay/docker/stack.sh up
btcpay/docker/stack.sh install-plugin
```

The exchange directory is made world-writable with the sticky bit (`-m 1777`): the sidecar runs as
its own user (uid 999) and writes its answers there; a plain `mkdir` gives a directory only you can
write to, and every `--out /exchange/…` would fail with "permission denied".

**2. The laptop: the keys.** The private keys are born here and never leave; only public keys
travel. Linux needs `libtss2-dev` for the TPM backend, `pcscd` and `libpcsclite-dev` for a
YubiKey; the tool is built with `cd owner/owner-cli && cargo build`.

```sh
mkdir -p ~/tee-owner/exchange
cd owner/owner-cli/target/debug
./owner-cli keygen --role recovery --out /media/USB1/recovery.key
./owner-cli keygen --role owner --backend tpm --handle 0x81000100
./owner-cli pubkey --key tpm:0x81000100 > ~/tee-owner/exchange/owner.pub
./owner-cli pubkey --key /media/USB1/recovery.key > ~/tee-owner/exchange/recovery.pub
```

The recovery key asks a passphrase and goes on two USB drives in two places; the owner key lives
inside the laptop's TPM (a YubiKey is setup 2; an encrypted keyfile on a third drive is the
permitted floor). Write the passphrases down somewhere safe: nothing can recover them. A passphrase is at least 4
characters — pick one you will still know in a year; the keyfile is scrypt-hardened and must never
leave your machine, which is what a short passphrase relies on.

Carry the two public keys to the server:

```sh
scp ~/tee-owner/exchange/owner.pub ~/tee-owner/exchange/recovery.pub you@your-server:tee-signer-exchange/
```

**3. The server: `init`.** What happens physically: the two public keys go into the enclave.
Inside it, 256 bits of hardware randomness become a 24-word BIP39 mnemonic and a BIP32 master
key; the account `m/84'/1'/0'` is derived; a second, small key is created — the enclave's
**stamp**, which signs the identity card and the receipts and never a transaction; the mnemonic
is encrypted to the recovery public key (the **recovery blob**); and all of it is sealed to this
enclave and written to the sidecar's state volume. The answer — the account xpub, the master
fingerprint, the stamp's public key, the signed identity card and the recovery blob — is a file.
The seed is in none of it, and nothing on the server can sign without the enclave.

```sh
docker exec tee-btcpay-tee-signer-1 signerd init --state-dir /var/lib/signerd --network signet --owner-pk-file /exchange/owner.pub --recovery-pk-file /exchange/recovery.pub --out /exchange/init-response.json
```

On T2 you also want the enclave's proof of identity. The nonce for it is yours, chosen on the
laptop, so that a quote made for anyone else is refused:

```sh
openssl rand -hex 32 > ~/tee-owner/exchange/nonce.txt
scp ~/tee-owner/exchange/nonce.txt you@your-server:tee-signer-exchange/
```

and on the server:

```sh
docker exec tee-btcpay-tee-signer-1 signerd quote --state-dir /var/lib/signerd --nonce-file /exchange/nonce.txt --out /exchange/quote.json
```

Carry both answers back to the laptop:

```sh
scp you@your-server:tee-signer-exchange/init-response.json ~/tee-owner/exchange/
scp you@your-server:tee-signer-exchange/quote.json ~/tee-owner/exchange/
```

**4. The laptop: verify the answer, write the wallet record, check the recovery blob.** Nothing
is sent anywhere in this step. `init --response` checks the identity card's signature and that
the card names the returned xpub, and — with the quote — runs the attestation verifier
**before** writing anything: the certificate chain to the Intel SGX Root CA compiled into
`owner-cli`, the DEBUG bit clear, MRENCLAVE equal to the release's (printed by the build),
MRSIGNER equal to the ceremony key, the identity card's signature, **your** nonce, and Intel's
TCB status (a platform advisory you have reviewed is accepted by name, with a date and a reason,
and that acceptance is part of the record). A failure at any step refuses and names the step;
no record is written, and you do not fund the wallet.

```sh
cd owner/owner-cli/target/debug
./owner-cli init --response ~/tee-owner/exchange/init-response.json --network signet --owner tpm:0x81000100 --recovery-pk-file ~/tee-owner/exchange/recovery.pub --out ~/tee-owner/wallet.json --expect-mrenclave <the release's MRENCLAVE> --quote ~/tee-owner/exchange/quote.json --nonce-file ~/tee-owner/exchange/nonce.txt --accept-advisory INTEL-SA-00615:2026-11-03:reviewed
./owner-cli recovery-verify --wallet ~/tee-owner/wallet.json --recovery-key /media/USB1/recovery.key
```

`--owner` is a *locator*, never a raw key: `tpm:<handle>`, `piv:<slot>` (a YubiKey slot is
attested to Yubico's root first and refused unless that verifies) or a keyfile path. `init`
prints the tier (`T2-release`), the xpub, the fingerprint and the stamp's public key, and writes
`~/tee-owner/wallet.json` — the identity card plus the recovery blob. Keep it; every later
command reads it. `recovery-verify` decrypts the blob with the recovery key, derives the xpub
from the mnemonic, compares it with the xpub the enclave reported, and prints only whether they
match — never the words. Do it before any money arrives.

**5. Import the wallet into BTCPay as cold.** In the store's wallet setup, import
`[<fingerprint>/84'/1'/0']<xpub>` (signet; both values are in `wallet.json`) as a watch-only
wallet. The plugin's settings page shows whether the signer's xpub matches the store wallet;
both signing paths refuse by name if it does not. "View seed", PayJoin and the stock payout
processor switch themselves off on a cold wallet — that is gate (a) of the e2e suite, and gate
(b) checks that NBXplorer's database holds no key material.

If coins reached the wallet before the import (or while BTCPay was not yet tracking the xpub),
the store shows a zero balance until you rescan: store → **Wallets** → **BTC** → the `…` menu →
**Rescan**. NBXplorer indexes a wallet from the moment it starts tracking it; the rescan finds what
came earlier. The enclave is not involved and nothing is signed.

**6. The mandate: written and signed on the laptop, handed to the server.** Start from the
example in [`POLICY.md`](POLICY.md) §2: your cold-storage descriptor as a *trusted*
destination with its own caps, `unlisted` caps for customer payouts (e.g. `maxPerTx` 1 000 000
sat, `maxPerWindow` 5 000 000 sat), `limits.window` of 144 blocks, fee bounds,
`validity.notAfterHeight` about a year ahead, `timelockBlocks` 144. The signed message names
the enclave and the next nonce, so the laptop needs the server's status file first.

On the server:

```sh
docker exec tee-btcpay-tee-signer-1 signerd status --state-dir /var/lib/signerd --out /exchange/status.json
```

Carry it, sign, carry the message back:

```sh
scp you@your-server:tee-signer-exchange/status.json ~/tee-owner/exchange/
cd owner/owner-cli/target/debug
./owner-cli policy-build --json ~/tee-owner/mandate.json --esplora https://mempool.space/signet/api --write
./owner-cli --status-file ~/tee-owner/exchange/status.json --wallet-record ~/tee-owner/wallet.json --out ~/tee-owner/exchange/policy-install.msg policy-sign --json ~/tee-owner/mandate.json --key tpm:0x81000100
scp ~/tee-owner/exchange/policy-install.msg you@your-server:tee-signer-exchange/
```

`policy-build` reads the signet tip from a public Esplora (for value: your own node, `--node-rpc
URL --node-cookie FILE` — the one connection the laptop opens is to *your* node or a public
explorer, never to the signer's server) and fills `chain.checkpoint`; `policy-sign` shows every field, signs the
canonical bytes with the owner key (nonce 0 = the install) and writes the message. On the
server, the file goes to the enclave and its answer comes back as a file:

```sh
docker exec tee-btcpay-tee-signer-1 signerd submit --state-dir /var/lib/signerd --file /exchange/policy-install.msg --out /exchange/policy-install.result.json
docker exec tee-btcpay-tee-signer-1 signerd status --state-dir /var/lib/signerd --out /exchange/status.json
```

`policy-install.result.json` says `ok` or `REFUSED` with the enclave's reasons; `status.json`
shows `installed: true`. Carry `status.json` back whenever you want the laptop's copy current.

**7. Point BTCPay at the signer.** Plugin settings page: signerd URL `http://tee-signer:7390`
(the sidecar's name in the stack), the token (in the sidecar's state volume: `docker exec
tee-btcpay-tee-signer-1 cat /var/lib/signerd/token`), minimum confirmations, a fallback fee
rate. Enable the **TEE signer** payout processor for the store's on-chain payouts; use **Send
through the enclave** for manual sends. Create a small pull payment and a payout: the processor
builds the PSBT, the enclave signs it, and `seq` in the status — the enclave's count of
signatures — advances by one. The token rate-limits and keeps stray containers out; it is not a
secret in the threat model (an attacker who has it is still bound by the mandate).

**8. After any restart of the signer** — a reboot, an update, a crash — the enclave signs nothing
until you approve that start (R7). The status file says `boot_armed: false` and carries the
start's challenge; the plugin's settings page shows the same pause, with the challenge. Approve it the same way as any
owner step: status file to the laptop, a signed message back.

On the server:

```sh
docker exec tee-btcpay-tee-signer-1 signerd status --state-dir /var/lib/signerd --out /exchange/status.json
```

On the laptop:

```sh
scp you@your-server:tee-signer-exchange/status.json ~/tee-owner/exchange/
cd owner/owner-cli/target/debug
./owner-cli --status-file ~/tee-owner/exchange/status.json --wallet-record ~/tee-owner/wallet.json --out ~/tee-owner/exchange/arm.msg arm --key tpm:0x81000100
scp ~/tee-owner/exchange/arm.msg you@your-server:tee-signer-exchange/
```

`arm` compares the enclave's sequence with the highest one your laptop has seen (kept in
`wallet.json`) and refuses if the enclave remembers less — the signature of a restored older
state; you can override that only in writing, and it is logged in the record. On the server:

```sh
docker exec tee-btcpay-tee-signer-1 signerd submit --state-dir /var/lib/signerd --file /exchange/arm.msg --out /exchange/arm.result.json
```

Payouts resume. A reboot at night is a pause until your morning, never a loss.

*With a TPM in front of the enclave (R9; built and tested, waiting for a server that has one — the
project's node does not yet):* a physical TPM on your own server, or the virtual TPM of a
Trusted-Launch VM. The enclave checks the TPM's counter against the value it sealed last and arms
itself when they agree, so a restart no longer waits for you; the pause above stays the fallback
whenever the counter disagrees. Against root inside the server the counter cannot be turned back;
against the cloud provider, who owns a virtual TPM, the protection is the same as without one. How to
set it up: ["How do I put a TPM in front of the signer?"](#how-do-i-put-a-tpm-in-front-of-the-signer-r9)
below.

**What you get:** the seed is never a file; a stolen admin login, a bad plugin or a hacked BTCPay
container can at most spend the current window's unlisted budget, to destinations capped per
transaction — that window cap is the ceiling on the damage. Root on the server cannot read the
seed, and cannot replay a window's payouts while you are away: that needs a restart, and a
restarted enclave waits for your key. You change the mandate, unfreeze or cancel by handing the
server a signed file; nobody has to be present for routine payouts.

**What to know:** the project's own T2 node is a shared Azure VM; a production deployment wants
a node of its own. The plugin's status page is the natural place for the status file and the
pasted answer — that is the next step, so that owner operations need no shell on the server at
all. Signet only, today.

---

## 2. "I want the strongest form: a YubiKey for the owner key, and my own proof that the enclave is the audited code. What else do I do?"

Everything in setup 1, plus the three things below. The parts that are not done yet are named
at the end.

**1. Reproduce the build yourself.** The build runs in a pinned container on a build box
(`docker/build-enclave.sh` with `RELEASE=1`); two independent builds give the same MRENCLAVE,
which the script prints at the end of every build (`MRENCLAVE: …`; it is
`enclave_css.body.enclave_hash.m` in the output's `sigstruct.dump`) — that value is what `init`
and `attest` pin. Signing is a two-step ceremony: the build produces the enclave hash, the
ceremony key (RSA-3072, offline, passphrase-protected) signs it on the owner's machine
(`scripts/ceremony-sign.sh`), and the build box assembles the signed enclave. The Makefile
refuses a build whose MRSIGNER is not the pinned ceremony key (gate 7), whose code contains a
runtime CPU probe, or whose LVI mitigation count is below the floor.

**2. The owner key on a YubiKey 5.** Generate it on the device with PIN ALWAYS and touch ALWAYS
(the only policies `owner-cli` accepts for the owner role), then verify the slot's attestation:

```sh
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --protect --touch
ykman piv keys generate -a ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 9a ~/tee-owner/9a.pub.pem
cd owner/owner-cli/target/debug
./owner-cli piv-attest --key piv:9a --out ~/tee-owner/9a-attest
./owner-cli pubkey --key piv:9a > ~/tee-owner/exchange/owner.pub
```

Every owner signature then asks the PIN and waits for a touch. In setup 1 use `--owner piv:9a`
and `--key piv:9a`; `init` and `rotate-owner` refuse the slot unless its attestation verifies
(an imported key, or one with a weaker policy, cannot become the owner).

**3. Check the enclave again, any time.** The same nonce-and-quote round trip as at `init`,
verified on the laptop with nothing sent:

```sh
openssl rand -hex 32 > ~/tee-owner/exchange/nonce.txt
scp ~/tee-owner/exchange/nonce.txt you@your-server:tee-signer-exchange/
```

on the server `docker exec tee-btcpay-tee-signer-1 signerd quote --state-dir /var/lib/signerd --nonce-file /exchange/nonce.txt --out /exchange/quote.json`, then on the laptop:

```sh
scp you@your-server:tee-signer-exchange/quote.json ~/tee-owner/exchange/
cd owner/owner-cli/target/debug
./owner-cli attest --wallet ~/tee-owner/wallet.json --replay ~/tee-owner/exchange/quote.json --nonce-file ~/tee-owner/exchange/nonce.txt --expect-mrenclave <the release's MRENCLAVE>
```

**What you get on T2:** everything from setup 1, plus the owner key behind a physical touch, and
your own answer to "is the enclave I am talking to the code that was audited?".

**What is not done yet, honestly:** mainnet needs explicit owner sign-off and has not been
touched by anything in this repo; the auditor's *own* reproduction of the pinned MRENCLAVE is a
carried item (deployment trust rests on it); the operator deployment guide is a carried item;
and the project's dev T2 node is a shared Azure VM — a production deployment wants a node of its
own. If the YubiKey is shared with other uses, its PIN is device-wide: three wrong PINs block
every slot (the PUK unblocks), and the PIN typed for one key is typed into the same applet as
the others.

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
  enclave; without that enclave on that CPU it does not open. (If they also get **root** on a T1
  server, they can read the enclave's memory — exactly as root can read today's BTCPay seed; see
  "What does root see?");
- **break things** — stop the feed, delete files, restart `signerd` with an older sealed state.
  None of that loosens the mandate. A withheld feed stops the windows from rolling (the current
  window's remaining budget is all there is); an older state is a **rollback** — but restoring the
  sidecar's state file needs root on the server, not a BTCPay login, and the restart it needs
  leaves the enclave unarmed until your key says otherwise (scenario 3 of "What can an attacker
  still steal?").

What they cannot do: change the mandate (it needs your owner key's signature with the next
nonce), unfreeze, rotate the owner, or get the seed out of a T2 enclave. What you do: on the server,
**freeze** — `docker exec tee-btcpay-tee-signer-1 signerd freeze --state-dir /var/lib/signerd
--out /exchange/freeze.result.json`, no signature needed — look at the chain, clean the server,
then hand it a signed `unfreeze` file from the laptop (status file over, `--out unfreeze.msg
unfreeze --key …` back) — or a tightening first, which applies at once.

### What can an attacker still steal?

Written the way an attacker thinks: who they are, what they do, what they get. The amounts use
the example mandate in [`POLICY.md`](POLICY.md): unlisted payouts capped at 0.01 BTC per
transaction and 0.05 BTC per window of 144 blocks.

1. **Logged in as your BTCPay admin, or running a plugin they planted** (the November 2026
   attack). They make the enclave pay to their own addresses: 0.01 BTC per transaction, 0.05 BTC
   per window, then nothing until the next window — whether or not you are awake. They cannot take the rest
   and cannot take the seed. *Closed down to the window budget, on both tiers.* What no enclave
   closes: a BTCPay admin can also swap the store's wallet for an xpub of their own, and customers
   then pay them — future revenue, not the balance; that is BTCPay's admin access, the same as
   today, and the plugin's status page shows the mismatch.
2. **Root on your T1 server** (the hosting provider, a full compromise). They read the seed out
   of the enclave's memory and own the whole hot wallet — what is in it now and what arrives
   later — exactly as with today's BTCPay. *Not closed on T1* — which is why T1 is the project's
   build-and-test tier and not offered for money. On T2 the seed is unreadable.
3. **Root on your T2 server.** They cannot read the seed and cannot make the enclave sign a
   transaction outside the mandate's shape. What they can do: let the enclave pay a window's
   budget to them, restore an older copy of the enclave's state file, restart it, and collect the
   same window again — a restart takes seconds. Assume root drains the hot wallet's balance, a
   window at a time — *that was the gap R7 closes.* Restoring an old state file needs a restart,
   and a restarted enclave judges and signs nothing until you approve that start with your key
   (`arm`): root gets a silent enclave, not a drain, while you are away. What remains: one
   window's budget per start you approve after a rollback you did not notice — `arm` refuses when
   the enclave remembers fewer operations than you last saw, unless you override it in writing.
   *Pause build only: an `AUTO_ARM` build forfeits this, and the loss bound against root reverts
   to the hot-wallet float.* Keep the float small anyway: move what you do not need to cold storage
   (a trusted destination; the sweep is a payout you or a script create in BTCPay).
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

### What holds while I sleep?

Nothing here asks you to wake up and press something. Against anyone who comes in through
BTCPay — the attack that happened — the mandate is the hard bound: the enclave will not sign
beyond it, at 3 a.m. or at noon, and by the time you look in the morning the loss is one
window's budget, not the wallet. A thief with your *owner* key can change nothing before the
mandate's timelock runs out; the timelock is yours to set (`timelockBlocks`: a day, a week —
longer than your longest absence), and the recovery key cancels. Against root on the server: a
rollback needs a restart, and a restarted enclave signs nothing until you approve that start with
your key — at 3 a.m. it simply waits (scenario 3; pause build only, `AUTO_ARM` forfeits it).

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
| state | `NOT_ARMED`, `FROZEN`, `MANDATE_EXPIRED`, `CHAIN_STALE`, `CHAIN_REORG`, `STATE_UNSEALABLE` | the signer was restarted and you have not approved the start yet (`owner-cli arm`); someone froze the signer; `validity.notAfterHeight` passed; the header feed stopped or a reorg deeper than `maxReorg` happened; the sealed state does not open |
| freshness | `FRESHNESS_MISSING`, `FRESHNESS_SIG`, `FRESHNESS_TIP`, `FRESHNESS_SEQ_BEHIND` | only if `freshness.required` is set in the mandate — a developer option, off and not part of the product (`DESIGN.md` §3) |
| owner messages | `POLICY_SIG`, `POLICY_NONCE`, `POLICY_NETWORK`, `POLICY_WALLET`, `POLICY_PENDING`, `ARM_CHALLENGE`, `ARM_SEQ_BEHIND` | signed by a key that is not the owner (a retired key, a pending one), a wrong nonce, a mandate for another wallet, a second change while one is pending; an `arm` for another start (a replay), or an `arm` that says you saw more operations than the enclave remembers (a rollback) |

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

**A payout that stays `AwaitingPayment`.** The plugin's processor retries every minute and logs
each attempt in BTCPay's log as `tee-signer: …`. Refusals that clear by themselves (the window's
budget, `FROZEN`, `NOT_ARMED`, a stale header feed) and "not enough funds" are retried for as long
as it takes and never switch the processor off; a refusal that can never clear (an amount above a
per-transaction cap, a destination the mandate forbids) switches the processor off *for that payout*
after ten attempts — the log says so; cancel it and create a correct one. If the store's balance is
below what a block explorer shows for the wallet, rescan (step 5 above). Restarting BTCPay does not
touch the enclave (the sidecar keeps running, no `arm` is needed); restarting the sidecar does.
A payout is never signed twice: when the node refuses the broadcast, the signed transaction is
kept and rebroadcast; the enclave is not asked again.

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

The same three places as in setup 1. On the server, the installed mandate and the status to files:

```sh
docker exec tee-btcpay-tee-signer-1 signerd policy --state-dir /var/lib/signerd --out /exchange/policy.json
docker exec tee-btcpay-tee-signer-1 signerd status --state-dir /var/lib/signerd --out /exchange/status.json
```

On the laptop: see the difference field by field, sign, carry the message back:

```sh
scp you@your-server:tee-signer-exchange/policy.json you@your-server:tee-signer-exchange/status.json ~/tee-owner/exchange/
cd owner/owner-cli/target/debug
./owner-cli policy-show --installed-file ~/tee-owner/exchange/policy.json --json ~/tee-owner/mandate-v2.json
./owner-cli --status-file ~/tee-owner/exchange/status.json --wallet-record ~/tee-owner/wallet.json --out ~/tee-owner/exchange/policy-v2.msg policy-sign --json ~/tee-owner/mandate-v2.json --key tpm:0x81000100
scp ~/tee-owner/exchange/policy-v2.msg you@your-server:tee-signer-exchange/
```

On the server:

```sh
docker exec tee-btcpay-tee-signer-1 signerd submit --state-dir /var/lib/signerd --file /exchange/policy-v2.msg --out /exchange/policy-v2.result.json
```

The result file says applied (a tightening) or pending with its activation height (a
loosening). The file is intent; the sealed state is law: editing a JSON file changes nothing
until it is signed with the next nonce and accepted. Keep the mandate JSON you signed next to
`wallet.json`.

### How do I move to a new enclave build (a new MRENCLAVE)?

A new build is a new wallet: the sealed state of the old enclave cannot be opened by the new one,
by design. So an upgrade is a retire-and-reinit, and the coins of the old wallet have to be moved.

1. **Empty the old wallet first**, while it still runs: a payout of the balance to a destination you
   control (within its mandate: a trusted destination, or the unlisted caps), or later from the
   recovery blob into any BIP84 wallet ([CONTINUITY.md](CONTINUITY.md)) — a new enclave can never
   reopen the old state.
2. **Server:** load the new sidecar image (`docker load -i …`), stop the sidecar, set the old state
   aside inside its volume, start on the new image:
   ```sh
   docker stop tee-btcpay-tee-signer-1
   docker run --rm -v tee-btcpay_tee_signer_datadir:/v ubuntu:22.04 sh -c 'mkdir -p /v/retired-<old-mrenclave>-<date> && mv /v/state.sealed /v/receipts.jsonl /v/token /v/retired-<old-mrenclave>-<date>/'
   TEE_FRAGMENT=opt-add-tee-signer-t2.custom TEE_EXTRA_FRAGMENTS=opt-save-storage-xxs btcpay/docker/stack.sh up --no-deps tee-signer
   ```
   The sidecar starts with an empty state and mints a new token; the old token stops working.
3. **Init, verify, mandate, BTCPay:** setup 1 steps 3–7 again (`init`, `quote`, the laptop's
   verification against the new build's MRENCLAVE, `recovery-verify`, the mandate signed at nonce 0,
   the store wallet re-imported with the new xpub, the plugin given the new token). A rescan (step 5)
   if coins arrived before the import. Then the restart drill of step 8 once, so you have seen the
   pause and the `arm` on this build.
4. Keep the old wallet record (it holds the recovery blob of the old seed) next to the new one.

The project's own run of this on 2026-11-10 is `scripts/t2-r7-redeploy.sh` (the dev stack: the
laptop carries the files through a relay box); it is a worked example, not a product tool — and not
idempotent: a second run retires the wallet it just created.

### How do I upgrade the plugin?

Build the DLL (`btcpay/docker/Dockerfile.plugin-build`, a container with the .NET SDK; nothing is
installed on the server), carry it to the server's `tee-signer-btcpay/plugin/` with `scp`, keep the
previous DLL next to it as `*.before-<date>`, then on the server:

```sh
btcpay/docker/stack.sh install-plugin
```

It copies the DLL into the BTCPay container's `Plugins/` directory and restarts BTCPay (~30 s). The
sidecar and the enclave are untouched: no pause, no `arm`. To roll back, copy the saved DLL back and
run the same command.


### How do I put a TPM in front of the signer (R9)?

You need a TPM 2.0 the signer's machine can reach as `/dev/tpmrm0`: a physical one on your own server,
or the virtual TPM of a cloud VM with Trusted Launch (on Azure this is a property of the VM, switched
on from the Azure account with `scripts/azure-enable-vtpm.sh <vm>` — one VM per run, downtime for every
tenant of that VM; the project's own node is waiting for it — issue #1). The signer build must carry the
`tss` feature (its `MANIFEST` says `signerd features: sgx,tss`). If the enclave you run today predates the
counter check (builds before R9 do — the check lives inside the enclave), moving to one that has it is a **new
enclave build and therefore a new wallet**: do ["How do I move to a new enclave build?"](#how-do-i-move-to-a-new-enclave-build-a-new-mrenclave)
first, and come back here before its step 2 `up`. Then, **once, on the server**, with the sidecar not
yet running against the TPM:

```sh
sudo apt-get install -y tpm2-tools
tpm2_getcap handles-persistent; tpm2_getcap handles-nv-index      # pick two handles nobody uses
export TEE_TPM_AUTH='<a secret of yours>'                          # the password of the two TPM objects
docker run --rm --device /dev/tpmrm0 --group-add $(getent group tss | cut -d: -f3) -e SIGNERD_TPM_AUTH="$TEE_TPM_AUTH" -v ~/tee-signer-exchange:/exchange --entrypoint /usr/local/bin/signerd tee-signer/signerd:t2 tpm-setup --ak-handle 0x81000200 --nv-index 0x01800200 --no-orderly --out /exchange/tpm-setup.json
```

`tpm-setup` creates two objects inside the TPM: an attestation key (it can only sign what the TPM
itself attests — nobody can make it sign a forged counter reading) and a monotonic counter. It
**refuses** a handle that is already in use — it never evicts another program's key — so a typo cannot
hurt anything; pick another handle. Keep `tpm-setup.json`: it is the only thing that can ever remove
the two objects again (`tpm-teardown`). The password matters: without it any process on the server
could advance the counter and pause your signer — never spend anything, but pause it. `--no-orderly`
makes a plain counter; the default hybrid one saves a physical TPM's flash but jumps forward after a
power loss, which the enclave treats as "unknown state" until you re-anchor. Now start the stack with
the TPM overlay, which maps `/dev/tpmrm0` into the sidecar and hands it the transport and the password:

```sh
TEE_FRAGMENT=opt-add-tee-signer-t2.custom TEE_EXTRA_FRAGMENTS="opt-save-storage-xxs;opt-add-tee-signer-tpm.custom" TEE_TPM_GID=$(getent group tss | cut -d: -f3) TEE_TPM_AUTH="$TEE_TPM_AUTH" ~/tee-signer/btcpay/docker/stack.sh gen
TEE_FRAGMENT=opt-add-tee-signer-t2.custom TEE_EXTRA_FRAGMENTS="opt-save-storage-xxs;opt-add-tee-signer-tpm.custom" TEE_TPM_GID=$(getent group tss | cut -d: -f3) TEE_TPM_AUTH="$TEE_TPM_AUTH" ~/tee-signer/btcpay/docker/stack.sh up
```

(If your handles differ from the example, add `TEE_TPM_SPEC='tss:device:/dev/tpmrm0?ak=0x…&nv=0x…'`.)

Then **you anchor** — tell the enclave which TPM and which counter value it must trust, with your
owner key, from an attested reading (the counter value never comes from the server's say-so):

```sh
# server: the key and the counter index                 → carry tpm-info.json to your machine
docker exec tee-btcpay-tee-signer-1 signerd tpm-info --state-dir /var/lib/signerd --out /exchange/tpm-info.json
# your machine: a nonce only you know                  → carry nonce.txt to the server
openssl rand -hex 32 > ~/tee-owner/exchange/nonce.txt
# server: the TPM certifies the counter over YOUR nonce → carry anchor-proof.json back
docker exec tee-btcpay-tee-signer-1 signerd tpm-certify --state-dir /var/lib/signerd --nonce-file /exchange/nonce.txt --out /exchange/anchor-proof.json
# your machine: verify the proof yourself and sign the anchor
./owner-cli --status-file ~/tee-owner/exchange/status.json --wallet-record ~/tee-owner/wallet.json --out ~/tee-owner/exchange/anchor.msg anchor --key piv:9a --tpm-info-file ~/tee-owner/exchange/tpm-info.json --proof-file ~/tee-owner/exchange/anchor-proof.json --proof-nonce-file ~/tee-owner/exchange/nonce.txt
# server
docker exec tee-btcpay-tee-signer-1 signerd submit --state-dir /var/lib/signerd --file /exchange/anchor.msg --out /exchange/anchor.result.json
```

From now on every payout and every state change carries a fresh counter proof, and a restart arms
itself when the counter agrees — no `arm` at night. When it does not agree (the counter jumped, the
state was restored from a backup, someone replaced the TPM) the signer pauses with `STATE_STALE` and
the plugin page tells you; you repeat the four anchor steps — the pause is the protection working.

### Why does the enclave have two keys?

The wallet key holds the money, so the only thing it ever signs is a Bitcoin transaction the
mandate has judged — a money key is never asked to sign anything else (the same reason you do
not sign chat messages with a cold-wallet key). The enclave's second, small key — its stamp —
signs the identity card at init, which is what binds "this xpub" to "this enclave" and what
`attest` checks on T2. It also signs a receipt for every signature; receipts are an audit and
development artifact, not a defense the product claims. Both keys are born inside the enclave
and never leave it.

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

### I forget passphrases. Can a key carry a hint?

Yes — a hint that says **where** the passphrase is kept, never **what** it is or what it looks like.
"Password manager, entry tee-recovery" or "envelope in the safe" helps only you; "4 digits", "same as
the PIN" or "my usual pattern" helps whoever steals the file just as much: the hint is plain text inside
the file, and the file's protection (scrypt + AES) assumes the thief has nothing to narrow the search —
a four-digit space is an hour. That is the trade: a thief with the file gains whatever the hint gives
away; you lose everything if you forget. The tools refuse only a hint that contains the passphrase
itself; how descriptive the rest is, is your call — this project's owner weighs forgetting as the more
real loss and writes hints accordingly. The hint is shown before every prompt. (It is not
tamper-protected: someone who can edit the file can only confuse you with it, not learn anything.)

```sh
./owner-cli keygen --out ~/tee-owner/recovery.key --role recovery --hint "password manager, entry tee-recovery"   # at creation (without --hint, keygen asks for one; Enter = none)
./owner-cli key-hint --key ~/tee-owner/recovery.key --set "envelope in the safe"   # later: asks the passphrase once, checks the hint against it
./owner-cli key-hint --key ~/tee-owner/recovery.key                                # show;  --clear removes it
./owner-cli --wallet-record ~/tee-owner/wallet.json key-hint --pin --set "the PIN is in the password manager, entry tee-yubikey"   # the YubiKey PIN hint lives in the wallet record
```

The ceremony key is an OpenSSL PEM file; its hint is a `Hint:` text line before the `-----BEGIN`
(OpenSSL skips leading text) that `scripts/ceremony-sign.sh` prints before the passphrase prompt. Set it
with the script, which asks the passphrase once, applies the same checks and verifies the key is unchanged:

```sh
scripts/ceremony-key-hint.sh --set "password manager, entry tee-ceremony"   # once; plain `scripts/ceremony-key-hint.sh` shows it, --clear removes it
```

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

### What does root on the server see? What is the real difference between T1 and T2?

Start from today. A BTCPay hot wallet's seed sits in NBXplorer's database; the BTCPay and
NBXplorer processes run as an ordinary service user, **not root**, and read it freely. So today
the seed is readable by that user, by anyone who logs in as BTCPay admin, by any plugin — and, of
course, by root.

**T1** (SGX1 without FLC) — the project's build-and-test tier, not for money — moves the seed into the enclave. The BTCPay user, the admin, the plugin,
the container cannot read it any more — that is the attack that happened, closed. What T1 does
**not** change is root: on this hardware the enclave can only run in debug mode, and root can
read a debug enclave's memory through the SGX debug interface, as it could read the seed before.
Root gains nothing new; everyone below root loses their access. If your threat is "someone got
into my BTCPay", T1 is the answer on hardware you already rent. If your threat includes your
hosting provider or a root compromise of the server, T1 is not enough and is not sold as such —
that is T2.

**T2** (FLC + DCAP): non-debug launch, memory encrypted and inaccessible to root, identity
attested. Root can still delete files, stop the daemon, withhold headers — refusals and pauses —
and replay an old sealed state, which repeats a window's payouts (scenario 3 of "What can an
attacker still steal?"). Never a signature outside the mandate's shape; the hot wallet's balance
is the exposure.

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
