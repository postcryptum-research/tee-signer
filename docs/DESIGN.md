# Design

**Status:** draft for the first audit round (2026-11-03). Pre-questions Q1–Q3 ruled
(`audit/RESP-prequestions-2026-11-03.md`); the runtime decision in §8 rests on the lab of the same day.

## 1. Components

```
 merchant's box (T1: cheap SGX1 bare metal · T2: FLC/DCAP)        merchant's pocket / desk
 ┌──────────────────────────────────────────────────────────┐    ┌───────────────────────┐
 │ btcpayserver-docker                                      │    │ owner-cli             │
 │  ┌───────────┐  watch-only xpub   ┌──────────────┐        │    │  hw-signer: YubiKey / │
 │  │ BTCPay    │ ────────────────▶ │ NBXplorer    │        │    │  TPM / Secure Enclave │
 │  │ + plugin  │                    └──────────────┘        │    │  builds, diffs, SIGNS │
 │  │           │  PSBT ──▶ /v1/sign ─────────┐              │    │  the mandate          │
 │  └───────────┘  ◀── signed PSBT + receipt  │              │    └──────────┬────────────┘
 │                                             ▼              │               │ signed policy,
 │  ┌──────────────────────────────────────────────────────┐ │               │ freeze/cancel,
 │  │ signerd (Rust, untrusted)   ◀── headers ── bitcoind  │ │◀──────────────┘ rotate
 │  │   loads the enclave, HTTP API, header feed,          │ │
 │  │   receipt log, sealed-state file I/O                  │ │
 │  │   ┌─────────────────────────────────────────────────┐ │ │
 │  │   │ signer-enclave (SGX)                            │ │ │
 │  │   │  C shell: ecalls, sgx_seal, RDRAND, tcrypto     │ │ │
 │  │   │  signer-core (no_std Rust):                     │ │ │
 │  │   │   PSBT parse · derivation · classification ·    │ │ │
 │  │   │   policy engine · header verifier · receipts ·  │ │ │
 │  │   │   canonical encodings · owner-sig verify (P-256)│ │ │
 │  │   └─────────────────────────────────────────────────┘ │ │
 │  └──────────────────────────────────────────────────────┘ │
 └──────────────────────────────────────────────────────────┘
```

| Component | Trust | Language | Notes |
|---|---|---|---|
| `signer-core` | **trusted** (in the measurement) | Rust `no_std` + `alloc` | pure modules; every function also runs on the host under test |
| `signer-enclave` | **trusted** | C (Intel SGX SDK) + linked `signer-core` | the thinnest possible shell: EDL, sealing, randomness, memory |
| `signerd` | untrusted | Rust | transport and storage only; cannot authorise anything |
| BTCPay plugin | untrusted | C# | TEE payout processor + Send-page action + status page; wallet stays cold (§9) |
| `owner-cli` | trusted by the owner, runs on the owner's machine | Rust | reuses TPM_sign `hw-signer` backends for the owner and recovery keys |
| `vectors/` | — | data | positive + refusal suites from signet |

## 2. Key lifecycle

1. **Init (once, by the owner, on a clean box).** `owner-cli init` sends the enclave the owner's
   public key (P-256, from the owner device), the recovery public key (P-256, generated offline and
   kept cold) and the initial mandate (signed). The enclave: draws 256 bits from RDRAND → BIP39
   mnemonic (24 words) → BIP32 master; derives the account at `m/84'/coin'/0'` (P2WPKH, v1; P2TR
   `m/86'` later); seals `{seed, owner_pk, recovery_pk, mandate, nonce=0, state}`; returns the
   account xpub, master fingerprint, the derivation path, the enclave identity public key, a
   signed **identity card** `{MRENCLAVE, xpub, fingerprint, identity_pk, tier}` the owner stores
   (TOFU made checkable: a swapped enclave cannot unseal the seed, so the card stops matching), and
   the **recovery blob** (mnemonic encrypted to the recovery key: ephemeral P-256 ECDH + HKDF-SHA256 +
   AES-256-GCM, AAD = fingerprint ‖ xpub). The recovery blob is produced **once**, at init; no later
   ecall can produce it or anything derived from the seed except signatures and public keys.
2. **Owner verifies off-box.** `owner-cli` on the owner's machine checks that the blob decrypts to
   a mnemonic whose `m/84'/coin'/0'` xpub equals the one the enclave returned (the decryption runs
   on an offline machine, per TPM_sign `KEY_POLICY.md` rule 5), records the xpub and fingerprint,
   and on T2 verifies the DCAP quote binding the enclave identity key and the xpub. On T1 this is
   trust-on-first-use, said plainly.
3. **BTCPay import.** The plugin (or the merchant, by hand) creates the store wallet from
   `[fingerprint/84'/coin'/0']xpub` as watch-only. Receiving needs nothing from the enclave.
4. **Signing** — §4.
5. **Mandate changes** — §6. **Owner rotation / recovery** — §7.
6. **Decommission / migration.** The merchant sweeps to cold storage (a trusted destination —
   automatic), or restores the mnemonic from the recovery blob into any BIP84 wallet.

## 3. Sealed state

One blob, sealed with `sgx_seal_data` (MRENCLAVE policy on T1 — a different enclave cannot open it;
on T2 MRSIGNER+ISVSVN policy with explicit upgrade rules is a later REQ), versioned, written by
`signerd` to disk after every state change and read at load. Contents:

```
SealedState v1 {
  seed[32], owner_pk[65], recovery_pk[65], enclave_identity_sk[32],
  mandate: Mandate (canonical bytes) + owner signature, nonce: u64,
  pending: Option<{ mandate, signature, nonce, activation_height }>,
  frozen: bool,
  chain: { checkpoint: header+height, best: header+height, cumulative_work, last_n_headers[maxReorg] },
  window: { start_height, outflow_total, outflow_unlisted, per_destination_usage[] },
  own_index_bound: { receive: u32, change: u32 },
  seq: u64,                      // receipt sequence
  last_signed_txids[ring]        // for the RBF/duplicate heuristic (advisory, never loosens)
}
```

Order of operations on sign: **verify → update state → seal → hand the sealed blob to the host →
sign → return signature + receipt**. The host may crash between seal and sign; then the budget was
charged and no signature exists — the conservative failure. The opposite order would let a crash
produce a signature the state does not remember.

Rollback (host presents an older blob): not preventable on SGX1 (no monotonic counters). Two
layers, both ruled acceptable (RESP-prequestions Q3):

- **Detection** (always on): the receipt sequence inside the blob; the owner's monitor sees `seq`
  go backwards. Bound without the next layer: one window's budget per rollback.
- **Prevention as a liveness pause** (`freshness.required = true` in the mandate): a **freshness
  witness** — the owner's monitor, off the box, holding a low-privilege P-256 key — periodically
  signs a token `{tip_hash, tip_height, last_seen_seq, nonce}`. The enclave signs a transaction
  only if it holds a token whose tip is in its verified chain within `freshness.maxTipLag` blocks of
  its best header **and** whose `last_seen_seq ≤ own seq`. A rolled-back enclave remembers a lower
  `seq` than the witness has seen, so every fresh token fails the second check and the enclave
  refuses until the owner re-arms it (an owner-signed `Rearm { seq }`). An old token replayed after
  a rollback fails the first check once the chain has moved. The witness key can pause signing or
  hide a rollback; it can never loosen the mandate or sign — so a hosted "watchtower" can hold it.

## 4. Signing flow

`POST /v1/sign { psbt }` → `signerd` → `ecall_sign(psbt_bytes, headers_since_last)`:

1. **Parse** the PSBT (BIP174, v0; v2 later) with the `bitcoin` crate in `no_std`. Unknown
   proprietary fields are ignored only if they are in the "may ignore" class; any field that affects
   the sighash or script semantics and is unknown ⇒ refuse.
2. **Classify inputs.** For each input: require `non_witness_utxo`; recompute its txid; require
   equality with the outpoint; take the amount and `scriptPubKey` from it. Require
   `bip32_derivation` for own inputs naming our fingerprint and a path `account/{0|1}/i`; derive the
   key in-enclave and require `scriptPubKey == P2WPKH(pubkey)`. An input that is not ours is
   *foreign* (payjoin); it is never signed.
3. **Classify outputs.** Own (derived match on branch 0/1, index ≤ bound + gap), trusted (mandate
   address list or descriptor-derived within gap), unlisted (everything else). OP_RETURN outputs
   with value 0 are allowed if the mandate permits; otherwise refused.
4. **Judge.** Invariants I5–I8 (`THREAT-MODEL.md §4`): per-tx caps, window budgets (window = 144
   blocks from `window.start_height`; rolled forward from the verified best height), fee bounds,
   sighash, version, script types, payjoin rule. All arithmetic is checked `u64`; overflow refuses.
5. **Commit.** Update window usage, bump `own_index_bound` if change used a new index, `seq += 1`,
   seal, return the blob to the host (ocall-free: the blob comes back as an `[out]` buffer and the
   host writes it; the enclave keeps the new state in memory as the only state).
6. **Sign** every own input (ECDSA secp256k1, RFC6979, low-s, `SIGHASH_ALL`, BIP143) and fill
   `partial_sigs`. Return the PSBT and a **receipt**: `{seq, txid, net_outflow, per_class,
   fee, height, mandate_hash, policy_nonce}` signed by the enclave identity key.
7. `signerd` returns both to the plugin; the plugin finalises and broadcasts through BTCPay as it
   would for any externally signed PSBT.

Refusals return a machine-readable reason list and are logged; nothing is charged to the budget.

## 5. The block clock

The enclave keeps a header chain from an **owner-pinned checkpoint** in the mandate
(`chain.checkpoint = {hash, height, target}`): each new header must link, meet the target, follow
the retarget rule for the network, and the accepted chain is the one with most cumulative work.
The enclave exposes `best_height`; windows, validity and timelocks are heights. `signerd` feeds
headers from the merchant's own `bitcoind` (already present in btcpayserver-docker). A withheld
feed cannot loosen anything: windows simply stop rolling, the budget of the current window is all
that remains, and the owner's monitor sees `best_height` standing still. There is no in-enclave
notion of "stale" because there is no in-enclave time; staleness is a monitoring concern.

Port shape: trust-bridge `enclave/src/btc_spv.cpp` (C++) proves the verifier shape in this stack;
`signer-core` reimplements the header-chain part in Rust (≈ 300 lines, SHA256d + target math), with
provenance recorded. Merkle inclusion is **not** needed in v1.

Network parameters (mainnet / testnet4 / signet, including signet's trivial PoW and testnet's
20-minute rule) are compiled into the enclave and selected by the mandate's `network`. The signet
label states that the block clock is only as strong as signet's work.

## 6. Mandate updates (the rare, expensive path)

Wire message `PolicyUpdate v1 { enclave_id[32], nonce: u64, canonical_mandate, sig: P-256 ECDSA
over SHA-256("tee-signer/policy/v1" ‖ enclave_id ‖ nonce ‖ canonical_mandate) }`.

**No blind signing** (carried ruling): the owner signs the mandate with its fields shown. With a
YubiKey the display is `owner-cli` on the owner's machine (`policy diff` is mandatory before
`policy sign`, and the digest signed is derived from the shown canonical bytes); the residual —
that machine is trusted for what-you-see-is-what-you-sign — is labeled in `THREAT-MODEL.md §5`. A
device with its own display removes it: the TPM_sign phone owner app, or a Bitcoin hardware wallet
signing the canonical mandate as a message (secp256k1, BIP137/BIP322 — the enclave already carries
secp256k1). Both are later rounds; v1 is P-256 through `hw-signer`.

1. `owner-cli policy diff` fetches the installed mandate + signature from `signerd`, verifies it
   against the owner public key the owner holds, and shows the diff with the new file (JSON →
   canonical bytes, unknown fields are an error).
2. `owner-cli policy sign` signs with the owner device (PIN + touch on a YubiKey), nonce =
   installed + 1.
3. `signerd` submits; the enclave verifies: signature, `enclave_id` match, nonce, network match,
   checkpoint not older than the current one.
4. **Tightening** (every field moves in the restrictive direction — defined field by field in
   `POLICY.md §5`) applies at once. **Loosening** becomes `pending` with `activation_height =
   best_height + timelock` (timelock from the *installed* mandate). While pending, the installed
   mandate stays in force; `GET /v1/policy` and every receipt carry the pending hash.
5. **Cancel**: a signed `Cancel { enclave_id, nonce }` by the owner **or** the recovery key clears
   `pending`. **Freeze**: `POST /v1/freeze` needs no signature (anyone, fail-closed); **unfreeze**
   needs the owner's signature with a nonce.
6. When `best_height ≥ activation_height`, the pending mandate becomes installed on the next ecall.

The same message family carries `RotateOwner { new_owner_pk }` (signed by the owner — tightening?
no: treated as **loosening**, timelocked) and `Recover { new_owner_pk }` (signed by the **recovery
key** — immediate, because the recovery key is the stronger factor and a thief with it already has
the blob path).

## 7. Owner and recovery keys

Both are P-256 so that TPM_sign's `hw-signer` backends apply unchanged: `yubikey-piv` (PIN + touch),
`tpm`, `secure-enclave`, `windows-tpm`, `tropic01`, and `software` for tests only. Rules carried
from TPM_sign `KEY_POLICY.md`: the owner key never lives on the merchant's BTCPay box; the recovery
key is cold (encrypted keyfile on removable media, scrypt N ≥ 2^18 + AEAD, decrypted only off the
box); the agent (here: the enclave) never opens the owner key — the enclave only holds the
*public* keys.

Why the enclave verifies P-256 rather than secp256k1 for the owner: it is what every consumer
secure element speaks (the TPM_sign pivot). The transaction key stays secp256k1 inside the
enclave; the two never mix.

## 8. Runtime and TCB — decided (lab 2026-11-03)

**Decision:** a `no_std` Rust staticlib (`signer-core`) linked into a minimal Intel SGX SDK C
enclave; stable toolchain (1.92), target `x86_64-unknown-linux-gnu`, `panic = "abort"`, allocator
over `sgx_tstdc` `malloc`/`free`/`memalign`. Proven on the T1 box in
`docs/studies/NOSTD-ENCLAVE-LAB-2026-11-03.md`: the staticlib links and runs in HW mode;
`bitcoin` 0.32 + `secp256k1` 0.29 (`alloc`, `lowmemory`) parse a PSBT, compute a BIP143 sighash
and produce an RFC6979 ECDSA signature inside the enclave that a host-side verifier accepts
byte-for-byte. Enclave `.so` 411 KB with the whole closure; `sgx_sign` required memory 4.2 MB.

Crate closure inside the enclave (each a provenance line, each a REQ to change):
`bitcoin` (no-std), `secp256k1` + `secp256k1-sys` (C, built by `cc` with
`USE_EXTERNAL_DEFAULT_CALLBACKS`, no libc I/O, links clean under `--no-undefined`), `sha2`
(**`force-soft`**), `hmac`, `pbkdf2` (BIP39), `p256` (owner and witness signature verify),
`aes-gcm` + `hkdf` (recovery blob). Host-side `base64` is **not** in the enclave: the PSBT crosses
the ecall as bytes; `signerd` decodes text forms.

Build rules the lab paid for (all enforced by the Makefile, each with a check):
1. **No runtime CPU detection inside the enclave.** `cpuid` is `#UD` in an enclave; `sha2`'s
   `cpufeatures` path crashed the first run (`0x1006`). Every hash/crypto crate is built with its
   software path (`force-soft`) and the build asserts `objdump -d enclave.so | grep -c cpuid` is 0.
   (trust-bridge reached the same rule from the other side: its Teaclave patch 2 replaces
   `is_x86_feature_detected!` with a compile-time constant.)
2. **`lto = true`, `codegen-units = 1`** in the release profile: removes the sysroot's
   `rust_eh_personality` reference without a dummy symbol or nightly flags.
3. **No `--allow-multiple-definition`, ever.** `compiler_builtins` on this target exports no
   `mem*` symbols; its libm-style symbols are weak against `sgx_tstdc`'s strong ones. The build
   asserts no duplicate strong symbols.
4. **No TEXTREL** (PIC is rustc's default here; the build asserts `TEXTREL` count 0 after link).
5. **edger8r outputs are make prerequisites** of their objects, or a stale ecall table links
   silently after an EDL edit (`0x1001`).
6. **secp256k1 context randomization** needs the `rand` feature wired to `sgx_read_rand`; it is
   off in the lab and is a REQ line for R2 (side-channel blinding, T2 matters).
7. **Heap is fixed at build time** (no EDMM on SGX1). The mandate's `maxInputs`/`maxOutputs`
   bound the PSBT; the heap is sized from the measured peak of the largest allowed PSBT, with
   headroom, and the number is written into `Enclave.config.xml` with its derivation.
8. **Panic = abort = `0x1006`** to the host, which `signerd` reports as a refusal with
   `ENCLAVE_CRASHED`; the budget is never charged on that path (commit happens before signing, but
   a panic before commit leaves state untouched, and a panic after commit loses nothing but a
   signature).

Why not Teaclave's `sgx_tstd` (trust-bridge's prover route): it exists for crates that need `std`
(Orchard); nothing here does, and its sysroot adds 17 crates to the TCB that no cargo listing
shows. Why not Gramine: it needs the in-kernel driver and FLC — absent on T1 hardware. The
fallback, if a later crate forces `std`, is Teaclave with trust-bridge's pinned fork and patches.

Enclave configuration: `DisableDebug=1` in the signed config on T2 builds; on T1 the launch is
debug (`SGX_DEBUG=1`) by hardware necessity and the binary **says so** at `GET /v1/status`
(`tier: T1-debug`), so no deployment can mistake one for the other. The C side of a T1 build is
compiled with the release flags regardless of `SGX_DEBUG` (the lab's `-O0 -g` is a sample-Makefile
default, not a choice).

## 9. BTCPay integration

Decided from the seam study (`docs/studies/BTCPAY-SIGNING-SEAMS-2026-11-03.md`, BTCPay 2.4.7).
Facts that fix the shape:

- BTCPay keeps no private key itself; a hot wallet's `Mnemonic` / `MasterHDKey` / `AccountHDKey`
  sit **in NBXplorer's Postgres** (`nbxv1_metadata`, plaintext JSONB), which the BTCPay container
  can read directly (`POSTGRES_HOST_AUTH_METHOD: trust` + `BTCPAY_EXPLORERPOSTGRES` in the stock
  docker deployment). **So the seed must never be generated through NBXplorer at all** — not even
  with `savePrivateKeys=false`, since the API response still carries the mnemonic.
- Exactly four in-process signing sites exist (UI send via `HotwalletSafe`; Greenfield
  `signWithSeed`; the automated payout processor; the PayJoin receiver). All four are structurally
  disabled when the store wallet is `IsHotWallet=false`. There is no signer interface and no plugin
  hook in any signing path; plugins may, however, register new services (a new
  `IPayoutProcessorFactory`) and add UI from the `onchain-wallet-send` extension point, and the
  stock `WalletSendVault` / `WalletPSBTReady` endpoints accept any signed PSBT.
- BTCPay's own incident statement (2026-11-02): *"Funds in wallets whose spending keys are held
  off the server, including hardware wallets, were unaffected by these thefts."* This project is
  that recommendation made automatic.

**v1 shape — a plugin, no fork (seam option B):**

1. The store wallet is imported from the enclave's `[fingerprint/84'/coin'/0']xpub` as a **cold
   wallet** (`IsHotWallet=false`). NBXplorer holds public material only. "View seed", PayJoin
   advertisement and the stock payout processor switch themselves off.
2. `BTCPayServer.Plugins.TeeSigner` (C#) registers:
   - a **TEE payout processor** (`IPayoutProcessorFactory` + a subclass of
     `BaseAutomatedPayoutProcessor<OnChainAutomatedPayoutBlob>` overriding `Process`): builds the
     payout PSBT through NBXplorer `CreatePSBT` (as the Send UI does), posts it to `signerd`
     `/v1/sign`, broadcasts the finalised transaction through NBXplorer and records the payout
     proof exactly as the stock processor does;
   - a **"Sign with TEE signer"** action on the Send page (extension point `onchain-wallet-send`):
     takes the `SigningContext` PSBT, posts it to `signerd`, and hands the signed PSBT to
     `WalletPSBTReady` for finalisation and broadcast;
   - a **store settings page**: `signerd` URL + bearer token, live status (tier, measurement,
     installed mandate hash, pending mandate, window usage, last receipt sequence) and the receipt
     log, read-only. Nothing on this page can change the mandate.
3. `signerd` runs as a sidecar in btcpayserver-docker via a custom fragment
   (`opt-add-tee-signer.custom.yml`): `devices: /dev/isgx` on T1 or `/dev/sgx_enclave` +
   `/dev/sgx_provision` and the AESM socket on T2; a dedicated volume for the sealed state; the
   header feed from the stack's own `bitcoind`.
4. The bearer token lets BTCPay *request* signatures; it is not a secret in the threat model
   (a V1 attacker holds it and is still bound by the mandate). It exists for rate limiting and so
   that a stray container cannot spam the enclave.

**Not in v1:** the PayJoin receiver (BIP78 signs synchronously inside the sender's request and
needs the fork path), the Greenfield `signWithSeed` path (returns 503 on a cold wallet; callers
use the plugin's processor or the PSBT round trip). `rules.payjoin` in the mandate is therefore
`none` in v1 and the parser refuses foreign inputs regardless of the plugin.

**Fallbacks and the upstream path:** seam option A (`signerd --greenfield`: the sidecar drives a
stock BTCPay through its Greenfield API for payouts and the PSBT round trip for sends) needs no
plugin and is kept as a documented mode; option C — an `IOnChainSigner` abstraction at the four
call sites, letting a TEE-backed wallet keep `IsHotWallet` semantics including PayJoin — is the
proposal to bring upstream once v1 runs, since the four sites are the entire surface.

## 10. Roadmap

| Round | Deliverable | Gate |
|---|---|---|
| R0 | this design + `POLICY.md` + `THREAT-MODEL.md`; lab result; seam study | DESIGN-PASS on `REQ-design` |
| R1 | `signer-core`: PSBT parse, derivation, classification, policy engine, canonical encodings, receipts; host tests; refusal vectors from signet | IMPL-PASS |
| R2 | `signer-enclave` + `signerd`: init, seal, sign, recovery blob; `owner-cli` with `software` + `yubikey-piv` | IMPL-PASS on T1 hardware |
| R3 | BTCPay plugin + docker fragment; e2e on signet with a BTCPay instance | IMPL-PASS |
| R4 | block clock, timelocked updates, freeze/cancel, receipts + owner monitor + freshness witness | IMPL-PASS |
| R5 | T2: DCAP-attested init and receipts on Azure DCsv3; `DisableDebug=1` build | IMPL-PASS |
| later | P2TR (`m/86'`), PSBTv2, RBF-aware accounting, phone owner app (TPM_sign mobile owner), hardware-wallet owner key with display, PayJoin via the upstream `IOnChainSigner` path | — |
