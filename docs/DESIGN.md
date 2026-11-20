# Design

**Status:** DESIGN-PASS (CONDITIONAL), `audit/RESP-design-2026-11-03.md`, 2026-11-03. Conditions
are worked in `audit/CONDITIONS.md`; implementation proceeds on branches per round.

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
   AES-256-GCM, AAD = fingerprint ‖ xpub). The ephemeral scalar comes from in-enclave RDRAND and is
   zeroized after the key agreement; the GCM nonce is a constant because the key is used exactly
   once — a fresh ephemeral gives a fresh HKDF output, so nonce uniqueness is structural, not a
   counter to get wrong (auditor R8). The recovery blob is produced **once**, at init; no later
   ecall can produce it or anything derived from the seed except signatures and public keys, and a
   vector proves it (C-R8c).
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
`signerd` to disk after every state change and read at load. **At load the blob is untrusted host
input**: the seal MAC is verified before a byte of it is used, a failed unseal refuses every
operation, and a *valid but older* blob is exactly what the freshness witness exists to catch
(auditor R7). Contents:

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

Rollback (host presents an older blob): not preventable by the enclave alone on any SGX (no
monotonic counter, no clock; the sealed state proves authorship, never recency). Re-read on
2026-11-05 with the auditor: without the third layer below the rollback is **repeatable** — root
restores the file, restarts, and re-pays the window; the header feed can be pinned, freeze rolls
back with the state, and a captured witness token keeps passing — so there is no loss bound, only
the hot wallet's balance (`THREAT-MODEL.md §5`). Three layers; the third is what the product
relies on, the first two are developer and audit tooling:

- **Detection** (always on): the receipt sequence inside the blob; the owner's monitor sees `seq`
  go backwards. Bound without the next layer: one window's budget per rollback.
- **Prevention as a liveness pause** (`freshness.required = true` in the mandate): a **freshness
  witness** — the owner's monitor, off the box, holding a low-privilege P-256 key — periodically
  signs a token `{tip_hash, tip_height, last_seen_seq, nonce}`. The enclave signs a transaction
  only if it holds a token whose tip is in its verified chain within `freshness.maxTipLag` blocks of
  its best header **and** whose `last_seen_seq ≤ own seq`. A rolled-back enclave remembers a lower
  `seq` than the witness has seen, so every fresh token fails the second check and the enclave
  refuses until the owner re-arms it (an owner-signed `Rearm { enclave_id, nonce, seq }` — with the
  owner nonce, so a captured Rearm cannot re-enable a later rollback; auditor R13). An old token
  replayed after a rollback fails the first check once the chain has moved; **within `maxTipLag`
  blocks of the rollback point it passes once** — `maxTipLag` is the residual, chosen small. The witness key can pause signing or
  hide a rollback; it can never loosen the mandate or sign — so a hosted "watchtower" can hold it.
- **No signature after a restart until the owner arms this load (R7, `audit/REQ-r7-arm-after-restart-design-2026-11-05.md`).**
  Every rollback is a restart: within a process the session high-water mark (§4a of `ENCLAVE.md`)
  refuses an older blob, so an older blob can only be loaded by a new process — and a new process
  is **unarmed**: `JUDGE` and `SIGN` refuse `NOT_ARMED` until the owner's `Arm { enclave_id, nonce,
  boot_challenge, seq_seen }` arrives, signed by the owner key over the 32-byte challenge the enclave
  drew from in-enclave RDRAND at that load and keeps in enclave memory only — never sealed (a
  sealed flag would roll back with the blob; the witness's sealed `s.armed` is a different field
  and never aliases it). A replayed `Arm` carries another load's challenge (`ARM_CHALLENGE`); an
  `Arm` whose `seq_seen` exceeds the enclave's sequence names a rollback (`ARM_SEQ_BEHIND`); the
  nonce is consumed; a successful `Arm` ratchets the session mark to the armed blob's sequence, so
  an armed process can never be handed a blob older than the one it was armed on. Nobody has to be
  awake: a rollback at night yields an enclave that is up and silent. Owner messages other than
  `Arm` are accepted while unarmed (a cancel or a tightening must not need an extra signature in
  an emergency; a loosening still waits its timelock, a freeze persists into the armed state).
  `owner-cli arm` keeps the highest sequence the owner has seen in the wallet record **on the
  owner's machine** and refuses to arm an enclave that remembers less, with a loud, logged,
  explicit override. Residual: one window's budget per start the owner approves over a rollback
  they did not notice. Opt-out only at build time (`AUTO_ARM=1`: the pause compiled out, its own
  MRENCLAVE, `auto_arm` in the card and status, never ceremony-signed); never a runtime switch.
  The chain-anchored budget (a control coin every signed transaction spends and recreates, so a
  rolled-back enclave can only sign double-spends) is on record as the zero-liveness-cost
  alternative, with serialized payouts as its price.

## 4. Signing flow

`POST /v1/sign { psbt }` → `signerd` → `ecall_sign(psbt_bytes, headers_since_last)`:

1. **Parse** the PSBT (BIP174, v0; v2 later) with the `bitcoin` crate in `no_std`. Unknown
   proprietary fields are ignored only if they are in the "may ignore" class; any field that affects
   the sighash or script semantics and is unknown ⇒ refuse.
2. **Classify inputs.** For **every** input, own or foreign: require `non_witness_utxo`; recompute
   its txid; require equality with the outpoint; take the amount and `scriptPubKey` from it (a
   `witness_utxo` that disagrees with it refuses). An input is **own** only through a
   `bip32_derivation` hint naming our fingerprint and a path `account/{0|1}/i` whose in-enclave
   derivation reproduces both the hinted key and `scriptPubKey == P2WPKH(pubkey)`; a hint that does
   not reproduce them refuses. An input without such a hint is *foreign* (payjoin): it is never
   signed, so misclassifying our own coin as foreign can only make the transaction unspendable,
   never cheaper. (R1 refinement: no bounded search for own inputs — the hint is the pointer.)
3. **Classify outputs.** Own = a verified hint on branch 0/1 with index < bound + `ownIndexGap`
   (a hint whose derivation does not reproduce the script refuses; **a missing hint makes the
   output unlisted**, the safe direction — it is charged to the budget); trusted = mandate address
   or descriptor-derived within gap; unlisted = everything else. OP_RETURN outputs with value 0
   are allowed if the mandate permits; otherwise refused.
4. **Judge.** Invariants I5–I8 (`THREAT-MODEL.md §4`): per-tx caps, window budgets (window = 144
   blocks from `window.start_height`; rolled forward from the verified best height), fee bounds
   (the fee-rate check uses a **lower-bound** vsize: own P2WPKH exact, foreign inputs at P2TR
   key-path size, shortest DER — a smaller vsize means a higher computed rate, so the estimate can
   only refuse more, never less), sighash, version, script types, payjoin rule. All arithmetic is
   checked `u64`; overflow refuses. Own inputs and own outputs both raise the sealed index bounds.
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
   `POLICY.md §5`; the classifier fails toward loosening on any field it cannot prove, auditor R6)
   applies at once. **Loosening** becomes `pending` with `activation_height =
   best_height + timelock` (timelock from the *installed* mandate). While pending, the installed
   mandate stays in force; `GET /v1/policy` and every receipt carry the pending hash.
5. **Cancel**: a signed `Cancel { enclave_id, nonce }` by the owner **or** the recovery key clears
   `pending`. **Freeze**: `POST /v1/freeze` needs no signature (anyone, fail-closed); **unfreeze**
   needs the owner's signature with a nonce. While a mandate is pending, **every** further update
   refuses (`POLICY_PENDING`, tightening included) — one change in flight keeps the timelock
   linear; the owner's answer to a malicious pending is therefore **freeze + cancel**, never a
   tightening over it (auditor, RESP-r1 D-7).
6. When `best_height ≥ activation_height`, the pending mandate becomes installed on the next ecall.

The same family carries `Arm { boot_challenge, seq_seen }` (owner; §3, R7: approves one enclave
load, verified against the challenge the enclave shell hands the pure core as data).
The same message family carries `RotateOwner { new_owner_pk }` (signed by the owner — tightening?
no: treated as **loosening**, timelocked) and `Recover { new_owner_pk }` (signed by the **recovery
key** — immediate, because the recovery key is the stronger factor and a thief with it already has
the blob path).

## 7. Owner and recovery keys

Both are P-256 so that TPM_sign's `hw-signer` backends apply unchanged: `yubikey-piv` (PIN + touch),
`tpm` (Linux TPM 2.0 — the owner's laptop qualifies), `secure-enclave`, `windows-tpm`, `tropic01`.
**Owner decision D3, ruled by the auditor (RESP-design supplement, carried verbatim):**

> A **plaintext** software owner key is refused outside a test-only build. An **encrypted
> off-box keyfile** meeting KEY_POLICY rule-5 — scrypt N ≥ 2^18 + AEAD at rest, decrypted ONLY off
> the box, and **never present on the BTCPay box** — is the permitted FLOOR. A hardware backend
> (YubiKey PIV / Linux-or-Windows TPM 2.0 / Secure Enclave / TROPIC01) is preferred.

Why the floor is sound: the owner key is not a theft-capable key on its own — a thief with it can
only submit a loosening (timelocked, cancellable by the cold recovery key) or a tightening (DoS),
so its compromise is bounded by the same timelock + recovery backstop as V5 whichever backend holds
it. The label the file option carries: *a file-based owner key is extractable on a compromised
owner signing machine, so a persistent compromise of that machine can forge future owner
signatures silently; a hardware backend with touch requires per-use presence. With a file key a
compromise of the owner's machine breaks both WYSIWYS and key secrecy at once; hardware + touch
splits them.* The test-only plaintext feature is compile-gated and provably absent from release
builds (C-R9). **The recovery key is held separately from the owner key — different medium,
different machine** — because it is the backstop that makes a file-based owner key tolerable
(C-D3b). Rules carried from
TPM_sign `KEY_POLICY.md`: the owner key never lives on the merchant's BTCPay box; the recovery
key is cold (encrypted keyfile on removable media, decrypted only off the box); the agent (here:
the enclave) never opens the owner key — the enclave only holds the *public* keys.

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

Build rules the lab paid for (all enforced by the Makefile, each with a check; the auditor made
1, 3, 4 and 9–11 **hard build gates**, C-R10a–d):
1. **No runtime CPU detection inside the enclave.** `cpuid` is `#UD` in an enclave; `sha2`'s
   `cpufeatures` path crashed the first run (`0x1006`). Every hash/crypto crate is built with its
   software path (`force-soft`) **and the build asserts `objdump -d enclave.so | grep -c cpuid`
   is 0** — the assertion, not the feature flag, is the gate, because a transitive dependency can
   reintroduce a runtime probe.
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
9. **Every enclave crate is exact-version pinned** (`=x.y.z`), `Cargo.lock` committed, builds
   `--locked`, and `core/PROVENANCE.md` carries one line per crate: version, source, why it is in
   the TCB. Changing the closure is a REQ.
10. **Reproducible enclave build**: a pinned container image, pinned toolchain, `--locked`,
    `SOURCE_DATE_EPOCH`, no path-dependent output; two independent builds must give the same
    MRENCLAVE. Required for T2 (DCAP attests a MRENCLAVE the owner must tie to audited source),
    recommended for T1 (lets a careful owner recompute the identity card's MRENCLAVE).
11. **secp256k1 context randomization** wired to `sgx_read_rand` is a T2 gate (side-channel
    blinding), scheduled in R2, not optional.
12. **The test-only software owner key** is behind a cargo feature that the release build script
    refuses, and the build asserts the symbol is absent from the release artifacts (C-R9).

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
| R1 | `signer-core`: PSBT parse, derivation, classification, policy engine, canonical encodings, receipts; host tests; refusal vectors from signet | **IMPL-PASS 2026-11-03** |
| R2 | `signer-enclave` + `signerd`: init, seal, sign, recovery blob; `owner-cli` with the encrypted keyfile (D3; hardware backends follow); the header verifier (pulled from R4); build gates; first live signet signature | **IMPL-PASS 2026-11-03** (reproducible build → R5) |
| R3 | BTCPay plugin + docker fragment; e2e on signet with a BTCPay instance, including the vector that asserts `IsHotWallet=false` end to end and zero key material in `nbxv1_metadata` (C-R11c) | **IMPL-PASS 2026-11-03** |
| R4 | the owner's monitor: receipt authenticity, `(session, seq)` fork detection, chain observation primary, feed stall, witness tokens, freeze reflex (block clock, timelocked updates, freeze/cancel, receipts landed in R1/R2) | **IMPL-PASS 2026-11-03** |
| R5 | T2: reproducible pinned build, `DisableDebug=1` launched non-debug on Azure DCsv3, DCAP-attested identity card (`REPORT` op), `owner-cli attest` with the ledgered TCB policy | **IMPL-PASS 2026-11-03** |
| R6 | owner key in the operator's TPM 2.0 (`tpm:` locator), ceremony enclave-signing key with two-step signing and gate 7, fused `init` (verifier before the record) | **IMPL-PASS 2026-11-03** |
| R6b | owner key on a YubiKey 5 PIV slot (`piv:` locator): PIN + touch per signature, owner slots accepted only with PIN ALWAYS + touch ALWAYS, and a slot becomes owner only through its attestation verified to Yubico's pinned root (`init --owner` / `rotate-owner --new-owner` / `recover --new-owner` take locators, never raw keys) | **IMPL-PASS 2026-11-04** (code; the live T2 custody transition is C-R6b-1) |
| R7 | no signature after a restart until the owner arms this enclave load (`Arm` over an in-enclave challenge); build-time opt-out `AUTO_ARM` labeled, never ceremony-signed | **SOURCE IMPL-PASS 2026-11-05**; deployment facet carried (C-R7-11..13) |
| R8 | no tunnel: the owner's steps as files (`signerd status|submit|init|quote|policy|freeze --out`, `owner-cli --status-file/--out`), the FAQ in three places | **SOURCE IMPL-PASS 2026-11-05** |
| **2029 horizon — SGX or a VM-level TEE** (study for the auditor, 2026-11-11, `docs/studies/SGX-VS-TDX-2026-11-11.md`) | Azure retires DCsv3 (the last SGX VMs) on 2029-10-31; successors are TDX/SEV-SNP confidential VMs, which protect a VM from the provider but **not** the signer from root inside the VM — our adversary of record. Options stated with honest labels: (1) SGX on the operator's own FLC hardware (unchanged label, strongest); (2) the signer as an attested **appliance** CVM (image measurement instead of MRENCLAVE, vTPM sealing + R9 counter built in, two VMs); (3) a confidential container. A shared CVM with BTCPay is rejected (protects against the party we already trust). `signer-core` is TEE-agnostic and carries over untouched. No decision taken; nothing started | owner's decision, no date |
| **freshness roadmap** (owner's decision 2026-11-05, `docs/studies/FRESHNESS-SOURCES-2026-11-05.md`) | for the current hardware the product stays on R7 (the owner arms each restart). Next: **(a) the operator's own FLC server with a physical TPM** — an NV monotonic counter certified with the enclave's nonce as the freshness source; unattended restarts, bound kept, no provider in the picture ("solves everything"); **(b) for the known Azure hardware, Trusted Launch** — check whether the existing VM can be switched on, or create one more DCsv3 VM with Trusted Launch so the hypervisor vTPM serves as the counter (the provider accepted as a residual, THREAT-MODEL V7). The chain-anchored control coin is **not** pursued — too complex (owner, 2026-11-05); it stays in the study only as the record of what else exists. **R9 (agreed 2026-11-05, next):** the TPM counter as the freshness source on the enclave side — the TPM's P-256 attestation key sealed at `init`, the expected counter in the state, a `TPM2_NV_Certify` over the enclave's nonce required at every blob-reading ecall and `+1` before every seal, mismatch → `STATE_STALE` with the owner's `Arm` as the attended override; developed and tested against the owner's laptop TPM through a reverse tunnel as a **development stand-in** (a two-operation agent: increment, certify), the transport being host-side only — the real TPM (physical or vTPM) is a transport swap, not an enclave change | **DESIGN-PASS + IMPL-PASS 2026-11-10** (`RESP-r9-tpm-counter-{design,impl}-2026-11-10.md`; C-R9-A…D discharged, E carried), **merged**: core verifier + anchor, enclave proof per state change, auto-arm on a fresh proof, software stand-in, owner `anchor`; T0 + e2e evidence. **Product path = a TPM in front of the node:** the owner froze the laptop-TPM dev agent (2026-11-10); [issue #1](https://github.com/postcryptum-research/tee-signer/issues/1) states what enabling a vTPM on the Azure SGX node (Trusted Launch on `sgx-node-3`, or a +1 counter VM) requires per Microsoft's docs, incl. the 2029-10-31 DCsv3 retirement; the local `tss` transport **exists** (2026-11-11, host-side, `host/signerd/src/tpm_tss.rs`, explicit handles + refuse-if-occupied per C-R9-E; run against the laptop's Intel PTT: a real `TPMS_ATTEST` through the enclave's parser, anchor, counter equality, auto-arm, rollback refused, teardown leaves the TPM as found — `scripts/e2e-tss-local.sh`); the T2 image recipe with it is prepared (2026-11-11, gate 5: `enclave.so` byte-identical under the old and the libtss2 build image, MRENCLAVE `c7c5d8ef…` = current `main`); **T2 moved to that build on 2026-11-12** (ceremony-signed, owner-run migration, new wallet `cc685457`, R7 pause + `arm` drilled live on the new measurement; unanchored until the vTPM); the product path now waits only for the vTPM (issue #1) → `tpm-setup`, the compose overlay, `anchor`; **2026-11-17:** enabling it re-places the VM, and sealing is CPU-bound (§3), so the live state is expected `STATE_UNSEALABLE` on the new host → a new wallet on the same MRENCLAVE with `tpm-setup` before `init`, anchored from its first seal; the old wallet via the recovery blob (CONTINUITY §1); **2026-11-18: R9 LIVE on T2 (signet)** — `sgx-node-3` converted (Trusted Launch vTPM, MSFT 1.38), `tpm-setup` at `0x81000200`/`0x01800200`, new wallet `7180f2b6` on the same MRENCLAVE (owner-run, quote verified), mandate, anchored. The first anchor exposed the **anchor-window race with the daemon's own header feed** (`STATE_STALE` 2 s after a legitimate anchor — THREAT-MODEL row, REQ-r9 §2 row 5, fix REQ-r9a: the Anchor pins the live deposited counter, verified against the sealed TPM identity — **DESIGN-PASS 2026-11-18 + IMPL-PASS 2026-11-19**, `RESP-r9a-anchor-live-counter-{2026-11-18,impl-2026-11-19}.md`, merged to `main`; **on T2 since 2026-11-19**: ceremony-signed build `2073c234…` (the auditor's decorrelated build = the deploy-content gate), new wallet `735e6acd` (owner-run, quote 7/7), first anchor clean 140 → 141 with no `STATE_STALE`, unattended restart re-armed on block 331560; `7180f2b6` retired at 0 sat); the re-anchor from `STATE_STALE` applied clean (race-free there: the feed is refused), and the unattended-restart drill armed itself on the next block (17:15Z, no owner) |
| **R10 — fuzzing** (owner's ask 2026-11-20: fuzzing next to the test coverage) | coverage-guided fuzzing of the critical sections: every host-facing decoder in `signer-core` (proto, mandate, owner message, state, `TPMS_ATTEST`, headers, PSBT classification, the policy engine's accept invariants), the `nosgx` ecall dispatcher as op sequences, then owner-cli's attestation parsers; a `fuzz/` crate outside the TCB (cargo-fuzz, a pinned nightly for the fuzz build only — the gates stay on 1.92.0), corpus + regression reproducers replayed on stable as a CI gate; runs on the laptop, never on the shared machines | **DESIGN-PASS (CONDITIONAL) 2026-11-20** (`RESP-r10-fuzzing-design-2026-11-20.md`: C-R10-1…7 — cross-type confusion oracle, strict canonicality on fuzzer-found inputs, signature covers the full canonical encoding, `disarms` exact both ways, `compare` a partial order, header work no-wrap, hollow-harness guard with the auditor's own injected-defect check; forward: fuzz-replay joins the IMPL-PASS bar, every new parser ratchets a target). **Phase 1 on `main` 2026-11-21, IMPL-PASS the same day** (`REQ-r10-fuzzing-impl-2026-11-20.md` → `RESP-r10-fuzzing-impl-2026-11-20.md` at `9e2d2fc`, the auditor's own run incl. his own decorrelated injected defect, caught): ten targets — every raw-byte decoder of `signer-core`, `TPMS_ATTEST`, `compare`, the cross-type oracle — one-hour runs clean on nine, and the tenth found **F-2026-11-20-01**: `compare` classifies a same-height checkpoint with different content as tightening in both directions, so a checkpoint-content change skips the installed mandate's timelock; the auditor ruled it a DEFECT with a second leg at install (`time`/`bits`/period fields not validated against the enclave's own header record). Fix as its own REQ (`REQ-r10-f01-checkpoint-impl-2026-11-20.md`, **DESIGN-PASS CONDITIONAL 2026-11-21**: unfrozen legs as drafted; a frozen re-pin applies at once — the block-height timelock cannot run while the chain is frozen, so timelocking it would brick the signer — checkpoint-only, residual V5 ∧ frozen labelled; `new_at_init` returns `Result`; POLICY §5 spelled out) — **IMPL-PASS 2026-11-21** (`RESP-r10-f01-checkpoint-impl-2026-11-21.md`, clean at `10f6770`, every protection site mutation-reddened, `scripts/hollow-f01.sh` 7/7), merged via PR #2; the deployed measurement `2073c234…` carries the finding until the next ceremony build (owner's). Phase 2 (structured ops, headers, PSBT, the policy engine, the dispatcher) next |
| later | P2TR (`m/86'`), PSBTv2, RBF-aware accounting, phone owner app (TPM_sign mobile owner), hardware-wallet owner key with display, PayJoin via the upstream `IOnChainSigner` path | — |
