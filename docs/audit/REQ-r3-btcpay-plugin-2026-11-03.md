# REQ — R3 BTCPay plugin, docker sidecar, four executable gates: IMPL review

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r3-btcpay-plugin` of `github.com/77ph/BTCPayTEE` (commit named in the sending message; this file
is added in the next commit). **Requested verdict:** IMPL-PASS / CONDITIONAL / FAIL for merging
`btcpay/` (plugin, docker fragment, e2e gates) to `main`. Design of record: `DESIGN.md §9`
(BTCPay integration, v1 = plugin, no fork), `docs/studies/BTCPAY-SIGNING-SEAMS-2026-11-03.md`.
**Gates named for this round:** C-R11a, C-R11b, C-R11c (`CONDITIONS.md`), plus the four
executable gates (a)–(d) you set in the R2 preview for this round. Nothing in this round touches
the TCB: `core/` and `enclave/` are unchanged from `main` at `7811f9c`. One **host-side** fix
in `host/signerd` (untrusted; §1a) came out of the e2e.

## 1. What is on the branch — all of it untrusted

| Part | Where | Lines | Trust |
|---|---|---|---|
| BTCPay plugin (C#, .NET 10, BTCPay 2.4.7) | `btcpay/BTCPayServer.Plugins.TeeSigner/` | ~830 (C# 767, Razor 94) | untrusted (V1 attacker runs it) |
| Plugin build without .NET on the host | `btcpay/docker/Dockerfile.plugin-build` | 11 | — |
| Sidecar image (signerd + enclave, host PSW libs) | `btcpay/docker/Dockerfile.signerd`, `build-signerd-image.sh` | 32 | untrusted host side |
| btcpayserver-docker fragment | `btcpay/docker/opt-add-tee-signer.custom.yml` | 33 | deploy |
| Dev-stack driver (generator in docker, localhost-only) | `btcpay/docker/stack.sh` | 52 | dev |
| The four gates, executable | `btcpay/e2e/gates.sh` | 105 | evidence |

TCB diff against `main`: **none** (`git diff 7811f9c --stat -- core enclave owner` is empty).

### 1a. Host fix found by the e2e: the header feed after a fork at the enclave's best

Signet forked at height 329268 while the enclave (fed by the trust-bridge node in R2) sat on the
losing branch; the dev stack's node had the other. The R2 feed restarted at `best − 10` on a
disagreement — but the enclave knows only `checkpoint..best` (R2 installed at 329261), so that
batch could never attach (`HEADER_INVALID` every 20 s; the enclave stayed at 329268, which is the
correct *enclave* behaviour: a batch that attaches nowhere is refused, nothing moves). The feed
now probes the fork point from the shallowest depth: the node's headers `[best−k ..= best+1]` for
`k = 0, 1, …` until the enclave accepts or freezes (`FORK_PROBE_DEPTH = 32`; the enclave keeps at
most `maxReorg + 12` recent headers so deeper probes cannot attach). A refused probe changes
nothing; a fork deeper than `maxReorg` makes the enclave freeze itself (`CHAIN_REORG`, sealed,
kept — the feed does not retry past it). Measured on the box: `fork_depth=1 accepted=2`, then
the ordinary extension to the tip. `core::headers` is untouched; this is the host learning to
offer what the verifier can judge.

## 2. What the plugin does, and what it structurally cannot do

The store wallet in BTCPay is the enclave's `[8c3ce9a6/84'/1'/0']xpub` imported **cold**
(`IsHotWallet=false`); NBXplorer holds public material only. The plugin registers:

| Piece | Where | What it does | What it cannot do |
|---|---|---|---|
| TEE payout processor (`IPayoutProcessorFactory` + `BaseAutomatedPayoutProcessor<OnChainAutomatedPayoutBlob>`) | `TeePayoutProcessor.cs` | `Process`: **refuses `IsHotWallet=true` first** (C-R11b, logs and returns); builds the batch PSBT through NBXplorer `CreatePSBT` with `AlwaysIncludeNonWitnessUTXO=true` (I2) and `RebaseKeyPaths` = the store's master-fingerprint rules (I1/I3 origin hints), `RBF`, `ReserveChangeAddress`, the store's `MinConfirmations`, `FeePreference{BlockTarget, FallbackFeeRate}`; `POST /v1/sign` (JUDGE+SIGN in the enclave); on a refusal logs the stable reasons, increments the payout error count (BTCPay's own 10-strikes rule disables the processor for that payout), leaves the payout `AwaitingPayment`; on success `TryFinalize`, `ExtractTransaction`, sets `InProgress` + `PayoutTransactionOnChainBlob` proof, broadcasts through NBXplorer, reverts to `AwaitingPayment` on a node refusal, attaches the wallet transaction — the stock processor's bookkeeping | hold or derive a key; alter the mandate; sign anything the enclave refuses; change what it signs after JUDGE (byte-bound) |
| Send through the enclave | `UITeeSignerController.Send` (cookie auth, `CanSignWalletTransactions`) | one destination, explicit fee rate, same PSBT construction, same sign/finalize/broadcast; shows txid, receipt seq, session id or the refusal reasons | same |
| Settings + status page | `UITeeSignerController.Settings` (cookie auth, `CanModifyStoreSettings`) | signerd URL + token + min confirmations + fallback fee rate; live status (tier, MRENCLAVE, installed, mandate hash, best height, seq, window usage), **xpub match** against the store wallet, `walletIsHot`, receipts (read-only); enable/disable the processor | reach any mandate operation: the client (`TeeSignerClient.cs`) has exactly three calls — status, sign, receipts |
| Greenfield-style API (API key, store permissions) | `GreenfieldTeeSignerController` (`[ApiController]`, Greenfield scheme, as BTCPay's own) | `PUT api/{storeId}/settings`, `GET api/{storeId}/status`, `POST api/{storeId}/processor?enable=` — what the gates drive | same |
| UI notes | `onchain-wallet-send`, `store-onchain-wallet-setup` extension points | a link to the Send page; a note that the wallet must stay cold | — |

The bearer token (DESIGN §9.4) sits in BTCPay's `Settings` table like every other store setting;
it is a rate-limit credential, not an authorisation — a V1 attacker holds it and is bound by the
mandate. `signerd`'s `/v1/freeze` is reachable with the same token (tightening only, by design);
the plugin does not expose it, the gates call it directly.

**Fee plumbing (D-R3-2 below):** BTCPay's own fee provider chain ends in a **static 100 sat/vB**
fallback (`FeeProviderFactory.cs`, `StaticFeeProvider(new FeeRate(100L, 1))`) when no estimate
exists (fresh node, signet). The processor instead passes NBXplorer `FeePreference.FallbackFeeRate`
from a store setting (default 10 sat/vB) so a dead estimator produces a payout inside the
mandate's `maxFeeRate`/`maxFeeAbs` rather than a guaranteed refusal. Plumbing only: the enclave's
fee caps are what is enforced (the R2 live run showed `FEE_ABS` refusing first).

## 3. Deployment shape (owner's constraint: BTCPay web part only in Docker, localhost, no nginx)

`stack.sh gen` runs the btcpayserver-docker generator **in a container**
(`btcpayserver/docker-compose-generator`), `BTCPAYGEN_REVERSEPROXY=none`, `LIGHTNING=none`,
HTTP bound to `127.0.0.1:7392` only; nothing is installed on the host and nothing reaches nginx.
The fragment adds the `tee-signer` sidecar (image built on the box from the R2 `signerd` binary,
`enclave.signed.so`, and the **host's** PSW 2.25 `libsgx_{enclave_common,urts,launch}` — the
current Intel apt repo, 2.27+, has dropped the legacy `/dev/isgx` driver that T1 hardware needs,
so host and container PSW must be the same version), `devices: /dev/isgx`, `/var/run/aesmd`
mount, the stack's `bitcoin_datadir` read-only for the RPC cookie (image uid 999 = the stack's
bitcoin user), a dedicated `tee_signer_datadir` volume for the sealed state, header feed from the
stack's own `bitcoind` (`http://bitcoind:43782`). `ports: 127.0.0.1:7390:7390` is **dev only**
(the owner tool reaches the sidecar through an SSH tunnel); the production fragment drops it.
The plugin DLL is built in a `dotnet/sdk:10.0` container that clones `btcpayserver@v2.4.7`
(`Dockerfile.plugin-build`) and is copied into BTCPay's plugins volume (`stack.sh install-plugin`;
release images ignore `BTCPAY_DEBUG_PLUGINS`).

The sidecar holds the **same signet wallet state** as the R2 host daemon (moved, not re-initialised;
the host daemon is stopped): fingerprint `8c3ce9a6`, mandate `unlisted 100000/500000`, `maxFeeAbs
5000`, `maxFeeRate 50`, window 144 blocks, R2 receipt seq 1.

## 4. The four gates, executed (`btcpay/e2e/gates.sh`, run on the box against the live stack)

Stack: BTCPay 2.4.7 + NBXplorer + bitcoind (signet, full IBD to 329277) + Postgres + the
`tee-signer` sidecar (T1-debug, MRENCLAVE `d7c1afd0…bc0b`, session `b07572be…`), all on the SGX
box, HTTP on `127.0.0.1:7392` only. Store wallet: `[8c3ce9a6/84'/1'/0']tpubDDHLUqe…HVrc` imported
cold through Greenfield; coins indexed by NBXplorer's UTXO-set scan (86 923 sat over 10 UTXOs,
the owner's faucet funding). `gates.sh setup` then `gates.sh run`, verbatim output (the run log is
kept on the box as `~/tee-signer-btcpay/e2e/run-*.log`):

```
== gate (a): IsHotWallet=false in the store record
  PASS store wallet is cold (IsHotWallet absent = false)
== 3. plugin: signer settings + processor
  settings: {"saved":true} [200]
  enclave: {'tier': 'T1-debug', 'installed': True, 'seq': 1, 'xpub': 'tpubDDHLUqe…HVrc'} xpubMatches: True walletIsHot: False error: None
  PASS enclave xpub matches the store wallet
  processor: {"enabled":true} [200]
== gate (b): no key material in nbxv1_metadata
  PASS nbxv1_metadata key rows = 0
== gate (c): the four in-process signing sites are inert
  PASS S2 Greenfield signWithSeed → 503 ({"code":"not-available","message":"You cannot send from a cold wallet"})
  PASS S4 payjoin not advertised in the invoice BIP21 (cold wallet)
  PASS S3 stock hot-wallet processor absent; configured: TeeSignerPayoutProcessor
  PASS S1 (UI seed path) follows from (a): HotwalletSafe.TryUnlock returns null for IsHotWallet=false (study §2b)
== gate (d.1): a payout through the enclave
  enclave seq before: 3
  payout un5z2KtD48ykYN3DeqWU35xuVaT created (2000 sat to tb1q63m9p2628gs9ane23jf3kkpqncz9v5cudhm2ff)
  payout state: InProgress proof txid: 1b481cdac590cbb1723ccf0699eb81bdbe084317499aad9c8de1f5a467e27481
  enclave seq now 4
  PASS the tx BTCPay broadcast is the one the enclave signed (receipt seq 4, txid 1b481cda…7481)
  PASS node holds 1b481cda…7481 in its mempool
== gate (d.2): a frozen signer refuses, charges nothing, the payout waits
  payout sE7RHFciW3bmoTooKjf5QJtUy75 created while frozen (1000 sat to tb1qks42fdtdx8y6qj8mu382vktfj7lpd3d26pzwd6)
  PASS frozen: payout sE7RHFciW3bmoTooKjf5QJtUy75 stays AwaitingPayment, seq unchanged (4)
  btcpay: info: TeeSigner: tee-signer: payout batch signed in the enclave (seq 4, session b07572bea48308be3ee613a41b894938) and broadcast as 1b481cda…7481
  btcpay: warn: TeeSigner: tee-signer: enclave refused the payout batch: FROZEN
  PASS BTCPay logged the refusal by name (FROZEN)
== gate (a) again after a BTCPay restart
  PASS still cold after restart
  PASS nbxv1_metadata key rows still 0
R3 gates: ALL PASS (signer left FROZEN for the operator to unfreeze with the owner key)
```

Three signet transactions were signed by the enclave through the plugin during this round, each
with a receipt whose txid equals what BTCPay broadcast (`signerd /v1/receipts`):

| seq | txid | payee | enclave's classification | window after |
|---|---|---|---|---|
| 2 | `5a59d34671dc1d362d3fadeebb594f11eed7e7b5e3820dfa1d11bc0e6539946b` | `tb1qm0u7r…qflw` — turned out to be an address **of the wallet** (I had reused the R2 destination) | **own** via the verified origin hint; `window_unlisted` unchanged at 5000, fee 705 charged | outflow 6705 / unlisted 5000 / fees 1705 |
| 3 | `74e3b89ab2cb3fd3d1974064b9723f16f91575bc45bcbc2ea3f08eda75f2854c` | throwaway P2WPKH, random program | unlisted 2000 + fee | unlisted 7000 |
| 4 | `1b481cdac590cbb1723ccf0699eb81bdbe084317499aad9c8de1f5a467e27481` | throwaway P2WPKH, random program | unlisted 2000 + fee | unlisted 9000 |

Seq 2 is worth a line: the plugin presented a payout to a wallet address with NBXplorer's own
`bip32_derivation` hint; the enclave verified the hint and classified the output **own** (fee only
charged to the window) — exactly R1's classifier at work in the live stack, not a plugin decision.
The gates were then fixed to use a fresh throwaway address per payout (BTCPay also refuses a
second payout to an address already used by another: `duplicate-destination`).

Fee: the node had no estimate (`estimatesmartfee 2` → "Insufficient data"); NBXplorer used the
store's `FallbackFeeRate` 5 sat/vB → 705 sat on 141 vB; under `maxFeeRate 50` / `maxFeeAbs 5000`.
Without §2's setting BTCPay would have asked for 100 sat/vB and the enclave would have refused
every payout with `FEE_RATE`.

Also exercised, outside the gate script: the owner's `unfreeze` through the SSH tunnel after each
frozen run (`{"applied":true}`); the signer is left unfrozen at the end of the round.

## 5. Decisions to rule

- **D-R3-1 — API surface shape.** The plugin's automation API mirrors BTCPay's Greenfield
  controllers (`[ApiController]` on `ControllerBase`, Greenfield auth scheme, store-scoped
  permissions `CanModifyStoreSettings`/`CanViewStoreSettings`). It can set the signerd URL/token
  and toggle the processor; it cannot reach a mandate operation (the client has no such call, and
  every mandate message is owner-signed anyway). Is "an API key can repoint the store at a
  different signerd" an acceptable V1-level capability? (It is equivalent to the attacker running
  their own BTCPay; the real wallet's coins still sit behind the real enclave's mandate.)
- **D-R3-2 — fallback fee rate as a plugin setting** (§2). Alternative considered: use BTCPay's
  `IFeeProviderFactory` (mempool.space on mainnet) + an explicit rate capped by a setting. Chosen
  the NBXplorer-native `FallbackFeeRate` because it keeps the stack's node as the only fee oracle
  and adds one knob, not two. Either way the mandate is the ceiling.
- **D-R3-3 — the payout error path.** A refusal increments BTCPay's per-payout error count; ten
  refusals disable *this* processor for that payout (stock semantics), after which the operator
  re-enables or pays by hand. The alternative — never disabling — would retry a refused payout
  every minute forever. Acceptable?
- **D-R3-4 — labeled, not verified in the plugin:** the receipt signature is not checked by the
  plugin (an untrusted verifier adds nothing; the owner's monitor (R4) verifies against the
  identity key). The plugin shows `seq`, `session_id` and the receipt hex as given.

## 6. What is not in this round (labeled)

- PayJoin receiver (needs the fork path; `rules.payjoin = none`, the parser refuses foreign inputs
  regardless of the plugin) — DESIGN §9.
- Greenfield `signWithSeed` stays 503 on the cold wallet (gate (c) asserts it); callers use the
  processor or the PSBT round trip.
- R4 monitor (C-R2-2) and R5 repro build / RELEASE=1 on FLC (C-R2-3/4) — unchanged, carried.
- The dev stack runs `MinConfirmations=0` and `FeeTargetBlock=2`; a production store sets its own.
- Hardware owner-key backend (YubiKey/TPM) in `owner-cli` — later round; v1 = encrypted keyfile
  off the BTCPay box (D3).

## 7. Reproduce

On the box: `cd ~/tee-signer/btcpay/docker && ./stack.sh gen && ./stack.sh up && TEE_PLUGIN_DIR=~/tee-signer-btcpay/plugin ./stack.sh install-plugin`;
then `cd ../e2e && SIGNER_TOKEN_FILE=... TEE_XPUB=... TEE_FINGERPRINT=... PAYEE=... ./gates.sh setup`
and, once `bitcoin-cli getblockchaininfo` shows `blocks == headers` and NBXplorer reports ready,
`./gates.sh run`. The script exits non-zero at the first failed gate.
