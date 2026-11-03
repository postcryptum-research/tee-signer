# REQ — R3 BTCPay plugin, docker sidecar, four executable gates: IMPL review

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r3-btcpay-plugin` of `github.com/77ph/BTCPayTEE` (commit named in the sending message; this file
is added in the next commit). **Requested verdict:** IMPL-PASS / CONDITIONAL / FAIL for merging
`btcpay/` (plugin, docker fragment, e2e gates) to `main`. Design of record: `DESIGN.md §9`
(BTCPay integration, v1 = plugin, no fork), `docs/studies/BTCPAY-SIGNING-SEAMS-2026-11-03.md`.
**Gates named for this round:** C-R11a, C-R11b, C-R11c (`CONDITIONS.md`), plus the four
executable gates (a)–(d) you set in the R2 preview for this round. Nothing in this round touches
the TCB: `core/`, `enclave/`, `host/signerd` are unchanged from `main` at `7811f9c` except as
listed in §1 (none).

## 1. What is on the branch — all of it untrusted

| Part | Where | Lines | Trust |
|---|---|---|---|
| BTCPay plugin (C#, .NET 10, BTCPay 2.4.7) | `btcpay/BTCPayServer.Plugins.TeeSigner/` | ~830 (C# 767, Razor 94) | untrusted (V1 attacker runs it) |
| Plugin build without .NET on the host | `btcpay/docker/Dockerfile.plugin-build` | 11 | — |
| Sidecar image (signerd + enclave, host PSW libs) | `btcpay/docker/Dockerfile.signerd`, `build-signerd-image.sh` | 32 | untrusted host side |
| btcpayserver-docker fragment | `btcpay/docker/opt-add-tee-signer.custom.yml` | 33 | deploy |
| Dev-stack driver (generator in docker, localhost-only) | `btcpay/docker/stack.sh` | 52 | dev |
| The four gates, executable | `btcpay/e2e/gates.sh` | 105 | evidence |

TCB diff against `main`: **none** (`git diff 7811f9c --stat -- core enclave host owner` is empty).

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

<<RUN EVIDENCE PENDING — filled in after the signet sync completes>>

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
