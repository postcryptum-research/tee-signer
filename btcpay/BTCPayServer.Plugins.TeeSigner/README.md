# BTCPayServer.Plugins.TeeSigner

Untrusted glue between BTCPay Server (≥ 2.4.7, .NET 10) and the tee-signer daemon. The store
wallet is a **cold** xpub in BTCPay; the plugin

- registers a **TEE payout processor** (`TeeSignerPayoutProcessor`): builds payout PSBTs through
  NBXplorer with full previous transactions and origin hints, sends them to `signerd`
  (`POST /v1/sign` = judge + sign in the enclave), broadcasts, records proofs as the stock
  processor does; refuses a hot wallet outright;
- adds **Send through the enclave** (`/plugins/teesigner/{storeId}/send`) and a **settings/status
  page** (`/plugins/teesigner/{storeId}/settings`: signerd URL + token, tier, MRENCLAVE, xpub match
  against the store wallet, mandate hash, window usage, receipts);
- shows notes on the Send page and the wallet setup page.

It never holds a key; a malicious copy of it can only ask the enclave, which answers inside the
owner's mandate. Before building any PSBT, both signing paths check that the signer's xpub is the
store's wallet (C-R3-4) and refuse by name otherwise.

Build (no .NET on the host): `btcpay/docker/Dockerfile.plugin-build` — a `dotnet/sdk:10.0`
container clones `btcpayserver` at `v2.4.7` and publishes this project. Install: the published
`BTCPayServer.Plugins.TeeSigner.dll` under the BTCPay `Plugins/BTCPayServer.Plugins.TeeSigner/`
directory, or `BTCPAY_DEBUG_PLUGINS=/path/to/BTCPayServer.Plugins.TeeSigner.dll` for a dev stack.

## Payout processor: failure handling (2026-11-10)

The processor batches the store's pending payouts into one PSBT, asks the enclave once, and
broadcasts. Three rules, each from a live failure:

- **Fee floor.** The fee rate is the node's estimate for the target (the store's fallback when the
  node has none), never below 1 sat/vB. On a quiet signet the estimate equals the node's own minimum
  relay fee and the rounded fee then falls one satoshi short at broadcast. The mandate's `maxFeeRate`
  is the ceiling; the enclave refuses above it.
- **Never signed twice.** When the node refuses the broadcast, the payout stays `InProgress` with the
  txid as its proof and BTCPay's delayed broadcaster retries the *same* transaction. The enclave has
  already charged the mandate's window for it; handing the payout back to be re-signed would cost
  another signature per minute (three in three minutes on the test stack).
- **Transient failures never disable the processor.** `CreatePSBT` failures (deposits not yet
  confirmed, an empty wallet) and the enclave's self-clearing refusals (`CAP_*_WINDOW`, `FEE_WINDOW`,
  `FROZEN`, `NOT_ARMED`, `CHAIN_STALE`, `CHAIN_REORG`, `FRESHNESS_*`, `SEQ_BEHIND_SESSION`) are retried
  every tick, cost no signature and are counted but never switch the processor off for the payout.
  Ten failures of any other kind (a destination the mandate will never allow, a malformed payout)
  disable the processor for that payout, as BTCPay's own processor does.

