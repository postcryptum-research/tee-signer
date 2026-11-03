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
