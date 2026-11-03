# Study: BTCPay Server v2.4.7 hot-wallet signing seams (2026-11-03)

> Produced by a research sub-session from shallow clones of `btcpayserver@v2.4.7` (`2868dee`), `NBXplorer@v2.6.22`, `btcpayserver-docker@0daecee`. Every `file:line` was verified against those checkouts on 2026-11-03. Clone paths in the text are the scratch locations used that day.

Sources (shallow clones, all under `/tmp/claude-1000/-home-andrey-llm-btcpay-tee/23be7ea3-a209-4d7f-b04f-54115b296fa3/scratchpad/btcpay-research/`):

| Repo | Ref | Commit |
|---|---|---|
| `btcpayserver/` | tag `v2.4.7` | `2868dee` "Bump and changelog" (released 2026-10-29) |
| `NBXplorer/` | master = tag `v2.6.22` | `8f85dc5` |
| `btcpayserver-docker/` | master | `0daecee` (pins btcpayserver:2.4.7, nbxplorer:2.6.21) |

All `file:line` references below are relative to those clone roots. Line numbers were verified against the checked-out sources.

---

## 2a. How a hot wallet is created and where the key lives

### BTCPay side (UI)

`btcpayserver/BTCPayServer/Plugins/Wallets/Controllers/UIStoreOnChainWalletsController.cs`

* GET `…/onchain/{cryptoCode}/generate/{method}` (`GenerateWallet`, 260-301): method `HotWallet` vs `WatchOnly` vs `Seed`(import). Line 274-278 checks `CanUseHotWallet()`; 292-297 builds `WalletSetupRequest { SavePrivateKeys = isHotWallet, PayJoinEnabled = canUsePayJoin }`.
* POST (305-424):
  ```csharp
  351  response = await client.GenerateWalletAsync(request);            // request : NBXplorer GenerateWalletRequest (SavePrivateKeys)
  367  var derivationSchemeSettings = new DerivationSchemeSettings(response.DerivationScheme, network);
  371  derivationSchemeSettings.IsHotWallet = request.SavePrivateKeys;   // (import path)
  376  derivationSchemeSettings.IsHotWallet = method == WalletSetupMethod.HotWallet;
  379-382  accountSettings.AccountKeyPath / RootFingerprint / AccountOriginal   (xpub + origin only)
  386  vm.AccountKey = response.AccountHDKey.Neuter().ToWif();           // xpub only is kept by BTCPay
  403-415  RecoverySeedBackupViewModel { Mnemonic = response.Mnemonic, IsStored = request.SavePrivateKeys } -> RedirectToRecoverySeedBackup
  ```
  The one-time seed display is done via a POST-redirect that puts the mnemonic in a form (`BTCPayServer/Extensions.cs:936-953`, `{ "mnemonic", vm.Mnemonic }` at 945) to `UIHome.RecoverySeedBackup`.
* The "Is hot wallet" toggle for seed import: `Plugins/Wallets/Views/UIStoreOnChainWallets/_GenerateWalletForm.cshtml:53-68` (`asp-for="SavePrivateKeys"`).
* PayJoin is enabled by default only for hot wallets: line 237 `storeBlob.PayJoinEnabled = strategy.IsHotWallet && …`.

### BTCPay side (Greenfield API)

`Plugins/Wallets/Controllers/GreenfieldStoreOnChainPaymentMethodsController.WalletGeneration.cs`
* `POST /api/v1/stores/{storeId}/payment-methods/{pmi}/wallet/generate` (21-119). 45-55: policy check; 66-75:
  ```csharp
  response = await client.GenerateWalletAsync(new() { …, SavePrivateKeys = request.SavePrivateKeys });
  ```
  92 `derivationSchemeSettings.IsHotWallet = request.SavePrivateKeys;` 113 `result.Mnemonic = response.GetMnemonic();` (mnemonic is returned in the API response).

### Who may create a hot wallet

`BTCPayServer/Extensions/AuthorizationExtensions.cs:21-40`
```csharp
return isAdmin ? new(true, true)
     : new(policiesSettings?.AllowHotWalletForAll is true, policiesSettings?.AllowCreateColdWalletForAll is true);
```
(`Services/PoliciesSettings.cs:55,57`). Server admins always can; others only if the server policy allows. `IsHotWallet` cannot be flipped through config update APIs: `Payments/Bitcoin/BitcoinLikePaymentHandler.cs:289-296` ("IsHotWallet cannot be set through this API. Generate or import a wallet with private keys instead.").

### What BTCPay persists

`DerivationSchemeSettings` (`BTCPayServer/DerivationSchemeSettings.cs`: `Source` 64, `IsHotWallet` 66, `AccountDerivation` 68, `AccountKeySettings[]` with xpub/`AccountKeyPath`/`RootFingerprint`) is JSON-serialised into the store row: `Data/StoreDataExtensions.cs:106-114` writes `storeData.DerivationStrategies` (column on `Stores`, `BTCPayServer.Data/Data/StoreData.cs:25`). **No private key, mnemonic or xprv is stored in BTCPay's own database** — only the `IsHotWallet` flag and public material.

### NBXplorer side — where the secret actually lives

`NBXplorer/NBXplorer/Controllers/DerivationSchemesController.cs:205-295` (`POST /v1/cryptos/{code}/derivations` → `GenerateWallet`):
```csharp
244  mnemonic = new Mnemonic(request.WordList, request.WordCount.Value);
246  var masterKey = mnemonic.DeriveExtKey(request.Passphrase).GetWif(network.NBitcoinNetwork);
248  var accountKey = masterKey.Derive(keyPath);
258  if (request.SavePrivateKeys)
262      repo.SaveMetadata(derivationTrackedSource, WellknownMetadataKeys.Mnemonic, mnemonic.ToString()),
263      repo.SaveMetadata(derivationTrackedSource, WellknownMetadataKeys.MasterHDKey, masterKey),
264      repo.SaveMetadata(derivationTrackedSource, WellknownMetadataKeys.AccountHDKey, accountKey),
265      repo.SaveMetadata(…, WellknownMetadataKeys.Birthdate, …)
269  AccountKeyPath, 270 ImportAddressToRPC, 272 AccountDescriptor are always saved (public)
282-294  response JSON contains MasterHDKey, AccountHDKey, Mnemonic, Passphrase  (returned even when SavePrivateKeys=false)
```
Keys: `NBXplorer/NBXplorer.Client/WellknownMetadataKeys.cs:3-12` (`Mnemonic`, `MasterHDKey`, `AccountHDKey`, `AccountDescriptor`, `Birthdate`, `AccountKeyPath`, `ImportAddressToRPC`).

Persistence: `NBXplorer/NBXplorer/Backend/Repository.cs:1152-1161` (`SaveMetadata`) → `Backend/DbConnectionHelper.cs:195-201`:
```csharp
197  if (value is null) return await Connection.ExecuteAsync("DELETE FROM nbxv1_metadata WHERE wallet_id=@walletId AND key=@key", …) == 1;
200  return await Connection.ExecuteAsync("INSERT INTO nbxv1_metadata VALUES (@walletId, @key, @data::JSONB) ON CONFLICT (wallet_id, key) DO UPDATE SET data=EXCLUDED.data;", …);
```
Table: `NBXplorer/NBXplorer/DBScripts/FullSchema.sql:990-994`
```sql
CREATE TABLE nbxv1_metadata ( wallet_id text NOT NULL, key text NOT NULL, data jsonb );
```
**Not encrypted at rest**: the xprv/mnemonic are plain JSONB strings in Postgres (`grep -ri encrypt|dataprotect` over NBXplorer → no hits). Readable over HTTP via `GET/POST /v1/cryptos/{code}/derivations/{scheme}/metadata/{key}` (`Controllers/CommonRoutesController.cs:195-207`), guarded only by NBXplorer cookie auth (`CookieRepository.cs:17-28` writes `<datadir>/.cookie`; `--noauth` disables it, `Configuration/ExplorerConfiguration.cs:176`). NBXplorer itself also uses `AccountHDKey` to push the xprv into Bitcoin Core when `ImportAddressToRPC` is `Descriptors`/`Legacy` (`Backend/Repository.cs:248-274` and `1044-1060`, `rpc.ImportPrivKeyAsync`) — only when wallet generation asked for `ImportKeysToRPC` (`DerivationSchemesController.cs:212`).

Deployment consequences (see §4): Postgres runs with `POSTGRES_HOST_AUTH_METHOD: trust` and BTCPay is given a direct connection string to the NBXplorer database (`BTCPAY_EXPLORERPOSTGRES`), and the NBXplorer datadir (cookie) is mounted into the BTCPay container. Anyone with code execution in the btcpayserver container, or on the compose network, can read `nbxv1_metadata`.

---

## 2b. Every code path that retrieves the private key to sign

Exactly four places call `GetMetadataAsync` for a private key (grep `MasterHDKey|AccountHDKey` in `BTCPayServer/`):

| # | File:line | Metadata key | Used for |
|---|---|---|---|
| 1 | `BTCPayServer/Plugins/Wallets/HotwalletSafe.cs:41,44` | `MasterHDKey`, `Mnemonic` | UI send/sign, view seed |
| 2 | `BTCPayServer/Plugins/Wallets/Controllers/GreenfieldStoreOnChainWalletsController.cs:564-566` | `MasterHDKey` | Greenfield create-tx with `signWithSeed` |
| 3 | `BTCPayServer/PayoutProcessors/OnChain/OnChainAutomatedPayoutProcessor.cs:86-88` | `AccountHDKey` | automated payouts |
| 4 | `BTCPayServer/Payments/PayJoin/PayJoinEndpointController.cs:406-408` | `AccountHDKey` | PayJoin receiver |

Files referencing `ExtKey`/`.PrivateKey` in `BTCPayServer/` are only: the four above plus `UIWalletsController.cs`, `UIWalletsController.PSBT.cs`, `Views/ViewModels/SignWithSeedViewModel.cs` (user-typed seed). No in-tree plugin (Shopify, Nostr, Subscriptions, …) touches keys. No Lightning-related on-chain sweep exists (`grep -i sweep` → none; LND/CLN hold their own keys).

### (1) `HotwalletSafe` — the UI "unlock" gate (introduced in commit `dffdda64`, 2026-05-07, PR #7354 "Ensure the seed isn't leaking to user with can sign permission")

`Plugins/Wallets/HotwalletSafe.cs:14-55`
```csharp
public record HotwalletRecord(StoreData Store, ClaimsPrincipal User, DerivationSchemeSettings Settings, ExtKey ExtKey, string? Mnemonic, bool CanSign, bool CanSee);
public async Task<HotwalletRecord?> TryUnlock(ClaimsPrincipal user, WalletId walletId)
{
    …
39  if (d?.IsHotWallet is not true) return null;
41  var metadata = await client.GetMetadataAsync<string>(d.AccountDerivation, WellknownMetadataKeys.MasterHDKey);
44  var mnemo   = await client.GetMetadataAsync<string>(d.AccountDerivation, WellknownMetadataKeys.Mnemonic);
49  client.Network.NBitcoinNetwork.Parse<BitcoinExtKey>(metadata).ExtKey,
51  CanSign = Authorize(user, storeId, WalletPolicies.CanSignWalletTransactions)
52  CanSee  = Authorize(user, storeId, Policies.CanModifyStoreSettings)
```
Registered `services.AddTransient<HotwalletSafe>()` in `Plugins/Wallets/WalletsPlugin.cs:19`. Concrete class, `TryUnlock` is **not virtual**, and the record exposes a raw in-memory `ExtKey` — there is no interface.

Consumers:
* `Plugins/Wallets/Controllers/UIWalletsController.cs:1135-1136` `CanAutoSignWithHotWallet` → `NBXSeedAvailable` (1106, 1213; `UIWalletsController.PSBT.cs:140,168`).
* `UIWalletsController.PSBT.cs:77-124` `POST {walletId}/sign` (`WalletSign`), policy `CanSignWalletTransactions`:
  ```csharp
   97  switch (command) { case "vault": return ViewVault(..); case "seed": return ViewSignWithSeed(..); case "decode": … }
  107  var hw = await hotwalletSafe.TryUnlock(User, walletId);
  108  if (hw?.CanSign is true)
  110      return await SignWithSeed(walletId, new SignWithSeedViewModel { UseHotWallet = true, SigningContext = vm.SigningContext, … });
  118  return View("WalletSigningOptions", …);   // cold wallet → choose Vault / PSBT / seed
  ```
* `UIWalletsController.cs:1740-1829` `POST {walletId}/psbt/seed` (`SignWithSeed`): `GetExtKey` (1831-1837) returns the hot-wallet `ExtKey` when `UseHotWallet && TryUnlock(...).CanSign`, else parses the user-typed seed/xprv. Then:
  ```csharp
  1795  psbt.RebaseKeyPaths(signingKeySettings.AccountKey, rootedKeyPath);
  1796  signingKey = extKey.Derive(rootedKeyPath.KeyPath);
  1802  var changed = psbt.PSBTChanged(() => psbt.SignAll(settings.AccountDerivation, signingKey, rootedKeyPath));
  1807  …UpdatePSBTAsync(update) then retry SignAll (1809)
  1820  RedirectToWalletPSBTReady(.. SigningKey = viewModel.UseHotWallet ? null : signingKey.GetWif(..), UseHotWallet, SigningKeyPath ..)
  ```
  (Note: for the *typed-seed* flow the derived account xprv WIF travels in the next form post as `SigningKey`.)
* `UIWalletsController.cs:1838-1856` `GetSigningExtKey` → used by `UIWalletsController.PSBT.cs:478-483` (`WalletPSBTReady`, command `payjoin`) to re-sign the receiver's payjoin proposal: `proposedPayjoin.SignAll(derivationSchemeSettings.AccountDerivation, extKey, RootedKeyPath.Parse(vm.SigningKeyPath))`.
* View seed: `UIStoreOnChainWalletsController.cs:630-664` (see 2c), `CanSeeSeed` at 490.

### (2) Greenfield `POST /api/v1/stores/{storeId}/payment-methods/{pmi}/wallet/transactions`

`GreenfieldStoreOnChainWalletsController.cs:344-650` (`CreateOnChainTransaction`), `[Authorize(Policy = WalletPolicies.CanCreateWalletTransactions)]` (344):
```csharp
359  requires CanSignWalletTransactions (+ CanBroadcastWalletTransactions if ProceedWithBroadcast)
365  if (request.SignWithSeed && !(await CanUseHotWallet()).CanCreateHotWallet) → 503 "You need to allow non-admins to use hotwallets…"
546  if (!request.SignWithSeed) return Ok(new CreateOnChainTransactionResponse { PSBT = psbt.PSBT.ToBase64() });   // unsigned PSBT out
564  var signingKeyStr = await explorerClient.GetMetadataAsync<string>(derivationScheme.AccountDerivation, WellknownMetadataKeys.MasterHDKey);
567  if (!derivationScheme.IsHotWallet || signingKeyStr is null) → 503 ("You cannot send from a cold wallet" / "NBXplorer doesn't have the seed of the wallet")
576  var signingKey = ExtKey.Parse(signingKeyStr, network.NBitcoinNetwork);
586  var accountKey = signingKey.Derive(rootedKeyPath.KeyPath);
593  psbt.PSBT.SignAll(derivationScheme.AccountDerivation, accountKey, rootedKeyPath)
603-605  Finalize / ExtractTransaction; 621 payjoin re-sign; 627 explorerClient.BroadcastAsync
```

### (3) Automated on-chain payout processor → see 2e.

### (4) PayJoin receiver → see 2f.

### Refunds / pull payments
No separate signer. A refund creates a pull payment → payouts. Payouts are paid either by (3), or manually: `Controllers/UIStorePullPaymentsController.PullPayments.cs:415-418` (`case "pay": return await handler.InitiatePayment(payoutIds)`) → `Data/Payouts/BitcoinLike/BitcoinLikePayoutHandler.cs:280-330` builds BIP21 URIs with `payout=<id>` and redirects into the wallet **Send** UI (`UIWalletsController.WalletSend` accepts `bip21`, 1189-1218), i.e. path (1). Conversely, the Send UI "Schedule transaction" button (`WalletSend.cshtml:238`, policy `CanManagePayouts`, handled at `UIWalletsController.cs:1200`) creates payouts.

### Hardware/offline flows (key never on server)
* Vault/HWI: `Blazor/VaultBridge/HWIController.cs:187-252` (`SignHWIController`), `psbt = await device.SignPSBTAsync(psbt, cancellationToken)` at 248.
* PSBT export/import: `UIWalletsController.PSBT.cs:144-…` commands `decode|save-psbt|collect|combine|broadcast|update|createpending` (policy matrix 153-159).

---

## 2c. "View seed" and "remove private key"

* Link: `Plugins/Wallets/Views/UIStoreOnChainWallets/WalletSettings.cshtml:48-50` (`@if (Model.CanSeeSeed)` → `asp-action="WalletSeed"`, id `ViewSeed`). `CanSeeSeed = hw?.CanSee is true` (`UIStoreOnChainWalletsController.cs:490`).
* Handler: `UIStoreOnChainWalletsController.cs:630-664`, `GET {storeId}/onchain/{cryptoCode}/seed`, `[Authorize(Policy = Policies.CanModifyStoreSettings)]`:
  ```csharp
  643  var hw = await hotwalletSafe.TryUnlock(User, new WalletId(storeId, cryptoCode));
  644  if (hw is { CanSee: true, Mnemonic: not null }) → RedirectToRecoverySeedBackup(new RecoverySeedBackupViewModel { Mnemonic = hw.Mnemonic, IsStored = true, RequireConfirm = false, … })
  657  else "The seed was not found"
  ```
  So any store owner (`CanModifyStoreSettings`) can display the mnemonic as long as NBXplorer still holds the `Mnemonic` metadata (wallets imported from xprv have `MasterHDKey` but no mnemonic → "seed not found" although signing still works).
* **There is no "remove hot wallet private key" feature.** `grep SetMetadataAsync|DeleteMetadata|RemoveMetadata` in `BTCPayServer/` → nothing. `ConfirmDeleteWallet` (`UIStoreOnChainWalletsController.cs:722-748`) only does `store.SetPaymentMethodConfig(pmi, null)` (738); `ConfirmReplaceWallet` (685-701) just redirects to setup. NBXplorer keeps `Mnemonic/MasterHDKey/AccountHDKey` in `nbxv1_metadata` forever (and will serve them again if the same xpub is re-imported as a hot wallet). The only way to strip them is NBXplorer's API with a null body (`POST …/metadata/MasterHDKey` → `DELETE`, `DbConnectionHelper.cs:197-198`) or SQL. Even then BTCPay's `IsHotWallet=true` flag remains and the UI will report "NBXplorer doesn't have the seed".

---

## 2d. Existing external-signing options and extension mechanisms

### BTCPay Vault (HWI bridge)
* Server side is a Blazor Server component (`Blazor/VaultBridge/VaultBridgeUI.razor`, `VaultController.cs:14-56`, `HWIController.cs`). `VaultUri => "http://127.0.0.1:65092/hwi-bridge/v1"` (`HWIController.cs:21`).
* Transport: the **user's browser** performs the HTTP calls via JS interop (`VaultClient.cs:17-36` → `js.InvokeAsync("vault.askVaultPermission"| "vault.sendRequest")`; `wwwroot/js/vaultbridge.js`):
  * `GET http://127.0.0.1:65092/hwi-bridge/v1/request-permission` (vaultbridge.js:27-45) — Vault desktop app shows a consent dialog; 200/401.
  * `POST http://127.0.0.1:65092/hwi-bridge/v1` with `Content-Type: text/plain`, body `{"params": ["<hwi arg>", …]}` (vaultbridge.js:2-25; `VaultHWITransport.cs:15-21`) — i.e. raw HWI CLI arguments; response body is HWI's stdout (JSON string). `HwiClient` (`BTCPayServer.Hwi`) builds commands such as `enumerate`, `--fingerprint … getxpub`, `signtx`.
  * Signed PSBT returns to the server by JS `vault.setSignedPSBT` (`HWIController.cs:250`) → form `POST {walletId}/vault` (`UIWalletsController.cs:1616-1628`, `WalletSendVault`) → `RedirectToWalletPSBTReady` (1630-…). **`WalletSendVault` does no verification that Vault signed anything; it simply accepts `SigningContext.PSBT`.**
* Non-interactive use: **not possible from the server** — the bridge lives on the operator's workstation, behind a human consent prompt, and the flow is driven by a Blazor circuit in a browser session. Only shown when `network.VaultSupported` (`WalletSigningOptions.cshtml:24`).

### Sign with PSBT file
`WalletSigningOptions.cshtml:56-74` (command `decode`) → `WalletPSBT` page: download PSBT, later upload the signed one (`collect`/`combine`/`broadcast`, `UIWalletsController.PSBT.cs:153-159`). Greenfield equivalent: `POST …/wallet/transactions` with `signWithSeed=false` → unsigned PSBT (546-552); `POST …/wallet/transactions/broadcast` (`[Authorize(CanBroadcastWalletTransactions)]`, 655-700+) accepts a finalized PSBT or raw hex and broadcasts via NBXplorer.

### Sign with seed/key typed in the browser
`WalletSigningOptions.cshtml:76-92` (command `seed`) → `SignWithSeed` GET/POST (`UIWalletsController.cs:1720-1829`); `SignWithSeedViewModel.GetExtKey` (`Views/ViewModels/SignWithSeedViewModel.cs:29`) accepts 12/24 words or xprv.

### Multisig "pending transaction" (signature collection)
`HostedServices/PendingTransactionService.cs` (`CollectSignature`, expiry/invalidation on `NewOnChainTransactionEvent`, 37-90). Entered via `createpending` (`UIWalletsController.PSBT.cs:184`) and `RedirectToWalletPSBTReady` (1632-1648). UI-only; no Greenfield routes (`grep pending-transactions` in Greenfield → none).

### Is there a pluggable signer abstraction? **No.**
* No `ISigner`/`IHotWalletSigner` interface. `HotwalletSafe` is concrete with a non-virtual method returning an `ExtKey`; the payout processor and PayJoin controller bypass it and read NBXplorer metadata directly; the Greenfield controller does likewise.
* The only wallet-related extension points in views: `ui-extension-point` locations `wallets-top` (`ListWallets.cshtml:9`), `onchain-wallet-setup-post-body` (`_LayoutWalletSetup.cshtml:24`), `onchain-wallet-send` (`WalletSend.cshtml:242`), `store-onchain-wallet-setup` (`SetupWallet.cshtml:45`). `WalletSigningOptions.cshtml` has **none**.

### Plugin hook mechanism
* Contracts: `BTCPayServer.Abstractions/Contracts/IPluginHookService.cs:6-13` (`Task ApplyAction(string hook, object args)`, `Task<object> ApplyFilter(string hook, object args)`), `IPluginHookFilter.cs` (`string Hook; Task<object> Execute(object args)`), `IPluginHookAction.cs` (`string Hook; Task Execute(object args)`).
* Implementation `BTCPayServer/Plugins/PluginHookService.cs:10-66`: collects every DI-registered `IPluginHookAction`/`IPluginHookFilter`, matches `Hook` case-insensitively, runs sequentially, swallows+logs exceptions (so a filter cannot veto by throwing).
* Hooks invoked by core in v2.4.7 (complete list):
  * filters: `resolve-lnurlp-request-for-lightning-address` (`Controllers/UILNURLController.cs:421`), `modify-lnurlp-request` (463, 681), `modify-lnurlp-description` (848)
  * actions: `before-automated-payout-processing` (`PayoutProcessors/BaseAutomatedPayoutProcessor.cs:123`, args `BeforePayoutActionData(store, PayoutProcessorSettings, payouts)`), `after-automated-payout-processing` (142, `AfterPayoutActionData`).
  * **None in any signing path.**
* Service registration by plugins: `IBTCPayServerPlugin.Execute(IServiceCollection)` (`Abstractions/Contracts/IBTCPayServerPlugin.cs:19`). Order: `Startup.ConfigureServices` calls `services.AddBTCPayServer(...)` (`Hosting/Startup.cs:127`) then `.AddPlugins(...)` (198); `PluginManager.AddPlugins` queues in-assembly "system plugins" first (`Plugins/PluginManager.cs:209-223`, e.g. `WalletsPlugin`), then external plugins from `~/.btcpayserver/Plugins/<Id>/<Id>.dll` (254-273), topologically sorts by declared dependencies (335) and calls `plugin.Execute(new PluginServiceCollection(serviceCollection, bootstrapServiceProvider))` (363-364). `PluginServiceCollection` (`Plugins/PluginServiceCollection.cs:8-…`) is a thin pass-through `IServiceCollection` wrapper — a plugin gets full access: it can `Add` (later descriptor wins for single-service resolution), `Remove`/`Replace`/`RemoveAll` core descriptors, or append to `IEnumerable<T>` sets. **So yes, a plugin can override a singleton/scoped/transient service**, provided the consumer resolves it by a type the plugin can satisfy. For `HotwalletSafe` that is useless (non-virtual method, `ExtKey` in the record). For `IPayoutProcessorFactory` (`PayoutProcessors/PayoutProcessorsExtensions.cs:13-16`, `IEnumerable<IPayoutProcessorFactory>` consumed by `PayoutProcessorService.cs:32-40`) a plugin can add a **new** processor. Controllers are `AddControllersAsServices()` (`Startup.cs:200`) but routes are attribute-based; a plugin cannot cleanly replace a core controller action without route conflicts.

---

## 2e. Automated payout processor — hot wallet required

`BTCPayServer/PayoutProcessors/OnChain/OnChainAutomatedPayoutProcessor.cs` (`Process`, 72-214):
```csharp
 74  if (paymentMethodConfig is not DerivationSchemeSettings { IsHotWallet: true } config) { DisableProcessor(payouts); return; }
 84  var explorerClient = _explorerClientProvider.GetExplorerClient(Network.CryptoCode);
 86  var extKeyStr = await explorerClient.GetMetadataAsync<string>(config.AccountDerivation, WellknownMetadataKeys.AccountHDKey);
 89  if (extKeyStr == null) { DisableProcessor(payouts); return; }
 97  var reccoins = (await wallet.GetUnspentCoins(config.AccountDerivation)).ToArray();
100  var accountKey = ExtKey.Parse(extKeyStr, Network.NBitcoinNetwork);
101  var keys = reccoins.Select(coin => accountKey.Derive(coin.KeyPath).PrivateKey).ToArray();
104  changeAddress = await explorerClient.GetUnusedAsync(config.AccountDerivation, DerivationFeature.Change, 0, true);
131  var txBuilder = Network.NBitcoinNetwork.CreateTransactionBuilder().AddCoins(coins).AddKeys(keys);
144  txBuilder.Send(bitcoinClaimDestination.Address, new Money(payout.Amount.Value, MoneyUnit.BTC));
149-151  SetChange / SendEstimatedFees(feeRate) / workingTx = txBuilder.BuildTransaction(true);   // sign=true, in-process
186  var broadcastResult = await explorerClient.BroadcastAsync(workingTx, cts.Token);
```
* Condition: **both** `IsHotWallet == true` in the store config **and** `AccountHDKey` present in NBXplorer; otherwise the processor disables itself on those payouts (`DisableProcessor`, 216-224, sets `blob.DisableProcessor(OnChainAutomatedPayoutSenderFactory.ProcessorName)`).
* It never produces a PSBT: it signs with `TransactionBuilder.AddKeys` + `BuildTransaction(true)`. A watch-only wallet + external signer is **not supported** by this class; the configure page also says so (`UIOnChainAutomatedPayoutProcessorsController.cs:56-64`: "…it is not a hot wallet. This processor cannot function until a hot wallet is configured").
* Factory: `OnChainAutomatedPayoutSenderFactory` (`PayoutProcessors/OnChain/OnChainAutomatedPayoutSenderFactory.cs:17,40-41,56`), registered `AddSingleton<OnChainAutomatedPayoutSenderFactory>()` + `AddSingleton<IPayoutProcessorFactory>(…)` (`PayoutProcessorsExtensions.cs:13-14`).
* Base loop: `BaseAutomatedPayoutProcessor.Act` (`PayoutProcessors/BaseAutomatedPayoutProcessor.cs:105-159`): fetches `AwaitingPayment` payouts for the store/processor (114-121), fires hook `before-automated-payout-processing` (123), calls `ProcessShouldSave` → `Process` (99-103), `SaveChangesAsync`, publishes `PayoutEvent`, fires `after-automated-payout-processing` (142), sleeps `blob.Interval`. `Process` is `protected virtual` (96) — subclassable.

---

## 2f. PayJoin receiver — hot wallet required, signs in-process

`BTCPayServer/Payments/PayJoin/PayJoinEndpointController.cs` (BIP78 endpoint):
```csharp
390  var receiverStore = await _storeRepository.FindStore(walletId.StoreId);
391  var receiverSettings = receiverStore?.GetDerivationSchemeSettings(_handlers, walletId.CryptoCode);
392  if (receiverSettings?.IsHotWallet is not true || receiverSettings.AccountDerivation?.ToString() != accountDerivation.ToString())
395      return CreatePayjoinErrorAndLog(503, PayjoinReceiverWellknownErrors.Unavailable, "The receiving store's wallet is not a hot wallet");
404  await _broadcaster.Schedule(DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2.0), ctx.OriginalTransaction, network);  // fallback broadcast of original tx
406  var extKeyStr = await explorer.GetMetadataAsync<string>(accountDerivation, WellknownMetadataKeys.AccountHDKey);
409  if (extKeyStr == null) → 503 "The HD Key of the store changed"
429-435  add selected receiver UTXOs as inputs; ourNewOutput.Value += contributedAmount
499  var accountKey = ExtKey.Parse(extKeyStr, network.NBitcoinNetwork);
501  var newPsbt = PSBT.FromTransaction(newTx, network.NBitcoinNetwork);
502-518  for each contributed UTXO: UpdateFromCoin; privateKey = accountKey.Derive(selectedUtxo.KeyPath).PrivateKey;
514      signedInput.Sign(privateKey); 515 signedInput.FinalizeInput(); 516 copy FinalScriptWitness into newTx
```
* Payjoin is only advertised on invoices if the wallet is hot: `GreenfieldStoreOnChainWalletsController.cs:133`, `UIWalletsController.cs:891`, `UIStoreOnChainWalletsController.cs:237,501,613`.
* Signing happens synchronously inside the sender's HTTP request (BIP78 round-trip), per-input `signedInput.Sign(privateKey)` — an external signer here must be low-latency and must understand a "payjoin" policy (receiver contributes inputs; receiver's own output value increases; sender's change may shrink).

---

## 2g. Watch-only wallet model — what the Send flow does

A store wallet with `IsHotWallet=false` (sources `ManualDerivationScheme`, `Vault`, `NBXplorerGenerated` cold, `ImportedSeed` without SavePrivateKeys):
1. `WalletSend` (GET `UIWalletsController.cs:~1060-1133`) sets `NBXSeedAvailable=false` (1106). Buttons (`WalletSend.cshtml:231-238`): "Sign transaction" (`sign`, needs `CanSignWalletTransactions`), "Create pending transaction" (`createpending`), "Create PSBT" (`analyze-psbt`), "Schedule transaction" (`schedule` → payouts).
2. POST `WalletSend` builds the PSBT through NBXplorer `CreatePSBTAsync` (`UIWalletsController.PSBT.cs:69`) then `WalletSign` (77-124): `TryUnlock` returns null (`IsHotWallet` false, line 39 of HotwalletSafe) → renders `WalletSigningOptions` (118-123) = **Hardware wallet (Vault)** / **PSBT (offline)** / **Private key or seed**.
3. `WalletPSBTDecoded.cshtml:100-105`: for cold wallets the "Create pending transaction" button appears (`!Model.NBXSeedAvailable`), enabling multisig/offline collection; once signatures are in, `WalletPSBTReady` (`PSBT.cs:430-…`) broadcasts (`broadcast`/`payjoin`).
4. Greenfield: `POST …/wallet/transactions` with `signWithSeed=false` → unsigned PSBT; `POST …/wallet/transactions/broadcast` with a finalized PSBT/raw tx.
5. Automatically disabled for cold wallets: PayJoin (2f), automated on-chain payouts (2e). Payouts then wait in `AwaitingPayment` for manual "pay" (→ Send UI) or `mark-paid` (`GreenfieldPullPaymentController.cs:687-688`).

---

## 3. Release notes, incident, git history

### 2.4.7 (Changelog.md:3-115; GitHub release published 2026-10-29)
"This bug-fix release addresses security, reliability, and payment-accounting issues… Thank you to **Anthropic** and its OSS Scanner program… fixes **85 security findings** (Critical 1, High 13, Medium 52, Low 19)… Details of Critical and High findings are intentionally omitted." Wallet/hot-wallet-relevant lines:
* "**Greenfield**: Honor the server policy restricting non-administrators to cold wallets when generating wallets (#7754)" (Changelog.md:~95)
* "**Internal-node payouts**: Require an eligible, unrestricted administrator in the store before authorizing automated internal-node payments"
* "**On-chain payouts**: Restore the previous payout state and proof after an explicitly rejected broadcast…" / "Treat payments merely sending funds into the store wallet as external payments requiring merchant confirmation (#7764)"
* "**Wallet receive addresses**: Invalidate cached addresses after wallet replacement, removal, or multisig setup… (#7768)"
* "**Wallet**: Avoid repeated PSBT finalization work on large transactions and update NBitcoin to 10.0.19 (#7765)"

### 2.4.6 (Changelog.md:117-156) — the item that matches the Nov-2026 attack vector reported by third parties
* "**API Keys**: Keep restricted API keys within their granted store and user permission scope, including when the key owner is a server administrator (#7684) @Kukks"
* "**Authentication**: Require protected POST requests for logout…", "**Security hardening**: Strengthen store permissions, browser actions, external URLs, Payjoin requests…", "**Basic authentication**: Allow Greenfield API access when account passwords contain colons".

### 2.4.5 / 2.4.4 / 2.4.2
* 2.4.5: SSRF blocking by default; refunds auto-approval restricted; invoice privacy.
* 2.4.4/2.4.3 (Changelog.md:207-260): "Greenfield: Disable Basic authentication by default five minutes after account creation", "Fix TOTP two-factor authentication bypass via Greenfield Basic authentication (#7491)", "Prevent disabling the last active server administrator (#7541)", "Keep new API keys out of authorization redirect URLs (#7542)".
* 2.4.2 (2026-08-07): commit `af8b6e5c Various security fixes` = the LND admin-macaroon exposure fix.

### GitHub security advisories
`gh api repos/btcpayserver/btcpayserver/security-advisories` → `[]` (no published GHSA). Commit `c7ed9579 Direct security reports to GitHub Security Advisories (#7683)` only changed the reporting policy.

### The November 2026 hot-wallet incident (not in the repo; from BTCPay's blog, fetched 2026-11-03)
* Blog post **"Security Incident Affecting BTCPay Server 2.4.1 and Earlier"** (2026-11-02, https://blog.btcpayserver.org/btcpay-server-security-incident-2-4-1-and-earlier/): on 1 Nov 2026 BTC and LTC were stolen from **hot wallets** on instances running **2.4.1 (2026-07-23) or earlier**; attackers "used a different method to exploit the vulnerability fixed in 2.4.2". Operators were told to `./btcpay-down.sh`, move to a fresh server with a new wallet, sweep remaining hot-wallet funds, rotate all hosting/SSH/application/API/Lightning credentials, and not restore old configuration. Key quote: *"Funds in wallets whose spending keys are held off the server, including hardware wallets, were unaffected by these thefts. Accepting payments into these wallets remains our recommended practice."*
* Blog post **"BTCPay Server Security Incident: Our Response and Next Steps"** (2026-08-10, updated 2026-11-02, https://blog.btcpayserver.org/btcpay-server-security-incident-response-and-next-steps/): the August incident = unauthenticated retrieval of LND admin macaroons → Lightning nodes drained; fixed in 2.4.2 (also regenerates the macaroon). Guidance: *"keep funds in cold storage whenever possible. If you need a hot wallet for daily operations, regularly move excess funds to cold storage"*; more code scanning; "prioritizing security patches and hardening over major new features".
* Third-party write-ups (The Hacker News 2026-11, TFTC, crypto.news) describe the Nov vector as admin-owned restricted Greenfield API keys escaping their scope to reach hot-wallet spend endpoints — consistent with the 2.4.6 #7684 fix — **but BTCPay's own post does not confirm a root cause**; treat as unconfirmed.
* No "remove hot wallet key" or signer-isolation feature was added in any 2.4.x release; the only architectural reaction so far is policy/permission hardening (`HotwalletSafe` gating in May 2026, `CanUseHotWallet` enforcement in 2.4.7).

### `git log --oneline v2.4.2..v2.4.7` (358 commits; those touching auth/admin/hot-wallet/signing)
```
c35a67f1 Use authoritative UTXOs for payjoin (#7774)
7cc69750 Fix wallet address, email credential and invoice policy handling (#7768)
b5a8de3c Harden template paths, authenticator attempts, pairing and POS forms (#7770)
2636ec6e Revert payouts whose broadcast the node refused
da150878 Check account status before authorizing internal node payouts
37bc0693 Update NBitcoin and avoid repeated PSBT finalization work (#7765)
0d8b801a Fix store isolation and wallet policy enforcement (#7754)
f4a1b7c7 Fix LNURL authentication, rate expansion and subscription credit rounding (#7762)
c1e480f4 Fix payout finality and checkout safeguards (#7756)
30ee7381 Bind authorized API keys to the selected store (#7748)
f7b8f4cf Separate password lockouts from account restrictions
5e9d4c4a Fix Basic auth passwords containing colons
68bd3424 Validate API key authorization redirects (#7721)
f3481aa5 Reject workflow state from seed signing links (#7713)   <- SignWithSeed GET clears PendingTransactionId/OriginalPSBT (UIWalletsController.cs:1725-1726)
a2983873 Improve Payjoin payment handling (#7723)
717ff11d Harden wallet error handling and PSBT input (#7701)
4fa9a330 Bound profile and wallet object fields (#7693)
c7ed9579 Direct security reports to GitHub Security Advisories (#7683)
d416854c Harden payment and wallet validation (#7664)
bc1e4dc3 Use the configured server URL for sensitive links (#7663)
768e81dc Initialize server Base URL on admin login (#7661)
9238d6bb Scope payout payments to current store (#7642)
252f3a1a Stop leaking API key in the authorize redirect URL (#7542)
a21f0151 Prevent locking the last enabled administrator via the Greenfield API (#7541)
5350b71e Demoting an admin should invalidate its cookie (#7529)
0e4fc389 Prevent monetization from overriding administrator account lockout (#7523)
af8b6e5c Various security fixes            <- 2.4.2 (LND macaroon)
```
`HotwalletSafe.cs` was added in `dffdda64` (2026-05-07, #7354) — before the 2.4.x security series.

---

## 4. Docker deployment (btcpayserver-docker @ `0daecee`)

Generator: `docker-compose-generator/` (C#), fragments in `docker-compose-generator/docker-fragments/*.yml`. Output `Generated/docker-compose.generated.yml` (do not edit; regenerated by `btcpay-setup.sh`/`btcpay-update.sh`).

### Relevant fragments
* `docker-fragments/btcpayserver.yml`
  ```yaml
  services:
    btcpayserver:
      image: ${BTCPAY_IMAGE:-btcpayserver/btcpayserver:2.4.7}
      expose: ["49392"]
      environment:
        BTCPAY_POSTGRES: User ID=postgres;Host=postgres;Port=5432;Application Name=btcpayserver;Database=btcpayserver${NBITCOIN_NETWORK:-regtest}
        BTCPAY_NETWORK / BTCPAY_BIND: 0.0.0.0:49392 / BTCPAY_DOCKERDEPLOYMENT: "true" / BTCPAY_NODEFAULTCHAIN: "true"
      links: [postgres]
      volumes: ["btcpay_datadir:/datadir", "btcpay_pluginsdir:/root/.btcpayserver/Plugins"]
  required: [postgres, btcpayserver]; recommended: [btcpay-host]
  ```
  (lines 1-32). Plugins are loaded from the `btcpay_pluginsdir` volume → a signer-client plugin can be installed there.
* `docker-fragments/nbxplorer.yml` (1-27): `nicolasdorier/nbxplorer:2.6.21`, `expose 32838`, `NBXPLORER_POSTGRES: …Database=nbxplorer${NBITCOIN_NETWORK}`, volume `nbxplorer_datadir:/datadir`; **and** adds to `btcpayserver`: `BTCPAY_EXPLORERPOSTGRES` (direct read access to NBXplorer's DB, line 22) and mounts `nbxplorer_datadir:/root/.nbxplorer` (line 24, for the auth cookie).
* `docker-fragments/bitcoin.yml` (1-48): `bitcoind` (`btcpayserver/bitcoin:32.1`, RPC 43782, P2P 39388, `rpcallowip=0.0.0.0/0`), `NBXPLORER_BTCRPCURL: http://bitcoind:43782/`, `BTCPAY_BTCEXPLORERURL: http://nbxplorer:32838/`; `required: [nbxplorer]`.
* `docker-fragments/postgres.yml` (1-14): `btcpayserver/postgres:18.6`, **`POSTGRES_HOST_AUTH_METHOD: trust`**, volume `postgres_datadir`. (Any container on the stack network can read `nbxv1_metadata` — the plaintext xprv.)
* `docker-fragments/btcpay-host.yml`: host SSH integration (`BTCPAY_SSHCONNECTION`, key mount) used for updates/maintenance.
* No explicit `networks:` in the core fragments → all services share the default compose network and address each other by service name; the generator merges `services/volumes/configs/networks/secrets` from every fragment (`docker-compose-generator/src/DockerComposeDefinition.cs:98-141`), so a fragment may add `networks:`, `devices:`, `secrets:` etc.

### Adding a sidecar (custom fragment mechanism)
* Env var selection: `BTCPAYGEN_ADDITIONAL_FRAGMENTS` (semicolon/comma list, `.yml` suffix optional; `docker-compose-generator/src/DockerComposition.cs:49-53`) and `BTCPAYGEN_EXCLUDE_FRAGMENTS` (54-58). Persisted into the login profile by `btcpay-setup.sh:281-290`; documented at `btcpay-setup.sh:82,93`.
* Custom fragments: file in `docker-compose-generator/docker-fragments/<name>.custom.yml` (`*.custom.yml` is gitignored: `docker-fragments/.gitignore`), then `btcpay-fragments add <name>.custom` (root; regenerates and re-applies the stack) or `export BTCPAYGEN_ADDITIONAL_FRAGMENTS="...;<name>.custom"; . ./btcpay-setup.sh -i` — see `docs/customization.md:7-32`. `btcpay-fragments show|add|remove|exclude|unexclude` (`btcpay-fragments:16-27`).
* Fragment metadata keys honoured by the generator: `required`, `recommended`, `exclusive`, `excluded`, `required-routes`/`optional-routes` (examples: `opt-add-cloudflared.yml`, `bitcoin.yml`).
* Sketch of a signer sidecar fragment `opt-add-tee-signer.custom.yml`:
  ```yaml
  services:
    tee-signer:
      image: your/tee-signer:…
      restart: unless-stopped
      expose: ["8900"]
      devices: ["/dev/sgx_enclave:/dev/sgx_enclave"]   # or /dev/sev-guest, as applicable
      environment:
        SIGNER_NBXPLORER_URL: http://nbxplorer:32838/     # if the signer needs UTXO/PSBT services
      volumes: ["tee_signer_datadir:/data"]
    btcpayserver:
      environment:
        BTCPAY_TEESIGNER_URL: http://tee-signer:8900/      # read by your BTCPay plugin
  volumes:
    tee_signer_datadir:
  required: ["btcpayserver", "nbxplorer"]
  ```

---

## Integration seam candidates (substituting the hot-wallet signer)

Legend of the four in-process signing sites that must be neutralised or redirected: **S1** UI send (`HotwalletSafe` → `SignWithSeed`/`GetSigningExtKey`), **S2** Greenfield `CreateOnChainTransaction(signWithSeed=true)`, **S3** `OnChainAutomatedPayoutProcessor.Process`, **S4** `PayJoinEndpointController`.

### Option A — Watch-only wallet + external signer driven purely through Greenfield (no BTCPay code changes)
* Store wallet is imported as xpub (`IsHotWallet=false`); NBXplorer never sees a private key. The TEE holds the seed and the spending policy.
* Sidecar loop: `GET /api/v1/stores/{storeId}/payouts?…` (AwaitingPayment) → `POST …/wallet/transactions` with `signWithSeed:false` (needs API key perms `btcpay.store.cancreatewallettransactions` + `cansigntransactions`, `GreenfieldStoreOnChainWalletsController.cs:344,359`) → PSBT into TEE (policy check + sign + finalize) → `POST …/wallet/transactions/broadcast` (`canbroadcastwallettransactions`, 655-700) → `POST /api/v1/stores/{storeId}/payouts/{payoutId}/mark-paid` (`GreenfieldPullPaymentController.cs:687`). Interactive manual sends use "Create PSBT"/"PSBT" flow and the sidecar as a PSBT-signing tool, or the Vault emulation of Option E.
* Pros: zero fork, works on stock 2.4.7, S1–S4 are *structurally* disabled because `IsHotWallet=false` (`HotwalletSafe.cs:39`, `GreenfieldStoreOnChainWalletsController.cs:567`, `OnChainAutomatedPayoutProcessor.cs:74`, `PayJoinEndpointController.cs:392`). Compromise of BTCPay can at most *request* a transaction; the TEE policy decides.
* Cons: PayJoin receiver unavailable (BIP78 needs in-request signing); the built-in payout processor is unusable (must mark-paid out of band or the payouts stay "AwaitingPayment"); UI "Send" is a two-step PSBT round-trip; the sidecar needs a BTCPay API key with sign/broadcast permissions (which is itself a hot credential — but it can only move funds through the TEE policy).

### Option B — BTCPay plugin adding a *new* payout processor + a "Sign with TEE" page (no fork)
* `IBTCPayServerPlugin.Execute(IServiceCollection)` registers: (1) `AddSingleton<IPayoutProcessorFactory, TeeOnChainPayoutSenderFactory>()` whose processor subclasses `BaseAutomatedPayoutProcessor<OnChainAutomatedPayoutBlob>` and overrides `Process` (`BaseAutomatedPayoutProcessor.cs:96`) to build a PSBT (NBXplorer `CreatePSBTAsync`, same as `UIWalletsController.PSBT.cs:69`) → call the sidecar → `explorerClient.BroadcastAsync` → set `PayoutTransactionOnChainBlob` proof exactly as lines 168-203 of the stock processor; works with `IsHotWallet=false`; (2) a UI page reachable from the `onchain-wallet-send` extension point (`WalletSend.cshtml:242`) or a wallet nav item that takes the `SigningContext` PSBT, sends it to the TEE, and POST-redirects the signed PSBT into `WalletSendVault`/`WalletPSBTReady` (`UIWalletsController.cs:1616-1628`, which accept any signed PSBT); (3) optionally an `IPluginHookAction` on `before-automated-payout-processing` to disable the stock processor's payouts for the store.
* Pros: no fork; the stock S1–S4 remain disabled by `IsHotWallet=false`; automated payouts fully restored with policy enforcement in the TEE; store-level "Configure" UI can be provided by the plugin (mirror `UIOnChainAutomatedPayoutProcessorsController`).
* Cons: still no PayJoin; the "Sign" button in the stock UI still leads to `WalletSigningOptions` (no extension point there) so the TEE path is a separate button; plugin must track BTCPay API changes (`BaseAutomatedPayoutProcessor` ctor signature, `PayoutProcessorData`).

### Option C — Fork/patch: introduce `IHotWalletSigner` and swap the four sites
* Add e.g. `interface IOnChainSigner { Task<bool> CanSign(StoreData, DerivationSchemeSettings); Task<PSBT> SignAsync(WalletId, PSBT, SigningContext/Intent, CancellationToken); }` with a default `NBXplorerHotWalletSigner` (current behaviour) and let a plugin `services.Replace(...)` it (legal via `PluginServiceCollection`).
* Patch points: `HotwalletSafe.TryUnlock` (make it return a signer handle, not an `ExtKey`; `HotwalletRecord.ExtKey` at line 31), `UIWalletsController.SignWithSeed` 1794-1816 and `GetSigningExtKey` 1838-1856, `GreenfieldStoreOnChainWalletsController.cs:564-621`, `OnChainAutomatedPayoutProcessor.cs:86-151` (switch from `TransactionBuilder.AddKeys` to PSBT build + `SignAsync`), `PayJoinEndpointController.cs:406-517` (per-input sign → `SignAsync` on the payjoin PSBT with an explicit "payjoin" intent).
* Pros: complete coverage incl. PayJoin and the stock UI; a TEE-backed wallet can still be flagged `IsHotWallet=true` so every existing feature keeps working; upstream-able as a generic "remote signer" feature (BTCPay has publicly committed to hardening).
* Cons: maintaining a fork across the fast-moving 2.4.x security series (358 commits in 3 months); `IsHotWallet=true` also keeps "View seed" and the `CanUseHotWallet` policy semantics — would need a new `Source`/flag such as `IsRemoteSigner`.

### Option D — NBXplorer-level interposition (kill-switch only)
* Put a reverse proxy between BTCPay and NBXplorer (`BTCPAY_BTCEXPLORERURL`) that returns 404 for `GET …/metadata/MasterHDKey|AccountHDKey|Mnemonic`, or delete those rows (`POST …/metadata/<key>` with null body → `DELETE`, `DbConnectionHelper.cs:197`). BTCPay then behaves as "NBXplorer doesn't have the seed" (S2 573, S3 89-93 disables processor, S4 412 503, S1 TryUnlock null at 42-43).
* Pros: immediate hardening of an existing hot wallet without touching BTCPay. Cons: cannot *provide* signatures; `IsHotWallet=true` stays set, so PayJoin keeps being advertised and then fails; must also lock down Postgres (`trust` auth) and the shared cookie volume, otherwise the key is still reachable.

### Option E — BTCPay Vault emulation (interactive only)
* A daemon on the operator's workstation on `127.0.0.1:65092` implementing `GET /hwi-bridge/v1/request-permission` and `POST /hwi-bridge/v1` `{ "params": [hwi-args…] }` → HWI-compatible JSON (`enumerate`, `getxpub`, `signtx`, `displayaddress`), forwarding `signtx` to the TEE. Server sees the device as a "hardware wallet" (`Source = "Vault"`, `GetXPubController` `HWIController.cs:254-309`).
* Pros: zero server changes; uses the recommended cold-wallet path; policy enforced in the TEE; works for manual sends and multisig pending transactions. Cons: requires a browser session + human click; useless for automated payouts/PayJoin; `SignHWIController` checks fingerprint/xpub consistency (208-231) so the emulator must answer `getxpub` correctly.

### Recommendation ordering for a TEE project
1. **A + E** first (no fork): cold wallet, Greenfield-driven payouts via the sidecar, Vault emulation for interactive sends.
2. **B** to restore first-class automated payouts and a one-click UI path without forking.
3. **C** if PayJoin and full stock-UI parity are required, ideally proposed upstream as an `IOnChainSigner` abstraction (the four call sites above are the entire surface).

### Hardening notes independent of the option chosen
* Postgres `trust` auth (`postgres.yml:9`) + `BTCPAY_EXPLORERPOSTGRES` (`nbxplorer.yml:22`) + cookie volume (`nbxplorer.yml:24`) mean the NBXplorer key store is reachable from the BTCPay container even without BTCPay code; a TEE design must leave **no** `MasterHDKey/AccountHDKey/Mnemonic` rows in `nbxv1_metadata` (never call `GenerateWallet` with `savePrivateKeys=true`; prefer importing the TEE's xpub).
* NBXplorer `GenerateWallet` returns the mnemonic/xprv in the HTTP response even when `savePrivateKeys=false` (`DerivationSchemesController.cs:282-294`); generate the seed *inside* the TEE instead.
* Greenfield create-tx with `signWithSeed=false` still demands `CanSignWalletTransactions` (`GreenfieldStoreOnChainWalletsController.cs:359`) — scope the sidecar API key to the single store.
