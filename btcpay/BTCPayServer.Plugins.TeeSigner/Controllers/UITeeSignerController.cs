using BTCPayServer.Abstractions.Constants;
using BTCPayServer.Abstractions.Extensions;
using BTCPayServer.Client;
using BTCPayServer.Data;
using BTCPayServer.Payments;
using BTCPayServer.PayoutProcessors;
using BTCPayServer.Plugins.Wallets;
using BTCPayServer.PayoutProcessors.OnChain;
using BTCPayServer.Payouts;
using BTCPayServer.Services;
using BTCPayServer.Services.Invoices;
using BTCPayServer.Services.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NBitcoin;
using NBXplorer;
using NBXplorer.Models;
using PayoutProcessorData = BTCPayServer.Data.PayoutProcessorData;

namespace BTCPayServer.Plugins.TeeSigner.Controllers;

[Route("plugins/teesigner")]
[Authorize(Policy = Policies.CanModifyStoreSettings, AuthenticationSchemes = AuthenticationSchemes.Cookie)]
public class UITeeSignerController : Controller
{
    private const string CryptoCode = "BTC";
    private readonly StoreRepository _stores;
    private readonly TeeSignerSettingsStore _settings;
    private readonly TeeSignerClientFactory _clients;
    private readonly PaymentMethodHandlerDictionary _handlers;
    private readonly PayoutMethodHandlerDictionary _payoutHandlers;
    private readonly ExplorerClientProvider _explorers;
    private readonly BTCPayNetworkProvider _networks;
    private readonly PayoutProcessorService _processors;
    private readonly EventAggregator _events;
    private readonly TeePayoutProcessorFactory _factory;

    public UITeeSignerController(StoreRepository stores, TeeSignerSettingsStore settings, TeeSignerClientFactory clients,
        PaymentMethodHandlerDictionary handlers, PayoutMethodHandlerDictionary payoutHandlers, ExplorerClientProvider explorers,
        BTCPayNetworkProvider networks, PayoutProcessorService processors, EventAggregator events, TeePayoutProcessorFactory factory)
    {
        _stores = stores;
        _settings = settings;
        _clients = clients;
        _handlers = handlers;
        _payoutHandlers = payoutHandlers;
        _explorers = explorers;
        _networks = networks;
        _processors = processors;
        _events = events;
        _factory = factory;
    }

    public class SettingsVm
    {
        public string StoreId { get; set; } = "";
        public string SignerdUrl { get; set; } = "";
        public string Token { get; set; } = "";
        public int MinConfirmations { get; set; } = 1;
        public int FallbackFeeRateSatVb { get; set; } = 10;
        public bool Configured { get; set; }
        public string? Error { get; set; }
        public TeeSignerClient.StatusJson? Status { get; set; }
        public string? WalletXpub { get; set; }
        public bool WalletIsHot { get; set; }
        public bool WalletConfigured { get; set; }
        public bool XpubMatches { get; set; }
        public bool ProcessorEnabled { get; set; }
        public string? ReceiptsRaw { get; set; }
    }

    internal async Task<SettingsVm> BuildVm(string storeId, StoreData store)
    {
        var vm = new SettingsVm { StoreId = storeId };
        var s = await _settings.Get(storeId);
        if (s is not null)
        {
            vm.Configured = true;
            vm.SignerdUrl = s.SignerdUrl;
            vm.Token = s.Token;
            vm.MinConfirmations = s.MinConfirmations;
            vm.FallbackFeeRateSatVb = s.FallbackFeeRateSatVb;
        }
        var scheme = store.GetDerivationSchemeSettings(_handlers, CryptoCode);
        if (scheme is not null)
        {
            vm.WalletConfigured = true;
            vm.WalletIsHot = scheme.IsHotWallet;
            vm.WalletXpub = scheme.AccountDerivation?.ToString();
        }
        var (client, _) = await _clients.For(storeId);
        if (client is not null)
        {
            try
            {
                vm.Status = await client.Status();
                // the enclave's account xpub must be the store's wallet: compare the base58 xpub
                // against the derivation scheme string (NBXplorer form "tpub...", possibly with
                // suffixes for non-P2WPKH schemes, which v1 does not use)
                if (vm.Status?.Xpub is not null && vm.WalletXpub is not null)
                    vm.XpubMatches = vm.WalletXpub.StartsWith(vm.Status.Xpub, StringComparison.Ordinal);
                vm.ReceiptsRaw = await client.ReceiptsRaw();
            }
            catch (Exception e)
            {
                vm.Error = e.Message;
            }
        }
        var pmId = PayoutTypes.CHAIN.GetPayoutMethodId(CryptoCode);
        var active = (await _processors.GetProcessors(new PayoutProcessorService.PayoutProcessorQuery
        {
            Stores = new[] { storeId },
            Processors = new[] { _factory.Processor },
            PayoutMethods = new[] { pmId }
        })).FirstOrDefault();
        vm.ProcessorEnabled = active is not null;
        return vm;
    }

    [HttpGet("{storeId}/settings")]
    public async Task<IActionResult> Settings(string storeId)
    {
        var store = await _stores.FindStore(storeId);
        if (store is null) return NotFound();
        return View($"{Plugin.ViewsDirectory}/Settings.cshtml", await BuildVm(storeId, store));
    }

    [HttpPost("{storeId}/settings")]
    public async Task<IActionResult> Settings(string storeId, SettingsVm vm, string command)
    {
        var store = await _stores.FindStore(storeId);
        if (store is null) return NotFound();
        if (command == "save")
        {
            await _settings.Set(storeId, new TeeSignerSettings
            {
                SignerdUrl = (vm.SignerdUrl ?? "").Trim(),
                Token = (vm.Token ?? "").Trim(),
                MinConfirmations = Math.Max(0, vm.MinConfirmations),
                FallbackFeeRateSatVb = Math.Max(1, vm.FallbackFeeRateSatVb)
            });
            TempData.SetStatusSuccess("tee-signer settings saved");
        }
        else if (command == "enable-processor" || command == "disable-processor")
        {
            var scheme = store.GetDerivationSchemeSettings(_handlers, CryptoCode);
            if (scheme is null) { TempData.SetStatusMessageModel(new Abstractions.Models.StatusMessageModel { Severity = Abstractions.Models.StatusMessageModel.StatusSeverity.Error, Message = "No BTC wallet on this store" }); return RedirectToAction(nameof(Settings), new { storeId }); }
            if (scheme.IsHotWallet) { TempData.SetStatusMessageModel(new Abstractions.Models.StatusMessageModel { Severity = Abstractions.Models.StatusMessageModel.StatusSeverity.Error, Message = "The store wallet is HOT. tee-signer refuses to operate on a hot wallet: re-import the enclave xpub as a cold wallet." }); return RedirectToAction(nameof(Settings), new { storeId }); }
            var pmId = PayoutTypes.CHAIN.GetPayoutMethodId(CryptoCode);
            var active = (await _processors.GetProcessors(new PayoutProcessorService.PayoutProcessorQuery
            {
                Stores = new[] { storeId },
                Processors = new[] { _factory.Processor },
                PayoutMethods = new[] { pmId }
            })).FirstOrDefault();
            var tcs = new TaskCompletionSource();
            if (command == "enable-processor")
            {
                active ??= new PayoutProcessorData();
                active.HasTypedBlob<OnChainAutomatedPayoutBlob>().SetBlob(new OnChainAutomatedPayoutBlob
                {
                    Interval = TimeSpan.FromMinutes(1),
                    ProcessNewPayoutsInstantly = true,
                    FeeTargetBlock = 2,
                    Threshold = 0
                });
                active.StoreId = storeId;
                active.PayoutMethodId = pmId.ToString();
                active.Processor = _factory.Processor;
                _events.Publish(new PayoutProcessorUpdated { Data = active, Id = active.Id, Processed = tcs });
                await tcs.Task;
                TempData.SetStatusSuccess("TEE payout processor enabled (every minute, instantly on approval)");
            }
            else if (active is not null)
            {
                _events.Publish(new PayoutProcessorUpdated { Data = null, Id = active.Id, Processed = tcs });
                await tcs.Task;
                TempData.SetStatusSuccess("TEE payout processor disabled");
            }
        }
        return RedirectToAction(nameof(Settings), new { storeId });
    }

    public class SendVm
    {
        public string StoreId { get; set; } = "";
        public string Destination { get; set; } = "";
        public long AmountSats { get; set; }
        public decimal FeeRateSatVb { get; set; } = 2;
        public string? Result { get; set; }
        public string? Error { get; set; }
        public List<string> Reasons { get; set; } = new();
        public string? Txid { get; set; }
        public ulong Seq { get; set; }
        public string? ReceiptHex { get; set; }
        public string? SessionId { get; set; }
    }

    [HttpGet("{storeId}/send")]
    [Authorize(Policy = WalletPolicies.CanSignWalletTransactions, AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    public IActionResult Send(string storeId) => View($"{Plugin.ViewsDirectory}/Send.cshtml", new SendVm { StoreId = storeId });

    /// <summary>Build a PSBT for one destination through NBXplorer, judge+sign it in the enclave,
    /// finalize, broadcast. The enclave decides; this page only routes.</summary>
    [HttpPost("{storeId}/send")]
    [Authorize(Policy = WalletPolicies.CanSignWalletTransactions, AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    public async Task<IActionResult> Send(string storeId, SendVm vm, CancellationToken ct)
    {
        vm.StoreId = storeId;
        var store = await _stores.FindStore(storeId);
        if (store is null) return NotFound();
        var network = _networks.GetNetwork<BTCPayNetwork>(CryptoCode);
        var scheme = store.GetDerivationSchemeSettings(_handlers, CryptoCode);
        if (network is null || scheme is null) { vm.Error = "no BTC wallet on this store"; return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        if (scheme.IsHotWallet) { vm.Error = "the store wallet is HOT; tee-signer refuses"; return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        var (client, settings) = await _clients.For(storeId);
        if (client is null || settings is null) { vm.Error = "tee-signer is not configured for this store"; return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        BitcoinAddress dest;
        try { dest = BitcoinAddress.Create(vm.Destination.Trim(), network.NBitcoinNetwork); }
        catch (Exception e) { vm.Error = $"destination: {e.Message}"; return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        var explorer = _explorers.GetExplorerClient(CryptoCode);
        var request = new CreatePSBTRequest
        {
            Destinations = new List<CreatePSBTDestination> { new() { Destination = dest, Amount = Money.Satoshis(vm.AmountSats) } },
            FeePreference = new FeePreference { ExplicitFeeRate = new FeeRate(vm.FeeRateSatVb) },
            ReserveChangeAddress = true,
            RBF = true,
            MinConfirmations = settings.MinConfirmations,
            AlwaysIncludeNonWitnessUTXO = true,
            RebaseKeyPaths = scheme.GetPSBTRebaseKeyRules().ToList()
        };
        PSBT psbt;
        try { psbt = (await explorer.CreatePSBTAsync(scheme.AccountDerivation, request, ct)).PSBT; }
        catch (NBXplorerException e) { vm.Error = $"CreatePSBT: {e.Error?.Message}"; return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        TeeSignerClient.SignResult result;
        try { result = await client.Sign(psbt.ToBase64(), ct); }
        catch (Exception e) { vm.Error = $"signerd: {e.Message}"; return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        if (result.Refused is not null)
        {
            vm.Error = "refused by the enclave";
            vm.Reasons = result.Refused.Reasons;
            return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm);
        }
        var signed = PSBT.Parse(result.Ok!.Psbt, network.NBitcoinNetwork);
        if (!signed.TryFinalize(out var errors)) { vm.Error = "finalize: " + string.Join(";", errors.Select(e => e.ToString())); return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        var tx = signed.ExtractTransaction();
        var br = await explorer.BroadcastAsync(tx, ct);
        if (!br.Success) { vm.Error = $"broadcast refused by the node: {br.RPCMessage}"; return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm); }
        vm.Txid = tx.GetHash().ToString();
        vm.Seq = result.Ok.Seq;
        vm.ReceiptHex = result.Ok.ReceiptHex;
        vm.SessionId = result.Ok.SessionId;
        vm.Result = "signed in the enclave and broadcast";
        return View($"{Plugin.ViewsDirectory}/Send.cshtml", vm);
    }
}
