using BTCPayServer.Abstractions.Constants;
using BTCPayServer.Client;
using BTCPayServer.Data;
using BTCPayServer.Payments;
using BTCPayServer.PayoutProcessors;
using BTCPayServer.PayoutProcessors.OnChain;
using BTCPayServer.Payouts;
using BTCPayServer.Services;
using BTCPayServer.Services.Invoices;
using BTCPayServer.Services.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using PayoutProcessorData = BTCPayServer.Data.PayoutProcessorData;

namespace BTCPayServer.Plugins.TeeSigner.Controllers;

/// <summary>Greenfield-style API (API-key auth) for automation and the e2e gates. Shaped exactly
/// like BTCPay's own Greenfield controllers (ApiController on ControllerBase, Greenfield scheme).</summary>
[ApiController]
[Authorize(AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
[EnableCors(CorsPolicies.All)]
[Route("plugins/teesigner/api")]
public class GreenfieldTeeSignerController : ControllerBase
{
    private const string CryptoCode = "BTC";
    private readonly StoreRepository _stores;
    private readonly TeeSignerSettingsStore _settings;
    private readonly PaymentMethodHandlerDictionary _handlers;
    private readonly PayoutProcessorService _processors;
    private readonly EventAggregator _events;
    private readonly TeePayoutProcessorFactory _factory;
    private readonly UITeeSignerController _ui;

    public GreenfieldTeeSignerController(StoreRepository stores, TeeSignerSettingsStore settings, PaymentMethodHandlerDictionary handlers,
        PayoutProcessorService processors, EventAggregator events, TeePayoutProcessorFactory factory, UITeeSignerController ui)
    {
        _stores = stores;
        _settings = settings;
        _handlers = handlers;
        _processors = processors;
        _events = events;
        _factory = factory;
        _ui = ui;
    }

    public class ApiSettingsBody
    {
        public string? SignerdUrl { get; set; }
        public string? Token { get; set; }
        public int MinConfirmations { get; set; } = 1;
    }

    [HttpPut("{storeId}/settings")]
    [Authorize(Policy = Policies.CanModifyStoreSettings, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
    public async Task<IActionResult> ApiSettings(string storeId, [FromBody] ApiSettingsBody body)
    {
        if (await _stores.FindStore(storeId) is null) return NotFound();
        if (string.IsNullOrWhiteSpace(body.SignerdUrl)) return UnprocessableEntity(new { error = "signerdUrl required" });
        await _settings.Set(storeId, new TeeSignerSettings { SignerdUrl = body.SignerdUrl.Trim(), Token = (body.Token ?? "").Trim(), MinConfirmations = Math.Max(0, body.MinConfirmations) });
        return Ok(new { saved = true });
    }

    [HttpGet("{storeId}/status")]
    [Authorize(Policy = Policies.CanViewStoreSettings, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
    public async Task<IActionResult> ApiStatus(string storeId)
    {
        var store = await _stores.FindStore(storeId);
        if (store is null) return NotFound();
        var vm = await _ui.BuildVm(storeId, store);
        return Ok(new
        {
            configured = vm.Configured,
            walletConfigured = vm.WalletConfigured,
            walletIsHot = vm.WalletIsHot,
            walletXpub = vm.WalletXpub,
            xpubMatches = vm.XpubMatches,
            processorEnabled = vm.ProcessorEnabled,
            error = vm.Error,
            enclave = vm.Status
        });
    }

    [HttpPost("{storeId}/processor")]
    [Authorize(Policy = Policies.CanModifyStoreSettings, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
    public async Task<IActionResult> ApiProcessor(string storeId, [FromQuery] bool enable = true)
    {
        var store = await _stores.FindStore(storeId);
        if (store is null) return NotFound();
        var scheme = store.GetDerivationSchemeSettings(_handlers, CryptoCode);
        if (scheme is null) return UnprocessableEntity(new { error = "no BTC wallet" });
        if (scheme.IsHotWallet) return UnprocessableEntity(new { error = "wallet is HOT; tee-signer refuses" });
        var pmId = PayoutTypes.CHAIN.GetPayoutMethodId(CryptoCode);
        var active = (await _processors.GetProcessors(new PayoutProcessorService.PayoutProcessorQuery
        {
            Stores = new[] { storeId },
            Processors = new[] { _factory.Processor },
            PayoutMethods = new[] { pmId }
        })).FirstOrDefault();
        var tcs = new TaskCompletionSource();
        if (enable)
        {
            active ??= new PayoutProcessorData();
            active.HasTypedBlob<OnChainAutomatedPayoutBlob>().SetBlob(new OnChainAutomatedPayoutBlob { Interval = TimeSpan.FromMinutes(1), ProcessNewPayoutsInstantly = true, FeeTargetBlock = 2, Threshold = 0 });
            active.StoreId = storeId;
            active.PayoutMethodId = pmId.ToString();
            active.Processor = _factory.Processor;
            _events.Publish(new PayoutProcessorUpdated { Data = active, Id = active.Id, Processed = tcs });
            await tcs.Task;
            return Ok(new { enabled = true });
        }
        if (active is not null)
        {
            _events.Publish(new PayoutProcessorUpdated { Data = null, Id = active.Id, Processed = tcs });
            await tcs.Task;
        }
        return Ok(new { enabled = false });
    }
}
