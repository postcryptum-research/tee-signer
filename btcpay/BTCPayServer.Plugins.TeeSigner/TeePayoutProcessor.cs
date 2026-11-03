using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Client.Models;
using BTCPayServer.Data;
using BTCPayServer.HostedServices;
using BTCPayServer.Payments;
using BTCPayServer.PayoutProcessors;
using BTCPayServer.PayoutProcessors.OnChain;
using BTCPayServer.Payouts;
using BTCPayServer.Services;
using BTCPayServer.Services.Invoices;
using BTCPayServer.Services.Stores;
using BTCPayServer.Services.Wallets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBXplorer;
using NBXplorer.DerivationStrategy;
using NBXplorer.Models;
using PayoutData = BTCPayServer.Data.PayoutData;
using PayoutProcessorData = BTCPayServer.Data.PayoutProcessorData;

namespace BTCPayServer.Plugins.TeeSigner;

/// <summary>
/// The automated payout processor for a COLD store wallet: builds the payout PSBT through
/// NBXplorer (full previous transactions and origin hints included, as the enclave requires),
/// sends it to signerd, broadcasts what comes back, and records the proof exactly as the stock
/// processor does. It never holds a key. It refuses a hot wallet outright.
/// </summary>
public class TeePayoutProcessor : BaseAutomatedPayoutProcessor<OnChainAutomatedPayoutBlob>
{
    private readonly ExplorerClientProvider _explorerClientProvider;
    private readonly BTCPayNetworkJsonSerializerSettings _serializer;
    private readonly BitcoinLikePayoutHandler _handler;
    private readonly TeeSignerClientFactory _clients;
    private readonly WalletRepository _walletRepository;
    private readonly ILogger _log;

    public BTCPayNetwork Network { get; }

    public TeePayoutProcessor(
        PayoutMethodId payoutMethodId,
        ApplicationDbContextFactory applicationDbContextFactory,
        ExplorerClientProvider explorerClientProvider,
        BTCPayNetworkJsonSerializerSettings serializer,
        ILoggerFactory logger,
        EventAggregator eventAggregator,
        WalletRepository walletRepository,
        StoreRepository storeRepository,
        PayoutProcessorData settings,
        PayoutMethodHandlerDictionary payoutHandlers,
        PaymentMethodHandlerDictionary handlers,
        IPluginHookService pluginHookService,
        TeeSignerClientFactory clients) :
        base(PaymentTypes.CHAIN.GetPaymentMethodId(((BitcoinLikePayoutHandler)payoutHandlers[payoutMethodId]).Network.CryptoCode),
            logger, storeRepository, settings, applicationDbContextFactory, handlers, pluginHookService, eventAggregator)
    {
        _explorerClientProvider = explorerClientProvider;
        _serializer = serializer;
        _handler = (BitcoinLikePayoutHandler)payoutHandlers[payoutMethodId];
        Network = _handler.Network;
        _clients = clients;
        _walletRepository = walletRepository;
        _log = logger.CreateLogger("TeeSigner");
    }

    protected override async Task Process(object paymentMethodConfig, List<PayoutData> payouts)
    {
        if (paymentMethodConfig is not DerivationSchemeSettings config)
            return;
        // gate (a): the plugin itself refuses a hot wallet — the seed must be in the enclave, nowhere else
        if (config.IsHotWallet)
        {
            _log.LogError("tee-signer: store {Store} wallet is flagged HOT; refusing to process payouts. Re-import the enclave xpub as a cold wallet.", PayoutProcessorSettings.StoreId);
            return;
        }
        if (!_explorerClientProvider.IsAvailable(Network.CryptoCode))
            return;
        var (client, settings) = await _clients.For(PayoutProcessorSettings.StoreId);
        if (client is null || settings is null)
        {
            _log.LogWarning("tee-signer: store {Store} has no signer configured", PayoutProcessorSettings.StoreId);
            return;
        }
        var blob = GetBlob(PayoutProcessorSettings);
        if (payouts.Sum(p => p.Amount) < blob.Threshold)
            return;

        var explorer = _explorerClientProvider.GetExplorerClient(Network.CryptoCode);
        var destinations = new List<(PayoutData payout, CreatePSBTDestination dest)>();
        foreach (var payout in payouts)
        {
            var pb = payout.GetBlob(_serializer);
            var (destination, error) = await _handler.ParseClaimDestination(pb.Destination, CancellationToken);
            if (!string.IsNullOrEmpty(error) || destination is not IBitcoinLikeClaimDestination bd)
            {
                pb.DisableProcessor(TeePayoutProcessorFactory.ProcessorName);
                payout.SetBlob(pb, _serializer);
                continue;
            }
            destinations.Add((payout, new CreatePSBTDestination
            {
                Destination = bd.Address,
                Amount = new Money(payout.Amount!.Value, MoneyUnit.BTC)
            }));
        }
        if (destinations.Count == 0)
            return;

        var request = new CreatePSBTRequest
        {
            Destinations = destinations.Select(d => d.dest).ToList(),
            FeePreference = new FeePreference { BlockTarget = Math.Max(blob.FeeTargetBlock, 1), FallbackFeeRate = new FeeRate((decimal)Math.Max(1, settings.FallbackFeeRateSatVb)) },
            ReserveChangeAddress = true,
            RBF = true,
            MinConfirmations = settings.MinConfirmations,
            AlwaysIncludeNonWitnessUTXO = true,            // I2: the enclave needs the full previous transaction
            RebaseKeyPaths = config.GetPSBTRebaseKeyRules().ToList() // origin hints with the master fingerprint (I1/I3)
        };
        PSBT psbt;
        try
        {
            psbt = (await explorer.CreatePSBTAsync(config.AccountDerivation, request, CancellationToken)).PSBT;
        }
        catch (NBXplorerException e)
        {
            _log.LogWarning("tee-signer: CreatePSBT failed: {Err}", e.Error?.Message);
            foreach (var (payout, _) in destinations)
            {
                var pb = payout.GetBlob(_serializer);
                if (pb.IncrementErrorCount() >= 10) pb.DisableProcessor(TeePayoutProcessorFactory.ProcessorName);
                payout.SetBlob(pb, _serializer);
            }
            return;
        }

        var result = await client.Sign(psbt.ToBase64(), CancellationToken);
        if (result.Refused is not null)
        {
            _log.LogWarning("tee-signer: enclave refused the payout batch: {Reasons}", string.Join(",", result.Refused.Reasons));
            foreach (var (payout, _) in destinations)
            {
                var pb = payout.GetBlob(_serializer);
                if (pb.IncrementErrorCount() >= 10) pb.DisableProcessor(TeePayoutProcessorFactory.ProcessorName);
                payout.SetBlob(pb, _serializer);
            }
            return;
        }
        var signed = PSBT.Parse(result.Ok!.Psbt, Network.NBitcoinNetwork);
        if (!signed.TryFinalize(out var errors))
        {
            _log.LogError("tee-signer: finalize failed: {Err}", string.Join(";", errors.Select(e => e.ToString())));
            return;
        }
        var tx = signed.ExtractTransaction();
        var txHash = tx.GetHash();
        var previousProofs = destinations.ToDictionary(d => d.payout.Id, d => d.payout.Proof);
        foreach (var (payout, _) in destinations)
        {
            payout.State = PayoutState.InProgress;
            _handler.SetProofBlob(payout, new PayoutTransactionOnChainBlob
            {
                Accounted = true,
                TransactionId = txHash,
                Candidates = new HashSet<uint256> { txHash }
            });
        }
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var broadcast = await explorer.BroadcastAsync(tx, cts.Token);
        if (!broadcast.Success)
        {
            _log.LogError("tee-signer: broadcast refused by the node: {Err}", broadcast.RPCMessage);
            foreach (var (payout, _) in destinations)
            {
                payout.State = PayoutState.AwaitingPayment;
                payout.Proof = previousProofs[payout.Id];
            }
            return;
        }
        var walletId = new WalletId(PayoutProcessorSettings.StoreId, Network.CryptoCode);
        foreach (var (payout, _) in destinations)
            await _walletRepository.AddWalletTransactionAttachment(walletId, txHash, Attachment.Payout(payout.PullPaymentDataId, payout.Id));
        _log.LogInformation("tee-signer: payout batch signed in the enclave (seq {Seq}, session {Session}) and broadcast as {Txid}", result.Ok.Seq, result.Ok.SessionId, txHash);
    }
}

public class TeePayoutProcessorFactory : IPayoutProcessorFactory
{
    private readonly PayoutMethodHandlerDictionary _handlers;
    private readonly IServiceProvider _sp;
    private readonly LinkGenerator _links;
    private readonly PayoutMethodId[] _supported;

    public TeePayoutProcessorFactory(PayoutMethodHandlerDictionary handlers, IServiceProvider sp, LinkGenerator links)
    {
        _handlers = handlers;
        _sp = sp;
        _links = links;
        _supported = handlers.OfType<BitcoinLikePayoutHandler>().Select(h => h.PayoutMethodId).ToArray();
    }

    public static string ProcessorName => "TeeSignerPayoutProcessor";
    public string Processor => ProcessorName;
    public string FriendlyName => "TEE signer (policy-bound, cold wallet)";

    public string ConfigureLink(string storeId, PayoutMethodId payoutMethodId, HttpRequest request)
        => _links.GetUriByAction("Settings", "UITeeSigner", new { storeId }, request.Scheme, request.Host, request.PathBase) ?? "";

    public IEnumerable<PayoutMethodId> GetSupportedPayoutMethods() => _supported;

    public Task<IHostedService> ConstructProcessor(PayoutProcessorData settings)
    {
        if (settings.Processor != Processor)
            throw new NotSupportedException("This processor cannot handle the provided requirements");
        var pm = settings.GetPayoutMethodId();
        if (!_handlers.TryGetValue(pm, out _))
            return Task.FromResult<IHostedService>(null!);
        return Task.FromResult<IHostedService>(ActivatorUtilities.CreateInstance<TeePayoutProcessor>(_sp, settings, pm));
    }
}
