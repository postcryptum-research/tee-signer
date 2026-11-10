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
    private readonly DelayedTransactionBroadcaster _broadcaster;
    private readonly ILogger _log;

    /// <summary>Refusals that clear by themselves (a window rolls over, the owner unfreezes or arms,
    /// the header feed catches up). They never count towards disabling the processor for a payout:
    /// retrying costs nothing (no signature is produced), and disabling would strand a legitimate
    /// payout queued at the end of a window — the T2 stall of 2026-11-10.</summary>
    private static readonly HashSet<string> TransientReasons = new()
    {
        "CAP_WINDOW", "CAP_UNLISTED_WINDOW", "CAP_TRUSTED_WINDOW", "FEE_WINDOW",
        "FROZEN", "NOT_ARMED", "CHAIN_STALE", "CHAIN_REORG",
        "FRESHNESS_MISSING", "FRESHNESS_SIG", "FRESHNESS_TIP", "FRESHNESS_SEQ_BEHIND", "SEQ_BEHIND_SESSION",
    };

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
        DelayedTransactionBroadcaster broadcaster,
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
        _broadcaster = broadcaster;
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

        // C-R3-4 (defense-in-depth to D-R3-1): the signer must hold THIS store's wallet. A signerd
        // with another seed could not produce a valid signature for the store's inputs anyway; this
        // names the misconfiguration before any PSBT is built instead of leaving it to the enclave's refusal.
        TeeSignerClient.StatusJson status;
        try { status = await client.Status(CancellationToken); }
        catch (Exception e)
        {
            _log.LogWarning("tee-signer: signerd status unavailable: {Err}", e.Message);
            return;
        }
        var walletScheme = config.AccountDerivation?.ToString();
        var walletFp = TeeSignerClient.WalletFingerprint(config);
        if (!TeeSignerClient.XpubMatches(status, walletScheme, walletFp))
        {
            _log.LogError("tee-signer: the signer's xpub {SignerXpub} / fingerprint {SignerFp} does not match the store wallet {Wallet} / {WalletFp}; refusing to process payouts (C-R3-4)", status.Xpub, status.Fingerprint, walletScheme, walletFp);
            return;
        }

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

        // Fee rate: the node's estimate for the target (the store's fallback when the node has none),
        // floored at 1 sat/vB. On a quiet signet the estimate equals the node's own minimum relay fee
        // (0.1 sat/vB) and the rounded transaction fee then falls one satoshi short at broadcast
        // ("min relay fee not met, 20 < 21", T1 2026-11-10). The mandate's maxFeeRate stays the
        // ceiling: the enclave refuses anything above it.
        var fallback = new FeeRate((decimal)Math.Max(1, settings.FallbackFeeRateSatVb));
        FeeRate feeRate;
        try { feeRate = (await explorer.GetFeeRateAsync(Math.Max(blob.FeeTargetBlock, 1), fallback, CancellationToken)).FeeRate; }
        catch (Exception) { feeRate = fallback; }
        if (feeRate.SatoshiPerByte < 1m)
            feeRate = new FeeRate(1m);
        var request = new CreatePSBTRequest
        {
            Destinations = destinations.Select(d => d.dest).ToList(),
            FeePreference = new FeePreference { ExplicitFeeRate = feeRate },
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
            // Transient by nature (deposits not yet confirmed, an empty wallet, NBXplorer behind):
            // counted, never disabling. Ten such minutes used to switch this processor off for the
            // payout for good — the T2 stall of 2026-11-10, where the faucet deposit confirmed on the
            // 11th minute and the payout then waited forever.
            _log.LogWarning("tee-signer: CreatePSBT failed: {Err} (will retry)", e.Error?.Message);
            foreach (var (payout, _) in destinations)
            {
                var pb = payout.GetBlob(_serializer);
                pb.IncrementErrorCount();
                payout.SetBlob(pb, _serializer);
            }
            return;
        }

        var result = await client.Sign(psbt.ToBase64(), CancellationToken);
        if (result.Refused is not null)
        {
            var transient = result.Refused.Reasons.Count > 0 && result.Refused.Reasons.All(TransientReasons.Contains);
            _log.LogWarning("tee-signer: enclave refused the payout batch: {Reasons}{Note}", string.Join(",", result.Refused.Reasons), transient ? " (transient, will retry)" : "");
            if (!transient)
            {
                foreach (var (payout, _) in destinations)
                {
                    var pb = payout.GetBlob(_serializer);
                    if (pb.IncrementErrorCount() >= 10) pb.DisableProcessor(TeePayoutProcessorFactory.ProcessorName);
                    payout.SetBlob(pb, _serializer);
                }
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
            // The enclave has signed and charged the mandate's window for THIS transaction, so the
            // payout is never handed back to be signed again (every retry used to cost one more
            // signature — three in three minutes on T1, 2026-11-10). It stays InProgress with the
            // txid as its proof, and BTCPay's delayed broadcaster retries the same transaction
            // (persisted in PlannedTransactions) until the node takes it.
            _log.LogError("tee-signer: broadcast refused by the node: {Err}; {Txid} (enclave seq {Seq}) is scheduled for rebroadcast, the payout stays InProgress", broadcast.RPCMessage, txHash, result.Ok.Seq);
            await _broadcaster.Schedule(DateTimeOffset.UtcNow, tx, Network);
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
