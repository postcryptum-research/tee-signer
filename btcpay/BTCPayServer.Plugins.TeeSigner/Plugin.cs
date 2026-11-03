using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Abstractions.Models;
using BTCPayServer.PayoutProcessors;
using Microsoft.Extensions.DependencyInjection;

namespace BTCPayServer.Plugins.TeeSigner;

/// <summary>
/// tee-signer for BTCPay Server. Untrusted by design (docs/DESIGN.md §9): it can only ROUTE a
/// PSBT to the signer daemon and read its status; it never sees a key, and a malicious copy of
/// it stays bound by the enclave's mandate. It refuses to operate on a hot wallet, so the four
/// in-process signing paths of BTCPay stay structurally off (IsHotWallet=false).
/// </summary>
public class Plugin : BaseBTCPayServerPlugin
{
    public const string Area = "TeeSigner";
    public const string ViewsDirectory = "/Plugins/" + Area + "/Views";

    public override IBTCPayServerPlugin.PluginDependency[] Dependencies { get; } =
    {
        new IBTCPayServerPlugin.PluginDependency { Identifier = nameof(BTCPayServer), Condition = ">=2.4.7" }
    };

    public override void Execute(IServiceCollection services)
    {
        services.AddSingleton<TeeSignerSettingsStore>();
        services.AddSingleton<TeeSignerClientFactory>();
        services.AddSingleton<TeePayoutProcessorFactory>();
        services.AddSingleton<IPayoutProcessorFactory>(p => p.GetRequiredService<TeePayoutProcessorFactory>());
        services.AddUIExtension("onchain-wallet-send", $"{ViewsDirectory}/SendAction.cshtml");
        services.AddUIExtension("store-onchain-wallet-setup", $"{ViewsDirectory}/WalletSetupNote.cshtml");
    }
}
