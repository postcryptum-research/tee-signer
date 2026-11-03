using BTCPayServer.Abstractions.Contracts;

namespace BTCPayServer.Plugins.TeeSigner;

/// <summary>Per-store connection to the signer daemon. The token is a rate-limit credential, not
/// an authorisation (the mandate binds every signature); still kept out of logs.</summary>
public class TeeSignerSettings
{
    public string SignerdUrl { get; set; } = "http://tee-signer:7390";
    public string Token { get; set; } = "";
    /// <summary>Minimum confirmations for coins the payout processor may spend (0 for tests).</summary>
    public int MinConfirmations { get; set; } = 1;
}

public class TeeSignerSettingsStore
{
    private readonly ISettingsRepository _settings;
    public TeeSignerSettingsStore(ISettingsRepository settings) => _settings = settings;
    private static string Key(string storeId) => $"TeeSigner:{storeId}";
    public Task<TeeSignerSettings?> Get(string storeId) => _settings.GetSettingAsync<TeeSignerSettings>(Key(storeId));
    public Task Set(string storeId, TeeSignerSettings s) => _settings.UpdateSetting(s, Key(storeId));
}
