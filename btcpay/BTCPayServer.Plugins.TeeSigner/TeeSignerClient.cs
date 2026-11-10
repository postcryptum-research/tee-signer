using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BTCPayServer.Plugins.TeeSigner;

/// <summary>HTTP client for signerd (host/signerd). Three calls: status, sign, receipts.</summary>
public class TeeSignerClient
{
    private readonly HttpClient _http;
    private readonly string _base;

    public TeeSignerClient(HttpClient http, TeeSignerSettings s)
    {
        _http = http;
        _base = s.SignerdUrl.TrimEnd('/');
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", s.Token);
        _http.Timeout = TimeSpan.FromSeconds(60);
    }

    public class StatusJson
    {
        [JsonPropertyName("enclave")] public string? Enclave { get; set; }
        [JsonPropertyName("initialised")] public bool Initialised { get; set; }
        [JsonPropertyName("installed")] public bool Installed { get; set; }
        [JsonPropertyName("tier")] public string? Tier { get; set; }
        [JsonPropertyName("mrenclave")] public string? Mrenclave { get; set; }
        [JsonPropertyName("session_id")] public string? SessionId { get; set; }
        [JsonPropertyName("network")] public int Network { get; set; }
        [JsonPropertyName("xpub")] public string? Xpub { get; set; }
        [JsonPropertyName("fingerprint")] public string? Fingerprint { get; set; }
        [JsonPropertyName("identity_pk")] public string? IdentityPk { get; set; }
        [JsonPropertyName("nonce")] public ulong Nonce { get; set; }
        [JsonPropertyName("seq")] public ulong Seq { get; set; }
        [JsonPropertyName("frozen")] public bool Frozen { get; set; }
        [JsonPropertyName("armed")] public bool Armed { get; set; }
        /// <summary>R7: false after every start of the enclave until the owner signs an `arm` for this start;
        /// the enclave signs nothing meanwhile. Absent (null) on a pre-R7 build.</summary>
        [JsonPropertyName("boot_armed")] public bool? BootArmed { get; set; }
        /// <summary>R7: this start's 32-byte challenge the owner's `arm` must name (hex).</summary>
        [JsonPropertyName("boot_challenge")] public string? BootChallenge { get; set; }
        /// <summary>R7: true only on the operator's opt-out build (AUTO_ARM=1): no pause after a restart.</summary>
        [JsonPropertyName("auto_arm")] public bool? AutoArm { get; set; }
        [JsonPropertyName("chain_frozen")] public bool ChainFrozen { get; set; }
        [JsonPropertyName("best_height")] public uint BestHeight { get; set; }
        [JsonPropertyName("window_start")] public uint WindowStart { get; set; }
        [JsonPropertyName("window_outflow")] public ulong WindowOutflow { get; set; }
        [JsonPropertyName("window_unlisted")] public ulong WindowUnlisted { get; set; }
        [JsonPropertyName("window_fees")] public ulong WindowFees { get; set; }
        [JsonPropertyName("mandate_hash")] public string? MandateHash { get; set; }
        [JsonPropertyName("clock_label")] public string? ClockLabel { get; set; }
    }

    public class SignOk
    {
        [JsonPropertyName("psbt")] public string Psbt { get; set; } = "";
        [JsonPropertyName("receipt_hex")] public string ReceiptHex { get; set; } = "";
        [JsonPropertyName("receipt_sig_hex")] public string ReceiptSigHex { get; set; } = "";
        [JsonPropertyName("session_id")] public string SessionId { get; set; } = "";
        [JsonPropertyName("seq")] public ulong Seq { get; set; }
        [JsonPropertyName("txid")] public string Txid { get; set; } = "";
    }

    public class SignRefused
    {
        [JsonPropertyName("error")] public string Error { get; set; } = "";
        [JsonPropertyName("reasons")] public List<string> Reasons { get; set; } = new();
    }

    public record SignResult(SignOk? Ok, SignRefused? Refused);

    /// <summary>C-R3-4: the enclave's account xpub must be the store's wallet. NBXplorer's scheme
    /// string is the base58 xpub (P2WPKH in v1), possibly followed by a suffix; compare by prefix.</summary>
    public static bool XpubMatches(StatusJson? status, string? walletScheme, string? walletFingerprint = null)
        => status?.Xpub is not null && walletScheme is not null
           && walletScheme.StartsWith(status.Xpub, StringComparison.Ordinal)
           && (walletFingerprint is null || status.Fingerprint is null
               || string.Equals(walletFingerprint, status.Fingerprint, StringComparison.OrdinalIgnoreCase));

    /// <summary>The store wallet's master fingerprint as imported (`[fp/84'/coin'/0']xpub`), or null.</summary>
    public static string? WalletFingerprint(BTCPayServer.DerivationSchemeSettings scheme)
    {
        try { return scheme.GetSigningAccountKeySettings()?.RootFingerprint?.ToString(); }
        catch { return null; }
    }

    public async Task<StatusJson> Status(CancellationToken ct = default)
    {
        var r = await _http.GetAsync($"{_base}/v1/status", ct);
        r.EnsureSuccessStatusCode();
        return JsonSerializer.Deserialize<StatusJson>(await r.Content.ReadAsStringAsync(ct))!;
    }

    /// <summary>JUDGE + SIGN in the enclave; a refusal comes back as 422 with the stable reasons.</summary>
    public async Task<SignResult> Sign(string psbtBase64, CancellationToken ct = default)
    {
        var payload = JsonSerializer.Serialize(new { psbt = psbtBase64 });
        using var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
        var r = await _http.PostAsync($"{_base}/v1/sign", content, ct);
        var body = await r.Content.ReadAsStringAsync(ct);
        if (r.IsSuccessStatusCode)
            return new SignResult(JsonSerializer.Deserialize<SignOk>(body), null);
        if ((int)r.StatusCode == 422)
            return new SignResult(null, JsonSerializer.Deserialize<SignRefused>(body) ?? new SignRefused { Error = body });
        throw new HttpRequestException($"signerd /v1/sign: {(int)r.StatusCode} {body}");
    }

    public async Task<string> ReceiptsRaw(CancellationToken ct = default)
    {
        var r = await _http.GetAsync($"{_base}/v1/receipts", ct);
        r.EnsureSuccessStatusCode();
        return await r.Content.ReadAsStringAsync(ct);
    }
}

public class TeeSignerClientFactory
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly TeeSignerSettingsStore _store;
    public TeeSignerClientFactory(IHttpClientFactory httpFactory, TeeSignerSettingsStore store)
    {
        _httpFactory = httpFactory;
        _store = store;
    }
    public async Task<(TeeSignerClient? client, TeeSignerSettings? settings)> For(string storeId)
    {
        var s = await _store.Get(storeId);
        if (s is null || string.IsNullOrWhiteSpace(s.SignerdUrl)) return (null, null);
        return (new TeeSignerClient(_httpFactory.CreateClient("tee-signer"), s), s);
    }
}
