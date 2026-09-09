using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using RateMyWaf.Components;
using RateMyWaf.Services;
using RateMyWaf.Services.Azure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

builder.Services.AddResponseCompression(opts =>
{
    opts.EnableForHttps = true;
    opts.Providers.Add<BrotliCompressionProvider>();
    opts.Providers.Add<GzipCompressionProvider>();
});

// Credential: Azure CLI (az login) by default; set Azure:Credential to "Default" for DefaultAzureCredential
// (managed identity / environment / VS / CLI chain) when hosting the app somewhere other than a workstation.
builder.Services.AddSingleton<TokenCredential>(sp =>
{
    var mode = builder.Configuration["Azure:Credential"] ?? "Cli";
    return mode.Equals("Default", StringComparison.OrdinalIgnoreCase)
        ? new DefaultAzureCredential(new DefaultAzureCredentialOptions { ExcludeInteractiveBrowserCredential = true })
        : new AzureCliCredential();
});

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddSignalR(options =>
{
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(180);
    options.MaximumReceiveMessageSize = 512 * 1024;
});

builder.Services.AddSingleton<IAzureApi, AzureApi>();
builder.Services.AddSingleton<WafDiscoveryService>();
builder.Services.AddSingleton<WafLogAnalysisService>();
builder.Services.AddScoped<AzureSubscriptionService>();
builder.Services.AddScoped<SessionState>();
builder.Services.AddScoped<WafFlowService>();

var app = builder.Build();

app.UseResponseCompression();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseStaticFiles();
app.UseAntiforgery();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();
