# RateMyWAF

Find every Azure Web Application Firewall in a tenant, grade each one **A to F**, and see exactly which change lifts the grade.

RateMyWAF is a read-only Blazor Server app with two separate flows, one per product:

| Flow | What it rates |
|---|---|
| **Front Door WAFs** | Classic, Standard and Premium Front Doors. Coverage is rated per endpoint and custom domain against the WAF security policies that actually cover them. |
| **Application Gateway WAFs** | Application Gateways of any tier. Coverage is rated per HTTP listener (gateway-level policy, per-listener policy or the legacy inline WAF configuration). Non-WAF tiers are called out. |

Each flow is three steps: **Scope** (tenant and subscriptions) → **Grades** (A–F per resource, findings with fixes, policy inventory, Word reports) → **Logs** (WAF log analysis with false-positive / real-attack assessment and fix scripts).

## Scoring model

The scoring model is the WAFFLOW model, applied unchanged to both products: 100 points across six weighted categories, mapped to a letter, with hard caps.

| Category | Points | What earns it |
|---|---|---|
| WAF coverage & state | 30 | An enabled WAF policy on every endpoint / domain / listener (pro-rated) |
| Prevention mode | 20 | Linked policies blocking rather than only logging (pro-rated) |
| Managed rule protection | 20 | Default rule set 10 · on the latest version 5 · Bot Manager rule set 5 |
| Logging & monitoring | 15 | WAF diagnostic logs enabled 10 · flowing to Log Analytics 5 |
| Tuning hygiene | 10 | Deductions for disabled managed rules, action overrides and exclusions |
| Hardening extras | 5 | Rate-limit rule 2 · geo/IP rule 1 · request body inspection 2 |

Grade bands: **A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 45 · **E** ≥ 30 · **F** below.

Caps: no enabled WAF → **F** · any endpoint, domain or listener without a WAF → at most **D** (no WAF is worse than a detection-only WAF) · detection-only → at most **C** · no managed rule set → at most **C** · WAF logging off → at most **B**.

Every improvement is listed with the points it gains and the grade it would produce, so the biggest win is always visible.

## Running it

Prerequisites: .NET 10 SDK, Azure CLI, and a signed-in account with Reader access to the subscriptions you want to scan.

```powershell
az login                       # optionally: az login --tenant <tenant-id>
cd src/RateMyWaf
dotnet run
```

Open <http://localhost:5210>. Pick a flow, choose the subscriptions (only those containing that product are highlighted), scan, and read the grades.

No Azure access? Click **Try with sample data** on the home page. Both flows then run on a realistic built-in estate that covers every grade band, without calling Azure.

### Authentication

The app uses `AzureCliCredential` by default. To run it somewhere without the Azure CLI (App Service, a container with a managed identity), set `Azure:Credential` to `Default` in `appsettings.json` or as the environment variable `Azure__Credential=Default` to use `DefaultAzureCredential`.

The credential needs **Reader** on the subscriptions and, for the Logs step, **Log Analytics Reader** on the workspace the WAF logs land in.

### What the scan reads

Everything is read-only, through Azure Resource Graph and ARM `GET` calls:

- Front Doors (classic and CDN profiles with a Front Door SKU), their endpoints, custom domains and security policies
- Application Gateways, listeners, URL path rules and legacy inline WAF configuration
- WAF policies: state, mode, managed rule sets and overrides, exclusions, custom rules, associations
- The latest available managed rule set versions per product
- Diagnostic settings (which WAF log categories are enabled and where they go)
- For the Logs step: a resource-scoped Log Analytics query over `AzureDiagnostics` / `FrontDoorWebApplicationFirewallLog` / `AGWFirewallLogs`

RateMyWAF never modifies a resource. The fix scripts it generates are PowerShell you review and run yourself.

## Tests

```powershell
dotnet test
```

The suite covers the rating engine (the Front Door cases are the WAFFLOW reference cases and must keep producing identical scores), Application Gateway rating, JSON parsing of every Azure shape, findings, log classification, fix scripts, Word/HTML reports, the sample estate, and the Blazor components (bUnit).

## Project layout

```
src/RateMyWaf/
  Components/Pages       Home, FrontDoorPage, AppGatewayPage
  Components/Shared      WafFlow (wizard), ScopeStep, GradesStep, LogsStep, modals, badges
  Services/
    WafRatingService     The A–F engine (shared by both products)
    WafDiscoveryService  Resource Graph / ARM discovery, coverage, versions, diagnostics
    WafFindingsBuilder   Findings with remediation guidance
    WafLogAnalysisService  KQL queries, classification, changes vs previous period
    WafReportService     Summary and detailed-findings reports (docx + HTML preview)
    FixScriptService     PowerShell remediation scripts per product
    DemoDataService      The sample estate
tests/RateMyWaf.Tests    xUnit + bUnit
```

### Browser walkthrough

`tests/e2e/walkthrough.mjs` drives the running app in headless Chromium through both flows on sample data (scan, grades, findings, policy detail, reports, log analysis, fix scripts, reload, dark theme, mobile) and fails on any browser error:

```powershell
dotnet run --project src/RateMyWaf        # in one terminal
cd tests/e2e; npm install; npx playwright install chromium; npm test
```

Set `PW_EXE` to a Chromium executable to use an existing browser instead of the one Playwright downloads.
