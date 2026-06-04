<#
.SYNOPSIS
Wrapper script that reads environment variables or config.json and invokes the Intune Master Report generator.
#>
param(
    [string]$ConfigPath,
    [string]$OutputBasePath
)

# Priority 1: Environment Variables (from Node.js)
if ($env:REPORT_TENANT_ID -and $env:REPORT_CLIENT_ID -and $env:REPORT_CLIENT_SECRET) {
    $script:TenantId     = $env:REPORT_TENANT_ID
    $script:ClientId     = $env:REPORT_CLIENT_ID
    $script:ClientSecret = $env:REPORT_CLIENT_SECRET
    $script:BaseOutputPath = $env:REPORT_OUTPUT_PATH
    $script:LogoPath       = $env:REPORT_LOGO_PATH
} 
# Priority 2: Config File
elseif ($ConfigPath -and (Test-Path $ConfigPath)) {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    $script:TenantId     = $config.TenantId
    $script:ClientId     = $config.ClientId
    $script:ClientSecret = $config.ClientSecret
    $script:BaseOutputPath = $OutputBasePath
    if (-not [string]::IsNullOrWhiteSpace($config.LogoPath)) {
        $script:LogoPath = $config.LogoPath
    }
}
else {
    Write-Error "No credentials provided via environment variables or config file."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($script:TenantId) -or
    [string]::IsNullOrWhiteSpace($script:ClientId) -or
    [string]::IsNullOrWhiteSpace($script:ClientSecret)) {
    Write-Error "TenantId, ClientId, and ClientSecret must be provided."
    exit 1
}

# Find the main dashboard script in multiple possible locations
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SearchPaths = @(
    (Join-Path $ScriptDir "intune-report.ps1"),
    "C:\Users\Admin\Desktop\EndUserRepo\intune-report.ps1"
)

$MainScript = $null
foreach ($p in $SearchPaths) {
    if (Test-Path $p) { $MainScript = $p; break }
}

if (-not $MainScript) {
    Write-Error "Main script not found. Searched: $($SearchPaths -join ', ')"
    exit 1
}

. $MainScript
