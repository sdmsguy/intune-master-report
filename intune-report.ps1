<#
.SYNOPSIS
Intune Master Report by SDMSGUY - Cloud Analysis Dashboard

.DESCRIPTION
The complete Cloud Analysis of your End user environment.
READ-ONLY. Uses Microsoft Graph + Defender for Endpoint APIs.

REQUIRED APPLICATION PERMISSIONS
Microsoft Graph: AuditLog.Read.All, Device.Read.All, DeviceManagementApps.Read.All,
DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All,
DeviceManagementServiceConfig.Read.All, Directory.Read.All, Domain.Read.All,
Group.Read.All, IdentityRiskEvent.Read.All, IdentityRiskyUser.Read.All,
LicenseAssignment.Read.All, MailboxSettings.Read, Organization.Read.All,
Policy.Read.All, PrivilegedAccess.Read.AzureAD, PrivilegedAccess.Read.AzureResources,
Reports.Read.All, SecurityAlert.Read.All, SecurityEvents.Read.All,
ThreatAssessment.Read.All, User.Read.All

WindowsDefenderATP: Alert.Read.All, Machine.Read.All, Score.Read.All,
Software.Read.All, Vulnerability.Read.All
#>

# =============================
# CONFIGURATION - UPDATE THESE
# =============================
# Respect environment variables if provided by the web runner
if ($env:REPORT_TENANT_ID)     { $TenantId = $env:REPORT_TENANT_ID }
else { $TenantId = "" }

if ($env:REPORT_CLIENT_ID)     { $ClientId = $env:REPORT_CLIENT_ID }
else { $ClientId = "" }

if ($env:REPORT_CLIENT_SECRET) { $ClientSecret = $env:REPORT_CLIENT_SECRET }
else { $ClientSecret = "" }

if ($env:REPORT_LOGO_PATH)     { $LogoPath = $env:REPORT_LOGO_PATH }
else { $LogoPath = "" }

if ($env:REPORT_OUTPUT_PATH)   { $BaseOutputPath = $env:REPORT_OUTPUT_PATH }
else { $BaseOutputPath = "C:\Temp\1234Report123" }

$Stale7Days  = 7
$Stale30Days = 30
$EntraStaleDays = 90
$CriticalVulnerabilitySeverity = @("Critical")
$HighVulnerabilitySeverity = @("High")
$PatchHealthySyncDays = 14
$PatchAttentionSyncDays = 30

# =============================
# SAFETY GUARDRAILS
# =============================
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
# If REPORT_OUTPUT_PATH is set, we use it directly as the destination
if ($env:REPORT_OUTPUT_PATH) {
    $OutputPath = $BaseOutputPath
} else {
    $OutputPath = Join-Path $BaseOutputPath $Timestamp
}
$LogFile    = Join-Path $OutputPath "Execution.log"
$HtmlPath   = Join-Path $OutputPath "Intune_Master_Report_Dashboard.html"
$PdfPath    = Join-Path $OutputPath "Intune_Master_Report_Dashboard.pdf"

New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Add-Type -AssemblyName System.Web

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message,[ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Assert-Config {
    if ([string]::IsNullOrWhiteSpace($TenantId) -or $TenantId -like "PASTE-*") { throw "Update TenantId before running." }
    if ([string]::IsNullOrWhiteSpace($ClientId) -or $ClientId -like "PASTE-*") { throw "Update ClientId before running." }
    if ([string]::IsNullOrWhiteSpace($ClientSecret) -or $ClientSecret -like "PASTE-*") { throw "Update ClientSecret before running." }
}

function HtmlEncode { param([object]$Value); if ($null -eq $Value) { return "" }; return [System.Web.HttpUtility]::HtmlEncode([string]$Value) }
function SafePercent { param([int]$Part,[int]$Total); if ($Total -le 0) { return 0 }; return [math]::Round(($Part / $Total) * 100, 1) }
function Format-DateSafe { param([object]$Value); if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return "Not available" }; try { return ([datetime]$Value).ToString("dd MMM yyyy HH:mm") } catch { return [string]$Value } }
function DaysSince { param([object]$Value); if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }; try { return [math]::Round(((Get-Date) - [datetime]$Value).TotalDays, 0) } catch { return $null } }

function Get-OsReleaseLabel {
    param([string]$OperatingSystem,[string]$OsVersion)
    if ([string]::IsNullOrWhiteSpace($OperatingSystem)) { return "Unknown" }
    if ($OperatingSystem -notmatch "Windows") { return $OperatingSystem }
    if ([string]::IsNullOrWhiteSpace($OsVersion)) { return "Windows - version unknown" }
    $build = 0
    $parts = $OsVersion.Split(".")
    if ($parts.Count -ge 3) { [void][int]::TryParse($parts[2], [ref]$build) }
    if ($build -ge 26200) { return "Windows 11 25H2" }
    elseif ($build -ge 26100) { return "Windows 11 24H2" }
    elseif ($build -ge 22631) { return "Windows 11 23H2" }
    elseif ($build -ge 22621) { return "Windows 11 22H2" }
    elseif ($build -ge 22000) { return "Windows 11 21H2" }
    elseif ($build -ge 19045) { return "Windows 10 22H2" }
    elseif ($build -ge 19044) { return "Windows 10 21H2" }
    elseif ($build -gt 0) { return "Windows Build $build" }
    else { return "Windows $OsVersion" }
}

function Get-OsEditionLabel {
    param([object]$Device)
    if ($null -eq $Device) { return "Unknown" }
    $platform = [string]$Device.operatingSystem
    if ($platform -notmatch "Windows") {
        if ($platform -match "iOS|iPad|Android|Mac") { return "Not applicable" }
        return "Unknown"
    }
    $candidates = @()
    foreach ($name in @("skuFamily","windowsSkuFamily","windowsEditionType","operatingSystemEdition","edition")) {
        if ($Device.PSObject.Properties.Name -contains $name -and -not [string]::IsNullOrWhiteSpace([string]$Device.$name)) { $candidates += [string]$Device.$name }
    }
    if ($Device.PSObject.Properties.Name -contains "hardwareInformation" -and $Device.hardwareInformation) {
        foreach ($name in @("operatingSystemEdition","productName")) {
            if ($Device.hardwareInformation.PSObject.Properties.Name -contains $name -and -not [string]::IsNullOrWhiteSpace([string]$Device.hardwareInformation.$name)) { $candidates += [string]$Device.hardwareInformation.$name }
        }
    }
    $raw = ($candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($raw)) { return "Unknown" }
    switch -Regex ($raw) {
        "Enterprise" { return "Enterprise" }
        "Professional|\bPro\b" { return "Pro" }
        "Home" { return "Home" }
        "Education" { return "Education" }
        "Business" { return "Business" }
        default { return $raw }
    }
}

function Get-EditionRiskLabel {
    param([string]$Edition,[string]$Platform)
    if ($Platform -notmatch "Windows") { return "Not applicable" }
    switch -Regex ($Edition) {
        "Home" { return "Not supported for business MDM" }
        "Pro|Enterprise|Education|Business" { return "Supported" }
        default { return "Needs validation" }
    }
}

function Get-PlatformLabel {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "Unknown" }
    switch -Regex ($Value) {
        "Windows" { return "Windows" }
        "iOS|iPad" { return "iOS/iPadOS" }
        "Android" { return "Android" }
        "Mac" { return "macOS" }
        default { return $Value }
    }
}

function Get-HealthBand {
    param([int]$Score)
    if ($Score -ge 85) { return @{Label="Strong"; Class="good"} }
    elseif ($Score -ge 65) { return @{Label="Moderate"; Class="warn"} }
    else { return @{Label="Needs attention"; Class="bad"} }
}

function Get-AccessToken {
    param([Parameter(Mandatory=$true)][string]$ResourceScope)
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{ client_id = $ClientId; client_secret = $ClientSecret; scope = $ResourceScope; grant_type = "client_credentials" }
    $response = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    return $response.access_token
}

function Invoke-ReadOnlyRest {
    param([Parameter(Mandatory=$true)]$Uri,[Parameter(Mandatory=$true)]$Headers,[string]$Label = "API call")
    try { return Invoke-RestMethod -Method Get -Uri ([string]$Uri) -Headers $Headers -ContentType "application/json" -ErrorAction Stop }
    catch { Write-Log "$Label failed: $($_.Exception.Message)" "WARN"; return $null }
}

function Invoke-PagedGet {
    param([Parameter(Mandatory=$true)]$Uri,[Parameter(Mandatory=$true)]$Headers,[string]$Label = "Paged API call")
    $all = @()
    $next = [string]$Uri
    do {
        $result = Invoke-ReadOnlyRest -Uri $next -Headers $Headers -Label $Label
        if ($null -eq $result) { break }
        if ($null -ne $result.value) { foreach ($item in @($result.value)) { $all += $item } }
        elseif ($result -is [array]) { foreach ($item in $result) { $all += $item } }
        else { $all += $result }
        $next = $null
        if ($result.PSObject.Properties.Name -contains '@odata.nextLink') { $next = [string]$result.'@odata.nextLink' }
    } while (![string]::IsNullOrWhiteSpace($next))
    return @($all)
}

function ConvertTo-DataTableHtml {
    param([array]$Data,[string[]]$Columns,[hashtable]$Headers,[string]$EmptyMessage = "No records found.")
    if ($null -eq $Data -or $Data.Count -eq 0) { return "<div class='empty'>$EmptyMessage</div>" }
    $html = "<div class='table-wrap'><table><thead><tr>"
    foreach ($col in $Columns) { if ($Headers.ContainsKey($col)) { $title = $Headers[$col] } else { $title = $col }; $html += "<th>$(HtmlEncode $title)</th>" }
    $html += "</tr></thead><tbody>"
    foreach ($row in $Data) { $html += "<tr>"; foreach ($col in $Columns) { $value = $row.$col; $html += "<td>$(HtmlEncode $value)</td>" }; $html += "</tr>" }
    $html += "</tbody></table></div>"
    return $html
}

function New-Card {
    param([string]$Title,[string]$Value,[string]$SubText,[string]$Class="neutral")
    return "<div class='kpi $Class'><div class='kpi-title'>$(HtmlEncode $Title)</div><div class='kpi-value'>$(HtmlEncode $Value)</div><div class='kpi-sub'>$(HtmlEncode $SubText)</div></div>"
}

function New-Bar {
    param([int]$Percent,[string]$Class="good")
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    return "<div class='bar'><div class='bar-fill $Class' style='width:$Percent%'></div></div>"
}

function ConvertTo-Donut {
    param([int]$Percent,[string]$Label,[string]$Class="good")
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    return "<div class='donut-wrap'><div class='donut $Class' style='--p:$Percent'><div class='donut-inner'><strong>$Percent%</strong></div></div><div class='donut-label'>$(HtmlEncode $Label)</div></div>"
}

function Export-DataCsv {
    param([array]$Data,[string]$Name)
    $path = Join-Path $OutputPath $Name
    try { @($Data) | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 } catch { Write-Log "CSV export failed for $Name : $($_.Exception.Message)" "WARN" }
}

function Try-ExportPdf {
    param([string]$HtmlFile,[string]$PdfFile)
    $browserCandidates = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )
    $browser = $browserCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $browser) { Write-Log "PDF export skipped. Edge/Chrome not found." "WARN"; return $false }
    try {
        $fileUri = (New-Object System.Uri($HtmlFile)).AbsoluteUri
        $args = @("--headless", "--disable-gpu", "--print-to-pdf=$PdfFile", $fileUri)
        Start-Process -FilePath $browser -ArgumentList $args -Wait -WindowStyle Hidden
        if (Test-Path $PdfFile) { Write-Log "PDF generated: $PdfFile" "SUCCESS"; return $true }
        return $false
    } catch { Write-Log "PDF export failed: $($_.Exception.Message)" "WARN"; return $false }
}

# =============================
# START
# =============================
Write-Log "Intune Master Report cloud analysis started."
Assert-Config

Write-Log "Acquiring Microsoft Graph token."
$GraphToken = Get-AccessToken -ResourceScope "https://graph.microsoft.com/.default"
$GraphHeaders = @{ Authorization = "Bearer $GraphToken"; ConsistencyLevel = "eventual" }

Write-Log "Acquiring Microsoft Defender for Endpoint token."
$DefenderToken = $null
$DefenderHeaders = $null
try {
    $DefenderToken = Get-AccessToken -ResourceScope "https://api.securitycenter.microsoft.com/.default"
    $DefenderHeaders = @{ Authorization = "Bearer $DefenderToken" }
} catch { Write-Log "Defender token acquisition failed. $($_.Exception.Message)" "WARN" }

$GraphBase = "https://graph.microsoft.com"

Write-Log "Collecting tenant metadata."
$OrgData = Invoke-ReadOnlyRest -Uri "$GraphBase/v1.0/organization" -Headers $GraphHeaders -Label "Organization"
$Organization = @($OrgData.value | Select-Object -First 1)
if ($Organization.displayName) { $TenantName = $Organization.displayName } else { $TenantName = "Customer Tenant" }
if ($Organization.verifiedDomains) { $TenantDefaultDomain = (@($Organization.verifiedDomains) | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1).name } else { $TenantDefaultDomain = "Not available" }
if (-not $TenantDefaultDomain) { $TenantDefaultDomain = "Not available" }

Write-Log "Collecting users."
$Users = Invoke-PagedGet -Uri "$GraphBase/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime&`$top=999" -Headers $GraphHeaders -Label "Users"
$EnabledUsers = @($Users | Where-Object { $_.accountEnabled -eq $true })
$GuestUsers   = @($Users | Where-Object { $_.userType -eq "Guest" })

Write-Log "Collecting Microsoft Entra devices."
$Devices = Invoke-PagedGet -Uri "$GraphBase/v1.0/devices?`$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,accountEnabled,approximateLastSignInDateTime&`$top=999" -Headers $GraphHeaders -Label "Entra devices"

Write-Log "Collecting Intune managed devices."
$ManagedDevices = Invoke-PagedGet -Uri "$GraphBase/beta/deviceManagement/managedDevices?`$select=id,azureADDeviceId,deviceName,userPrincipalName,manufacturer,model,serialNumber,operatingSystem,osVersion,skuFamily,joinType,complianceState,managementAgent,enrolledDateTime,lastSyncDateTime,isEncrypted,deviceEnrollmentType,jailBroken,partnerReportedThreatState&`$top=999" -Headers $GraphHeaders -Label "Intune managed devices"

Write-Log "Collecting Conditional Access policies."
$ConditionalAccessPolicies = Invoke-PagedGet -Uri "$GraphBase/v1.0/identity/conditionalAccess/policies?`$top=999" -Headers $GraphHeaders -Label "CA policies"

Write-Log "Collecting Windows update and configuration policies."
$DeviceConfigurations = Invoke-PagedGet -Uri "$GraphBase/beta/deviceManagement/deviceConfigurations?`$select=id,displayName,description&`$top=999" -Headers $GraphHeaders -Label "Device configurations"
$SettingsCatalogPolicies = Invoke-PagedGet -Uri "$GraphBase/beta/deviceManagement/configurationPolicies?`$top=999" -Headers $GraphHeaders -Label "Settings catalog policies"
$FeatureUpdateProfiles = Invoke-PagedGet -Uri "$GraphBase/beta/deviceManagement/windowsFeatureUpdateProfiles?`$top=999" -Headers $GraphHeaders -Label "Feature update profiles"
$QualityUpdateProfiles = Invoke-PagedGet -Uri "$GraphBase/beta/deviceManagement/windowsQualityUpdateProfiles?`$top=999" -Headers $GraphHeaders -Label "Quality update profiles"

Write-Log "Collecting Identity Protection risky users."
$RiskyUsers = Invoke-PagedGet -Uri "$GraphBase/beta/identityProtection/riskyUsers?`$top=999" -Headers $GraphHeaders -Label "Risky users"

Write-Log "Collecting Microsoft Secure Score."
$SecureScores = Invoke-PagedGet -Uri "$GraphBase/v1.0/security/secureScores?`$top=1" -Headers $GraphHeaders -Label "Secure Score"
$LatestSecureScore = @($SecureScores | Sort-Object createdDateTime -Descending | Select-Object -First 1)

Write-Log "Collecting MFA registration details."
$MFARegistrations = @()
try { $MFARegistrations = Invoke-PagedGet -Uri "$GraphBase/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=999" -Headers $GraphHeaders -Label "MFA registrations" } catch { Write-Log "MFA registration data unavailable." "WARN" }

$AppControlPolicies = @($DeviceConfigurations | Where-Object { $_.displayName -match "WDAC|AppLocker|Application.Control|Allowlist|Allow.List|AppGuard" })
$AppControlSC = @($SettingsCatalogPolicies | Where-Object { $_.name -match "WDAC|AppLocker|Application.Control|Allowlist" })
$MacroPolicies = @($DeviceConfigurations | Where-Object { $_.displayName -match "Macro|Office.Hardening|Office.Restriction" })
$MacroPoliciesSC = @($SettingsCatalogPolicies | Where-Object { $_.name -match "Macro|Office.Hardening" })
$BrowserHardeningPolicies = @($DeviceConfigurations | Where-Object { $_.displayName -match "Browser|Hardening|Edge.Security|USB|Clipboard" })
$BrowserHardeningSC = @($SettingsCatalogPolicies | Where-Object { $_.name -match "Browser|Hardening|Edge|USB|Clipboard" })

$GlobalAdmins = @()
try {
    $gaResp = Invoke-ReadOnlyRest -Uri "$GraphBase/v1.0/directoryRoles?`$filter=displayName eq 'Global Administrator'" -Headers $GraphHeaders -Label "Global Admin role"
    if ($gaResp -and @($gaResp.value).Count -gt 0) {
        $gaRoleId = @($gaResp.value)[0].id
        $gaMembers = Invoke-PagedGet -Uri "$GraphBase/v1.0/directoryRoles/$gaRoleId/members" -Headers $GraphHeaders -Label "Global Admin members"
        $GlobalAdmins = @($gaMembers | Where-Object { $_.accountEnabled -ne $false })
    }
} catch { Write-Log "Global Admin membership unavailable." "WARN" }

$PIMEnabled = $false
$PIMAssignments = @()
try {
    $PIMAssignments = Invoke-PagedGet -Uri "$GraphBase/beta/roleManagement/directory/roleEligibilitySchedules?`$top=50" -Headers $GraphHeaders -Label "PIM schedules"
    if ($PIMAssignments.Count -gt 0) { $PIMEnabled = $true }
} catch { Write-Log "PIM data unavailable." "WARN" }

$SecureScoreControls = @()
try { $SecureScoreControls = Invoke-PagedGet -Uri "$GraphBase/v1.0/security/secureScoreControlProfiles?`$top=999" -Headers $GraphHeaders -Label "Secure Score controls" } catch { Write-Log "Secure Score controls unavailable." "WARN" }

function Get-SSControlStatus {
    param([string[]]$Keywords)
    foreach ($kw in $Keywords) {
        $match = @($SecureScoreControls | Where-Object { $_.title -match $kw -or $_.id -match $kw })
        if ($match.Count -gt 0) { return $true }
    }
    return $false
}
$SSHasSafeLinks       = Get-SSControlStatus @("SafeLinks","Safe Links","safeLinks")
$SSHasSafeAttachments = Get-SSControlStatus @("SafeAttachments","Safe Attachments","safeAttachments")
$SSHasAntiPhishing    = Get-SSControlStatus @("AntiPhish","anti-phish","phishing")
$SSHasDLP             = Get-SSControlStatus @("DLP","DataLossPrevention","data loss")
$SSHasAuditLog        = Get-SSControlStatus @("AuditLog","audit log","auditLog")

Write-Log "Collecting OneDrive usage report."
$OneDriveUsers = @()
$OneDriveActiveUsers = 0
$OneDriveTotalStorageGB = 0
$OneDriveUsedStorageGB  = 0
try {
    $ouRaw = Invoke-ReadOnlyRest -Uri "$GraphBase/v1.0/reports/getOneDriveUsageAccountDetail(period='D30')" -Headers $GraphHeaders -Label "OneDrive usage"
    if ($ouRaw) {
        $ouLines = ($ouRaw -split "`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($ouLines.Count -gt 1) {
            $OneDriveUsers = $ouLines | ConvertFrom-Csv | Where-Object { $_.'Is Deleted' -eq 'False' -and -not [string]::IsNullOrWhiteSpace($_.'Owner Principal Name') }
            $OneDriveActiveUsers = @($OneDriveUsers | Where-Object { -not [string]::IsNullOrWhiteSpace($_.'Last Activity Date') }).Count
            $totalBytes = ($OneDriveUsers | ForEach-Object { $v = 0; [void][long]::TryParse($_.'Storage Used (Byte)', [ref]$v); $v } | Measure-Object -Sum).Sum
            $allocBytes = ($OneDriveUsers | ForEach-Object { $v = 0; [void][long]::TryParse($_.'Storage Allocated (Byte)', [ref]$v); $v } | Measure-Object -Sum).Sum
            $OneDriveUsedStorageGB  = [math]::Round($totalBytes / 1GB, 1)
            $OneDriveTotalStorageGB = [math]::Round($allocBytes / 1GB, 1)
        }
    }
} catch { Write-Log "OneDrive usage report unavailable." "WARN" }

$BackupCompliancePolicies = @($DeviceConfigurations | Where-Object { $_.displayName -match "Backup|OneDrive|KFM|Known.Folder" })
$BackupSCPolicies = @($SettingsCatalogPolicies | Where-Object { $_.name -match "Backup|OneDrive|KFM|Known.Folder" })
$BackupPolicyCount = $BackupCompliancePolicies.Count + $BackupSCPolicies.Count

$KFMDeployedSignal = $false
if ($EnabledUsers.Count -gt 0 -and $OneDriveUsers.Count -gt 0) {
    if (($OneDriveUsers.Count / $EnabledUsers.Count) -ge 0.5) { $KFMDeployedSignal = $true }
}

$AttackSimulations = @()
try { $AttackSimulations = Invoke-PagedGet -Uri "$GraphBase/beta/security/attackSimulation/simulations?`$top=20" -Headers $GraphHeaders -Label "Attack simulations" } catch { Write-Log "Attack simulation data unavailable." "WARN" }
$AttackSimCount      = $AttackSimulations.Count
$AttackSimCompleted  = @($AttackSimulations | Where-Object { $_.status -eq "Succeeded" -or $_.status -eq "Completed" }).Count

$DefenderO365Alerts = @()
try { $DefenderO365Alerts = Invoke-PagedGet -Uri "$GraphBase/v1.0/security/alerts_v2?`$top=50&`$filter=serviceSource eq 'microsoftDefenderForOffice365'" -Headers $GraphHeaders -Label "Defender O365 alerts" } catch { Write-Log "O365 alerts unavailable." "WARN" }
$O365AlertsActive = @($DefenderO365Alerts | Where-Object { $_.status -ne "resolved" }).Count

$SharedMailboxes = @()
try { $SharedMailboxes = Invoke-PagedGet -Uri "$GraphBase/v1.0/users?`$filter=mailboxSettings/userPurpose eq 'shared'&`$select=id,displayName,userPrincipalName,accountEnabled&`$top=999" -Headers $GraphHeaders -Label "Shared mailboxes" } catch { Write-Log "Shared mailbox query unavailable." "WARN" }

$SensitivityLabels = @()
try { $SensitivityLabels = Invoke-PagedGet -Uri "$GraphBase/beta/security/informationProtection/sensitivityLabels" -Headers $GraphHeaders -Label "Sensitivity labels" } catch { Write-Log "Sensitivity labels unavailable." "WARN" }
$SensitivityLabelCount = $SensitivityLabels.Count

$DefenderMachines = @()
$DefenderAlerts = @()
$DefenderVulnerabilities = @()
$DefenderSoftware = @()
if ($DefenderHeaders) {
    $DefenderMachines = Invoke-PagedGet -Uri "https://api.securitycenter.microsoft.com/api/machines" -Headers $DefenderHeaders -Label "Defender machines"
    $DefenderAlerts = Invoke-PagedGet -Uri "https://api.securitycenter.microsoft.com/api/alerts" -Headers $DefenderHeaders -Label "Defender alerts"
    $DefenderVulnerabilities = Invoke-PagedGet -Uri "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities?`$top=1000" -Headers $DefenderHeaders -Label "Defender vulnerabilities"
    $DefenderSoftware = Invoke-PagedGet -Uri "https://api.securitycenter.microsoft.com/api/software?`$top=200" -Headers $DefenderHeaders -Label "Defender software"
}

# =============================
# NORMALIZATION
# =============================
$Now = Get-Date

$UpdatePolicyDetails = @(
    @($DeviceConfigurations | Where-Object { $_.displayName -match "Update|WUfB|Windows Update|Feature|Quality|Autopatch|Patch" } | Select-Object @{Name="PolicyName";Expression={$_.displayName}}, @{Name="PolicyType";Expression={"Device Configuration"}}, @{Name="Description";Expression={$_.description}})
    @($SettingsCatalogPolicies | Where-Object { $_.name -match "Update|WUfB|Windows Update|Feature|Quality|Autopatch|Patch" } | Select-Object @{Name="PolicyName";Expression={$_.name}}, @{Name="PolicyType";Expression={"Settings Catalog"}}, @{Name="Description";Expression={$_.description}})
    @($FeatureUpdateProfiles | Select-Object @{Name="PolicyName";Expression={$_.displayName}}, @{Name="PolicyType";Expression={"Feature Update Profile"}}, @{Name="Description";Expression={$_.description}})
    @($QualityUpdateProfiles | Select-Object @{Name="PolicyName";Expression={$_.displayName}}, @{Name="PolicyType";Expression={"Quality Update Profile"}}, @{Name="Description";Expression={$_.description}})
)

$MFAEnabled = @($MFARegistrations | Where-Object { $_.isMfaRegistered -eq $true })
$MFACapable = @($MFARegistrations | Where-Object { $_.isMfaCapable   -eq $true })
$MFANotReg  = @($MFARegistrations | Where-Object { $_.isMfaRegistered -eq $false -and $_.userType -ne "Guest" })
if ($MFARegistrations.Count -gt 0) { $MFACoveragePercent = [math]::Round(($MFAEnabled.Count / $MFARegistrations.Count) * 100) } else { $MFACoveragePercent = 0 }
$MFADataAvailable = $MFARegistrations.Count -gt 0

$CompliantManagedDevices = @($ManagedDevices | Where-Object { $_.complianceState -eq "compliant" })
$NonCompliantManagedDevices = @($ManagedDevices | Where-Object { $_.complianceState -eq "noncompliant" })
$InGraceManagedDevices = @($ManagedDevices | Where-Object { $_.complianceState -eq "inGracePeriod" })

$EncryptedManagedDevices = @($ManagedDevices | Where-Object { $_.isEncrypted -eq $true })
$NotEncryptedManagedDevices = @($ManagedDevices | Where-Object { $_.isEncrypted -eq $false })

$ActiveManagedDevices7Days = @($ManagedDevices | Where-Object { $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime -ge $Now.AddDays(-$Stale7Days)) })
$DevicesNotSynced7Days = @($ManagedDevices | Where-Object { -not $_.lastSyncDateTime -or ([datetime]$_.lastSyncDateTime -lt $Now.AddDays(-$Stale7Days)) })
$DevicesNotSynced30Days = @($ManagedDevices | Where-Object { -not $_.lastSyncDateTime -or ([datetime]$_.lastSyncDateTime -lt $Now.AddDays(-$Stale30Days)) })

$EntraStale90 = @($Devices | Where-Object { -not $_.approximateLastSignInDateTime -or ([datetime]$_.approximateLastSignInDateTime -lt $Now.AddDays(-$EntraStaleDays)) })

$WindowsManaged = @($ManagedDevices | Where-Object { $_.operatingSystem -match "Windows" })

$ManagedCoveragePercent = SafePercent -Part $ManagedDevices.Count -Total $Devices.Count
$CompliancePercent = SafePercent -Part $CompliantManagedDevices.Count -Total $ManagedDevices.Count
$EncryptionPercent = SafePercent -Part $EncryptedManagedDevices.Count -Total $ManagedDevices.Count
$ActiveSyncPercent = SafePercent -Part $ActiveManagedDevices7Days.Count -Total $ManagedDevices.Count

$ManagedAzureIds = @($ManagedDevices | ForEach-Object { if ($_.azureADDeviceId) { $_.azureADDeviceId.ToString().ToLower() } })
$DefenderMapped = @()
if ($DefenderMachines.Count -gt 0 -and $ManagedAzureIds.Count -gt 0) {
    $DefenderMapped = @($DefenderMachines | Where-Object {
        $aad = $null
        if ($_.aadDeviceId) { $aad = $_.aadDeviceId.ToString().ToLower() } elseif ($_.azureAdDeviceId) { $aad = $_.azureAdDeviceId.ToString().ToLower() }
        $aad -and ($ManagedAzureIds -contains $aad)
    })
}
$DefenderCoveragePercent = SafePercent -Part $DefenderMapped.Count -Total $ManagedDevices.Count

$ActiveDefenderAlerts = @($DefenderAlerts | Where-Object { $_.status -notin @("Resolved","InProgress") })
$HighDefenderAlerts = @($DefenderAlerts | Where-Object { $_.severity -in @("High","Critical") })

$HighRiskUsers = @($RiskyUsers | Where-Object { $_.riskLevel -eq "high" -and $_.riskState -ne "remediated" })
$RiskyUsersActive = @($RiskyUsers | Where-Object { $_.riskState -ne "remediated" })

$CAPoliciesEnabled = @($ConditionalAccessPolicies | Where-Object { $_.state -eq "enabled" })
$CAPoliciesReportOnly = @($ConditionalAccessPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })

$SecureScorePercent = 0
if ($LatestSecureScore -and $LatestSecureScore.currentScore -and $LatestSecureScore.maxScore) {
    $SecureScorePercent = SafePercent -Part ([int]$LatestSecureScore.currentScore) -Total ([int]$LatestSecureScore.maxScore)
}

$HealthScore = [math]::Round((
    ($CompliancePercent * 0.25) + ($EncryptionPercent * 0.20) + ($ActiveSyncPercent * 0.20) +
    ($ManagedCoveragePercent * 0.15) + ($DefenderCoveragePercent * 0.10) +
    ($(if ($RiskyUsersActive.Count -eq 0) { 100 } else { 60 }) * 0.05) +
    ($(if ($CAPoliciesEnabled.Count -gt 0) { 100 } else { 50 }) * 0.05)
),0)
$HealthBand = Get-HealthBand -Score $HealthScore

$ManagedDeviceDetails = @($ManagedDevices | Select-Object `
    @{Name="DeviceName";Expression={$_.deviceName}},
    @{Name="AssignedUser";Expression={$_.userPrincipalName}},
    @{Name="Make";Expression={$_.manufacturer}},
    @{Name="Model";Expression={$_.model}},
    @{Name="SerialNumber";Expression={$_.serialNumber}},
    @{Name="Platform";Expression={Get-PlatformLabel $_.operatingSystem}},
    @{Name="OSRelease";Expression={Get-OsReleaseLabel $_.operatingSystem $_.osVersion}},
    @{Name="OSVersion";Expression={$_.osVersion}},
    @{Name="OSEdition";Expression={Get-OsEditionLabel $_}},
    @{Name="EditionRisk";Expression={Get-EditionRiskLabel -Edition (Get-OsEditionLabel $_) -Platform (Get-PlatformLabel $_.operatingSystem)}},
    @{Name="JoinType";Expression={if ($_.joinType) {$_.joinType} else {$_.deviceEnrollmentType}}},
    @{Name="Compliance";Expression={$_.complianceState}},
    @{Name="Encrypted";Expression={if ($_.isEncrypted -eq $true) {"Yes"} elseif ($_.isEncrypted -eq $false) {"No"} else {"Unknown"}}},
    @{Name="ThreatState";Expression={$_.partnerReportedThreatState}},
    @{Name="LastSync";Expression={Format-DateSafe $_.lastSyncDateTime}},
    @{Name="DaysSinceSync";Expression={DaysSince $_.lastSyncDateTime}}
)

$Stale7Details = @($ManagedDeviceDetails | Where-Object { $_.DaysSinceSync -eq $null -or $_.DaysSinceSync -gt $Stale7Days })
$Stale30Details = @($ManagedDeviceDetails | Where-Object { $_.DaysSinceSync -eq $null -or $_.DaysSinceSync -gt $Stale30Days })
$NotEncryptedDetails = @($ManagedDeviceDetails | Where-Object { $_.Encrypted -eq "No" -or $_.Encrypted -eq "Unknown" })
$NonCompliantDetails = @($ManagedDeviceDetails | Where-Object { $_.Compliance -ne "compliant" })
$WindowsHomeDetails = @($ManagedDeviceDetails | Where-Object { $_.Platform -eq "Windows" -and $_.OSEdition -eq "Home" })
$EditionUnknownDetails = @($ManagedDeviceDetails | Where-Object { $_.Platform -eq "Windows" -and ($_.OSEdition -eq "Unknown" -or [string]::IsNullOrWhiteSpace($_.OSEdition)) })

$EntraStaleDetails = @($EntraStale90 | Select-Object `
    @{Name="DeviceName";Expression={$_.displayName}},
    @{Name="Platform";Expression={$_.operatingSystem}},
    @{Name="TrustType";Expression={$_.trustType}},
    @{Name="Enabled";Expression={if ($_.accountEnabled -eq $true) {"Yes"} else {"No"}}},
    @{Name="LastSignIn";Expression={Format-DateSafe $_.approximateLastSignInDateTime}},
    @{Name="DaysInactive";Expression={DaysSince $_.approximateLastSignInDateTime}},
    @{Name="RecommendedAction";Expression={
        $d = DaysSince $_.approximateLastSignInDateTime
        if ($null -eq $d) { "DISABLE - No sign-in recorded" }
        elseif ($d -gt 180) { "DELETE - Inactive $d days" }
        else { "DISABLE - Inactive $d days" }
    }}
)

$EntraStale180Count = @($EntraStale90 | Where-Object { $d = DaysSince $_.approximateLastSignInDateTime; ($null -eq $d) -or ($d -gt 180) }).Count
$EntraDisableCount = $EntraStale90.Count - $EntraStale180Count

if ($EntraStale90.Count -gt 0) {
    $EntraStaleBanner = "<div style='background:#fef2f2;border:2px solid #fecaca;border-radius:14px;padding:20px 22px;margin-bottom:18px'><div style='font-size:16px;font-weight:800;color:#991b1b;margin-bottom:12px'>&#9888;&#65039; Action Required - $($EntraStale90.Count) Unused Device Record(s) Found</div><div style='font-size:13.5px;color:#7f1d1d;line-height:1.8;margin-bottom:14px'>Your Entra ID directory contains <b>$($EntraStale90.Count) device record(s)</b> not signed in for <b>90+ days</b>.<br><br><b>$EntraDisableCount device(s) should be disabled</b> (90-180 days) &nbsp;|&nbsp; <b>$EntraStale180Count device(s) should be deleted</b> (180+ days)</div></div>"
    $EntraCleanupSteps = "<div style='background:#f0f9ff;border:1px solid #bae6fd;border-radius:12px;padding:16px 18px;margin-bottom:14px'><div style='font-size:13px;font-weight:700;color:#0369a1;margin-bottom:10px'>Recommended Cleanup Steps</div><div style='font-size:12.5px;color:#0c4a6e;line-height:1.8'><b>Step 1 - Review:</b> Confirm each stale device with your team before action.<br><b>Step 2 - Disable:</b> Devices inactive 90-180 days will be disabled (reversible).<br><b>Step 3 - Delete:</b> After 30 days, if still not needed, permanently delete.<br><b>Step 4 - Confirm:</b> Before/after report provided.</div></div>"
} else {
    $EntraStaleBanner  = "<div style='background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:16px 18px;margin-bottom:14px;color:#166534;font-size:13.5px'>&#9989; <b>All clear.</b> All Entra devices signed in within 90 days.</div>"
    $EntraCleanupSteps = ""
}

$RiskyUserDetails = @($RiskyUsersActive | Select-Object `
    @{Name="User";Expression={$_.userDisplayName}},
    @{Name="UPN";Expression={$_.userPrincipalName}},
    @{Name="RiskLevel";Expression={$_.riskLevel}},
    @{Name="RiskState";Expression={$_.riskState}},
    @{Name="RiskDetail";Expression={$_.riskDetail}}
)

$DefenderMachineDetails = @($DefenderMapped | Select-Object `
    @{Name="DeviceName";Expression={$_.computerDnsName}},
    @{Name="HealthStatus";Expression={$_.healthStatus}},
    @{Name="RiskScore";Expression={$_.riskScore}},
    @{Name="ExposureLevel";Expression={$_.exposureLevel}},
    @{Name="OSPlatform";Expression={$_.osPlatform}},
    @{Name="Version";Expression={$_.version}},
    @{Name="LastSeen";Expression={Format-DateSafe $_.lastSeen}}
)

$DefenderAlertDetails = @($DefenderAlerts | Sort-Object lastUpdateTime -Descending | Select-Object -First 100 `
    @{Name="Title";Expression={$_.title}},
    @{Name="Severity";Expression={$_.severity}},
    @{Name="Status";Expression={$_.status}},
    @{Name="Category";Expression={$_.category}},
    @{Name="DeviceName";Expression={$_.computerDnsName}},
    @{Name="LastUpdate";Expression={Format-DateSafe $_.lastUpdateTime}}
)

$VulnerabilityDetails = @($DefenderVulnerabilities | Select-Object -First 500 `
    @{Name="DeviceId";Expression={$_.machineId}},
    @{Name="CveId";Expression={$_.cveId}},
    @{Name="Severity";Expression={$_.severity}},
    @{Name="Product";Expression={$_.productName}},
    @{Name="Vendor";Expression={$_.productVendor}},
    @{Name="Version";Expression={$_.productVersion}},
    @{Name="FixingKb";Expression={$_.fixingKbId}}
)

$CriticalVulnCount = @($VulnerabilityDetails | Where-Object { $_.Severity -eq "Critical" }).Count
$HighVulnCount     = @($VulnerabilityDetails | Where-Object { $_.Severity -eq "High" }).Count
$MediumVulnCount   = @($VulnerabilityDetails | Where-Object { $_.Severity -eq "Medium" }).Count
$LowVulnCount      = @($VulnerabilityDetails | Where-Object { $_.Severity -eq "Low" }).Count

# Patch health
$DefenderMachineByAad = @{}
$DefenderMachineByName = @{}
$VulnByMachine = @{}
foreach ($m in @($DefenderMachines)) {
    $aad = $null
    if ($m.aadDeviceId) { $aad = [string]$m.aadDeviceId } elseif ($m.azureAdDeviceId) { $aad = [string]$m.azureAdDeviceId }
    if (-not [string]::IsNullOrWhiteSpace($aad)) { $DefenderMachineByAad[$aad.ToLower()] = $m }
    if (-not [string]::IsNullOrWhiteSpace([string]$m.computerDnsName)) { $DefenderMachineByName[[string]$m.computerDnsName.ToLower()] = $m }
}
foreach ($v in @($DefenderVulnerabilities | Where-Object { ([string]$_.productName).ToLower() -match "windows|edge|chrome|office|defender|teams|microsoft" })) {
    $mid = [string]$v.machineId
    if ([string]::IsNullOrWhiteSpace($mid)) { continue }
    if (-not $VulnByMachine.ContainsKey($mid)) { $VulnByMachine[$mid] = New-Object System.Collections.Generic.List[object] }
    $VulnByMachine[$mid].Add($v)
}

$PatchDetailsList = New-Object System.Collections.Generic.List[object]
foreach ($d in @($ManagedDevices | Where-Object { $_.operatingSystem -match "Windows" })) {
    $dm = $null
    if ($d.azureADDeviceId -and $DefenderMachineByAad.ContainsKey(([string]$d.azureADDeviceId).ToLower())) { $dm = $DefenderMachineByAad[([string]$d.azureADDeviceId).ToLower()] }
    elseif ($d.deviceName -and $DefenderMachineByName.ContainsKey(([string]$d.deviceName).ToLower())) { $dm = $DefenderMachineByName[([string]$d.deviceName).ToLower()] }
    $machineVulns = @()
    $defenderSeen = $false
    if ($dm -and $dm.id) {
        $defenderSeen = $true
        $dmIdStr = "$($dm.id)"
        if ($VulnByMachine.ContainsKey($dmIdStr)) { try { $machineVulns = $VulnByMachine[$dmIdStr].ToArray() } catch { $machineVulns = @() } }
    }
    $crit = @($machineVulns | Where-Object { $_.severity -eq "Critical" }).Count
    $high = @($machineVulns | Where-Object { $_.severity -eq "High" }).Count
    $med  = @($machineVulns | Where-Object { $_.severity -eq "Medium" }).Count
    $osRelease = Get-OsReleaseLabel $d.operatingSystem $d.osVersion
    $days = DaysSince $d.lastSyncDateTime
    $signals = New-Object System.Collections.Generic.List[string]

    # Lifecycle status (informational only - separate from patch status)
    $featureStatus = "Current / Supported"
    if ($osRelease -match "Windows 10") { $featureStatus = "Upgrade to Windows 11 Recommended" }
    elseif ($osRelease -match "Windows 11 21H2") { $featureStatus = "Feature Update Recommended (end of servicing)" }
    elseif ($osRelease -match "version unknown") { $featureStatus = "Validate OS Version" }

    # ===== PATCH STATUS LOGIC (rewritten) =====
    # A device is "Healthy" if it's actively syncing and has no critical patch backlog.
    # OS feature release (e.g. Win10 22H2 vs Win11 24H2) is a LIFECYCLE concern, not a patch concern -
    # those releases still receive security updates and are correctly patched if syncing recently.
    $status = "Healthy"

    if ($days -eq $null) {
        # No sync data at all - we genuinely don't know patch state
        $status = "Monitor"
        $signals.Add("No sync data available")
    }
    elseif ($days -gt $PatchAttentionSyncDays) {
        # Not synced in 30+ days - cannot confirm patching
        $status = "Needs Attention"
        $signals.Add("Not reported in $days days - cannot verify patch state")
    }
    elseif ($crit -ge 3) {
        # Multiple critical vulns - real patch backlog
        $status = "Needs Attention"
        $signals.Add("$crit critical vulnerability finding(s) detected")
    }
    elseif ($days -gt $PatchHealthySyncDays) {
        # 14-30 days since sync - watch but not urgent
        $status = "Monitor"
        $signals.Add("Last reported $days days ago")
    }
    elseif ($crit -gt 0) {
        $status = "Monitor"
        $signals.Add("$crit critical finding(s) - review at next patch cycle")
    }
    elseif ($high -ge 10) {
        # Significant high-severity backlog
        $status = "Monitor"
        $signals.Add("$high high-severity finding(s) detected")
    }

    # Add positive signals when healthy
    if ($status -eq "Healthy") {
        if ($defenderSeen -and $machineVulns.Count -eq 0) { $signals.Add("Defender reports no outstanding vulnerabilities") }
        elseif ($defenderSeen) { $signals.Add("Patched - $($machineVulns.Count) low/medium finding(s) within normal range") }
        else { $signals.Add("Syncing within $PatchHealthySyncDays days - patch policies applying") }
    }

    # Lifecycle note appended separately - informational, doesn't downgrade patch status
    if ($featureStatus -ne "Current / Supported") { $signals.Add("Lifecycle: $featureStatus") }

    if ($signals.Count -eq 0) { $signals.Add("No patch concerns identified") }

    $PatchDetailsList.Add([pscustomobject]@{ DeviceName=$d.deviceName; AssignedUser=$d.userPrincipalName; Make=$d.manufacturer; Model=$d.model; OSRelease=$osRelease; OSVersion=$d.osVersion; OSEdition=(Get-OsEditionLabel $d); FeatureStatus=$featureStatus; PatchStatus=$status; CriticalUpdateFindings=$crit; HighUpdateFindings=$high; MediumUpdateFindings=$med; LastSync=(Format-DateSafe $d.lastSyncDateTime); DaysSinceSync=$days; UpdateSignal=($signals -join "; ") })
}
$PatchDetails = @($PatchDetailsList.ToArray())
$PatchHealthy = @($PatchDetails | Where-Object { $_.PatchStatus -eq "Healthy" })
$PatchMonitor = @($PatchDetails | Where-Object { $_.PatchStatus -eq "Monitor" })
$PatchAttention = @($PatchDetails | Where-Object { $_.PatchStatus -eq "Needs Attention" })

# ENTERPRISE PATCH SCORING FIX
# Do not show Patch Health as 0% when devices checked in yesterday.
# "Healthy" = no concerns; "Monitor" = actively reporting but has vulnerability signals to review.
# Only "Needs Attention" devices reduce patch health because patch state cannot be validated or has confirmed backlog.
# Vulnerability exposure remains visible separately in the Vulnerabilities section.
$PatchManagedOk = @($PatchDetails | Where-Object { $_.PatchStatus -in @("Healthy","Monitor") })
$PatchHealthPercent = SafePercent -Part $PatchManagedOk.Count -Total $PatchDetails.Count

$SoftwareDetails = @($DefenderSoftware | Select-Object -First 500 `
    @{Name="Vendor";Expression={$_.vendor}},
    @{Name="Software";Expression={$_.name}},
    @{Name="Version";Expression={$_.version}},
    @{Name="Weaknesses";Expression={$_.weaknesses}},
    @{Name="PublicExploit";Expression={$_.publicExploit}}
)

Export-DataCsv -Data $ManagedDeviceDetails -Name "All_Intune_Managed_Devices.csv"
Export-DataCsv -Data $NonCompliantDetails -Name "Non_Compliant_Devices.csv"
Export-DataCsv -Data $WindowsHomeDetails -Name "Windows_Home_Devices.csv"
Export-DataCsv -Data $EditionUnknownDetails -Name "Windows_Edition_Unknown_Devices.csv"
Export-DataCsv -Data $NotEncryptedDetails -Name "Encryption_Attention_Devices.csv"
Export-DataCsv -Data $Stale7Details -Name "Stale_Devices_7_Days.csv"
Export-DataCsv -Data $Stale30Details -Name "Stale_Devices_30_Days.csv"
Export-DataCsv -Data $EntraStaleDetails -Name "Entra_Stale_Devices_90_Days.csv"
Export-DataCsv -Data $RiskyUserDetails -Name "Risky_Users.csv"
Export-DataCsv -Data $DefenderMachineDetails -Name "Defender_Mapped_Devices.csv"
Export-DataCsv -Data $DefenderAlertDetails -Name "Defender_Alerts.csv"
Export-DataCsv -Data $VulnerabilityDetails -Name "Defender_Vulnerabilities.csv"
Export-DataCsv -Data $PatchDetails -Name "Windows_Patch_Update_Health.csv"
Export-DataCsv -Data $UpdatePolicyDetails -Name "Windows_Update_Policies.csv"
Export-DataCsv -Data $SoftwareDetails -Name "Defender_Software_Inventory.csv"


# =============================
# ACSC ESSENTIAL EIGHT ASSESSMENT
# =============================
function New-ACSCControl {
    param([string]$ID,[string]$Name,[string]$L1Status,[string]$L2Status,[string]$L3Status,[string]$L1Evidence,[string]$L2Evidence,[string]$L3Evidence,[string]$L1Gap,[string]$L2Gap,[string]$L3Gap)
    return [PSCustomObject]@{ ID=$ID; Name=$Name; L1Status=$L1Status; L2Status=$L2Status; L3Status=$L3Status; L1Evidence=$L1Evidence; L2Evidence=$L2Evidence; L3Evidence=$L3Evidence; L1Gap=$L1Gap; L2Gap=$L2Gap; L3Gap=$L3Gap }
}

$AC1_L1 = $AppControlPolicies.Count -gt 0 -or $AppControlSC.Count -gt 0
$AC1_L1Status = if ($AC1_L1) { "Detected" } else { "Not Detected" }
$AC1_L1Evidence = if ($AC1_L1) { "$($AppControlPolicies.Count + $AppControlSC.Count) application control policy/policies detected." } else { "No WDAC, AppLocker, or allowlist policy detected." }
$AC1_L1Gap = if ($AC1_L1) { "Validate policies are assigned to all device groups." } else { "Deploy WDAC or AppLocker via Intune." }
$AC1_L2 = $AC1_L1 -and $DefenderCoveragePercent -ge 80
$AC1_L2Status = if ($AC1_L2) { "Partial" } elseif ($AC1_L1) { "Partial" } else { "Not Detected" }
$AC1_L2Evidence = if ($AC1_L2) { "App control + Defender at $DefenderCoveragePercent%." } else { "Defender coverage $DefenderCoveragePercent% below 80% threshold." }
$AC1_L2Gap = "Confirm WDAC in enforcement mode (not audit). Validate via Defender compliance."
$AC1_L3 = $AC1_L2 -and $DefenderCoveragePercent -ge 95 -and $HighDefenderAlerts.Count -eq 0
$AC1_L3Status = if ($AC1_L3) { "Partial" } else { "Not Detected" }
$AC1_L3Evidence = if ($AC1_L3) { "Strong Defender coverage; no critical alerts." } else { "L3 requires 95%+ Defender + active SOC monitoring." }
$AC1_L3Gap = "Implement WDAC enforcement across 100% devices. Integrate violations with SIEM."
$E8_C1 = New-ACSCControl -ID "1" -Name "Application Control" -L1Status $AC1_L1Status -L2Status $AC1_L2Status -L3Status $AC1_L3Status -L1Evidence $AC1_L1Evidence -L2Evidence $AC1_L2Evidence -L3Evidence $AC1_L3Evidence -L1Gap $AC1_L1Gap -L2Gap $AC1_L2Gap -L3Gap $AC1_L3Gap

$AC2_L1 = $QualityUpdateProfiles.Count -gt 0 -or ($UpdatePolicyDetails.Count -gt 0)
$AC2_L1Status = if ($AC2_L1) { "Detected" } else { "Not Detected" }
$AC2_L1Evidence = if ($AC2_L1) { "$($QualityUpdateProfiles.Count) quality update profile(s). $($UpdatePolicyDetails.Count) update policies total." } else { "No update profiles detected." }
$AC2_L1Gap = if ($AC2_L1) { "Verify policies are assigned and monthly cadence is met." } else { "Create Intune WUfB rings, max 30-day deferral." }
$AC2_L2 = $AC2_L1 -and $PatchHealthPercent -ge 75
$AC2_L2Status = if ($AC2_L2) { "Detected" } elseif ($AC2_L1) { "Partial" } else { "Not Detected" }
$AC2_L2Evidence = if ($AC2_L2) { "Patch health $PatchHealthPercent%. 14-day patch window targeted." } elseif ($AC2_L1) { "Patch health $PatchHealthPercent% below 75%." } else { "No patch evidence." }
$AC2_L2Gap = "Configure 14-day max deferral for critical patches. Review $($PatchAttention.Count) attention devices."
$AC2_L3 = $AC2_L2 -and $PatchHealthPercent -ge 90
$AC2_L3Status = if ($AC2_L3) { "Detected" } elseif ($AC2_L2) { "Partial" } else { "Not Detected" }
$AC2_L3Evidence = if ($AC2_L3) { "Patch health $PatchHealthPercent%. Supports 48-hour critical patching." } else { "L3 requires 90%+ + automated enforcement." }
$AC2_L3Gap = "Automate patch enforcement. Configure Autopatch / zero-deferral WUfB."
$E8_C2 = New-ACSCControl -ID "2" -Name "Patch Applications" -L1Status $AC2_L1Status -L2Status $AC2_L2Status -L3Status $AC2_L3Status -L1Evidence $AC2_L1Evidence -L2Evidence $AC2_L2Evidence -L3Evidence $AC2_L3Evidence -L1Gap $AC2_L1Gap -L2Gap $AC2_L2Gap -L3Gap $AC2_L3Gap

$AC3_L1 = $MacroPolicies.Count -gt 0 -or $MacroPoliciesSC.Count -gt 0
$AC3_L1Status = if ($AC3_L1) { "Detected" } else { "Not Detected" }
$AC3_L1Evidence = if ($AC3_L1) { "$($MacroPolicies.Count + $MacroPoliciesSC.Count) macro/Office restriction policy/policies detected." } else { "No macro restriction policy detected." }
$AC3_L1Gap = if ($AC3_L1) { "Validate macro policy blocks internet macros, allows only signed macros." } else { "Deploy macro restriction policy: block internet macros; allow only signed/trusted." }
$AC3_L2Status = if ($AC3_L1) { "Partial" } else { "Not Detected" }
$AC3_L2Evidence = if ($AC3_L1) { "Macro signals detected. L2 needs enforcement across all Office apps." } else { "No macro policy detected." }
$AC3_L2Gap = "Extend to all Office apps. Validate via Intune compliance."
$AC3_L3Status = if ($AC3_L1 -and $CompliancePercent -ge 90) { "Partial" } else { "Not Detected" }
$AC3_L3Evidence = if ($AC3_L1 -and $CompliancePercent -ge 90) { "High compliance supports reach. L3 needs SOC alerting." } else { "L3 needs full enforcement + SIEM alerting." }
$AC3_L3Gap = "Integrate macro violations with SIEM. Implement signed macro catalogue."
$E8_C3 = New-ACSCControl -ID "3" -Name "Configure Microsoft Office Macros" -L1Status $AC3_L1Status -L2Status $AC3_L2Status -L3Status $AC3_L3Status -L1Evidence $AC3_L1Evidence -L2Evidence $AC3_L2Evidence -L3Evidence $AC3_L3Evidence -L1Gap $AC3_L1Gap -L2Gap $AC3_L2Gap -L3Gap $AC3_L3Gap

$AC4_L1 = $BrowserHardeningPolicies.Count -gt 0 -or $BrowserHardeningSC.Count -gt 0
$AC4_L1Status = if ($AC4_L1) { "Detected" } else { "Not Detected" }
$AC4_L1Evidence = if ($AC4_L1) { "$($BrowserHardeningPolicies.Count + $BrowserHardeningSC.Count) browser/app hardening policy/policies." } else { "No browser/app hardening policy detected." }
$AC4_L1Gap = if ($AC4_L1) { "Validate hardening disables Flash/Java, blocks risky sites." } else { "Deploy Edge security baseline: disable Flash/Java, enable SmartScreen." }
$AC4_L2Status = if ($AC4_L1) { "Partial" } else { "Not Detected" }
$AC4_L2Evidence = if ($AC4_L1) { "Hardening signals detected. L2 extends to DLP/USB." } else { "No hardening policy." }
$AC4_L2Gap = "Add DLP policies for USB and clipboard control."
$AC4_L3 = $AC4_L1 -and $BrowserHardeningPolicies.Count + $BrowserHardeningSC.Count -ge 3
$AC4_L3Status = if ($AC4_L3) { "Partial" } else { "Not Detected" }
$AC4_L3Evidence = if ($AC4_L3) { "Multiple hardening policies indicate layered approach." } else { "L3 needs USB DLP + SOC integration." }
$AC4_L3Gap = "Implement L3 USB/clipboard/browser hardening. Integrate with SIEM."
$E8_C4 = New-ACSCControl -ID "4" -Name "User Application Hardening" -L1Status $AC4_L1Status -L2Status $AC4_L2Status -L3Status $AC4_L3Status -L1Evidence $AC4_L1Evidence -L2Evidence $AC4_L2Evidence -L3Evidence $AC4_L3Evidence -L1Gap $AC4_L1Gap -L2Gap $AC4_L2Gap -L3Gap $AC4_L3Gap

$AC5_AdminOk = $GlobalAdmins.Count -gt 0 -and $GlobalAdmins.Count -le 5
$AC5_AdminWarn = $GlobalAdmins.Count -gt 5 -and $GlobalAdmins.Count -le 10
$AC5_AdminBad = $GlobalAdmins.Count -gt 10
$AC5_L1Status = if ($AC5_AdminOk) { "Detected" } elseif ($AC5_AdminWarn) { "Partial" } elseif ($AC5_AdminBad) { "Not Detected" } else { "Partial" }
$AC5_L1Evidence = if ($GlobalAdmins.Count -eq 0) { "Global Admin data unavailable - check Directory.Read.All." } elseif ($AC5_AdminOk) { "$($GlobalAdmins.Count) enabled Global Admins. Within best practice (<=5)." } elseif ($AC5_AdminWarn) { "$($GlobalAdmins.Count) Global Admins. Recommended max 5." } else { "$($GlobalAdmins.Count) Global Admins - excessive." }
$AC5_L1Gap = if ($AC5_AdminOk) { "Review admin privileges quarterly. Confirm separate admin accounts." } else { "Reduce to <=5 admins. Use dedicated admin accounts." }
$AC5_L2 = $AC5_AdminOk -and $CAPoliciesEnabled.Count -gt 0
$AC5_L2Status = if ($AC5_L2) { "Detected" } elseif ($AC5_AdminOk) { "Partial" } else { "Not Detected" }
$AC5_L2Evidence = if ($AC5_L2) { "Admin count OK + CA policies in place." } elseif ($AC5_AdminOk) { "Admin count OK but no CA policy confirms admin MFA." } else { "Admin count too high for L2." }
$AC5_L2Gap = "Create CA policy targeting admin roles: MFA + compliant device."
$AC5_L3 = $AC5_L2 -and $PIMEnabled
$AC5_L3Status = if ($AC5_L3) { "Detected" } elseif ($AC5_L2) { "Partial" } else { "Not Detected" }
$AC5_L3Evidence = if ($AC5_L3) { "PIM active with $($PIMAssignments.Count) eligible assignment(s)." } elseif ($AC5_L2) { "PIM not detected - may need P2." } else { "L3 needs PIM + dedicated accounts + SOC alerting." }
$AC5_L3Gap = "Enable PIM for all privileged roles. Configure access reviews."
$E8_C5 = New-ACSCControl -ID "5" -Name "Restrict Administrative Privileges" -L1Status $AC5_L1Status -L2Status $AC5_L2Status -L3Status $AC5_L3Status -L1Evidence $AC5_L1Evidence -L2Evidence $AC5_L2Evidence -L3Evidence $AC5_L3Evidence -L1Gap $AC5_L1Gap -L2Gap $AC5_L2Gap -L3Gap $AC5_L3Gap

$AC6_L1 = $FeatureUpdateProfiles.Count -gt 0 -or $UpdatePolicyDetails.Count -gt 0
$AC6_L1Status = if ($AC6_L1) { "Detected" } else { "Not Detected" }
$AC6_L1Evidence = if ($AC6_L1) { "$($FeatureUpdateProfiles.Count) feature update profile(s). $($UpdatePolicyDetails.Count) update policies." } else { "No feature update profiles." }
$AC6_L1Gap = if ($AC6_L1) { "Validate profiles target current Windows release." } else { "Deploy Intune Feature Update profiles for Win11 latest. Max 30-day deferral." }
$AC6_L2 = $AC6_L1 -and $PatchHealthPercent -ge 75
$unsupportedOSCount = @($PatchDetails | Where-Object { $_.OSRelease -match "Windows 10" -or $_.FeatureStatus -match "Upgrade Recommended" }).Count
$AC6_L2Status = if ($AC6_L2 -and $unsupportedOSCount -eq 0) { "Detected" } elseif ($AC6_L2) { "Partial" } elseif ($AC6_L1) { "Partial" } else { "Not Detected" }
$AC6_L2Evidence = if ($AC6_L1) { "Patch health $PatchHealthPercent%. $unsupportedOSCount device(s) need OS upgrade." } else { "No OS patching evidence." }
$AC6_L2Gap = "Upgrade $unsupportedOSCount Win10 to Win11. Set OS deferral <=14 days."
$AC6_L3 = $AC6_L2 -and $PatchHealthPercent -ge 90 -and $unsupportedOSCount -eq 0
$AC6_L3Status = if ($AC6_L3) { "Detected" } elseif ($AC6_L2) { "Partial" } else { "Not Detected" }
$AC6_L3Evidence = if ($AC6_L3) { "Patch health $PatchHealthPercent%; no legacy OS." } else { "L3 needs 90%+ patch + zero legacy OS." }
$AC6_L3Gap = "Implement Autopatch / zero-deferral. Automate isolation via CA."
$E8_C6 = New-ACSCControl -ID "6" -Name "Patch Operating Systems" -L1Status $AC6_L1Status -L2Status $AC6_L2Status -L3Status $AC6_L3Status -L1Evidence $AC6_L1Evidence -L2Evidence $AC6_L2Evidence -L3Evidence $AC6_L3Evidence -L1Gap $AC6_L1Gap -L2Gap $AC6_L2Gap -L3Gap $AC6_L3Gap

$AC7_L1Status = if ($MFACoveragePercent -ge 80 -and $CAPoliciesEnabled.Count -gt 0) { "Detected" } elseif ($MFACoveragePercent -ge 60 -or $CAPoliciesEnabled.Count -gt 0) { "Partial" } else { "Not Detected" }
$AC7_L1Evidence = if ($MFADataAvailable) { "MFA: $MFACoveragePercent% ($($MFAEnabled.Count) registered). $($MFANotReg.Count) users without MFA. $($CAPoliciesEnabled.Count) CA policies." } else { "MFA data unavailable. $($CAPoliciesEnabled.Count) CA policies." }
$AC7_L1Gap = "Enable MFA for $($MFANotReg.Count) users. CA policy: MFA for remote/VPN/cloud."
$AC7_L2 = $MFACoveragePercent -ge 90 -and $CAPoliciesEnabled.Count -gt 0
$AC7_L2Status = if ($AC7_L2) { "Detected" } elseif ($MFACoveragePercent -ge 75) { "Partial" } else { "Not Detected" }
$AC7_L2Evidence = if ($AC7_L2) { "MFA $MFACoveragePercent% meets L2 (>=90%). $($CAPoliciesEnabled.Count) CA policies." } elseif ($MFADataAvailable) { "MFA $MFACoveragePercent% below 90% target." } else { "MFA data unavailable." }
$AC7_L2Gap = "Achieve 90%+ MFA. Block legacy auth via CA."
$AC7_L3 = $AC7_L2 -and $HighRiskUsers.Count -eq 0
$AC7_L3Status = if ($AC7_L3) { "Detected" } elseif ($AC7_L2) { "Partial" } else { "Not Detected" }
$AC7_L3Evidence = if ($AC7_L3) { "MFA $MFACoveragePercent%; zero high-risk; $($CAPoliciesEnabled.Count) policies." } else { "$($HighRiskUsers.Count) high-risk + MFA $MFACoveragePercent% - L3 needs phishing-resistant MFA." }
$AC7_L3Gap = "Implement phishing-resistant MFA (WHfB/FIDO2) for privileged users."
$E8_C7 = New-ACSCControl -ID "7" -Name "Multi-Factor Authentication" -L1Status $AC7_L1Status -L2Status $AC7_L2Status -L3Status $AC7_L3Status -L1Evidence $AC7_L1Evidence -L2Evidence $AC7_L2Evidence -L3Evidence $AC7_L3Evidence -L1Gap $AC7_L1Gap -L2Gap $AC7_L2Gap -L3Gap $AC7_L3Gap

$AC8_L1 = $KFMDeployedSignal -or $BackupPolicyCount -gt 0
$AC8_L1Status = if ($AC8_L1 -and ($OneDriveActiveUsers -gt 0)) { "Detected" } elseif ($AC8_L1) { "Partial" } else { "Not Detected" }
$AC8_L1Evidence = if ($OneDriveUsers.Count -gt 0) { "OneDrive: $($OneDriveUsers.Count) accounts, $OneDriveActiveUsers active (30d), $OneDriveUsedStorageGB GB used. $BackupPolicyCount backup policies." } else { "OneDrive data unavailable. $BackupPolicyCount backup policies." }
$AC8_L1Gap = if ($AC8_L1) { "Validate KFM redirects Desktop/Docs/Pictures to OneDrive." } else { "Deploy OneDrive KFM via Intune." }
$AC8_L2 = $AC8_L1 -and $OneDriveActiveUsers -gt 0
$AC8_L2Status = if ($AC8_L2 -and $OneDriveUsers.Count -ge ($EnabledUsers.Count * 0.75)) { "Detected" } elseif ($AC8_L2) { "Partial" } else { "Not Detected" }
$activePct = if ($EnabledUsers.Count -gt 0) { [math]::Round(($OneDriveActiveUsers / $EnabledUsers.Count) * 100) } else { 0 }
$AC8_L2Evidence = if ($OneDriveActiveUsers -gt 0) { "$OneDriveActiveUsers active ($activePct% of enabled). L2 needs retention + versioning." } else { "OneDrive active count unavailable." }
$AC8_L2Gap = "Configure versioning + retention in Purview. Monthly backup checks."
$AC8_L3 = $AC8_L2 -and $OneDriveUsers.Count -ge ($EnabledUsers.Count * 0.90)
$AC8_L3Status = if ($AC8_L3) { "Partial" } else { "Not Detected" }
$AC8_L3Evidence = if ($AC8_L3) { "High OneDrive coverage. L3 needs DR automation + annual testing." } else { "L3 needs 90%+ coverage + automated DR + annual testing." }
$AC8_L3Gap = "Integrate OneDrive alerts with SOC. Annual DR simulation."
$E8_C8 = New-ACSCControl -ID "8" -Name "Regular Backups" -L1Status $AC8_L1Status -L2Status $AC8_L2Status -L3Status $AC8_L3Status -L1Evidence $AC8_L1Evidence -L2Evidence $AC8_L2Evidence -L3Evidence $AC8_L3Evidence -L1Gap $AC8_L1Gap -L2Gap $AC8_L2Gap -L3Gap $AC8_L3Gap

$E8Controls = @($E8_C1, $E8_C2, $E8_C3, $E8_C4, $E8_C5, $E8_C6, $E8_C7, $E8_C8)
$E8_L1Detected = @($E8Controls | Where-Object { $_.L1Status -eq "Detected" }).Count
$E8_L2Detected = @($E8Controls | Where-Object { $_.L2Status -eq "Detected" }).Count
$E8_L3Detected = @($E8Controls | Where-Object { $_.L3Status -eq "Detected" }).Count
$E8_L1Partial  = @($E8Controls | Where-Object { $_.L1Status -eq "Partial" }).Count
$E8_L2Partial  = @($E8Controls | Where-Object { $_.L2Status -eq "Partial" }).Count
$E8_L3Partial  = @($E8Controls | Where-Object { $_.L3Status -eq "Partial" }).Count

if     ($E8_L1Detected -ge 6) { $E8_MaturityLabel = "Approaching Maturity Level 1"; $E8_MaturityClass = "warn" }
elseif ($E8_L1Detected -ge 4) { $E8_MaturityLabel = "Progressing to Maturity Level 1"; $E8_MaturityClass = "warn" }
else                           { $E8_MaturityLabel = "Below Maturity Level 1"; $E8_MaturityClass = "bad" }
if ($E8_L2Detected -ge 6)     { $E8_MaturityLabel = "Approaching Maturity Level 2"; $E8_MaturityClass = "good" }
if ($E8_L3Detected -ge 6)     { $E8_MaturityLabel = "Approaching Maturity Level 3"; $E8_MaturityClass = "good" }

$E8CsvData = @($E8Controls | Select-Object ID, Name, L1Status, L1Evidence, L1Gap, L2Status, L2Evidence, L2Gap, L3Status, L3Evidence, L3Gap)
Export-DataCsv -Data $E8CsvData -Name "ACSC_Essential8_Assessment.csv"

# BACKUP NORMALIZATION
$BackupUsersTable = @()
if ($OneDriveUsers.Count -gt 0) {
    $BackupUsersTable = @($OneDriveUsers | Select-Object -First 50 `
        @{Name="User";Expression={$_.'Owner Principal Name'}},
        @{Name="LastActivity";Expression={$_.'Last Activity Date'}},
        @{Name="FilesViewedModified";Expression={$_.'Viewed Or Edited File Count'}},
        @{Name="FilesSynced";Expression={$_.'Synced File Count'}},
        @{Name="StorageGB";Expression={ $b = 0; [void][long]::TryParse($_.'Storage Used (Byte)', [ref]$b); [math]::Round($b/1GB, 2) }},
        @{Name="Status";Expression={if ([string]::IsNullOrWhiteSpace($_.'Last Activity Date')) {"Inactive"} else {"Active"}}}
    )
}
Export-DataCsv -Data $BackupUsersTable -Name "OneDrive_Backup_Status.csv"

# COLLABORATION
$CollabEOPSignal = $SSHasSafeLinks -or $SSHasSafeAttachments -or $SSHasAntiPhishing
$CollabDLPSignal = $SSHasDLP -or $SensitivityLabelCount -gt 0
$CollabMFAOk = $MFACoveragePercent -ge 90 -and $CAPoliciesEnabled.Count -gt 0

$CollabSignals = @(
    # 1. EOP
    if ($SSHasSafeLinks -and $SSHasSafeAttachments -and $SSHasAntiPhishing) { $eopStatus = "Detected" } elseif ($CollabEOPSignal) { $eopStatus = "Partial" } else { $eopStatus = "Not Detected" }
    if ($CollabEOPSignal) { $eopGap = "Validate policies assigned to all users." } else { $eopGap = "Enable EOP. Configure Safe Links/Attachments via Defender for O365." }
    if ($SSHasSafeLinks)        { $sl = 'Yes' } else { $sl = 'No' }
    if ($SSHasSafeAttachments)  { $sa = 'Yes' } else { $sa = 'No' }
    if ($SSHasAntiPhishing)     { $ap = 'Yes' } else { $ap = 'No' }
    [PSCustomObject]@{ Control = "Exchange Online Protection (EOP)"; Status = $eopStatus; Detail = "Safe Links: $sl | Safe Attachments: $sa | Anti-Phishing: $ap"; Gap = $eopGap }

    # 2. MFA
    if ($CollabMFAOk) { $mfaStatus = "Detected" } elseif ($MFACoveragePercent -ge 70) { $mfaStatus = "Partial" } else { $mfaStatus = "Not Detected" }
    if ($CollabMFAOk) { $mfaGap = "Confirm MFA enforced for M365 apps via CA." } else { $mfaGap = "Enforce MFA via CA. Target $($MFANotReg.Count) missing users." }
    [PSCustomObject]@{ Control = "Multi-Factor Authentication (Collab)"; Status = $mfaStatus; Detail = "MFA: $MFACoveragePercent%. $($CAPoliciesEnabled.Count) CA policies. $($MFANotReg.Count) without MFA."; Gap = $mfaGap }

    # 3. DLP
    if ($CollabDLPSignal) { $dlpStatus = "Partial" } else { $dlpStatus = "Not Detected" }
    if ($CollabDLPSignal) { $dlpGap = "Configure DLP in Exchange/Teams. Map labels to DLP rules." } else { $dlpGap = "Deploy Purview DLP. Create sensitivity labels." }
    if ($SSHasDLP) { $dlpSig = 'Present' } else { $dlpSig = 'Not detected' }
    [PSCustomObject]@{ Control = "Data Loss Prevention (DLP)"; Status = $dlpStatus; Detail = "Sensitivity labels: $SensitivityLabelCount. DLP signal: $dlpSig."; Gap = $dlpGap }

    # 4. CA
    if ($CAPoliciesEnabled.Count -ge 2) { $caStatus = "Detected" } elseif ($CAPoliciesEnabled.Count -eq 1) { $caStatus = "Partial" } else { $caStatus = "Not Detected" }
    if ($CAPoliciesEnabled.Count -ge 2) { $caGap = "Validate CA covers MFA, legacy auth block, compliant device." } else { $caGap = "Implement CA baseline: MFA all users, block legacy auth." }
    [PSCustomObject]@{ Control = "Conditional Access - Collaboration"; Status = $caStatus; Detail = "$($CAPoliciesEnabled.Count) enabled, $($CAPoliciesReportOnly.Count) report-only."; Gap = $caGap }

    # 5. Audit Logging
    if ($SSHasAuditLog) { $audStatus = "Detected"; $audDetail = "Audit log signal: Present."; $audGap = "Retain logs 90 days (L1/L2) or 365 (L3)." }
    else { $audStatus = "Not Detected"; $audDetail = "Audit log signal: Not detected."; $audGap = "Enable unified audit logging." }
    [PSCustomObject]@{ Control = "Audit Logging"; Status = $audStatus; Detail = $audDetail; Gap = $audGap }

    # 6. Attack Sim
    if ($AttackSimCount -gt 0) { $simStatus = "Detected"; $simGap = "Continue quarterly simulations." }
    else { $simStatus = "Not Detected"; $simGap = "Enable Attack Simulation Training. Quarterly phishing sims." }
    [PSCustomObject]@{ Control = "Attack Simulation Training"; Status = $simStatus; Detail = "$AttackSimCount simulation(s). $AttackSimCompleted completed."; Gap = $simGap }

    # 7. Defender O365 Alerts
    if ($O365AlertsActive -eq 0) { $o365Status = "Detected"; $o365Gap = "Maintain monitoring." }
    elseif ($O365AlertsActive -le 3) { $o365Status = "Partial"; $o365Gap = "$O365AlertsActive alert(s) - review." }
    else { $o365Status = "Not Detected"; $o365Gap = "$O365AlertsActive alerts need SOC triage." }
    [PSCustomObject]@{ Control = "Defender for Office 365 - Active Alerts"; Status = $o365Status; Detail = "$O365AlertsActive active O365 alert(s)."; Gap = $o365Gap }

    # 8. Shared Mailboxes
    if ($SharedMailboxes.Count -eq 0) { $smStatus = "Not Detected"; $smGap = "None detected." }
    else { $smStatus = "Detected"; $smGap = "Validate delegation requires MFA." }
    [PSCustomObject]@{ Control = "Shared Mailboxes"; Status = $smStatus; Detail = "$($SharedMailboxes.Count) shared mailbox(es)."; Gap = $smGap }
)
$CollabSignals = @($CollabSignals | Where-Object { $_ -is [PSCustomObject] })
Export-DataCsv -Data $CollabSignals -Name "Collaboration_Voice_Security.csv"

# HIGH-RISK
$DefenderMappedIds = @($DefenderMapped | ForEach-Object {
    $id = $null
    if ($_.aadDeviceId) { $id = "$($_.aadDeviceId)".ToLower() } elseif ($_.azureAdDeviceId) { $id = "$($_.azureAdDeviceId)".ToLower() }
    if ($id) { $id }
})
$HighRiskDevices = @($ManagedDeviceDetails | Where-Object {
    ($_.Encrypted -eq "No") -or ($_.Compliance -ne "compliant") -or ($_.PatchStatus -eq "Needs Attention")
} | ForEach-Object {
    $dev = $_
    $aadId = "$($ManagedDevices | Where-Object {$_.deviceName -eq $dev.DeviceName} | Select-Object -First 1 -ExpandProperty azureADDeviceId)".ToLower()
    $defenderCovered = $DefenderMappedIds -contains $aadId
    $riskFlags = @()
    if ($dev.Encrypted -eq "No") { $riskFlags += "Not Encrypted" }
    if ($dev.Compliance -ne "compliant") { $riskFlags += "Non-Compliant" }
    if (-not $defenderCovered) { $riskFlags += "No Defender" }
    if ($dev.PatchStatus -eq "Needs Attention") { $riskFlags += "Patch Attention" }
    if ($dev.DaysSinceSync -gt 7) { $riskFlags += "Stale $($dev.DaysSinceSync)d" }
    [PSCustomObject]@{
        DeviceName=$dev.DeviceName; AssignedUser=$dev.AssignedUser; OSRelease=$dev.OSRelease;
        Encrypted=$dev.Encrypted; Compliance=$dev.Compliance;
        DefenderStatus=if ($defenderCovered) {"Covered"} else {"Not Covered"};
        PatchStatus=$dev.PatchStatus; LastSync=$dev.LastSync;
        RiskFlags=$riskFlags -join " | "; RiskCount=$riskFlags.Count
    }
} | Sort-Object RiskCount -Descending)
Export-DataCsv -Data $HighRiskDevices -Name "High_Risk_Device_Correlation.csv"

# TREND
$BaselineFile = Join-Path $BaseOutputPath "last_baseline_$($TenantId).json"
$TrendData = $null
$CurrentBaseline = @{ RunDate=(Get-Date -Format "dd MMM yyyy"); CompliancePercent=$CompliancePercent; EncryptionPercent=$EncryptionPercent; MFACoverage=$MFACoveragePercent; DefenderCoverage=$DefenderCoveragePercent; PatchHealth=$PatchHealthPercent; RiskyUsers=$RiskyUsersActive.Count; HighAlerts=$HighDefenderAlerts.Count; SecureScore=$SecureScorePercent }
if (Test-Path $BaselineFile) {
    try {
        $PreviousBaseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json
        $TrendData = @{
            PreviousDate=$PreviousBaseline.RunDate
            Compliance=@{ Prev=$PreviousBaseline.CompliancePercent; Curr=$CompliancePercent; Unit="%" }
            Encryption=@{ Prev=$PreviousBaseline.EncryptionPercent; Curr=$EncryptionPercent; Unit="%" }
            MFA=@{ Prev=$PreviousBaseline.MFACoverage; Curr=$MFACoveragePercent; Unit="%" }
            DefenderCoverage=@{ Prev=$PreviousBaseline.DefenderCoverage; Curr=$DefenderCoveragePercent; Unit="%" }
            PatchHealth=@{ Prev=$PreviousBaseline.PatchHealth; Curr=$PatchHealthPercent; Unit="%" }
            RiskyUsers=@{ Prev=$PreviousBaseline.RiskyUsers; Curr=$RiskyUsersActive.Count; Unit="" }
            HighAlerts=@{ Prev=$PreviousBaseline.HighAlerts; Curr=$HighDefenderAlerts.Count; Unit="" }
            SecureScore=@{ Prev=$PreviousBaseline.SecureScore; Curr=$SecureScorePercent; Unit="%" }
        }
    } catch { Write-Log "Trend load failed." "WARN" }
}
try { $CurrentBaseline | ConvertTo-Json | Set-Content -Path $BaselineFile -Encoding UTF8 } catch { }

function Get-TrendArrow {
    param([double]$Prev,[double]$Curr,[bool]$LowerIsBetter=$false)
    if ($Prev -eq $null -or $Curr -eq $null) { return "<span style='color:#94a3b8'>--</span>" }
    $diff = $Curr - $Prev
    if ($diff -gt 0) { if ($LowerIsBetter) { $color = "#dc2626" } else { $color = "#16a34a" }; return "<span style='color:$color;font-weight:700'>&#9650; +$([math]::Round($diff,1))</span>" }
    elseif ($diff -lt 0) { if ($LowerIsBetter) { $color = "#16a34a" } else { $color = "#dc2626" }; return "<span style='color:$color;font-weight:700'>&#9660; $([math]::Round($diff,1))</span>" }
    else { return "<span style='color:#64748b'>&#8594; No change</span>" }
}

if ($TrendData) {
    $TrendHtml = "<div class='table-wrap'><table><thead><tr><th>Metric</th><th>Previous ($($TrendData.PreviousDate))</th><th>Current</th><th>Trend</th></tr></thead><tbody>"
    foreach ($row in @(
        @{Name="Compliance"; Data=$TrendData.Compliance; Lower=$false},
        @{Name="Encryption"; Data=$TrendData.Encryption; Lower=$false},
        @{Name="MFA Coverage"; Data=$TrendData.MFA; Lower=$false},
        @{Name="Defender Coverage"; Data=$TrendData.DefenderCoverage; Lower=$false},
        @{Name="Patch Health"; Data=$TrendData.PatchHealth; Lower=$false},
        @{Name="Risky Users"; Data=$TrendData.RiskyUsers; Lower=$true},
        @{Name="High Alerts"; Data=$TrendData.HighAlerts; Lower=$true},
        @{Name="Secure Score"; Data=$TrendData.SecureScore; Lower=$false}
    )) {
        $unit = $row.Data.Unit
        $arrow = Get-TrendArrow -Prev $row.Data.Prev -Curr $row.Data.Curr -LowerIsBetter $row.Lower
        $TrendHtml += "<tr><td>$($row.Name)</td><td>$($row.Data.Prev)$unit</td><td><strong>$($row.Data.Curr)$unit</strong></td><td>$arrow</td></tr>"
    }
    $TrendHtml += "</tbody></table></div>"
} else {
    $TrendHtml = "<div class='note'>First run - no previous baseline. Trend will appear next run.</div>"
}

$MFANotRegDetails = @($MFANotReg | Select-Object @{Name="User";Expression={$_.userDisplayName}}, @{Name="UPN";Expression={$_.userPrincipalName}}, @{Name="MFARegistered";Expression={if ($_.isMfaRegistered -eq $true) {"Yes"} else {"No"}}}, @{Name="DefaultMethod";Expression={$_.defaultMfaMethod}}, @{Name="UserType";Expression={$_.userType}} | Where-Object { $_.UserType -ne "Guest" } | Sort-Object UPN)
Export-DataCsv -Data $MFANotRegDetails -Name "MFA_Not_Registered.csv"

# OBSERVATIONS
$Findings = New-Object System.Collections.Generic.List[string]
$Actions = New-Object System.Collections.Generic.List[string]
if ($CompliancePercent -ge 90) { $Findings.Add("Compliance is strong at $CompliancePercent%.") } else { $Findings.Add("Compliance is $CompliancePercent%."); $Actions.Add("Review non-compliant devices and remediate.") }
if ($EncryptionPercent -ge 95) { $Findings.Add("Encryption is strong at $EncryptionPercent%.") } else { $Findings.Add("Encryption is $EncryptionPercent%; $($NotEncryptedDetails.Count) devices need attention."); $Actions.Add("Validate encryption policy and remediate.") }
if ($DevicesNotSynced7Days.Count -gt 0) { $Findings.Add("$($DevicesNotSynced7Days.Count) devices not synced in $Stale7Days days."); $Actions.Add("Contact owners of stale devices.") }
if ($EntraStale90.Count -gt 0) { $Findings.Add("$($EntraStale90.Count) Entra devices stale 90+ days."); $Actions.Add("Review stale Entra devices.") }
if ($RiskyUsersActive.Count -gt 0) { $Findings.Add("$($RiskyUsersActive.Count) risky users."); $Actions.Add("Review and remediate risky users.") } else { $Findings.Add("No active risky users.") }
if ($CAPoliciesEnabled.Count -gt 0) { $Findings.Add("$($CAPoliciesEnabled.Count) CA policies enabled.") } else { $Findings.Add("No CA policies enabled."); $Actions.Add("Validate CA baseline.") }
if ($DefenderMapped.Count -gt 0) { $Findings.Add("Defender mapped $($DefenderMapped.Count) devices.") } else { $Findings.Add("No Defender mapping."); $Actions.Add("Validate Defender onboarding.") }
if ($HighDefenderAlerts.Count -gt 0) { $Findings.Add("$($HighDefenderAlerts.Count) high/critical alerts."); $Actions.Add("Review high/critical alerts.") }
if ($PatchDetails.Count -gt 0) { $Findings.Add("Patch health $PatchHealthPercent%.") }
if ($PatchAttention.Count -gt 0) { $Actions.Add("Review patch attention devices.") }
if ($Actions.Count -eq 0) { $Actions.Add("Continue regular operational reviews.") }
$FindingsHtml = ($Findings | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join "`n"
$ActionsHtml  = ($Actions | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join "`n"

# TABLES
$DeviceHeaders = @{ DeviceName="Device Name"; AssignedUser="Assigned User"; Make="Make"; Model="Model"; Platform="Platform"; OSRelease="OS Release"; OSEdition="OS Edition"; Compliance="Compliance"; Encrypted="Encrypted"; LastSync="Last Sync"; DaysSinceSync="Days Since Sync" }
$RiskHeaders = @{ User="User"; UPN="UPN"; RiskLevel="Risk Level"; RiskState="Risk State"; RiskDetail="Risk Detail" }
$DefenderHeadersFriendly = @{ DeviceName="Device Name"; HealthStatus="Health"; RiskScore="Risk Score"; ExposureLevel="Exposure"; OSPlatform="OS"; Version="Version"; LastSeen="Last Seen" }
$AlertHeaders = @{ Title="Title"; Severity="Severity"; Status="Status"; Category="Category"; DeviceName="Device"; LastUpdate="Last Update" }
$NonCompliantHtml = ConvertTo-DataTableHtml -Data $NonCompliantDetails -Columns @("DeviceName","AssignedUser","Make","Model","Platform","OSRelease","OSEdition","Compliance","Encrypted","LastSync") -Headers $DeviceHeaders -EmptyMessage "No non-compliant devices."
$NotEncryptedHtml = ConvertTo-DataTableHtml -Data $NotEncryptedDetails -Columns @("DeviceName","AssignedUser","Make","Model","Platform","OSRelease","OSEdition","Encrypted","Compliance","LastSync") -Headers $DeviceHeaders -EmptyMessage "No unencrypted devices."
$Stale7Html = ConvertTo-DataTableHtml -Data $Stale7Details -Columns @("DeviceName","AssignedUser","Make","Model","Platform","OSRelease","OSEdition","LastSync","DaysSinceSync") -Headers $DeviceHeaders -EmptyMessage "No stale devices > 7 days."
$Stale30Html = ConvertTo-DataTableHtml -Data $Stale30Details -Columns @("DeviceName","AssignedUser","Make","Model","Platform","OSRelease","OSEdition","LastSync","DaysSinceSync") -Headers $DeviceHeaders -EmptyMessage "No stale devices > 30 days."
$EntraStaleHtml = ConvertTo-DataTableHtml -Data $EntraStaleDetails -Columns @("DeviceName","Platform","TrustType","Enabled","LastSignIn","DaysInactive","RecommendedAction") -Headers @{DeviceName="Device";Platform="Platform";TrustType="Trust";Enabled="Enabled";LastSignIn="Last Sign-In";DaysInactive="Days Inactive";RecommendedAction="Recommended Action"} -EmptyMessage "No stale Entra devices."
$RiskyUsersHtml = ConvertTo-DataTableHtml -Data $RiskyUserDetails -Columns @("User","UPN","RiskLevel","RiskState","RiskDetail") -Headers $RiskHeaders -EmptyMessage "No risky users."
$DefenderMappedHtml = ConvertTo-DataTableHtml -Data $DefenderMachineDetails -Columns @("DeviceName","HealthStatus","RiskScore","ExposureLevel","OSPlatform","Version","LastSeen") -Headers $DefenderHeadersFriendly -EmptyMessage "No Defender devices mapped."
$DefenderAlertsHtml = ConvertTo-DataTableHtml -Data $DefenderAlertDetails -Columns @("Title","Severity","Status","Category","DeviceName","LastUpdate") -Headers $AlertHeaders -EmptyMessage "No Defender alerts."
$ManagedInventoryPreview = @($ManagedDeviceDetails | Sort-Object DeviceName | Select-Object -First 75)
$ManagedInventoryHtml = ConvertTo-DataTableHtml -Data $ManagedInventoryPreview -Columns @("DeviceName","AssignedUser","Make","Model","Platform","OSRelease","OSEdition","Compliance","Encrypted","LastSync") -Headers $DeviceHeaders -EmptyMessage "No managed device inventory."

$VulnerabilitySummaryHtml = "<div class='risk-strip'><div class='risk-tile bad'><span>Critical</span><strong>$CriticalVulnCount</strong><small>Patch within 48 hours</small></div><div class='risk-tile warn'><span>High</span><strong>$HighVulnCount</strong><small>Patch within 2 weeks</small></div><div class='risk-tile neutral'><span>Medium</span><strong>$MediumVulnCount</strong><small>Patch this quarter</small></div><div class='risk-tile good'><span>Low</span><strong>$LowVulnCount</strong><small>Monitor</small></div></div>"

if ($CriticalVulnCount -gt 0) {
    $vulnContext="red"; $vulnHeadline="Immediate action required - $CriticalVulnCount critical vulnerability/vulnerabilities."
    $vulnExplain="Critical vulnerabilities allow attacker control without user interaction."
    $vulnPlan="Patch/mitigate within 48 hours."
} elseif ($HighVulnCount -gt 0) {
    $vulnContext="orange"; $vulnHeadline="$HighVulnCount high-severity vulnerability/vulnerabilities."
    $vulnExplain="Significant risk requiring patching within 2 weeks."
    $vulnPlan="Schedule via maintenance window."
} elseif ($MediumVulnCount -gt 0) {
    $vulnContext="blue"; $vulnHeadline="$MediumVulnCount medium-severity vulnerability/vulnerabilities."
    $vulnExplain="Lower risk, included in normal patch cycle."
    $vulnPlan="Include in next scheduled patch cycle."
} else {
    $vulnContext="green"; $vulnHeadline="No critical or high vulnerabilities."
    $vulnExplain="Strong posture - no critical/high vulnerabilities."
    $vulnPlan="Continue monitoring."
}
$VulnContextHtml = "<div class='vuln-context vuln-$vulnContext'><div class='vuln-headline'>$(HtmlEncode $vulnHeadline)</div><div class='vuln-explain'>$(HtmlEncode $vulnExplain)</div><div class='vuln-plan'><strong>Action Plan:</strong> $(HtmlEncode $vulnPlan)</div></div>"

$PatchHeaders = @{ DeviceName="Device"; AssignedUser="User"; Make="Make"; Model="Model"; OSRelease="OS"; OSEdition="Edition"; FeatureStatus="Feature Update"; PatchStatus="Patch Health"; CriticalUpdateFindings="Critical"; HighUpdateFindings="High"; LastSync="Last Sync"; UpdateSignal="Signal" }
# Show true patch attention items only. Monitor devices remain counted as managed/validated and are visible in CSV.
$PatchAttentionHtml = ConvertTo-DataTableHtml -Data @($PatchDetails | Where-Object { $_.PatchStatus -eq "Needs Attention" } | Sort-Object DaysSinceSync -Descending) -Columns @("DeviceName","AssignedUser","Make","Model","OSRelease","OSEdition","FeatureStatus","PatchStatus","CriticalUpdateFindings","HighUpdateFindings","LastSync","UpdateSignal") -Headers $PatchHeaders -EmptyMessage "No patch attention items."
$PatchSummaryData = @(
    [pscustomobject]@{ Category="Healthy"; Count=$PatchHealthy.Count; Meaning="Recent sync, no concerns" },
    [pscustomobject]@{ Category="Monitor"; Count=$PatchMonitor.Count; Meaning="Review during patch cycle" },
    [pscustomobject]@{ Category="Needs Attention"; Count=$PatchAttention.Count; Meaning="Operational follow-up" }
)
$PatchSummaryHtml = ConvertTo-DataTableHtml -Data $PatchSummaryData -Columns @("Category","Count","Meaning") -Headers @{Category="Patch Health";Count="Count";Meaning="Meaning"} -EmptyMessage "No patch summary."
$UpdatePolicyHtml = ConvertTo-DataTableHtml -Data $UpdatePolicyDetails -Columns @("PolicyName","PolicyType","Description") -Headers @{PolicyName="Policy";PolicyType="Type";Description="Description"} -EmptyMessage "No update policies found."

$OSSummary = @($ManagedDeviceDetails | Group-Object OSRelease | Sort-Object Count -Descending | Select-Object @{Name="OSRelease";Expression={$_.Name}}, Count)
$OSSummaryHtml = ConvertTo-DataTableHtml -Data $OSSummary -Columns @("OSRelease","Count") -Headers @{OSRelease="OS Release";Count="Count"} -EmptyMessage "No OS summary."
$EditionSummary = @($ManagedDeviceDetails | Where-Object { $_.Platform -eq "Windows" } | Group-Object OSEdition | Sort-Object Count -Descending | Select-Object @{Name="OSEdition";Expression={$_.Name}}, Count)
$EditionSummaryHtml = ConvertTo-DataTableHtml -Data $EditionSummary -Columns @("OSEdition","Count") -Headers @{OSEdition="Edition";Count="Count"} -EmptyMessage "No edition summary."
$ModelSummary = @($ManagedDeviceDetails | Group-Object Make,Model | Sort-Object Count -Descending | Select-Object -First 20 @{Name="MakeModel";Expression={$_.Name}}, Count)
$ModelSummaryHtml = ConvertTo-DataTableHtml -Data $ModelSummary -Columns @("MakeModel","Count") -Headers @{MakeModel="Make/Model";Count="Count"} -EmptyMessage "No model summary."

# ============================================================
# PATCH 5: LOGO PROCESSING (FIXED)
# Produces clean <img> for white pill container (.brand-logo)
# ============================================================
$LogoHtml = ""
if ($LogoPath -and (Test-Path $LogoPath)) {
    try {
        $ext = [System.IO.Path]::GetExtension($LogoPath).TrimStart('.').ToLower()
        if ($ext -eq "jpg") { $ext = "jpeg" }
        if ($ext -in @("jpeg","png","gif","webp","svg+xml")) {
            $bytes = [System.IO.File]::ReadAllBytes($LogoPath)
            $b64 = [Convert]::ToBase64String($bytes)
            $LogoHtml = "<img src='data:image/$ext;base64,$b64' alt='Logo' />"
        }
    } catch { $LogoHtml = "" }
}
if ([string]::IsNullOrWhiteSpace($LogoHtml)) {
    $LogoHtml = "<span class='logo-fallback'>SDMSGUY</span>"
}

$GeneratedOn = (Get-Date).ToString("dd MMM yyyy HH:mm")
$QuarterLabel = "Q" + [math]::Ceiling((Get-Date).Month / 3).ToString() + " " + (Get-Date).Year.ToString()
if     ($HealthScore -ge 85) { $OverallStatus = "Healthy"; $BusinessRisk = "Low"; $OverallStatusColor = "#4ade80" }
elseif ($HealthScore -ge 65) { $OverallStatus = "Monitor"; $BusinessRisk = "Medium"; $OverallStatusColor = "#fbbf24" }
else                         { $OverallStatus = "At Risk"; $BusinessRisk = "High"; $OverallStatusColor = "#f87171" }
$ReportPeriodText = "This report summarises your organisation's device security, patching status, and risk posture from Microsoft cloud APIs."

$CardsHtml = ""
$CardsHtml += New-Card -Title "Overall Health" -Value "$HealthScore%" -SubText $HealthBand.Label -Class $HealthBand.Class
$CardsHtml += New-Card -Title "Managed Devices" -Value "$($ManagedDevices.Count)" -SubText "$ManagedCoveragePercent% of Entra inventory" -Class "neutral"
$CardsHtml += New-Card -Title "Compliance" -Value "$CompliancePercent%" -SubText "$($CompliantManagedDevices.Count) compliant" -Class $(if ($CompliancePercent -ge 90) {"good"} elseif ($CompliancePercent -ge 75) {"warn"} else {"bad"})
$CardsHtml += New-Card -Title "Encryption" -Value "$EncryptionPercent%" -SubText "$($EncryptedManagedDevices.Count) encrypted" -Class $(if ($EncryptionPercent -ge 95) {"good"} elseif ($EncryptionPercent -ge 80) {"warn"} else {"bad"})
$CardsHtml += New-Card -Title "Sync Health" -Value "$ActiveSyncPercent%" -SubText "$($DevicesNotSynced7Days.Count) stale" -Class $(if ($ActiveSyncPercent -ge 90) {"good"} elseif ($ActiveSyncPercent -ge 75) {"warn"} else {"bad"})
$CardsHtml += New-Card -Title "Defender Coverage" -Value "$DefenderCoveragePercent%" -SubText "$($DefenderMapped.Count) mapped" -Class $(if ($DefenderCoveragePercent -ge 90) {"good"} elseif ($DefenderCoveragePercent -ge 70) {"warn"} else {"bad"})
$CardsHtml += New-Card -Title "Patch Health" -Value "$PatchHealthPercent%" -SubText "$($PatchAttention.Count) need attention" -Class $(if ($PatchHealthPercent -ge 90) {"good"} elseif ($PatchHealthPercent -ge 75) {"warn"} else {"bad"})
$CardsHtml += New-Card -Title "Risky Users" -Value "$($RiskyUsersActive.Count)" -SubText "$($HighRiskUsers.Count) high risk" -Class $(if ($RiskyUsersActive.Count -eq 0) {"good"} elseif ($HighRiskUsers.Count -eq 0) {"warn"} else {"bad"})
$CardsHtml += New-Card -Title "Security Alerts" -Value "$($ActiveDefenderAlerts.Count)" -SubText "$($HighDefenderAlerts.Count) high/critical" -Class $(if ($HighDefenderAlerts.Count -eq 0) {"good"} else {"bad"})
$CardsHtml += New-Card -Title "Conditional Access" -Value "$($CAPoliciesEnabled.Count)" -SubText "policies enabled" -Class $(if ($CAPoliciesEnabled.Count -gt 0) {"good"} else {"bad"})
$CardsHtml += New-Card -Title "Secure Score" -Value "$SecureScorePercent%" -SubText "Microsoft 365 security score" -Class $(if ($SecureScorePercent -ge 70) {"good"} elseif ($SecureScorePercent -ge 50) {"warn"} elseif ($SecureScorePercent -gt 0) {"bad"} else {"neutral"})
if ($MFADataAvailable) {
    $CardsHtml += New-Card -Title "MFA Coverage" -Value "$MFACoveragePercent%" -SubText "$($MFANotReg.Count) without MFA" -Class $(if ($MFACoveragePercent -ge 90) {"good"} elseif ($MFACoveragePercent -ge 70) {"warn"} else {"bad"})
} else {
    $CardsHtml += New-Card -Title "MFA Coverage" -Value "N/A" -SubText "Add Reports.Read.All" -Class "neutral"
}

# Scorecard
if ($CompliancePercent -ge 90) { $CompScoreColor = "#16a34a"; $CompScoreText = "Healthy ($CompliancePercent%)" } elseif ($CompliancePercent -ge 75) { $CompScoreColor = "#d97706"; $CompScoreText = "Monitor ($CompliancePercent%)" } else { $CompScoreColor = "#dc2626"; $CompScoreText = "Needs Attention ($CompliancePercent%)" }
if ($EncryptionPercent -ge 95) { $EncScoreColor = "#16a34a"; $EncScoreText = "Healthy ($EncryptionPercent%)" } elseif ($EncryptionPercent -ge 80) { $EncScoreColor = "#d97706"; $EncScoreText = "Monitor ($EncryptionPercent%)" } else { $CompScoreColor = "#dc2626"; $EncScoreText = "Needs Attention ($EncryptionPercent%)" }
if ($CAPoliciesEnabled.Count -gt 0) { $CAScoreColor = "#16a34a"; $CAScoreText = "Healthy ($($CAPoliciesEnabled.Count) enabled)" } else { $CAScoreColor = "#dc2626"; $CAScoreText = "Needs Attention" }
if ($RiskyUsersActive.Count -eq 0) { $IdScoreColor = "#16a34a"; $IdScoreText = "Healthy" } elseif ($HighRiskUsers.Count -eq 0) { $IdScoreColor = "#d97706"; $IdScoreText = "Monitor ($($RiskyUsersActive.Count))" } else { $IdScoreColor = "#dc2626"; $IdScoreText = "Needs Attention ($($HighRiskUsers.Count) high)" }
if ($DefenderCoveragePercent -ge 90) { $DefScoreColor = "#16a34a"; $DefScoreText = "Healthy ($DefenderCoveragePercent%)" } elseif ($DefenderCoveragePercent -ge 70) { $DefScoreColor = "#d97706"; $DefScoreText = "Monitor ($DefenderCoveragePercent%)" } else { $DefScoreColor = "#dc2626"; $DefScoreText = "Needs Attention ($DefenderCoveragePercent%)" }
if ($MFADataAvailable) { if ($MFACoveragePercent -ge 90) { $MFAScoreColor = "#16a34a"; $MFAScoreText = "Healthy ($MFACoveragePercent%)" } elseif ($MFACoveragePercent -ge 70) { $MFAScoreColor = "#d97706"; $MFAScoreText = "Monitor ($MFACoveragePercent%)" } else { $MFAScoreColor = "#dc2626"; $MFAScoreText = "Needs Attention ($MFACoveragePercent%)" } } else { $MFAScoreColor = "#64748b"; $MFAScoreText = "Data unavailable" }

$HighRiskHtml = ConvertTo-DataTableHtml -Data $HighRiskDevices -Columns @("DeviceName","AssignedUser","OSRelease","Encrypted","Compliance","DefenderStatus","PatchStatus","LastSync","RiskFlags") -Headers @{DeviceName="Device";AssignedUser="User";OSRelease="OS";Encrypted="Encrypted";Compliance="Compliance";DefenderStatus="Defender";PatchStatus="Patch";LastSync="Last Sync";RiskFlags="Risk Flags"} -EmptyMessage "No high-risk devices."

if ($MFADataAvailable) {
    $MFANotRegHtml = ConvertTo-DataTableHtml -Data $MFANotRegDetails -Columns @("User","UPN","MFARegistered","DefaultMethod") -Headers @{User="User";UPN="UPN";MFARegistered="MFA";DefaultMethod="Default Method"} -EmptyMessage "All users have MFA."
} else {
    $MFANotRegHtml = "<div class='note'>MFA data needs <b>Reports.Read.All</b> permission.</div>"
}

if ($CAPoliciesEnabled.Count -eq 0) { $CAEnforcementNote = "No CA policies enforcing MFA - users can sign in without MFA." } else { $CAEnforcementNote = "CA policies actively controlling access." }

if ($NotEncryptedDetails.Count -gt 0) {
    $Rec1Html = "<div style='margin-bottom:12px;padding:14px 16px;background:#fff8f0;border-left:4px solid #e65100;border-radius:10px'><div style='font-weight:700;color:#7c2d12'>1. Enable Device Encryption</div><div style='font-size:13px;color:#431407'>$($NotEncryptedDetails.Count) device(s) unencrypted. Enable via Intune.<br><b>Owner:</b> IT | <b>Priority:</b> High | <b>Timeline:</b> 2 weeks</div></div>"
} else { $Rec1Html = "" }
if ($CAPoliciesEnabled.Count -eq 0) {
    $Rec2Html = "<div style='margin-bottom:12px;padding:14px 16px;background:#fff8f0;border-left:4px solid #e65100;border-radius:10px'><div style='font-weight:700;color:#7c2d12'>2. Implement Conditional Access & MFA</div><div style='font-size:13px;color:#431407'>No CA policies enforcing MFA.<br><b>Owner:</b> IT | <b>Priority:</b> Critical | <b>Timeline:</b> Immediate</div></div>"
} else { $Rec2Html = "" }
if ($DefenderCoveragePercent -lt 90) {
    $Rec3Html = "<div style='margin-bottom:12px;padding:14px 16px;background:#fffbeb;border-left:4px solid #d97706;border-radius:10px'><div style='font-weight:700;color:#78350f'>3. Complete Defender Onboarding</div><div style='font-size:13px;color:#451a03'>$DefenderCoveragePercent% coverage. Deploy via Intune.<br><b>Owner:</b> IT | <b>Priority:</b> Medium | <b>Timeline:</b> This quarter</div></div>"
} else { $Rec3Html = "" }

$ComplianceDonutHtml = ConvertTo-Donut -Percent ([int]$CompliancePercent) -Label "Compliant" -Class $(if($CompliancePercent -ge 90){'good'}elseif($CompliancePercent -ge 75){'warn'}else{'bad'})
$EncryptionDonutHtml = ConvertTo-Donut -Percent ([int]$EncryptionPercent) -Label "Encrypted" -Class $(if($EncryptionPercent -ge 95){'good'}elseif($EncryptionPercent -ge 80){'warn'}else{'bad'})
$ManagedCoverageDonutHtml = ConvertTo-Donut -Percent ([int]$ManagedCoveragePercent) -Label "Managed" -Class 'neutral'
$DefenderDonutHtml = ConvertTo-Donut -Percent ([int]$DefenderCoveragePercent) -Label "Mapped" -Class $(if($DefenderCoveragePercent -ge 90){'good'}elseif($DefenderCoveragePercent -ge 70){'warn'}else{'bad'})
$PatchDonutHtml = ConvertTo-Donut -Percent ([int]$PatchHealthPercent) -Label "Up to Date" -Class $(if($PatchHealthPercent -ge 90){'good'}elseif($PatchHealthPercent -ge 70){'warn'}else{'bad'})

$ConclusionText = "The organisation has established a $(if($HealthScore -ge 85){'strong'}elseif($HealthScore -ge 65){'moderate'}else{'developing'}) security posture.`n`nContinued focus on compliance, identity protection, and device monitoring will further strengthen the environment.`n`nQuarterly reviews are recommended."

$TopRiskItems = New-Object System.Collections.Generic.List[hashtable]
if ($NotEncryptedDetails.Count -gt 0) { $TopRiskItems.Add(@{ Icon="&#x1F513;"; Color="#dc2626"; Text="$($NotEncryptedDetails.Count) device(s) not encrypted."; Action="Enable BitLocker/FileVault." }) }
if ($PatchAttention.Count -gt 0) { $TopRiskItems.Add(@{ Icon="&#x26A0;"; Color="#d97706"; Text="$($PatchAttention.Count) device(s) need patch attention."; Action="Investigate critical findings." }) }
if ($HighDefenderAlerts.Count -gt 0) { $TopRiskItems.Add(@{ Icon="&#x1F6A8;"; Color="#dc2626"; Text="$($HighDefenderAlerts.Count) high/critical alert(s)."; Action="Review in Defender portal." }) }
if ($NonCompliantDetails.Count -gt 0 -and $TopRiskItems.Count -lt 3) { $TopRiskItems.Add(@{ Icon="&#x274C;"; Color="#dc2626"; Text="$($NonCompliantDetails.Count) non-compliant device(s)."; Action="Review and remediate." }) }
if ($RiskyUsersActive.Count -gt 0 -and $TopRiskItems.Count -lt 3) { $TopRiskItems.Add(@{ Icon="&#x1F464;"; Color="#d97706"; Text="$($RiskyUsersActive.Count) risky user(s)."; Action="Reset passwords, confirm MFA." }) }
if ($EntraStaleDetails.Count -gt 0 -and $TopRiskItems.Count -lt 3) { $TopRiskItems.Add(@{ Icon="&#x1F550;"; Color="#64748b"; Text="$($EntraStaleDetails.Count) stale device(s)."; Action="Disable or delete after confirmation." }) }
if ($TopRiskItems.Count -eq 0) { $TopRiskItems.Add(@{ Icon="&#x2705;"; Color="#16a34a"; Text="No critical risks identified."; Action="Continue regular monitoring." }) }

$TopRisksHtml = ""
$riskCount = 0
foreach ($risk in $TopRiskItems) {
    if ($riskCount -ge 3) { break }
    $riskCount++
    $TopRisksHtml += "<div class='top-risk'><div class='risk-icon'>$($risk.Icon)</div><div class='risk-body'><div class='risk-text' style='color:$($risk.Color)'>$(HtmlEncode $risk.Text)</div><div class='risk-action'>$(HtmlEncode $risk.Action)</div></div></div>"
}

# E8 / Backup / Collab HTML
function Get-E8StatusBadge {
    param([string]$Status)
    switch ($Status) {
        "Detected"     { return "<span style='display:inline-block;padding:3px 10px;border-radius:20px;background:#dcfce7;color:#166534;font-size:12px;font-weight:700'>&#10003; Detected</span>" }
        "Partial"      { return "<span style='display:inline-block;padding:3px 10px;border-radius:20px;background:#fef9c3;color:#854d0e;font-size:12px;font-weight:700'>&#9888; Partial</span>" }
        "Not Detected" { return "<span style='display:inline-block;padding:3px 10px;border-radius:20px;background:#fee2e2;color:#991b1b;font-size:12px;font-weight:700'>&#10007; Not Detected</span>" }
        default        { return "<span style='display:inline-block;padding:3px 10px;border-radius:20px;background:#f1f5f9;color:#64748b;font-size:12px;font-weight:700'>-- Unknown</span>" }
    }
}

$E8ScorecardHtml = "<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px'>"
$E8ScorecardHtml += "<div style='background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:16px;text-align:center'><div style='font-size:32px;font-weight:800;color:#166534'>$E8_L1Detected/8</div><div style='font-size:13px;color:#166534;font-weight:700'>Maturity Level 1</div><div style='font-size:12px;color:#4ade80;margin-top:4px'>$E8_L1Partial partial</div></div>"
$E8ScorecardHtml += "<div style='background:#fffbeb;border:1px solid #fde68a;border-radius:12px;padding:16px;text-align:center'><div style='font-size:32px;font-weight:800;color:#854d0e'>$E8_L2Detected/8</div><div style='font-size:13px;color:#854d0e;font-weight:700'>Maturity Level 2</div><div style='font-size:12px;color:#f59e0b;margin-top:4px'>$E8_L2Partial partial</div></div>"
$E8ScorecardHtml += "<div style='background:#fef2f2;border:1px solid #fecaca;border-radius:12px;padding:16px;text-align:center'><div style='font-size:32px;font-weight:800;color:#991b1b'>$E8_L3Detected/8</div><div style='font-size:13px;color:#991b1b;font-weight:700'>Maturity Level 3</div><div style='font-size:12px;color:#f87171;margin-top:4px'>$E8_L3Partial partial</div></div>"
$E8ScorecardHtml += "</div><div style='background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:12px 16px;margin-bottom:20px;font-size:13px;color:#334155'><b>Overall Assessment:</b> <span style='font-weight:700'>$E8_MaturityLabel</span></div>"

$E8TableHtml = "<div class='table-wrap'><table><thead><tr><th>Control</th><th style='text-align:center'>L1</th><th style='text-align:center'>L2</th><th style='text-align:center'>L3</th><th>Evidence</th><th>Action</th></tr></thead><tbody>"
foreach ($ctrl in $E8Controls) {
    $rowBg = switch ($ctrl.L1Status) { "Detected" {""} "Partial" {"style='background:#fffbeb'"} "Not Detected" {"style='background:#fff5f5'"} default {""} }
    $gapText = if ($ctrl.L1Status -ne "Detected") { $ctrl.L1Gap } elseif ($ctrl.L2Status -ne "Detected") { $ctrl.L2Gap } else { $ctrl.L3Gap }
    $evidenceText = if ($ctrl.L1Status -ne "Detected") { $ctrl.L1Evidence } elseif ($ctrl.L2Status -ne "Detected") { $ctrl.L2Evidence } else { $ctrl.L3Evidence }
    $E8TableHtml += "<tr $rowBg><td><strong>$(HtmlEncode $ctrl.Name)</strong></td><td style='text-align:center'>$(Get-E8StatusBadge $ctrl.L1Status)</td><td style='text-align:center'>$(Get-E8StatusBadge $ctrl.L2Status)</td><td style='text-align:center'>$(Get-E8StatusBadge $ctrl.L3Status)</td><td style='font-size:12px;color:#475569'>$(HtmlEncode $evidenceText)</td><td style='font-size:12px;color:#475569'>$(HtmlEncode $gapText)</td></tr>"
}
$E8TableHtml += "</tbody></table></div>"

$BackupSummaryHtml = "<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px'>"
$BackupSummaryHtml += "<div style='background:#f0f9ff;border:1px solid #bae6fd;border-radius:12px;padding:14px;text-align:center'><div style='font-size:28px;font-weight:800;color:#0369a1'>$($OneDriveUsers.Count)</div><div style='font-size:12px;color:#0369a1;font-weight:600'>OneDrive Accounts</div></div>"
$BackupSummaryHtml += "<div style='background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:14px;text-align:center'><div style='font-size:28px;font-weight:800;color:#166534'>$OneDriveActiveUsers</div><div style='font-size:12px;color:#166534;font-weight:600'>Active (30 days)</div></div>"
$BackupSummaryHtml += "<div style='background:#fafafa;border:1px solid #e2e8f0;border-radius:12px;padding:14px;text-align:center'><div style='font-size:28px;font-weight:800;color:#334155'>$OneDriveUsedStorageGB GB</div><div style='font-size:12px;color:#334155;font-weight:600'>Storage Used</div></div>"
$BackupSummaryHtml += "<div style='background:#fafafa;border:1px solid #e2e8f0;border-radius:12px;padding:14px;text-align:center'><div style='font-size:28px;font-weight:800;color:#334155'>$BackupPolicyCount</div><div style='font-size:12px;color:#334155;font-weight:600'>Backup Policies</div></div></div>"

$BackupMaturityHtml = "<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px'>"
foreach ($lvl in @(
    @{Label="Level 1 - Basic Backup"; Status=$AC8_L1Status; Evidence=$AC8_L1Evidence; Gap=$AC8_L1Gap},
    @{Label="Level 2 - Retention"; Status=$AC8_L2Status; Evidence=$AC8_L2Evidence; Gap=$AC8_L2Gap},
    @{Label="Level 3 - DR Automation"; Status=$AC8_L3Status; Evidence=$AC8_L3Evidence; Gap=$AC8_L3Gap}
)) {
    $bg = switch ($lvl.Status) { "Detected" {"#f0fdf4"} "Partial" {"#fffbeb"} default {"#fef2f2"} }
    $bd = switch ($lvl.Status) { "Detected" {"#bbf7d0"} "Partial" {"#fde68a"} default {"#fecaca"} }
    $tc = switch ($lvl.Status) { "Detected" {"#166534"} "Partial" {"#854d0e"} default {"#991b1b"} }
    $BackupMaturityHtml += "<div style='background:$bg;border:1px solid $bd;border-radius:12px;padding:14px'><div style='font-weight:700;color:$tc;margin-bottom:6px'>$(HtmlEncode $lvl.Label)</div>$(Get-E8StatusBadge $lvl.Status)<div style='font-size:12px;color:#475569;margin-top:8px'>$(HtmlEncode $lvl.Evidence)</div><div style='font-size:12px;color:$tc;margin-top:6px;font-style:italic'><b>Action:</b> $(HtmlEncode $lvl.Gap)</div></div>"
}
$BackupMaturityHtml += "</div>"

$BackupUsersHtml = ConvertTo-DataTableHtml -Data $BackupUsersTable -Columns @("User","LastActivity","FilesSynced","StorageGB","Status") -Headers @{User="User";LastActivity="Last Activity";FilesSynced="Files Synced";StorageGB="Storage (GB)";Status="Status"} -EmptyMessage "No OneDrive data returned."

$CollabTableHtml = "<div class='table-wrap'><table><thead><tr><th>Control</th><th style='text-align:center'>Status</th><th>Detail</th><th>Action</th></tr></thead><tbody>"
foreach ($sig in $CollabSignals) {
    $rowBg = switch ($sig.Status) { "Detected" {""} "Partial" {"style='background:#fffbeb'"} "Not Detected" {"style='background:#fff5f5'"} default {""} }
    $CollabTableHtml += "<tr $rowBg><td><strong>$(HtmlEncode $sig.Control)</strong></td><td style='text-align:center'>$(Get-E8StatusBadge $sig.Status)</td><td style='font-size:12px;color:#475569'>$(HtmlEncode $sig.Detail)</td><td style='font-size:12px;color:#475569'>$(HtmlEncode $sig.Gap)</td></tr>"
}
$CollabTableHtml += "</tbody></table></div>"

$CollabKpiHtml = "<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px'>"
$CollabKpiHtml += "<div style='background:$(if($CollabEOPSignal){"#f0fdf4"}else{"#fef2f2"});border:1px solid $(if($CollabEOPSignal){"#bbf7d0"}else{"#fecaca"});border-radius:12px;padding:14px;text-align:center'><div style='font-size:20px;font-weight:800;color:$(if($CollabEOPSignal){"#166534"}else{"#991b1b"})'>$(if($CollabEOPSignal){"EOP Active"}else{"EOP Gaps"})</div><div style='font-size:12px;color:#475569;margin-top:4px'>EOP</div></div>"
$CollabKpiHtml += "<div style='background:$(if($AttackSimCount -gt 0){"#f0fdf4"}else{"#fef2f2"});border:1px solid $(if($AttackSimCount -gt 0){"#bbf7d0"}else{"#fecaca"});border-radius:12px;padding:14px;text-align:center'><div style='font-size:28px;font-weight:800;color:$(if($AttackSimCount -gt 0){"#166534"}else{"#991b1b"})'>$AttackSimCount</div><div style='font-size:12px;color:#475569;margin-top:4px'>Simulations</div></div>"
$CollabKpiHtml += "<div style='background:$(if($O365AlertsActive -eq 0){"#f0fdf4"}else{"#fef2f2"});border:1px solid $(if($O365AlertsActive -eq 0){"#bbf7d0"}else{"#fecaca"});border-radius:12px;padding:14px;text-align:center'><div style='font-size:28px;font-weight:800;color:$(if($O365AlertsActive -eq 0){"#166534"}else{"#991b1b"})'>$O365AlertsActive</div><div style='font-size:12px;color:#475569;margin-top:4px'>Active Alerts</div></div>"
$CollabKpiHtml += "<div style='background:$(if($SensitivityLabelCount -gt 0){"#f0fdf4"}else{"#fffbeb"});border:1px solid $(if($SensitivityLabelCount -gt 0){"#bbf7d0"}else{"#fde68a"});border-radius:12px;padding:14px;text-align:center'><div style='font-size:28px;font-weight:800;color:$(if($SensitivityLabelCount -gt 0){"#166534"}else{"#854d0e"})'>$SensitivityLabelCount</div><div style='font-size:12px;color:#475569;margin-top:4px'>Labels (DLP)</div></div></div>"

$HtmlSection17 = "<div class='section' id='acsc'><div class='sec-num'>17</div><h2>ACSC Essential Eight Assessment</h2><div class='note'>Assesses controls against ACSC Essential Eight using Microsoft Graph, Intune, Entra ID, and Defender APIs.</div><div style='margin-top:16px'>$E8ScorecardHtml</div><div style='margin-top:8px'>$E8TableHtml</div></div>"
$HtmlSection21 = "<div class='section' id='backup'><div class='sec-num'>21</div><h2>Backup Health</h2><div class='note'>OneDrive usage + Intune backup policy detection.</div><div style='margin-top:16px'>$BackupSummaryHtml</div><h3 style='margin-top:16px'>Backup Maturity</h3>$BackupMaturityHtml<h3 style='margin-top:20px'>OneDrive Activity (Top 50)</h3>$BackupUsersHtml</div>"
$HtmlSection22 = "<div class='section' id='collab'><div class='sec-num'>22</div><h2>Collaboration & Voice Security</h2><div class='note'>M365 collaboration posture from Secure Score, Entra ID, Defender APIs.</div><div style='margin-top:16px'>$CollabKpiHtml</div><h3 style='margin-top:16px'>Control Assessment</h3>$CollabTableHtml</div>"


# ============================================================
# BUILD HTML - PATCHES 1, 2, 3, 4 APPLIED HERE
# ============================================================
$Html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8' />
<meta name='viewport' content='width=device-width, initial-scale=1' />
<title>EndUserRepo - $TenantName</title>
<!-- Apple-like Design: SF Pro via Inter/System stack -->
<link rel='preconnect' href='https://fonts.googleapis.com'>
<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>
<link href='https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap' rel='stylesheet'>
<style>
:root {
  --primary: #000000;
  --primary-2: #1d1d1f;
  --accent: #0071e3;
  --accent-2: #0071e3;
  --good: #28cd41;
  --good-soft: #f2fcf3;
  --warn: #ff9f0a;
  --warn-soft: #fff9f2;
  --bad: #ff3b30;
  --bad-soft: #fff5f5;
  --neutral: #86868b;
  --neutral-soft: #f5f5f7;
  --text: #1d1d1f;
  --text-soft: #424245;
  --border: #d2d2d7;
  --bg: #ffffff;
  --card: #ffffff;
  --radius: 20px;
  --shadow: 0 8px 30px rgba(0,0,0,0.04);
  --font-body: 'Inter', -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', sans-serif;
  --font-head: 'Inter', -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Helvetica Neue', sans-serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body { font-family: var(--font-body); background: var(--bg); color: var(--text); line-height: 1.55; font-size: 14px; font-feature-settings: 'cv11','ss01'; -webkit-font-smoothing: antialiased; }
.container { max-width: 1320px; margin: 0 auto; padding: 30px 28px 60px; }
h1, h2, h3, h4 { font-family: var(--font-head); margin: 0; color: var(--text); }
h2 { font-size: 22px; font-weight: 700; letter-spacing: -0.3px; }
h3 { font-size: 16px; font-weight: 600; color: var(--text-soft); margin-bottom: 8px; }

/* PATCH 3: ENTERPRISE-GRADE HEADER */
.header {
  background: #000000;
  border-radius: var(--radius);
  padding: 48px 40px;
  color: #fff;
  position: relative;
  overflow: hidden;
  margin-bottom: 32px;
}
.header::after {
  content: '';
  position: absolute;
  left: 40px; right: 40px; bottom: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.18), transparent);
  pointer-events: none;
}
.header-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; margin-bottom: 26px; position: relative; }
.brand { display: flex; align-items: center; gap: 18px; min-width: 0; }
.brand-logo {
  display: flex; align-items: center; justify-content: center;
  height: 64px; padding: 8px 14px;
  background: #ffffff;
  border-radius: 10px;
  box-shadow: 0 4px 14px rgba(0,0,0,0.18);
  flex-shrink: 0;
}
.brand-logo img { height: 44px; width: auto; max-width: 160px; display: block; object-fit: contain; }
.brand-logo .logo-fallback { font-family: var(--font-head); font-size: 18px; font-weight: 800; color: #0a1f44; letter-spacing: 1.5px; }
.brand-divider { width: 1px; align-self: stretch; background: linear-gradient(180deg, transparent, rgba(255,255,255,0.28), transparent); margin: 4px 0; }
.brand-text { display: flex; flex-direction: column; min-width: 0; }
.brand-eyebrow { font-size: 11px; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; color: rgba(255,255,255,0.5); margin-bottom: 4px; }
.brand-name { font-family: var(--font-head); font-size: 16px; font-weight: 600; color: #ffffff; letter-spacing: -0.1px; line-height: 1.2; }
.brand-sub { font-size: 12px; color: rgba(255,255,255,0.62); margin-top: 2px; letter-spacing: 0.2px; }
.report-meta { text-align: right; font-size: 12px; color: rgba(255,255,255,0.78); line-height: 1.7; flex-shrink: 0; }
.report-meta .meta-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; background: rgba(255,255,255,0.10); border: 1px solid rgba(255,255,255,0.18); border-radius: 999px; font-size: 11px; font-weight: 600; letter-spacing: 0.8px; text-transform: uppercase; color: #ffffff; margin-bottom: 8px; }
.report-meta .meta-line { color: rgba(255,255,255,0.78); }
.report-meta .meta-line b { color: #ffffff; font-weight: 500; }
.header-title { font-family: var(--font-head); font-size: 36px; font-weight: 700; letter-spacing: -0.8px; margin: 0 0 6px; line-height: 1.1; position: relative; }
.header-sub { font-size: 15px; color: rgba(255,255,255,0.82); font-weight: 400; margin-bottom: 24px; letter-spacing: 0.1px; position: relative; }
.header-stats { display: flex; gap: 0; flex-wrap: wrap; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.14); position: relative; }
.header-stat { display: flex; flex-direction: column; padding: 0 28px; border-right: 1px solid rgba(255,255,255,0.10); }
.header-stat:first-child { padding-left: 0; }
.header-stat:last-child { border-right: none; padding-right: 0; }
.header-stat-label { font-size: 10.5px; text-transform: uppercase; letter-spacing: 1.4px; color: rgba(255,255,255,0.62); font-weight: 600; margin-bottom: 6px; }
.header-stat-value { font-family: var(--font-head); font-size: 20px; font-weight: 600; color: #fff; letter-spacing: -0.3px; line-height: 1.2; }

/* TOC */
.toc { background: var(--card); border-radius: var(--radius); box-shadow: var(--shadow); padding: 20px 26px; margin-top: 22px; margin-bottom: 22px; }
.toc h3 { color: var(--primary); margin-bottom: 12px; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }
.toc-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.toc-item { padding: 8px 12px; border-radius: 8px; background: var(--neutral-soft); font-size: 13px; color: var(--text-soft); text-decoration: none; transition: background 0.2s; }
.toc-item:hover { background: #e0e7ff; color: var(--primary); }
.toc-num { display: inline-block; width: 22px; color: var(--primary); font-weight: 700; }

/* SECTIONS */
.section { background: var(--card); border-radius: var(--radius); box-shadow: var(--shadow); padding: 28px 30px; margin-bottom: 18px; position: relative; }
.section .sec-num { position: absolute; top: 22px; right: 26px; background: var(--neutral-soft); color: var(--text-soft); padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
.note { font-size: 13px; color: var(--text-soft); margin-top: 4px; line-height: 1.6; }

/* KPI GRID */
.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 16px; }
.kpi { background: linear-gradient(180deg, #ffffff, #fafafa); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px; transition: transform 0.15s; }
.kpi.good { border-left: 4px solid var(--good); }
.kpi.warn { border-left: 4px solid var(--warn); }
.kpi.bad  { border-left: 4px solid var(--bad); }
.kpi.neutral { border-left: 4px solid var(--neutral); }
.kpi-title { font-size: 11px; font-weight: 700; color: var(--text-soft); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
.kpi-value { font-size: 28px; font-weight: 800; color: var(--primary); line-height: 1.1; margin-bottom: 4px; }
.kpi-sub { font-size: 12px; color: var(--neutral); }

/* DONUTS */
.donut-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; margin-top: 22px; }
.donut-wrap { display: flex; flex-direction: column; align-items: center; gap: 12px; }
.donut { --p: 0; width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(var(--accent) calc(var(--p) * 1%), #e2e8f0 0); display: flex; align-items: center; justify-content: center; position: relative; flex-shrink: 0; }
.donut.good { background: conic-gradient(var(--good) calc(var(--p) * 1%), #e2e8f0 0); }
.donut.warn { background: conic-gradient(var(--warn) calc(var(--p) * 1%), #e2e8f0 0); }
.donut.bad  { background: conic-gradient(var(--bad)  calc(var(--p) * 1%), #e2e8f0 0); }
.donut.neutral { background: conic-gradient(var(--neutral) calc(var(--p) * 1%), #e2e8f0 0); }
.donut::before { content: ''; position: absolute; inset: 16%; background: #fff; border-radius: 50%; box-shadow: inset 0 1px 2px rgba(0,0,0,0.04); }
.donut-inner { position: relative; z-index: 1; text-align: center; line-height: 1; }
.donut-inner strong { display: block; font-family: var(--font-head); font-size: 24px; font-weight: 700; color: var(--primary); letter-spacing: -0.5px; }
.donut-label { font-size: 12px; font-weight: 600; color: var(--text-soft); text-align: center; letter-spacing: 0.2px; max-width: 120px; line-height: 1.3; }

/* BAR */
.bar { background: #e2e8f0; border-radius: 10px; height: 8px; overflow: hidden; margin-top: 8px; }
.bar-fill { height: 100%; border-radius: 10px; }
.bar-fill.good { background: var(--good); }
.bar-fill.warn { background: var(--warn); }
.bar-fill.bad { background: var(--bad); }

/* TABLE */
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; margin-top: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead th { background: linear-gradient(180deg, #f8fafc, #f1f5f9); color: var(--text-soft); text-align: left; padding: 10px 12px; font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; border-bottom: 2px solid var(--border); }
tbody td { padding: 9px 12px; border-bottom: 1px solid var(--border); color: var(--text); vertical-align: top; }
tbody tr:hover { background: #fafbff; }
tbody tr:last-child td { border-bottom: 0; }

/* RISK STRIP */
.risk-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 16px; }
.risk-tile { padding: 16px 18px; border-radius: 12px; color: #fff; box-shadow: var(--shadow); }
.risk-tile.bad { background: linear-gradient(135deg, #dc2626, #991b1b); }
.risk-tile.warn { background: linear-gradient(135deg, #f59e0b, #b45309); }
.risk-tile neutral { background: linear-gradient(135deg, #6366f1, #4338ca); }
.risk-tile.good { background: linear-gradient(135deg, #10b981, #047857); }
.risk-tile span { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; }
.risk-tile strong { display: block; font-size: 36px; font-weight: 800; margin: 6px 0 2px; }
.risk-tile small { font-size: 11px; opacity: 0.92; }

/* VULN CONTEXT */
.vuln-context { padding: 18px 22px; border-radius: 12px; margin-top: 16px; border-left: 5px solid; }
.vuln-context.vuln-red { background: #fff5f5; border-color: var(--bad); }
.vuln-context.vuln-orange { background: #fff8f0; border-color: var(--warn); }
.vuln-context.vuln-blue { background: #f0f9ff; border-color: var(--accent-2); }
.vuln-context.vuln-green { background: #f0fdf4; border-color: var(--good); }
.vuln-headline { font-size: 15px; font-weight: 800; color: var(--text); margin-bottom: 6px; }
.vuln-explain { font-size: 13px; color: var(--text-soft); line-height: 1.6; margin-bottom: 8px; }
.vuln-plan { font-size: 13px; color: var(--text); }

/* TOP RISKS */
.top-risk { display: flex; gap: 14px; padding: 14px 16px; background: #fafbff; border: 1px solid var(--border); border-radius: 12px; margin-bottom: 10px; align-items: center; }
.top-risk .risk-icon { font-size: 22px; flex-shrink: 0; }
.top-risk .risk-body { flex: 1; }
.top-risk .risk-text { font-size: 14px; font-weight: 700; margin-bottom: 2px; }
.top-risk .risk-action { font-size: 12px; color: var(--text-soft); }

/* EMPTY */
.empty { padding: 16px 18px; background: var(--neutral-soft); color: var(--text-soft); border-radius: 10px; font-size: 13px; text-align: center; margin-top: 12px; }

/* FOOTER */
.footer { margin-top: 30px; padding: 18px 22px; background: var(--card); border-radius: var(--radius); box-shadow: var(--shadow); font-size: 12px; color: var(--text-soft); display: flex; justify-content: space-between; align-items: center; }
.footer b { color: var(--primary); }

/* Scorecard */
.scorecard { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 14px; }
.scorecard-item { padding: 14px 16px; border-radius: 12px; background: #fafbff; border: 1px solid var(--border); }
.scorecard-item .label { font-size: 11px; font-weight: 700; color: var(--text-soft); text-transform: uppercase; letter-spacing: 1px; }
.scorecard-item .value { font-size: 15px; font-weight: 700; margin-top: 4px; }

@media print {
  body { background: #fff; }
  .container { padding: 16px; }
  .section { box-shadow: none; border: 1px solid var(--border); page-break-inside: avoid; }
  .header { box-shadow: none; }
}

/* =========================================== */
/* RESPONSIVE / MOBILE                          */
/* =========================================== */
@media (max-width: 1024px) {
  .container { padding: 22px 18px 40px; }
  .kpi-grid { grid-template-columns: repeat(3, 1fr); }
  .toc-grid { grid-template-columns: repeat(2, 1fr); }
  .donut-row { grid-template-columns: repeat(3, 1fr); }
  .risk-strip { grid-template-columns: repeat(2, 1fr); }
  .scorecard { grid-template-columns: repeat(2, 1fr); }
  /* Override inline-style grids inside sections (E8/Backup/Collab scorecards) */
  [style*='grid-template-columns:repeat(4'] { grid-template-columns: repeat(2, 1fr) !important; }
}

@media (max-width: 720px) {
  body { font-size: 13px; }
  .container { padding: 14px 10px 32px; }

  /* Header */
  .header { padding: 22px 20px 22px; border-radius: 12px; }
  .header::after { left: 20px; right: 20px; }
  .header-top { flex-direction: column; gap: 14px; margin-bottom: 18px; align-items: stretch; }
  .brand { gap: 14px; }
  .report-meta { text-align: left; }
  .brand-logo { height: 52px; padding: 6px 10px; }
  .brand-logo img { height: 36px; max-width: 130px; }
  .brand-logo .logo-fallback { font-size: 15px; }
  .brand-eyebrow { font-size: 10px; letter-spacing: 1.6px; }
  .brand-name { font-size: 14px; }
  .brand-sub { font-size: 11px; }
  .header-title { font-size: 24px; letter-spacing: -0.4px; margin-bottom: 4px; }
  .header-sub { font-size: 13px; margin-bottom: 18px; line-height: 1.4; }
  .header-stats { padding-top: 16px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px 12px; }
  .header-stat { padding: 0 !important; border-right: none !important; }
  .header-stat-label { font-size: 9.5px; letter-spacing: 1.2px; margin-bottom: 4px; }
  .header-stat-value { font-size: 16px; }

  /* Sections */
  .section { padding: 20px 16px; border-radius: 12px; margin-bottom: 14px; }
  .section .sec-num { top: 14px; right: 14px; font-size: 10px; padding: 2px 8px; }
  h2 { font-size: 18px; letter-spacing: -0.2px; }
  h3 { font-size: 14px; }

  /* TOC */
  .toc { padding: 16px 18px; }
  .toc h3 { font-size: 12px; }
  .toc-grid { grid-template-columns: 1fr; }
  .toc-item { font-size: 12.5px; padding: 7px 10px; }

  /* KPI cards */
  .kpi-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .kpi { padding: 12px 13px; border-radius: 12px; }
  .kpi-value { font-size: 22px; }
  .kpi-title { font-size: 10px; }
  .kpi-sub { font-size: 11px; }

  /* Donuts */
  .donut-row { grid-template-columns: repeat(2, 1fr); gap: 18px; }
  .donut { width: 108px; height: 108px; }
  .donut-inner strong { font-size: 22px; }
  .donut-label { font-size: 11.5px; }

  /* Risk strip */
  .risk-strip { grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .risk-tile { padding: 14px; }
  .risk-tile strong { font-size: 28px; }
  .risk-tile span { font-size: 11px; }

  /* Scorecard */
  .scorecard { grid-template-columns: 1fr; gap: 8px; }

  /* Vuln context */
  .vuln-context { padding: 14px 16px; }
  .vuln-headline { font-size: 14px; }
  .vuln-explain, .vuln-plan { font-size: 12.5px; }

  /* Tables - keep horizontal scroll */
  .table-wrap { font-size: 12px; }
  thead th { padding: 8px 9px; font-size: 10.5px; letter-spacing: 0.4px; }
  tbody td { padding: 7px 9px; }

  /* Top risk */
  .top-risk { padding: 12px 14px; gap: 10px; }
  .top-risk .risk-icon { font-size: 18px; }
  .top-risk .risk-text { font-size: 13px; }
  .top-risk .risk-action { font-size: 11.5px; }

  /* Footer */
  .footer { flex-direction: column; gap: 6px; align-items: flex-start; padding: 14px 16px; font-size: 11.5px; }

  /* Force ALL inline-style grids inside sections to stack */
  [style*='grid-template-columns:repeat'] { grid-template-columns: 1fr !important; }
}

@media (max-width: 420px) {
  .container { padding: 12px 8px 28px; }
  .header { padding: 18px 16px; }
  .header-stats { grid-template-columns: 1fr; gap: 12px; }
  .kpi-grid { grid-template-columns: 1fr; }
  .donut-row { grid-template-columns: 1fr; }
  .risk-strip { grid-template-columns: 1fr; }
  .header-title { font-size: 22px; }
  .brand-name { font-size: 13px; }
  .section { padding: 18px 14px; }
}
</style>
</head>
<body>
<div class='container'>

  <!-- PATCH 4: NEW ENTERPRISE HEADER HTML -->
  <div class='header'>
    <div class='header-top'>
      <div class='brand'>
        <div class='brand-logo'>$LogoHtml</div>
        <div class='brand-divider'></div>
        <div class='brand-text'>
          <div class='brand-eyebrow'>EndUserRepo</div>
          <div class='brand-name'>Cloud Analysis Dashboard</div>
          <div class='brand-sub'>The complete Cloud Analysis of your End user environment</div>
        </div>
      </div>
      <div class='report-meta'>
        <div class='meta-badge'>&#9679; $QuarterLabel Report</div>
        <div class='meta-line'>Generated <b>$GeneratedOn AEST</b></div>
        <div class='meta-line'>Tenant: <b>$TenantDefaultDomain</b></div>
      </div>
    </div>
    <div class='header-title'>$TenantName</div>
    <div class='header-sub'>Quarterly Security Posture & Compliance Review</div>
    <div class='header-stats'>
      <div class='header-stat'>
        <div class='header-stat-label'>Overall Status</div>
        <div class='header-stat-value' style='color:$OverallStatusColor'>$OverallStatus</div>
      </div>
      <div class='header-stat'>
        <div class='header-stat-label'>Health Score</div>
        <div class='header-stat-value'>$HealthScore%</div>
      </div>
      <div class='header-stat'>
        <div class='header-stat-label'>Business Risk</div>
        <div class='header-stat-value'>$BusinessRisk</div>
      </div>
      <div class='header-stat'>
        <div class='header-stat-label'>Managed Devices</div>
        <div class='header-stat-value'>$($ManagedDevices.Count)</div>
      </div>
      <div class='header-stat'>
        <div class='header-stat-label'>Active Users</div>
        <div class='header-stat-value'>$($EnabledUsers.Count)</div>
      </div>
    </div>
  </div>

  <!-- TOC -->
  <div class='toc'>
    <h3>Table of Contents</h3>
    <div class='toc-grid'>
      <a class='toc-item' href='#exec'><span class='toc-num'>1.</span> Executive Summary</a>
      <a class='toc-item' href='#topRisks'><span class='toc-num'>2.</span> Top Risks</a>
      <a class='toc-item' href='#trend'><span class='toc-num'>3.</span> Trends</a>
      <a class='toc-item' href='#kpi'><span class='toc-num'>4.</span> Key Indicators</a>
      <a class='toc-item' href='#posture'><span class='toc-num'>5.</span> Security Posture</a>
      <a class='toc-item' href='#highrisk'><span class='toc-num'>6.</span> High-Risk Devices</a>
      <a class='toc-item' href='#inv'><span class='toc-num'>7.</span> Device Inventory</a>
      <a class='toc-item' href='#nc'><span class='toc-num'>8.</span> Non-Compliant</a>
      <a class='toc-item' href='#enc'><span class='toc-num'>9.</span> Encryption</a>
      <a class='toc-item' href='#stale'><span class='toc-num'>10.</span> Stale Intune</a>
      <a class='toc-item' href='#entraStale'><span class='toc-num'>11.</span> Stale Entra</a>
      <a class='toc-item' href='#patch'><span class='toc-num'>12.</span> Patch Health</a>
      <a class='toc-item' href='#vuln'><span class='toc-num'>13.</span> Vulnerabilities</a>
      <a class='toc-item' href='#defender'><span class='toc-num'>14.</span> Defender Coverage</a>
      <a class='toc-item' href='#alerts'><span class='toc-num'>15.</span> Security Alerts</a>
      <a class='toc-item' href='#identity'><span class='toc-num'>16.</span> Identity & MFA</a>
      <a class='toc-item' href='#acsc'><span class='toc-num'>17.</span> ACSC Essential 8</a>
      <a class='toc-item' href='#rec'><span class='toc-num'>18.</span> Recommendations</a>
      <a class='toc-item' href='#concl'><span class='toc-num'>19.</span> Conclusion</a>
      <a class='toc-item' href='#meth'><span class='toc-num'>20.</span> Methodology</a>
      <a class='toc-item' href='#backup'><span class='toc-num'>21.</span> Backup Health</a>
      <a class='toc-item' href='#collab'><span class='toc-num'>22.</span> Collaboration</a>
    </div>
  </div>

  <!-- 1. EXECUTIVE SUMMARY -->
  <div class='section' id='exec'>
    <div class='sec-num'>1</div>
    <h2>Executive Summary</h2>
    <p class='note'>$ReportPeriodText</p>
    <div class='scorecard'>
      <div class='scorecard-item'><div class='label'>Device Compliance</div><div class='value' style='color:$CompScoreColor'>$CompScoreText</div></div>
      <div class='scorecard-item'><div class='label'>Disk Encryption</div><div class='value' style='color:$EncScoreColor'>$EncScoreText</div></div>
      <div class='scorecard-item'><div class='label'>Conditional Access</div><div class='value' style='color:$CAScoreColor'>$CAScoreText</div></div>
      <div class='scorecard-item'><div class='label'>Identity Risk</div><div class='value' style='color:$IdScoreColor'>$IdScoreText</div></div>
      <div class='scorecard-item'><div class='label'>Defender Coverage</div><div class='value' style='color:$DefScoreColor'>$DefScoreText</div></div>
      <div class='scorecard-item'><div class='label'>MFA Adoption</div><div class='value' style='color:$MFAScoreColor'>$MFAScoreText</div></div>
    </div>
    <h3 style='margin-top:20px'>Key Observations</h3>
    <ul style='margin:6px 0 0 20px;padding:0;color:var(--text-soft);font-size:13.5px;line-height:1.8'>$FindingsHtml</ul>
    <h3 style='margin-top:16px'>Suggested Actions</h3>
    <ul style='margin:6px 0 0 20px;padding:0;color:var(--text-soft);font-size:13.5px;line-height:1.8'>$ActionsHtml</ul>
  </div>

  <!-- 2. TOP RISKS -->
  <div class='section' id='topRisks'>
    <div class='sec-num'>2</div>
    <h2>Top Risks Right Now</h2>
    <div class='note'>Most pressing items needing attention this quarter.</div>
    <div style='margin-top:14px'>$TopRisksHtml</div>
  </div>

  <!-- 3. TRENDS -->
  <div class='section' id='trend'>
    <div class='sec-num'>3</div>
    <h2>Trends vs Last Run</h2>
    <div class='note'>Compares key metrics against the previous report run.</div>
    $TrendHtml
  </div>

  <!-- 4. KPI -->
  <div class='section' id='kpi'>
    <div class='sec-num'>4</div>
    <h2>Key Indicators</h2>
    <div class='note'>Headline measures of device and identity posture.</div>
    <div class='kpi-grid'>$CardsHtml</div>
  </div>

  <!-- 5. POSTURE -->
  <div class='section' id='posture'>
    <div class='sec-num'>5</div>
    <h2>Security Posture at a Glance</h2>
    <div class='note'>Coverage and compliance ratios from Microsoft cloud APIs.</div>
    <div class='donut-row'>
      $ManagedCoverageDonutHtml
      $ComplianceDonutHtml
      $EncryptionDonutHtml
      $DefenderDonutHtml
      $PatchDonutHtml
    </div>
  </div>

  <!-- 6. HIGH-RISK -->
  <div class='section' id='highrisk'>
    <div class='sec-num'>6</div>
    <h2>High-Risk Devices (Multi-Factor Correlation)</h2>
    <div class='note'>Devices triggering multiple risk signals.</div>
    $HighRiskHtml
  </div>

  <!-- 7. INVENTORY -->
  <div class='section' id='inv'>
    <div class='sec-num'>7</div>
    <h2>Device Inventory Overview</h2>
    <div class='note'>Showing first 75 managed devices. Full CSV in output folder.</div>
    $ManagedInventoryHtml
    <h3 style='margin-top:18px'>OS Release Distribution</h3>
    $OSSummaryHtml
    <h3 style='margin-top:18px'>Windows Edition Distribution</h3>
    $EditionSummaryHtml
    <h3 style='margin-top:18px'>Top Make/Model</h3>
    $ModelSummaryHtml
  </div>

  <!-- 8. NON-COMPLIANT -->
  <div class='section' id='nc'>
    <div class='sec-num'>8</div>
    <h2>Non-Compliant Devices</h2>
    <div class='note'>Devices marked non-compliant by Intune policy.</div>
    $NonCompliantHtml
  </div>

  <!-- 9. ENCRYPTION -->
  <div class='section' id='enc'>
    <div class='sec-num'>9</div>
    <h2>Devices Needing Encryption Attention</h2>
    <div class='note'>Managed devices not reporting encryption.</div>
    $NotEncryptedHtml
  </div>

  <!-- 10. STALE INTUNE -->
  <div class='section' id='stale'>
    <div class='sec-num'>10</div>
    <h2>Stale Managed Devices (>7 days)</h2>
    <div class='note'>Intune-managed devices not synced in 7+ days.</div>
    $Stale7Html
    <h3 style='margin-top:18px'>Stale Managed Devices (>30 days)</h3>
    $Stale30Html
  </div>

  <!-- 11. STALE ENTRA -->
  <div class='section' id='entraStale'>
    <div class='sec-num'>11</div>
    <h2>Stale Entra Devices (90+ days)</h2>
    <div class='note'>Directory hygiene - device records not signed in for 90+ days.</div>
    $EntraStaleBanner
    $EntraCleanupSteps
    $EntraStaleHtml
  </div>

  <!-- 12. PATCH -->
  <div class='section' id='patch'>
    <div class='sec-num'>12</div>
    <h2>Windows Patch & Update Health</h2>
    <div class='note'>Patch health is based on devices actively reporting and whether update state can be validated. Defender vulnerability findings are shown separately as exposure signals and do not automatically make patch health zero.</div>
    <h3 style='margin-top:14px'>Summary</h3>
    $PatchSummaryHtml
    <h3 style='margin-top:18px'>Devices Needing Attention</h3>
    $PatchAttentionHtml
    <h3 style='margin-top:18px'>Update Policies in Tenant</h3>
    $UpdatePolicyHtml
  </div>

  <!-- 13. VULNERABILITIES -->
  <div class='section' id='vuln'>
    <div class='sec-num'>13</div>
    <h2>Vulnerability Posture</h2>
    <div class='note'>Defender for Endpoint vulnerability findings.</div>
    $VulnerabilitySummaryHtml
    $VulnContextHtml
  </div>

  <!-- 14. DEFENDER -->
  <div class='section' id='defender'>
    <div class='sec-num'>14</div>
    <h2>Defender Coverage Mapping</h2>
    <div class='note'>Intune managed devices visible in Defender for Endpoint.</div>
    $DefenderMappedHtml
  </div>

  <!-- 15. ALERTS -->
  <div class='section' id='alerts'>
    <div class='sec-num'>15</div>
    <h2>Recent Defender Alerts</h2>
    <div class='note'>Showing latest 100 alerts.</div>
    $DefenderAlertsHtml
  </div>

  <!-- 16. IDENTITY -->
  <div class='section' id='identity'>
    <div class='sec-num'>16</div>
    <h2>Identity Protection & MFA</h2>
    <div class='note'>$CAEnforcementNote</div>
    <h3 style='margin-top:14px'>Risky Users (Active)</h3>
    $RiskyUsersHtml
    <h3 style='margin-top:18px'>Users Without MFA Registered</h3>
    $MFANotRegHtml
  </div>

  $HtmlSection17

  <!-- 18. RECOMMENDATIONS -->
  <div class='section' id='rec'>
    <div class='sec-num'>18</div>
    <h2>Recommendations (Operational Plan)</h2>
    <div class='note'>Prioritised actions for your environment.</div>
    <div style='margin-top:14px'>
      $Rec1Html
      $Rec2Html
      $Rec3Html
    </div>
  </div>

  <!-- 19. CONCLUSION -->
  <div class='section' id='concl'>
    <div class='sec-num'>19</div>
    <h2>Conclusion</h2>
    <p class='note' style='white-space:pre-line'>$ConclusionText</p>
  </div>

  <!-- 20. METHODOLOGY -->
  <div class='section' id='meth'>
    <div class='sec-num'>20</div>
    <h2>Methodology & Data Sources</h2>
    <p class='note'>This report uses read-only Microsoft Graph and Defender for Endpoint APIs. All findings are evidence-based and traceable to API responses.</p>
    <ul style='margin:8px 0 0 20px;color:var(--text-soft);font-size:13.5px;line-height:1.8'>
      <li><b>Microsoft Graph v1.0/beta:</b> Organization, Users, Devices, Managed Devices, Conditional Access, Identity Protection, Secure Score, MFA registration.</li>
      <li><b>Defender for Endpoint API:</b> Machines, alerts, vulnerabilities, software inventory.</li>
      <li><b>ACSC Essential Eight:</b> Mapped using detection signals (configuration policies, secure score controls, identity/admin posture).</li>
      <li><b>Output:</b> HTML dashboard + CSVs in <code>$OutputPath</code></li>
    </ul>
  </div>

  $HtmlSection21
  $HtmlSection22

  <div class='footer'>
    <div><b>EndUserRepo by SDMSGUY</b> | Confidential | $QuarterLabel</div>
    <div>Generated $GeneratedOn AEST | $TenantDefaultDomain</div>
  </div>

</div>
</body>
</html>
"@

# ============================================================
# WRITE FILE
# ============================================================
try {
    $Html | Set-Content -Path $HtmlPath -Encoding UTF8
    Write-Log "HTML dashboard written: $HtmlPath" "SUCCESS"
} catch {
    Write-Log "Failed to write HTML: $($_.Exception.Message)" "ERROR"
    throw
}

$pdfSuccess = Try-ExportPdf -HtmlFile $HtmlPath -PdfFile $PdfPath

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  EndUserRepo by SDMSGUY" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Tenant        : $TenantName" -ForegroundColor White
Write-Host "Domain        : $TenantDefaultDomain" -ForegroundColor White
Write-Host "Health Score  : $HealthScore% ($($HealthBand.Label))" -ForegroundColor White
Write-Host "Status        : $OverallStatus" -ForegroundColor White
Write-Host "Devices       : $($ManagedDevices.Count) managed / $($Devices.Count) Entra" -ForegroundColor White
Write-Host "Compliance    : $CompliancePercent%" -ForegroundColor White
Write-Host "Encryption    : $EncryptionPercent%" -ForegroundColor White
Write-Host "Defender Cov. : $DefenderCoveragePercent%" -ForegroundColor White
Write-Host "Patch Health  : $PatchHealthPercent%" -ForegroundColor White
Write-Host "MFA Coverage  : $MFACoveragePercent%" -ForegroundColor White
Write-Host "Active Alerts : $($ActiveDefenderAlerts.Count) ($($HighDefenderAlerts.Count) high/critical)" -ForegroundColor White
Write-Host ""
Write-Host "HTML Report   : $HtmlPath" -ForegroundColor Green
if ($pdfSuccess) { Write-Host "PDF Report    : $PdfPath" -ForegroundColor Green }
Write-Host "CSV Files     : $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Log "EndUserRepo cloud analysis complete." "SUCCESS"
