param(
    [string]$ConfigPath = "config.local.yml",
    [string]$EnvFilePath = ".env",
    [switch]$SkipDependencySync,
    [switch]$RunAfterSetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-Required {
    param([string]$Prompt)
    while ($true) {
        $value = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value.Trim()
        }
        Write-Host "Value is required." -ForegroundColor Yellow
    }
}

function Read-Default {
    param(
        [string]$Prompt,
        [string]$DefaultValue
    )
    $value = Read-Host "$Prompt [$DefaultValue]"
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }
    return $value.Trim()
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $false
    )
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $raw = Read-Host "$Prompt $suffix"
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $Default
        }
        switch ($raw.Trim().ToLowerInvariant()) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
            default { Write-Host "Please answer y or n." -ForegroundColor Yellow }
        }
    }
}

function Escape-YamlSingleQuoted {
    param([string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Escape-PowerShellSingleQuoted {
    param([string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Test-AutopsyInstallCandidate {
    param([string]$CandidatePath)

    if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return $false }
    if (-not (Test-Path -LiteralPath $CandidatePath -PathType Container)) { return $false }

    $markers = @(
        (Join-Path -Path $CandidatePath -ChildPath "bin\autopsy64.exe"),
        (Join-Path -Path $CandidatePath -ChildPath "bin\autopsy.exe"),
        (Join-Path -Path $CandidatePath -ChildPath "autopsy64.exe"),
        (Join-Path -Path $CandidatePath -ChildPath "autopsy.exe"),
        (Join-Path -Path $CandidatePath -ChildPath "bin\autopsy")
    )
    foreach ($m in $markers) {
        if (Test-Path -LiteralPath $m -PathType Leaf) {
            return $true
        }
    }

    return $CandidatePath.ToLowerInvariant().Contains("autopsy")
}

function Get-AutopsyInstallCandidates {
    $results = New-Object System.Collections.Generic.List[string]
    $seen = @{}

    $roots = @()
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $roots += $env:ProgramFiles
    }
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $roots += ${env:ProgramFiles(x86)}
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $roots += (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Programs")
    }

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($pattern in @("Autopsy*", "autopsy*")) {
            $dirs = Get-ChildItem -LiteralPath $root -Directory -Filter $pattern -ErrorAction SilentlyContinue
            foreach ($d in $dirs) {
                if (Test-AutopsyInstallCandidate -CandidatePath $d.FullName) {
                    $key = $d.FullName.ToLowerInvariant()
                    if (-not $seen.ContainsKey($key)) {
                        $seen[$key] = $true
                        $results.Add($d.FullName)
                    }
                }
            }
        }
    }

    foreach ($exeName in @("autopsy64.exe", "autopsy.exe")) {
        $cmd = Get-Command $exeName -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) {
            try {
                $exePath = [System.IO.Path]::GetFullPath($cmd.Source)
                $binDir = Split-Path -Path $exePath -Parent
                $candidate = Split-Path -Path $binDir -Parent
                if (Test-AutopsyInstallCandidate -CandidatePath $candidate) {
                    $key = $candidate.ToLowerInvariant()
                    if (-not $seen.ContainsKey($key)) {
                        $seen[$key] = $true
                        $results.Add($candidate)
                    }
                }
            } catch {
                # ignore
            }
        }
    }

    return $results
}

function Show-CaseDirHints {
    param([string]$CaseDir)

    if (-not (Test-Path -LiteralPath $CaseDir)) {
        Write-Host "Hint: case_dir path does not exist yet. Validation may fail until the case is available." -ForegroundColor Yellow
        return
    }

    $hasAut = $false
    $hasLogDir = Test-Path -LiteralPath (Join-Path -Path $CaseDir -ChildPath "Log") -PathType Container
    $hasDb = Test-Path -LiteralPath (Join-Path -Path $CaseDir -ChildPath "autopsy.db") -PathType Leaf

    try {
        $autFiles = Get-ChildItem -LiteralPath $CaseDir -Filter "*.aut" -File -ErrorAction SilentlyContinue
        $hasAut = ($autFiles | Measure-Object).Count -gt 0
    } catch {
        $hasAut = $false
    }

    if (-not $hasAut) {
        Write-Host "Hint: no .aut file found in case_dir (Autopsy case descriptor)." -ForegroundColor Yellow
    }
    if (-not ($hasLogDir -or $hasDb)) {
        Write-Host "Hint: expected either Log\ directory or autopsy.db in case_dir." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "AutopsyGuard Setup Wizard (Windows)" -ForegroundColor Cyan
Write-Host "This will generate a config file and a .env file for secrets." -ForegroundColor Cyan
Write-Host "Secrets in .env are loaded automatically by AutopsyGuard at startup." -ForegroundColor Cyan
Write-Host "OAuth web login for Gmail/Microsoft is supported via autopsyguard-oauth." -ForegroundColor Cyan
Write-Host ""
Write-Host "Quick guidance:" -ForegroundColor DarkCyan
Write-Host "  - case_dir should contain *.aut and (Log\ or autopsy.db)"
Write-Host "  - autopsy_install_dir is optional (mainly improves JVM crash file search)"
Write-Host "  - SMTP 587 -> smtp_use_ssl=false (STARTTLS), SMTP 465 -> smtp_use_ssl=true"
Write-Host "  - Install-dir lookup targets Windows defaults: Program Files / Program Files (x86)"
Write-Host ""

# Pre-flight check for Autopsy 4.22 on Windows 11
$wmicPath = Get-Command "wmic" -ErrorAction SilentlyContinue
if (-not $wmicPath) {
    Write-Host "[WARNING]: 'wmic' command is missing from your system!" -ForegroundColor Red
    Write-Host "Autopsy 4.22.1 requires 'wmic' to manage its embedded Solr service." -ForegroundColor Yellow
    Write-Host "Because Windows 11 recently removed 'wmic', Autopsy WILL CRASH on startup." -ForegroundColor Yellow
    Write-Host "To fix this, go to Windows Settings -> System -> Optional Features and install 'WMI Commandline Utility'." -ForegroundColor Yellow
    Write-Host ""
    
    $continueSetup = Read-YesNo "Do you want to continue setup anyway?" $false
    if (-not $continueSetup) {
        Write-Host "Setup aborted." -ForegroundColor Red
        exit 1
    }
    Write-Host ""
}

if (-not $SkipDependencySync) {
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($null -eq $uv) {
        Write-Host "Warning: 'uv' command not found. Install uv first, then run this script again." -ForegroundColor Yellow
    } else {
        if (Read-YesNo "Run 'uv sync' now?" $true) {
            uv sync
        }
    }
}
Write-Host ""
Write-Host "--- 1. Target Directories ---" -ForegroundColor Cyan
Write-Host "AutopsyGuard needs to know where your Autopsy case is located to monitor its logs and locks." -ForegroundColor Gray
Write-Host "If you don't have one yet, just press Enter to set it up later." -ForegroundColor Gray
$caseDir = Read-Host "Autopsy case directory (case_dir, optional)"
if ([string]::IsNullOrWhiteSpace($caseDir)) {
    $caseDir = "C:\Path\To\Your\Case"
    Write-Host "Note: You must edit config.local.yml to set the actual case_dir before running AutopsyGuard." -ForegroundColor Yellow
} else {
    if (-not (Test-Path -LiteralPath $caseDir)) {
        Write-Host "Warning: path does not currently exist: $caseDir" -ForegroundColor Yellow
    }
    Show-CaseDirHints -CaseDir $caseDir
}

$autopsyInstallDir = ""
$installCandidates = @(Get-AutopsyInstallCandidates)
if ($installCandidates.Count -gt 0) {
    Write-Host ""
    Write-Host "Detected Autopsy install-dir candidates:" -ForegroundColor Cyan
    $max = [Math]::Min(10, $installCandidates.Count)
    for ($i = 0; $i -lt $max; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $installCandidates[$i])
    }
    if ($installCandidates.Count -gt 10) {
        Write-Host ("  ... plus {0} more" -f ($installCandidates.Count - 10))
    }
    while ($true) {
        $selection = Read-Host "Choose candidate number [1], M for manual path, or S to skip"
        if ([string]::IsNullOrWhiteSpace($selection)) {
            $selection = "1"
        }
        $selection = $selection.Trim()
        if ($selection.Equals("M", [System.StringComparison]::OrdinalIgnoreCase)) {
            $autopsyInstallDir = Read-Host "Autopsy install directory (optional, for hs_err_pid*.log search)"
            break
        }
        if ($selection.Equals("S", [System.StringComparison]::OrdinalIgnoreCase)) {
            $autopsyInstallDir = ""
            break
        }
        $idx = 0
        if ([int]::TryParse($selection, [ref]$idx) -and $idx -ge 1 -and $idx -le $installCandidates.Count) {
            $autopsyInstallDir = $installCandidates[$idx - 1]
            break
        }
        Write-Host "Invalid selection. Please choose a valid number, M, or S." -ForegroundColor Yellow
    }
} else {
    Write-Host "No install dir auto-detected. You can leave it blank (optional)." -ForegroundColor Yellow
    $autopsyInstallDir = Read-Host "Autopsy install directory (optional, for hs_err_pid*.log search)"
}

Write-Host ""
Write-Host "--- 2. Performance & Polling ---" -ForegroundColor Cyan
Write-Host "Configure how often AutopsyGuard checks the system and when to assume the process is hung." -ForegroundColor Gray
$pollInterval = Read-Default "poll_interval (seconds)" "30.0"
$hangTimeout = Read-Default "hang_timeout (seconds)" "900.0"
$reportInterval = Read-Default "report_interval_hours (e.g., 12.0 for half-day, 0.5 for 30 min)" "12.0"
Write-Host ""
Write-Host "--- 3. Notifications (Email) ---" -ForegroundColor Cyan
Write-Host "Configure email alerts for crashes, warnings, and periodic status reports." -ForegroundColor Gray
Write-Host "Use App Passwords for Gmail/O365. Avoid sharing your main account password." -ForegroundColor Gray
$emailEnabled = Read-YesNo "Configure email notifications?" $true
$smtpHost = ""
$smtpPort = "587"
$smtpUseSsl = $false
$smtpAsync = $true
$emailSender = "autopsyguard@example.com"
$emailRecipient = ""
$emailCaseLabel = ""
$smtpUser = ""
$smtpPassword = ""
$smtpAuthMode = "password"
$smtpOauthProvider = ""
$smtpOauthClientId = ""
$smtpOauthClientSecret = ""
$smtpOauthTenant = "common"
$smtpOauthTokenFile = ""

if ($emailEnabled) {
    Write-Host "Email provider presets:" -ForegroundColor Cyan
    Write-Host "  [1] Gmail (smtp.gmail.com:587 STARTTLS)"
    Write-Host "  [2] Office 365 / Outlook (smtp.office365.com:587 STARTTLS)"
    Write-Host "  [3] Custom SMTP"
    $providerConfigured = $false
    while ($true) {
        $providerChoice = Read-Host "Provider [3]"
        if ([string]::IsNullOrWhiteSpace($providerChoice)) {
            $providerChoice = "3"
        }
        switch ($providerChoice.Trim()) {
            "1" {
                $smtpHost = "smtp.gmail.com"
                $smtpPort = "587"
                $smtpUseSsl = $false
                Write-Host "Preset selected: Gmail (STARTTLS on port 587)." -ForegroundColor Green
                $providerConfigured = $true
                continue
            }
            "2" {
                $smtpHost = "smtp.office365.com"
                $smtpPort = "587"
                $smtpUseSsl = $false
                Write-Host "Preset selected: Office 365 (STARTTLS on port 587)." -ForegroundColor Green
                $providerConfigured = $true
                continue
            }
            "3" {
                $smtpHost = Read-Required "SMTP host (smtp_host)"
                $smtpPort = Read-Default "SMTP port (smtp_port)" "587"
                $smtpUseSsl = Read-YesNo "Use SMTP SSL (smtp_use_ssl)? Use true for port 465, false for STARTTLS on 587" $false
                $providerConfigured = $true
                continue
            }
            default {
                Write-Host "Please choose 1, 2, or 3." -ForegroundColor Yellow
            }
        }
        if ($providerConfigured) {
            break
        }
    }
    $smtpAsync = Read-YesNo "Send email asynchronously (smtp_async)?" $true
    $emailSender = Read-Default "Email sender (email_sender)" "autopsyguard@example.com"
    $emailRecipient = Read-Required "Email recipient (email_recipient)"
    $emailCaseLabel = Read-Host "Email case label (email_case_label, optional)"

    $defaultOauth = $smtpHost -in @("smtp.gmail.com", "smtp.office365.com")
    if (Read-YesNo "Use OAuth2 web login for SMTP (recommended for Gmail/O365)?" $defaultOauth) {
        $smtpAuthMode = "oauth"
        Write-Host ""
        Write-Host "OAuth setup needs an app registration first (Client ID)." -ForegroundColor Cyan
        Write-Host "  - Google: Google Cloud Console > APIs & Services > Credentials > OAuth client ID" -ForegroundColor Gray
        Write-Host "  - Microsoft: Azure/Entra > App registrations > Application (client) ID" -ForegroundColor Gray
        if (-not (Read-YesNo "Do you already have an OAuth Client ID ready?" $true)) {
            Write-Host "Switching email auth mode to password for now. You can re-run setup later to enable OAuth." -ForegroundColor Yellow
            $smtpAuthMode = "password"
        }
    }

    if ($smtpAuthMode -eq "oauth") {
        if ($smtpHost -eq "smtp.gmail.com") {
            $smtpOauthProvider = "google"
        } elseif ($smtpHost -eq "smtp.office365.com") {
            $smtpOauthProvider = "microsoft"
        } else {
            while ($true) {
                $providerChoice = Read-Host "OAuth provider [1=Google, 2=Microsoft]"
                switch ($providerChoice.Trim()) {
                    "1" { $smtpOauthProvider = "google"; break }
                    "2" { $smtpOauthProvider = "microsoft"; break }
                    default { Write-Host "Please choose 1 or 2." -ForegroundColor Yellow }
                }
                if (-not [string]::IsNullOrWhiteSpace($smtpOauthProvider)) { break }
            }
        }

        $smtpUser = Read-Required "SMTP user / account email (smtp_user)"
        $smtpOauthClientId = Read-Required "OAuth client id (smtp_oauth_client_id) [from your app registration]"
        $smtpOauthClientSecret = Read-Host "OAuth client secret (optional; store in env as AUTOPSYGUARD_SMTP_OAUTH_CLIENT_SECRET)"
        if ($smtpOauthProvider -eq "microsoft") {
            $smtpOauthTenant = Read-Default "Microsoft tenant (smtp_oauth_tenant)" "common"
        }
        $safeUser = $smtpUser.ToLowerInvariant().Replace("@", "_at_")
        $defaultTokenFile = ".autopsyguard\oauth\$($smtpOauthProvider)_$safeUser.json"
        $smtpOauthTokenFile = Read-Default "OAuth token file path (smtp_oauth_token_file)" $defaultTokenFile
    } else {
        $smtpAuthMode = "password"
        $smtpUser = Read-Host "SMTP user (optional, stored in env as AUTOPSYGUARD_SMTP_USER)"
        $secure = Read-Host "SMTP password (optional, stored in env as AUTOPSYGUARD_SMTP_PASSWORD)" -AsSecureString
        if ($secure.Length -gt 0) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try {
                $smtpPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    if ($smtpUseSsl -and $smtpPort -eq "587") {
        Write-Host "Suggestion: SMTP port 587 usually uses STARTTLS (smtp_use_ssl=false)." -ForegroundColor Yellow
    }
    if (-not $smtpUseSsl -and $smtpPort -eq "465") {
        Write-Host "Suggestion: SMTP port 465 usually uses implicit SSL (smtp_use_ssl=true)." -ForegroundColor Yellow
    }
}
Write-Host ""
Write-Host "--- 4. Notifications (WhatsApp) ---" -ForegroundColor Cyan
Write-Host "You can receive alerts on WhatsApp via CallMeBot API (availability/limits depend on account/region)." -ForegroundColor Gray
Write-Host "If WhatsApp setup is not available for you, Telegram is usually simpler." -ForegroundColor Gray
$whatsappEnabled = Read-YesNo "Configure WhatsApp notifications?" $false
$whatsappPhone = ""
$whatsappApiKey = ""
if ($whatsappEnabled) {
    $whatsappPhone = Read-Required "WhatsApp phone (+countrycode...)"
    $whatsappApiKey = Read-Host "WhatsApp API key (optional; if blank, keep disabled until set)"
    if ([string]::IsNullOrWhiteSpace($whatsappApiKey)) {
        Write-Host "Note: WhatsApp requires AUTOPSYGUARD_WHATSAPP_APIKEY before alerts can be sent." -ForegroundColor Yellow
    }
}
Write-Host ""
Write-Host "--- 5. Notifications (Telegram) ---" -ForegroundColor Cyan
Write-Host "You can receive instant text alerts on Telegram via the free CallMeBot API." -ForegroundColor Gray
$telegramEnabled = Read-YesNo "Configure Telegram notifications?" $false
$telegramUser = ""
if ($telegramEnabled) {
    $telegramUser = Read-Required "Telegram user (e.g. @myusername)"
}

$configLines = @()
$configLines += "# Generated by scripts\setup-autopsyguard.ps1"
$configLines += "# You can edit this file manually after setup."
$configLines += "case_dir: $(Escape-YamlSingleQuoted $caseDir)"
if (-not [string]::IsNullOrWhiteSpace($autopsyInstallDir)) {
    $configLines += "autopsy_install_dir: $(Escape-YamlSingleQuoted $autopsyInstallDir.Trim())"
}
$configLines += "poll_interval: $pollInterval"
$configLines += "hang_timeout: $hangTimeout"
$configLines += "report_interval_hours: $reportInterval"
$configLines += ""
$configLines += "# Email (enabled when smtp_host and email_recipient are set)"
$configLines += "smtp_host: $(Escape-YamlSingleQuoted $smtpHost)"
$configLines += "smtp_port: $smtpPort"
$configLines += "smtp_use_ssl: $($smtpUseSsl.ToString().ToLowerInvariant())"
$configLines += "smtp_async: $($smtpAsync.ToString().ToLowerInvariant())"
$configLines += "smtp_auth_mode: $(Escape-YamlSingleQuoted $smtpAuthMode)"
$configLines += "smtp_oauth_provider: $(Escape-YamlSingleQuoted $smtpOauthProvider)"
$configLines += "smtp_oauth_client_id: $(Escape-YamlSingleQuoted $smtpOauthClientId)"
$configLines += "smtp_oauth_client_secret: ''"
$configLines += "smtp_oauth_tenant: $(Escape-YamlSingleQuoted $smtpOauthTenant)"
$configLines += "smtp_oauth_token_file: $(Escape-YamlSingleQuoted $smtpOauthTokenFile)"
$configLines += "email_sender: $(Escape-YamlSingleQuoted $emailSender)"
$configLines += "email_recipient: $(Escape-YamlSingleQuoted $emailRecipient)"
$configLines += "email_case_label: $(Escape-YamlSingleQuoted $emailCaseLabel)"
$configLines += ""
$configLines += "# WhatsApp (CallMeBot)"
$configLines += "whatsapp_enabled: $($whatsappEnabled.ToString().ToLowerInvariant())"
$configLines += "whatsapp_phone: $(Escape-YamlSingleQuoted $whatsappPhone)"
$configLines += "whatsapp_apikey: ''"
$configLines += ""
$configLines += "# Telegram (CallMeBot)"
$configLines += "telegram_enabled: $($telegramEnabled.ToString().ToLowerInvariant())"
$configLines += "telegram_user: $(Escape-YamlSingleQuoted $telegramUser)"

$configTarget = Join-Path -Path (Get-Location) -ChildPath $ConfigPath
$configParent = Split-Path -Path $configTarget -Parent
if (-not [string]::IsNullOrWhiteSpace($configParent) -and -not (Test-Path -LiteralPath $configParent)) {
    New-Item -ItemType Directory -Path $configParent -Force | Out-Null
}
[System.IO.File]::WriteAllLines($configTarget, $configLines, [System.Text.UTF8Encoding]::new($false))

$envLines = @()
$envLines += "# AutopsyGuard secrets - generated by scripts\setup-autopsyguard.ps1"
$envLines += "# This file is loaded automatically by AutopsyGuard at startup."
$envLines += "# Do NOT commit this file to version control."
if (-not [string]::IsNullOrWhiteSpace($smtpUser)) {
    $envLines += "AUTOPSYGUARD_SMTP_USER=" + $smtpUser.Trim()
}
if (-not [string]::IsNullOrWhiteSpace($smtpPassword)) {
    $envLines += "AUTOPSYGUARD_SMTP_PASSWORD=" + $smtpPassword
}
if (-not [string]::IsNullOrWhiteSpace($smtpOauthClientSecret)) {
    $envLines += "AUTOPSYGUARD_SMTP_OAUTH_CLIENT_SECRET=" + $smtpOauthClientSecret.Trim()
}
if (-not [string]::IsNullOrWhiteSpace($whatsappApiKey)) {
    $envLines += "AUTOPSYGUARD_WHATSAPP_APIKEY=" + $whatsappApiKey.Trim()
}
if ($envLines.Count -le 3) {
    $envLines += "# (No secret env vars were provided.)"
    $envLines += "# Example:"
    $envLines += "#   AUTOPSYGUARD_SMTP_USER=your-user"
    $envLines += "#   AUTOPSYGUARD_SMTP_PASSWORD=your-password"
    $envLines += "#   AUTOPSYGUARD_SMTP_OAUTH_CLIENT_SECRET=your-oauth-client-secret"
    $envLines += "#   AUTOPSYGUARD_WHATSAPP_APIKEY=your-callmebot-key"
}
$envTarget = Join-Path -Path (Get-Location) -ChildPath $EnvFilePath
$envParent = Split-Path -Path $envTarget -Parent
if (-not [string]::IsNullOrWhiteSpace($envParent) -and -not (Test-Path -LiteralPath $envParent)) {
    New-Item -ItemType Directory -Path $envParent -Force | Out-Null
}
[System.IO.File]::WriteAllLines($envTarget, $envLines, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Config file : $ConfigPath"
Write-Host "Secrets file: $EnvFilePath  (loaded automatically by AutopsyGuard)"

Write-Host ""
Write-Host "Next steps:"
if ($emailEnabled -and $smtpAuthMode -eq "oauth") {
    $oauthCmd = "uv run autopsyguard-oauth --provider $smtpOauthProvider --email $smtpUser --client-id `"$smtpOauthClientId`" --token-file `"$smtpOauthTokenFile`""
    if (-not [string]::IsNullOrWhiteSpace($smtpOauthClientSecret)) {
        $oauthCmd += " --client-secret `"$smtpOauthClientSecret`""
    }
    if ($smtpOauthProvider -eq "microsoft" -and -not [string]::IsNullOrWhiteSpace($smtpOauthTenant)) {
        $oauthCmd += " --tenant `"$smtpOauthTenant`""
    }
    Write-Host "  1. Run OAuth login once to create local refresh token:"
    Write-Host "     $oauthCmd"
    Write-Host "  2. uv run autopsyguard --config .\$ConfigPath"
    Write-Host "  3. Optional debug run: uv run autopsyguard --config .\$ConfigPath --verbose"
} else {
    Write-Host "  1. uv run autopsyguard --config .\$ConfigPath"
    Write-Host "  2. Optional debug run: uv run autopsyguard --config .\$ConfigPath --verbose"
}
Write-Host ""
Write-Host "Configuration summary:" -ForegroundColor Cyan
Write-Host "  - Email:     $($emailEnabled)"
if ($emailEnabled) {
    Write-Host "  - Email auth mode: $smtpAuthMode"
    if ($smtpAuthMode -eq "oauth") {
        Write-Host "  - OAuth provider: $smtpOauthProvider"
        Write-Host "  - OAuth token file: $smtpOauthTokenFile"
    }
}
Write-Host "  - WhatsApp:  $($whatsappEnabled)"
Write-Host "  - Telegram:  $($telegramEnabled)"
Write-Host "  - Polling:   $pollInterval s"
Write-Host "  - Hang timeout: $hangTimeout s"
Write-Host ""

if ($RunAfterSetup) {
    uv run autopsyguard --config ".\$ConfigPath"
}
