param(
    [string]$ConfigPath = "config.local.yml",
    [string]$EnvFilePath = ".env",
    [switch]$SkipDependencySync,
    [switch]$RunAfterSetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("--- {0} ---" -f $Title) -ForegroundColor Cyan
}

function Write-Note {
    param([string]$Message)
    Write-Host ("[NOTE] {0}" -f $Message) -ForegroundColor Gray
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("[WARN] {0}" -f $Message) -ForegroundColor Yellow
}

function Write-Blocker {
    param([string]$Message)
    Write-Host ("[BLOCK] {0}" -f $Message) -ForegroundColor Red
}

function Read-Required {
    param([string]$Prompt)
    while ($true) {
        $value = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value.Trim()
        }
        Write-Warn "Value is required."
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
            default { Write-Warn "Please answer y or n." }
        }
    }
}

function Escape-YamlSingleQuoted {
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
            }
        }
    }

    return $results
}

function Show-CaseDirHints {
    param([string]$CaseDir)

    if (-not (Test-Path -LiteralPath $CaseDir)) {
        Write-Warn "case_dir path does not exist yet. Validation may fail until the case is available."
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
        Write-Warn "No .aut file found in case_dir (Autopsy case descriptor)."
    }
    if (-not ($hasLogDir -or $hasDb)) {
        Write-Warn "Expected either Log\ directory or autopsy.db in case_dir."
    }
}

function Test-PlaceholderPath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return $false }
    $v = $PathValue.Trim().ToLowerInvariant()
    if ($v -eq "c:\path\to\your\case") { return $true }
    if ($v -eq "/path/to/your/case") { return $true }
    if ($v -match '(^|[\\/])path([\\/]|$)') { return $true }
    return $false
}

function Test-GoogleAppPasswordLike {
    param([string]$Password)
    if ([string]::IsNullOrWhiteSpace($Password)) { return $false }
    $normalized = ($Password -replace '\s', '')
    if ($normalized.Length -ne 16) { return $false }
    return $normalized -match '^[A-Za-z]{16}$'
}

function Validate-SmtpPortSsl {
    param(
        [string]$Port,
        [bool]$UseSsl
    )
    if ($Port -eq "587" -and $UseSsl) {
        return "Port 587 normally requires STARTTLS (smtp_use_ssl=false)."
    }
    if ($Port -eq "465" -and -not $UseSsl) {
        return "Port 465 normally requires implicit SSL (smtp_use_ssl=true)."
    }
    return ""
}

Write-Host ""
Write-Host "AutopsyGuard Setup Wizard (Windows)" -ForegroundColor Cyan
Write-Note "This wizard is security-first and optimized for production-safe defaults."
Write-Note "Gmail path is App Password-first. OAuth is supported by runtime but not configured here."
Write-Note "Detailed guide: docs/setup-wizard-guide.md"

Write-Section "1) Prerequisites Check"
Write-Note "Why this matters: missing platform dependencies can break Autopsy before monitoring starts."

$wmicPath = Get-Command "wmic" -ErrorAction SilentlyContinue
if (-not $wmicPath) {
    Write-Blocker "'wmic' command is missing. Autopsy 4.22.1 can crash on startup without it."
    Write-Note "Install 'WMI Commandline Utility' in Windows Optional Features."
    if (-not (Read-YesNo "Continue setup anyway?" $false)) {
        Write-Blocker "Setup aborted."
        exit 1
    }
}

if (-not $SkipDependencySync) {
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($null -eq $uv) {
        Write-Warn "'uv' command not found. Install uv, then run this wizard again."
    } elseif (Read-YesNo "Run 'uv sync' now?" $true) {
        uv sync
    }
}

Write-Section "2) Case and Autopsy Paths"
Write-Note "Why this matters: monitor needs the real case directory to detect ingest/log/locks correctly."
Write-Note "Safe default: provide an existing case folder now."

$caseDir = Read-Host "Autopsy case directory (case_dir)"
if ([string]::IsNullOrWhiteSpace($caseDir)) {
    $caseDir = "C:\Path\To\Your\Case"
}
$caseDir = $caseDir.Trim()
if (Test-PlaceholderPath $caseDir) {
    Write-Blocker "You entered a placeholder case_dir."
    if (-not (Read-YesNo "Proceed in DRAFT mode (you must edit case_dir before running)?" $false)) {
        $caseDir = Read-Required "Enter a real case_dir path"
    }
}
if (-not (Test-Path -LiteralPath $caseDir)) {
    Write-Warn "Path does not currently exist: $caseDir"
}
Show-CaseDirHints -CaseDir $caseDir

$autopsyInstallDir = ""
$installCandidates = @(Get-AutopsyInstallCandidates)
if ($installCandidates.Count -gt 0) {
    Write-Note "Detected Autopsy install-dir candidates:"
    $max = [Math]::Min(10, $installCandidates.Count)
    for ($i = 0; $i -lt $max; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $installCandidates[$i])
    }
    if ($installCandidates.Count -gt 10) {
        Write-Host ("  ... plus {0} more" -f ($installCandidates.Count - 10))
    }
    while ($true) {
        $selection = Read-Host "Choose candidate number [1], M for manual, or S to skip"
        if ([string]::IsNullOrWhiteSpace($selection)) { $selection = "1" }
        $selection = $selection.Trim()
        if ($selection.Equals("M", [System.StringComparison]::OrdinalIgnoreCase)) {
            $autopsyInstallDir = Read-Host "Autopsy install directory (optional)"
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
        Write-Warn "Invalid selection. Choose valid number, M, or S."
    }
} else {
    Write-Warn "No install dir auto-detected. You can skip (optional)."
    $autopsyInstallDir = Read-Host "Autopsy install directory (optional)"
}

Write-Section "3) Monitoring Performance"
Write-Note "Why this matters: polling and timeout values define alert speed vs false positives."
$pollInterval = Read-Default "poll_interval (seconds)" "30.0"
$hangTimeout = Read-Default "hang_timeout (seconds)" "900.0"
$reportInterval = Read-Default "report_interval_hours (example 12.0 or 0.5)" "12.0"

Write-Section "4) Notifications Setup"
Write-Note "Why this matters: reliable alerts require correct SMTP/security settings."
Write-Note "Recommended production path: Gmail + Google App Password."

$emailEnabled = Read-YesNo "Configure email notifications?" $true
$smtpHost = ""
$smtpPort = "587"
$smtpUseSsl = $false
$smtpAsync = $true
$smtpUser = ""
$smtpPassword = ""
$emailSender = "autopsyguard@example.com"
$emailRecipient = ""
$emailCaseLabel = ""
$smtpAuthMode = "password"
$smtpOauthProvider = ""
$smtpOauthClientId = ""
$smtpOauthClientSecret = ""
$smtpOauthTokenFile = ""
$providerLabel = ""

if ($emailEnabled) {
    Write-Host "Email provider presets:" -ForegroundColor Cyan
    Write-Host "  [1] Gmail (App Password, smtp.gmail.com:587 STARTTLS) [Recommended]"
    Write-Host "  [2] Office 365 / Outlook (smtp.office365.com:587 STARTTLS)"
    Write-Host "  [3] Custom SMTP"
    Write-Host "  [4] Local dev server (localhost:1025)"
    while ($true) {
        $providerChoice = Read-Host "Provider [1]"
        if ([string]::IsNullOrWhiteSpace($providerChoice)) { $providerChoice = "1" }
        switch ($providerChoice.Trim()) {
            "1" {
                $providerLabel = "gmail"
                $smtpHost = "smtp.gmail.com"
                $smtpPort = "587"
                $smtpUseSsl = $false
                break
            }
            "2" {
                $providerLabel = "office365"
                $smtpHost = "smtp.office365.com"
                $smtpPort = "587"
                $smtpUseSsl = $false
                break
            }
            "3" {
                $providerLabel = "custom"
                $smtpHost = Read-Required "SMTP host (smtp_host)"
                $smtpPort = Read-Default "SMTP port (smtp_port)" "587"
                $smtpUseSsl = Read-YesNo "Use SMTP SSL (smtp_use_ssl)? true for 465, false for 587 STARTTLS" $false
                break
            }
            "4" {
                $providerLabel = "local"
                $smtpHost = "localhost"
                $smtpPort = "1025"
                $smtpUseSsl = $false
                break
            }
            default {
                Write-Warn "Please choose 1, 2, 3, or 4."
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($providerLabel)) { break }
    }

    while ($true) {
        $hint = Validate-SmtpPortSsl -Port $smtpPort -UseSsl $smtpUseSsl
        if ([string]::IsNullOrWhiteSpace($hint)) {
            break
        }
        Write-Warn $hint
        if (Read-YesNo "Fix automatically to recommended pair?" $true) {
            if ($smtpPort -eq "587") {
                $smtpUseSsl = $false
            } elseif ($smtpPort -eq "465") {
                $smtpUseSsl = $true
            }
        } else {
            if (-not (Read-YesNo "Continue with current SMTP TLS/port mismatch?" $false)) {
                $smtpPort = Read-Default "SMTP port (smtp_port)" $smtpPort
                $smtpUseSsl = Read-YesNo "Use SMTP SSL (smtp_use_ssl)?" $smtpUseSsl
            } else {
                break
            }
        }
    }

    $smtpAsync = Read-YesNo "Send email asynchronously (smtp_async)?" $true
    $emailSender = Read-Default "Email sender (email_sender)" "autopsyguard@example.com"
    $emailRecipient = Read-Required "Email recipient (email_recipient)"
    $emailCaseLabel = Read-Host "Email case label (optional)"

    if ($providerLabel -eq "gmail") {
        Write-Note "Gmail App Password checklist:"
        Write-Note "  1) Google account has 2-Step Verification enabled."
        Write-Note "  2) Create App Password for 'Mail'."
        Write-Note "  3) Use app password here, never your normal account password."
        $smtpUser = Read-Required "SMTP user (your Gmail address)"
        $secure = Read-Host "Google App Password" -AsSecureString
        if ($secure.Length -gt 0) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try {
                $smtpPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                $smtpPassword = $smtpPassword -replace '\s', ''
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
        if (-not (Test-GoogleAppPasswordLike $smtpPassword)) {
            Write-Blocker "This does not look like a Google App Password (expected 16 letters)."
            if (-not (Read-YesNo "Continue anyway with potentially unsafe/invalid password?" $false)) {
                Write-Blocker "Setup aborted to protect email reliability. Re-run with valid App Password."
                exit 1
            }
        }
    } elseif ($providerLabel -eq "local") {
        $smtpUser = ""
        $smtpPassword = ""
    } else {
        $smtpUser = Read-Host "SMTP user (optional; written to .env if provided)"
        $secure = Read-Host "SMTP password (optional; written to .env if provided)" -AsSecureString
        if ($secure.Length -gt 0) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try {
                $smtpPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }
}

$whatsappEnabled = $false
$whatsappPhone = ""
$whatsappApiKey = ""
Write-Section "5) Optional Channels"
Write-Note "Why this matters: secondary channels reduce risk of missed critical alerts."
if (Read-YesNo "Configure WhatsApp notifications (CallMeBot)?" $false) {
    $whatsappEnabled = $true
    $whatsappPhone = Read-Required "WhatsApp phone (+countrycode...)"
    $whatsappApiKey = Read-Host "WhatsApp API key (optional)"
    if ([string]::IsNullOrWhiteSpace($whatsappApiKey)) {
        Write-Warn "WhatsApp channel stays configured but disabled until AUTOPSYGUARD_WHATSAPP_APIKEY is set."
    }
}

$telegramEnabled = $false
$telegramUser = ""
if (Read-YesNo "Configure Telegram notifications (CallMeBot)?" $false) {
    $telegramEnabled = $true
    $telegramUser = Read-Required "Telegram user (example @myusername)"
}

Write-Section "6) Final Review and File Generation"
$configLines = @()
$configLines += "# Generated by scripts\setup-autopsyguard.ps1"
$configLines += "# Security-first defaults. Review values before first production run."
$configLines += "case_dir: $(Escape-YamlSingleQuoted $caseDir)"
if (-not [string]::IsNullOrWhiteSpace($autopsyInstallDir)) {
    $configLines += "autopsy_install_dir: $(Escape-YamlSingleQuoted $autopsyInstallDir.Trim())"
}
$configLines += "poll_interval: $pollInterval"
$configLines += "hang_timeout: $hangTimeout"
$configLines += "report_interval_hours: $reportInterval"
$configLines += ""
$configLines += "# Localization and labels"
$configLines += "language: 'auto'"
$configLines += "case_name_source: 'real'"
$configLines += ""
$configLines += "# Email (enabled when smtp_host + email_recipient are set)"
$configLines += "smtp_host: $(Escape-YamlSingleQuoted $smtpHost)"
$configLines += "smtp_port: $smtpPort"
$configLines += "smtp_use_ssl: $($smtpUseSsl.ToString().ToLowerInvariant())"
$configLines += "smtp_async: $($smtpAsync.ToString().ToLowerInvariant())"
$configLines += "smtp_auth_mode: 'password'"
$configLines += "smtp_oauth_provider: ''"
$configLines += "smtp_oauth_client_id: ''"
$configLines += "smtp_oauth_client_secret: ''"
$configLines += "smtp_oauth_token_file: ''"
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
$envLines += "# Loaded automatically by AutopsyGuard at startup."
$envLines += "# Do NOT commit this file to version control."
if (-not [string]::IsNullOrWhiteSpace($smtpUser)) {
    $envLines += "AUTOPSYGUARD_SMTP_USER=" + $smtpUser.Trim()
}
if (-not [string]::IsNullOrWhiteSpace($smtpPassword)) {
    $envLines += "AUTOPSYGUARD_SMTP_PASSWORD=" + $smtpPassword.Trim()
}
if (-not [string]::IsNullOrWhiteSpace($whatsappApiKey)) {
    $envLines += "AUTOPSYGUARD_WHATSAPP_APIKEY=" + $whatsappApiKey.Trim()
}
if ($envLines.Count -le 3) {
    $envLines += "# (No secrets provided.)"
    $envLines += "# Example:"
    $envLines += "#   AUTOPSYGUARD_SMTP_USER=your-user"
    $envLines += "#   AUTOPSYGUARD_SMTP_PASSWORD=your-app-password"
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
Write-Host "Secrets file: $EnvFilePath"
Write-Host "Guide       : docs/setup-wizard-guide.md"

Write-Section "Operational Checklist"
Write-Host "1) Review generated files:"
Write-Host "   - $ConfigPath"
Write-Host "   - $EnvFilePath"
Write-Host "2) Start monitor:"
Write-Host "   uv run autopsyguard --config .\$ConfigPath"
Write-Host "3) Quick email channel smoke-check:"
Write-Host "   uv run autopsyguard --config .\$ConfigPath --verbose"
Write-Host "   (Open Autopsy case and confirm startup notification arrives.)"
Write-Host "4) If needed, use full setup notes:"
Write-Host "   docs/setup-wizard-guide.md"

Write-Host ""
Write-Host "Top 5 common failures and fixes:"
Write-Host "  - SMTP auth failed: verify App Password (not account password)."
Write-Host "  - TLS/port mismatch: use 587+STARTTLS or 465+SSL."
Write-Host "  - No email received: validate recipient, sender policy, spam folder."
Write-Host "  - Case not detected: ensure case_dir points to real folder with .aut."
Write-Host "  - WhatsApp not sending: set AUTOPSYGUARD_WHATSAPP_APIKEY in .env."

if ($RunAfterSetup) {
    uv run autopsyguard --config ".\$ConfigPath"
}
