# AutopsyGuard

AutopsyGuard is a real-time monitoring service for the Autopsy digital forensics platform.  
It detects process failures, JVM crashes, hangs, Solr health issues, and sustained resource pressure, then sends alerts and periodic status reports.

This repository is a final-year software engineering project focused on operational reliability for long-running forensic analysis sessions.

## Key capabilities

- Continuous polling-based monitoring while Autopsy is active
- Multi-signal hang detection (CPU + logs + Solr)
- Solr health and core checks (availability, latency, heap/CPU, core issues)
- Email, WhatsApp, and Telegram notifications
- Correlated incident alerts that group multi-detector cascades into one report
- Heartbeat reporting with metrics attachments and chart
- Heartbeat telemetry for `autopsy.db`, `autopsy.log.0`, case size, module folders, Solr status, and Autopsy CPU timeline
- Metrics persistence in SQLite outside the case directory

## Requirements

- Python 3.11+
- Autopsy 4.22+ (project config examples target 4.22.1)
- OS support: Windows and Linux
- Package manager/runtime: `uv`

## Quick Start (Guided Setup)

The easiest and recommended way to configure and run AutopsyGuard is using the interactive setup script. This script will automatically validate your Autopsy case directory, configure your notification settings (Email, WhatsApp, Telegram), and safely store your API credentials in a `.env` file.

### 1. Run the Setup Wizard

From the repository root, run the setup script for your operating system:

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-autopsyguard.ps1
```

**Linux / macOS (Bash):**
```bash
bash ./scripts/setup-autopsyguard.sh
```

The wizard will ask you a few simple questions, automatically detect your Autopsy installation, and generate a `config.local.yml` file tailored to your needs.

### 2. Start the Monitor

Once the setup wizard completes, you can start AutopsyGuard using `uv`. The monitor will automatically detect your configuration and load the hidden `.env` file created by the wizard.

```bash
uv run autopsyguard --config config.local.yml
```

> [!TIP]
> **Manual Configuration:** If you prefer to configure AutopsyGuard manually without the wizard, copy one of the provided templates (`config.production.example.yml` or `config.development.example.yml`) to a new `config.local.yml` file, edit it by hand, and run with `uv run autopsyguard --config config.local.yml`.

## CLI reference

```text
autopsyguard [case_dir] [options]
```

Options:

- `--config PATH` - YAML config path (if omitted, auto-discovers in current directory: `config.local.yml`, then `config.yml`)
- `--env-file FILE` - path to `.env` file with secrets (if omitted, auto-discovers `.env` in current directory)
- `--autopsy-dir PATH` - optional Autopsy install directory (used mainly for JVM crash file search)
- `--poll-interval SECONDS` - override `poll_interval`
- `--hang-timeout SECONDS` - override `hang_timeout`
- `-v`, `--verbose` - debug logging
- `--skip-validation` - skip case directory validation at startup

## Example config templates

The repository now ships scenario templates only:

- `config.development.example.yml`
- `config.production.example.yml`

These are **examples**, not your runtime config.  
Create your own `config.local.yml` from one of them (or use the setup scripts).

## Configuration

Configuration precedence (`MonitorConfig.from_sources()`):

1. Dataclass defaults (`src\autopsyguard\config.py`)
2. YAML file values
3. `.env` file variables (auto-loaded from cwd or `--env-file`), then real environment variables
4. CLI overrides

### Required setting

- `case_dir` (must point to a valid Autopsy case directory)

Validation expects:

- At least one `*.aut` file, and
- either `autopsy.db` or a `Log` directory.

### Optional but important settings

- `autopsy_install_dir` (optional): improves JVM crash file search coverage
- `report_interval_hours`: periodic heartbeat interval
- `language`: `auto` (OS locale), `pt`, or `en` for all notifications/reports
- `case_name_source`: `real` or `hash` when `email_case_label` is empty
- notification settings (`smtp_*`, `email_*`, `whatsapp_*`, `telegram_*`)

### Environment variables (supported overrides)

Set these in your `.env` file (auto-loaded) or in the real environment:

- `AUTOPSYGUARD_SMTP_USER` -> `smtp_user`
- `AUTOPSYGUARD_SMTP_PASSWORD` -> `smtp_password`
- `AUTOPSYGUARD_WHATSAPP_APIKEY` -> `whatsapp_apikey`

Real environment variables always take priority over `.env` values, so you can always override from the shell.

### Example minimal config

```yaml
case_dir: C:\Cases\Evidence-2025-001
poll_interval: 30.0
report_interval_hours: 12.0
```

### Notification channel enable rules

- Email enabled when both `smtp_host` and `email_recipient` are set
- WhatsApp enabled when `whatsapp_enabled: true` and both `whatsapp_phone` + `whatsapp_apikey` are set
- Telegram enabled when `telegram_enabled: true` and `telegram_user` is set

## Filesystem behavior

### Inputs read from Autopsy

- Case log: `<case_dir>\Log\autopsy.log.0`
- Case lock: `<case_dir>\Log\autopsy.log.0.lck`
- Global logs: `<autopsy_user_dir>\var\log\messages.log`, `<autopsy_user_dir>\var\log\autopsy.log.0`
- Global lock: `<autopsy_user_dir>\var\log\messages.log.lck`
- Solr logs: detected from process JVM args (`-Dsolr.log.dir`) or fallback under Autopsy log directories

### Autopsy user directory detection

- Windows: `%APPDATA%\autopsy` (fallback: `~\AppData\Roaming\autopsy`)
- Linux: `~/.autopsy`
- Linux snap layouts are auto-detected (including `~/snap/autopsy/common/.autopsy` and dev profile variants)

### AutopsyGuard state directory (outside case)

To avoid writing into evidence case folders, state is stored at:

- Windows: `%APPDATA%\autopsy\autopsyguard\<case_hash>\`
- Linux: `~/.autopsy/autopsyguard/<case_hash>/`
- Linux snap: `~/snap/autopsy/common/.autopsy/autopsyguard/<case_hash>/`

Where `<case_hash>` is the first 16 characters of `sha256(str(case_dir.resolve()))`.

Files written there:

- `metrics.db` (SQLite metrics store)
- `log_positions.json` (Autopsy log offsets)
- `solr_log_positions.json` (Solr log offsets)
- `autopsyguard.log` (rotating file mirror of terminal output)

### Report attachments

Email heartbeat reports can include:

- `metrics.json`
- `metrics.csv`
- inline PNG chart generated from sampled metrics

## Is `autopsy_install_dir` mandatory?

No. It is optional.

It is mainly used to expand search locations for `hs_err_pid*.log` files (JVM fatal crash artifacts).  
Without it, detection still uses fallback paths (home directory, process working directory, and `/tmp` on Linux).

All other core detection paths (process, logs, hangs, resources, Solr health) continue to work without it.

### Install-dir auto-detection coverage

The setup scripts try common install roots:

- **Windows:** `C:\Program Files\Autopsy*`, `C:\Program Files (x86)\Autopsy*`, `%LOCALAPPDATA%\Programs\Autopsy*`
- **Linux (native):** `/opt/autopsy*`, `/usr/local/autopsy*`, `/usr/share/autopsy`
- **Linux (snap):** `/snap/autopsy/current`, `/var/lib/snapd/snap/autopsy/current`, `~/snap/autopsy/current`

### When to rely on `autopsy_install_dir`

Set it when you want maximum JVM crash-file coverage, especially:

1. Service/daemon runs (different working directory than interactive shell)
2. Locked-down systems where process CWD/home may be inaccessible
3. Environments where `hs_err_pid*.log` is expected near the install tree

### When you can skip it

You can usually leave it empty for normal interactive usage.  
The monitor will still work and still detects JVM crash files via fallback search paths.

## Troubleshooting

- **Autopsy crashes immediately on Windows 11 (`wmic` error)**: Autopsy 4.22.1 requires the `wmic` command to manage its embedded Solr service, which Microsoft removed in Windows 11 (24H2+). To fix this, go to **Windows Settings > System > Optional Features** and install **WMI Commandline Utility**.
- **Missing `case_dir`**: provide it in YAML or as positional CLI argument
- **Invalid case directory error**: ensure the directory has `*.aut` plus `autopsy.db` or `Log\`
- **No email alerts**: confirm `smtp_host` + `email_recipient`; check SMTP auth settings; for Gmail/O365 prefer App Passwords
- **No WhatsApp alerts**: confirm `whatsapp_enabled`, phone, API key, and that CallMeBot is available for your account/region
- **No Telegram alerts**: confirm `telegram_enabled`, `telegram_user`
- **Linux process I/O metrics missing**: per-process I/O counters can require elevated permissions

## Development

Run tests:

```bash
uv run pytest
```

Tests are under `tests/`.

## Project structure (high level)

```text
.env.example
config.development.example.yml
config.production.example.yml
pyproject.toml
scripts/
  setup-autopsyguard.ps1
  setup-autopsyguard.sh
tests/
src/
  autopsyguard/
    detectors/
    notifiers/
    platform_utils/
    utils/
    __main__.py
    monitor.py
```

## Detection coverage

Detectors are wired in `src\autopsyguard\monitor.py` and run in this order:

1. `ProcessDetector`
2. `JvmCrashDetector`
3. `LogDetector`
4. `HangDetector`
5. `ResourceDetector`
6. `SolrDetector`

| Detector | What it detects | Event types |
|---|---|---|
| `ProcessDetector` | Main Autopsy process disappeared, abnormal exit code, zombie state, missing child Java process (possible Solr subprocess crash), stale lock without running process | `PROCESS_DISAPPEARED`, `ABNORMAL_EXIT`, `ZOMBIE`, `SOLR_CRASH` |
| `JvmCrashDetector` | New `hs_err_pid*.log` files (fatal HotSpot/JVM crash evidence) | `JVM_CRASH` |
| `LogDetector` | New error lines in Autopsy logs (`OutOfMemoryError`, `FATAL`, `SEVERE`, exceptions, custom regex patterns, Solr connection exceptions); also tracks ingest start/finish state | `OUT_OF_MEMORY`, `SOLR_CRASH`, `LOG_ERROR` |
| `HangDetector` | Correlated freeze symptoms (low CPU + stale logs + slow/unresponsive Solr), with confirmation window and ingest-aware suppression | `HANG` |
| `ResourceDetector` | Sustained high Autopsy CPU, high Autopsy memory share, low disk free space on case partition, and external memory pressure from other processes | `HIGH_RESOURCE_USAGE` |
| `SolrDetector` | Solr down/not responding, consecutive slow responses/timeouts, high heap/CPU, core init failures, suspicious doc-count drops, Solr log errors | `SOLR_CRASH`, `HANG`, `HIGH_RESOURCE_USAGE`, `LOG_ERROR` |

## Runtime state model

The monitor runs as a state machine:

- `WAITING`: Autopsy not active yet
- `ACTIVE`: process detected and lock evidence present
- `FINISHED`: process ended and locks were cleaned (graceful completion)

Activation requires:

- Autopsy process is running, and
- either case lock exists (`<case_dir>\Log\autopsy.log.0.lck`) **or** global lock exists (`<autopsy_user_dir>\var\log\messages.log.lck`).

## License

No `LICENSE` file is currently included in this repository.
