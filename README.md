# AutopsyGuard

Real-time monitoring system for the **Autopsy** digital forensics tool. AutopsyGuard watches Autopsy’s process + logs + embedded Solr health + machine resources and sends **alerts** (email and/or WhatsApp) plus periodic **heartbeat reports** (with charts + raw metrics attachments).

## What it monitors

AutopsyGuard runs a polling loop and raises events when it detects anomalies. Event types are defined in `src/autopsyguard/models.py`:

- **Process / lifecycle**
  - `PROCESS_DISAPPEARED`: Autopsy process vanished unexpectedly
  - `ABNORMAL_EXIT`: Autopsy exited with non-zero exit code (best-effort)
  - `ZOMBIE`: Autopsy process became a zombie (CRITICAL)
  - `SOLR_CRASH`: a tracked child Java process disappeared (warning; often Solr)
- **JVM fatal crash**
  - `JVM_CRASH`: new `hs_err_pid*.log` file detected (CRITICAL)
- **Log-based errors**
  - `OUT_OF_MEMORY`: `java.lang.OutOfMemoryError` in logs (CRITICAL)
  - `LOG_ERROR`: configured error patterns / SEVERE / exceptions (WARNING/CRITICAL)
- **Hang detection**
  - `HANG`: correlation of multiple “freeze” signals (CRITICAL) and/or Solr slow/timeout (WARNING/CRITICAL)
- **Resource pressure**
  - `HIGH_RESOURCE_USAGE`: sustained CPU, high RAM, low disk space, Solr heap/CPU warnings

## How it decides when to be “active”

AutopsyGuard only runs the detectors when it believes the case is actively open. In `src/autopsyguard/monitor.py`, the monitor transitions from **WAITING → ACTIVE** when:

- Autopsy is running (process detected), and
- either the **case lock file** exists (`<case_dir>/Log/autopsy.log.0.lck`) **or**
- the **global lock file** exists (`~/.autopsy/var/log/messages.log.lck` on Linux; similar under `%APPDATA%/autopsy` on Windows)

This avoids false positives when Autopsy is not running, but still catches early startup phases.

## Requirements

- **Python**: 3.11+ (see `pyproject.toml`)
- **OS**: Linux / Windows (paths and process names are platform-aware; macOS may work but is not explicitly tuned)
- **Autopsy**: Designed for Autopsy 4.x (production config file mentions 4.22.1 specifically)
- **Dependencies**: `psutil`, `pyyaml`, `matplotlib` (see `pyproject.toml`)

## Install

### Option A (recommended): uv

This repo includes `uv.lock`.

```bash
uv sync
```

For development/testing dependencies:

```bash
uv sync --extra dev
```

Run via uv:

```bash
uv run autopsyguard --config config.development.yml
```

### Option B: pip (editable)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

For tests:

```bash
pip install -e ".[dev]"
```

## Quick start

### 1) Choose a config file

This repository ships with two example configs:

- `config.development.yml`: fast polling and “dev-friendly” thresholds
- `config.production.yml`: conservative thresholds and detailed operational notes

### 2) Point `case_dir` to an Autopsy case directory

`case_dir` must look like an Autopsy case:

- contains a `*.aut` descriptor file, and
- contains either `autopsy.db` (single-user) **or** a `Log/` directory (multi-user / PostgreSQL)

### 3) Run

Using the installed CLI:

```bash
autopsyguard --config config.production.yml
```

Or via module execution:

```bash
python -m autopsyguard --config config.production.yml
```

You can also pass the case directory positionally (overrides YAML):

```bash
autopsyguard "/cases/active/Evidence-2025-001" --config config.production.yml
```

## CLI reference

Entry point: `autopsyguard = autopsyguard.__main__:main` (see `pyproject.toml`).

```text
autopsyguard [case_dir] [options]
```

Options (see `src/autopsyguard/__main__.py`):

- `case_dir` (positional, optional): path to case directory to monitor
- `--config PATH`: YAML config file path. If omitted, auto-discovers (in current working directory) in this order:
  - `config.development.yml`
  - `config.production.yml`
  - `config.yml`
- `--autopsy-dir PATH`: Autopsy install directory (used for JVM crash detection search paths)
- `--poll-interval SECONDS`: override `poll_interval`
- `--hang-timeout SECONDS`: override `hang_timeout`
- `-v, --verbose`: debug logging
- `--skip-validation`: do not validate `case_dir` on startup (useful for tests)

## Configuration

### Source precedence (important)

Configuration is built in `MonitorConfig.from_sources()`:

1. dataclass defaults (`src/autopsyguard/config.py`)
2. YAML values
3. environment variable overrides for secrets (below)
4. explicit CLI overrides

### Environment variables (recommended for secrets)

AutopsyGuard reads these environment variables (see `_ENV_OVERRIDES` in `src/autopsyguard/config.py`):

- `AUTOPSYGUARD_SMTP_USER` → `smtp_user`
- `AUTOPSYGUARD_SMTP_PASSWORD` → `smtp_password`
- `AUTOPSYGUARD_WHATSAPP_APIKEY` → `whatsapp_apikey`

### Full config reference (all keys)

All supported keys are validated; unknown keys cause startup failure (`Unknown config key(s) ...`).

Paths:

- **`case_dir`** (required): Autopsy case directory to monitor
- **`autopsy_install_dir`** (optional): Autopsy installation directory (helps JVM crash detection)

Polling:

- **`poll_interval`** (float, seconds, default `10.0`): main loop sleep between cycles

Hang detection (requires signal correlation; see `src/autopsyguard/detectors/hang_detector.py`):

- **`hang_cpu_threshold`** (percent, default `1.0`): CPU ≤ this is treated as “idle”
- **`hang_timeout`** (seconds, default `300.0`): low-CPU must persist this long to become a CPU signal
- **`hang_confirmation_duration`** (seconds, default `60.0`): correlated signals must persist before firing a HANG event
- **`log_stale_timeout`** (seconds, default `600.0`): logs unchanged for this long becomes a log-stale signal
- **`solr_ping_timeout`** (seconds, default `5.0`): Solr ping request timeout used by HangDetector
- **`solr_ping_slow_threshold`** (seconds, default `3.0`): ping slower than this counts as “slow”
- **`solr_ping_slow_duration`** (seconds, default `60.0`): slow pings must persist this long to count as a signal
- **`solr_unresponsive_duration`** (seconds, default `30.0`): Solr unreachable for this long becomes an “unresponsive” signal

Resource thresholds (Autopsy process + system disk for case partition):

- **`cpu_warning_percent`** (percent, default `95.0`): Autopsy process CPU% threshold
  - Note: process CPU% can exceed 100% on multi-core systems; see `ResourceDetector`.
- **`cpu_per_core_warning_percent`** (percent, default `90.0`): average per-core CPU threshold
- **`cpu_warning_duration`** (seconds, default `300.0`): sustained CPU above threshold before warning
- **`memory_warning_percent`** (percent, default `90.0`): Autopsy RSS as % of system RAM before warning
- **`disk_min_free_gb`** (GB, default `1.0`): free space on the case partition below this is CRITICAL

Solr (embedded Autopsy Solr health checks; see `src/autopsyguard/detectors/solr_detector.py`):

- **`solr_port`** (int, default `23232`)
- **`solr_timeout_seconds`** (float, default `5.0`): HTTP timeout for SolrDetector probes
- **`solr_slow_threshold_seconds`** (float, default `2.0`): response slower than this is “slow”
- **`solr_slow_count_threshold`** (int, default `3`): consecutive slow responses before warning HANG
- **`solr_heap_usage_warning`** (percent, default `85.0`)
- **`solr_heap_usage_critical`** (percent, default `95.0`)
- **`solr_cpu_warning`** (percent, default `90.0`)

Email notifications (see `src/autopsyguard/notifier.py`):

- **`smtp_host`** (string, default `""`): required if `email_recipient` is set
- **`smtp_port`** (int, default `587`)
- **`smtp_use_ssl`** (bool, default `False`): `True` for implicit SSL (typically port 465), `False` for STARTTLS (typically 587)
- **`smtp_async`** (bool, default `False`): send emails in a background thread (non-blocking)
- **`smtp_user`** (string, default `""`): prefer env var override
- **`smtp_password`** (string, default `""`): prefer env var override
- **`email_sender`** (string, default `"autopsyguard@example.com"`)
- **`email_recipient`** (string, default `""`): if empty, email is disabled
- **`email_case_label`** (string, default `""`): optional label shown in emails; if empty, notifier uses a short hash label like `Case #ABCD` to avoid leaking filesystem paths

WhatsApp notifications (CallMeBot; see `src/autopsyguard/whatsapp_notifier.py`):

- **`whatsapp_enabled`** (bool, default `False`)
- **`whatsapp_phone`** (string, default `""`): phone with country code, e.g. `"+351912345678"`
- **`whatsapp_apikey`** (string, default `""`): prefer env var override `AUTOPSYGUARD_WHATSAPP_APIKEY`

Periodic reporting:

- **`report_interval_hours`** (float, default `12.0`): heartbeat email/WhatsApp summary interval

Log error patterns (see `src/autopsyguard/detectors/log_detector.py`):

- **`error_patterns`** (list of strings): additional case-insensitive regex patterns that trigger `LOG_ERROR` warnings.
  - Built-ins are always active: `java.lang.OutOfMemoryError`, `SEVERE`, `Exception`, `FATAL`, `StackOverflowError`

### Example: minimal config (email disabled)

```yaml
case_dir: /cases/active/Evidence-2025-001
poll_interval: 30.0
report_interval_hours: 12.0
```

### Example: enable email securely

```bash
export AUTOPSYGUARD_SMTP_USER="autopsyguard@yourdomain.com"
export AUTOPSYGUARD_SMTP_PASSWORD="your-app-password"
```

```yaml
case_dir: /cases/active/Evidence-2025-001
smtp_host: smtp.gmail.com
smtp_port: 587
smtp_use_ssl: false
smtp_async: true
email_sender: autopsyguard@yourdomain.com
email_recipient: forensic-team@yourdomain.com
email_case_label: "Evidence Case 2025-001"
```

### Example: enable WhatsApp (CallMeBot)

CallMeBot setup (from `src/autopsyguard/whatsapp_notifier.py` and the example YAMLs):

1. Save `+34 644 31 82 94` in your contacts
2. Send: `I allow callmebot to send me messages` on WhatsApp
3. Receive an API key

Then:

```bash
export AUTOPSYGUARD_WHATSAPP_APIKEY="your-api-key"
```

```yaml
case_dir: /cases/active/Evidence-2025-001
whatsapp_enabled: true
whatsapp_phone: "+351912345678"
```

## Files and directories AutopsyGuard reads/writes

### Autopsy inputs (read)

- **Case log**: `<case_dir>/Log/autopsy.log.0`
- **Case lock**: `<case_dir>/Log/autopsy.log.0.lck`
- **Global logs**: `${AUTOPSY_USER_DIR}/var/log/messages.log` and `${AUTOPSY_USER_DIR}/var/log/autopsy.log.0`
- **Global lock**: `${AUTOPSY_USER_DIR}/var/log/messages.log.lck`

`AUTOPSY_USER_DIR` is:

- Linux: `~/.autopsy`
- Windows: `%APPDATA%/autopsy` (fallbacks to `~/AppData/Roaming/autopsy` if needed)

### AutopsyGuard state (write, outside evidence case)

To avoid writing into the evidence case directory, AutopsyGuard stores its own state under:

`$AUTOPSY_USER_DIR/autopsyguard/<case_hash>/`

Where `<case_hash>` is the first 16 hex chars of `sha256(str(case_dir.resolve()))` (see `get_autopsyguard_state_dir()` in `src/autopsyguard/platform_utils.py`).

Files written there:

- `metrics.db`: SQLite metrics store used for reports/charts (`src/autopsyguard/utils/metrics_store.py`)
- `log_positions.json`: offsets for Autopsy log tailing (LogDetector)
- `solr_log_positions.json`: offsets for Solr log tailing (SolrDetector)

### Email report attachments

Heartbeat reports can attach:

- `metrics.json`
- `metrics.csv`

and embed a system chart image (PNG) generated by `matplotlib` (`src/autopsyguard/utils/metrics_chart.py`).

## Troubleshooting

### “Missing required setting 'case_dir'”

Provide `case_dir` in YAML or as the positional CLI argument.

### “does not look like a valid Autopsy case directory”

AutopsyGuard validates `case_dir` unless you pass `--skip-validation`. A valid case directory must have:

- a `*.aut` file, and
- either `autopsy.db` or a `Log/` directory.

### Email not sending

Email is enabled only when both:

- `smtp_host` is set, and
- `email_recipient` is set.

If authentication is required, set credentials via env vars:

- `AUTOPSYGUARD_SMTP_USER`
- `AUTOPSYGUARD_SMTP_PASSWORD`

### WhatsApp not sending

WhatsApp is enabled only when all three are set:

- `whatsapp_enabled: true`
- `whatsapp_phone` non-empty
- `whatsapp_apikey` non-empty (or env var `AUTOPSYGUARD_WHATSAPP_APIKEY`)

### Linux permissions (process I/O counters)

AutopsyGuard tries to read per-process I/O counters for Autopsy. On Linux this may require elevated permissions (e.g., root or `CAP_SYS_PTRACE`) when monitoring processes owned by another user. If denied, it will still run; those per-process I/O metrics become 0/absent.

## Development

### Run tests

```bash
pytest
```

Tests live under `src/autopsyguard/tests` (configured in `pyproject.toml`).

## Notes for production use

- Use `config.production.yml` as a starting point; it contains conservative thresholds and operational guidance.
- Prefer running AutopsyGuard as a service (systemd on Linux, Windows Service) so environment variables and restarts are handled cleanly.
- For forensic hygiene, AutopsyGuard’s own state is stored outside the case directory; do not override that behavior by placing state files inside evidence mounts.

## License

No license file is currently included in this repository. If this project is intended to be redistributed, add a `LICENSE` and update this section accordingly.

