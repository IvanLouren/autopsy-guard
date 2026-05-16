# AutopsyGuard Setup Wizard Guide

This guide explains every setup wizard step for operators who need predictable, production-safe onboarding.

## 1. Prerequisites Checklist

Before running wizard:

- Python/uv environment available (`uv --version`)
- Autopsy installed and runnable
- Target case directory accessible from this machine
- Outbound network access for notification channels
- For Gmail: 2-Step Verification enabled and App Password created

Windows-only:

- Ensure `wmic` exists for Autopsy 4.22.1 environments

## 2. Security Model for Secrets

Wizard writes two files:

- `config.local.yml`: operational settings, safe to review/version manually
- `.env`: secrets only (SMTP credentials, API keys)

Rules:

- never commit `.env`
- rotate App Password/API keys if shared or exposed
- prefer environment-variable override in CI/servers

## 3. Prompt-by-Prompt Reference

## 3.1 Prerequisites Section

- `Run 'uv sync' now?`
  - Safe: `Yes` (ensures runtime dependencies)
  - Risky: `No` (possible missing packages later)

## 3.2 Case and Autopsy Paths

- `case_dir`
  - Safe: real case path containing `*.aut` + (`Log/` or `autopsy.db`)
  - Risky: placeholder path (`/path/...`, `C:\Path\...`)
  - Wizard behavior: placeholder requires explicit DRAFT-mode confirmation

- `autopsy_install_dir` (optional)
  - Safe: detected install candidate
  - Useful for wider JVM crash artifact search

## 3.3 Monitoring Performance

- `poll_interval`
  - Lower = faster detection, higher system overhead
- `hang_timeout`
  - Lower = more sensitive hang detection, higher false-positive risk
- `report_interval_hours`
  - controls heartbeat cadence

Balanced baseline defaults (when not overridden):

- `cpu_warning_percent: 350.0`
- `cpu_warning_duration: 600.0`
- `memory_warning_percent: 92.0`
- `disk_min_free_gb: 2.0`
- `hang_confirmation_duration: 90.0`
- `log_stale_timeout: 900.0`
- `solr_slow_threshold_seconds: 4.0`
- `solr_slow_count_threshold: 4`

When to override:

- lower CPU thresholds for small single-user lab datasets
- raise CPU thresholds for high-core servers with heavy parallel ingest
- lower Solr slow thresholds only if you need earlier performance alerts and accept more noise

## 3.4 Email Notifications

Provider presets:

- Gmail only (recommended and enforced)

Gmail flow:

- wizard assumes App Password path
- if provided secret does not look like App Password shape (16 letters), wizard raises blocker warning and requires explicit override

SMTP mode is fixed to Gmail STARTTLS:

- `smtp_host: smtp.gmail.com`
- `smtp_port: 587`
- `smtp_use_ssl: false`

## 3.5 Optional Channels

- WhatsApp (CallMeBot): requires phone + API key in `.env`
- Telegram (CallMeBot): requires valid target user

## 3.6 Final Validation

Wizard prints:

- exact run command
- quick smoke-check command
- top common failures and direct fixes

## 4. Verification Procedure (Post-Setup)

1. Launch Autopsy and open the target case first.
2. Wait for case load to complete. Do not start ingest yet.
3. Run monitor:
   - `uv run autopsyguard --config config.local.yml`
4. Run verbose smoke-check:
   - `uv run autopsyguard --config config.local.yml --verbose`
5. After AutopsyGuard is running, start ingest in Autopsy.
6. Confirm:
   - notification delivery (email/WA/TG)
   - expected telemetry in periodic report
   - `autopsyguard.log` written in state directory

Required operator order:

1. Open case in Autopsy
2. Start AutopsyGuard
3. Start ingest

## 5. Troubleshooting Quick Matrix

| Issue | Checks |
|---|---|
| SMTP auth fails | App Password used, `.env` loaded, sender policy allowed |
| No email | recipient correct, spam/junk, SMTP host/port reachable |
| TLS errors | 587/STARTTLS or 465/SSL pairing |
| Case validation fails | `case_dir` points to real case, contains `*.aut` |
| Channel silent (WA/TG) | required channel keys/users configured |
