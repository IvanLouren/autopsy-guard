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

## 3.4 Email Notifications

Provider presets:

- Gmail (recommended)
- Office 365 / Outlook
- Custom SMTP
- Local test SMTP

Gmail flow:

- wizard assumes App Password path
- if provided secret does not look like App Password shape (16 letters), wizard raises blocker warning and requires explicit override

SMTP TLS/port guidance:

- 587 -> STARTTLS (`smtp_use_ssl=false`)
- 465 -> SSL (`smtp_use_ssl=true`)

Wizard detects mismatch and offers correction.

## 3.5 Optional Channels

- WhatsApp (CallMeBot): requires phone + API key in `.env`
- Telegram (CallMeBot): requires valid target user

## 3.6 Final Validation

Wizard prints:

- exact run command
- quick smoke-check command
- top common failures and direct fixes

## 4. Verification Procedure (Post-Setup)

1. Run monitor:
   - `uv run autopsyguard --config config.local.yml`
2. Run verbose smoke-check:
   - `uv run autopsyguard --config config.local.yml --verbose`
3. Open Autopsy + case and wait for startup notification.
4. Confirm:
   - notification delivery (email/WA/TG)
   - expected telemetry in periodic report
   - `autopsyguard.log` written in state directory

## 5. Troubleshooting Quick Matrix

| Issue | Checks |
|---|---|
| SMTP auth fails | App Password used, `.env` loaded, sender policy allowed |
| No email | recipient correct, spam/junk, SMTP host/port reachable |
| TLS errors | 587/STARTTLS or 465/SSL pairing |
| Case validation fails | `case_dir` points to real case, contains `*.aut` |
| Channel silent (WA/TG) | required channel keys/users configured |

## 6. Migration Notes (Older Wizard Outputs)

If your old setup used OAuth wizard prompts:

- New wizard does not configure OAuth interactively.
- Existing OAuth runtime support remains available manually in YAML/env.
- Recommended migration path is Gmail App Password unless organization policy forbids it.

If your old config misses newer fields:

- Add:
  - `language: auto`
  - `case_name_source: real`
- Keep existing SMTP/channel keys unchanged unless rotating secrets.

## 7. Non-Interactive Mode (Future)

Non-interactive setup is planned but not implemented in this version.  
Current recommendation: run wizard once, then manage `config.local.yml` + `.env` via your own automation.
