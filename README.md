# AutopsyGuard

AutopsyGuard is a **real-time monitoring system** for the Autopsy digital forensics tool. It tracks execution, detects anomalies, logs activity, and sends notifications (Emails & Periodic Reports) on Windows and Linux systems.

## 🚀 Key Features

- **Solr Monitoring (JSON REST API):** Extracts CPU usage, RAM (Heap), GC time, and Thread activity in real-time.
- **Smart Log Analysis:** Automatically detects Fatal Exceptions (`OutOfMemoryError`, `SEVERE`) directly from Solr Server `.log` files through incremental processing.
- **False "Hang" Detection:** Distinguishes temporary network failures from true system freezes through consecutive temporal tracking.
- **System Heartbeat:** Actively sends periodic system status reports to ensure the forensic investigation remains uncompromised.

## ⚙️ System Configuration (Email)

AutopsyGuard is fully customizable through the `config.yml` file.

To enable **Email** notifications, we recommend using a free **Gmail** account with an generated "App Password", so you don't expose your real password.

### How to generate an App Password (Gmail)
1. Ensure your Google account has **2-Step Verification (2FA)** enabled.
2. Go to **MyAccount / Security** or open this direct link: [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
3. In the app selector, choose "Other (Custom name)" and type `AutopsyGuard`.
4. Click Generate and copy the 16-letter password shown on the yellow screen.

### Editing `config.yml`
In the project directory, open the `config.yml` file and replace the data with your new Password:

```yaml
# --- Email Notification Settings ---
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_user: "your_email@gmail.com"
smtp_password: "the16letterpassword"
email_sender: "AutopsyGuard <your_email@gmail.com>"
email_recipient: "target_email@domain.com"

# --- Periodic Reporting ---
report_interval_hours: 12.0  # Sends a report every 12 hours.
```

## 💻 How to Run and Test

Manage the environment through the `uv` framework and invoke the AutopsyGuard orchestrator:

```bash
uv run python -m autopsyguard --case-dir "C:\Path\To\The\Case" --config config.yml
```
*(During academic testing or demonstrations, reduce `report_interval_hours` to `0.005` (18 secs) to trigger the instant arrival of the report via Email).*