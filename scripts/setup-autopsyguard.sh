#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="config.local.yml"
ENV_FILE_PATH=".env"
SKIP_SYNC=false
RUN_AFTER_SETUP=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --env-file)
      ENV_FILE_PATH="$2"
      shift 2
      ;;
    --skip-sync)
      SKIP_SYNC=true
      shift
      ;;
    --run)
      RUN_AFTER_SETUP=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: bash scripts/setup-autopsyguard.sh [--config <path>] [--env-file <path>] [--skip-sync] [--run]" >&2
      exit 1
      ;;
  esac
done

section() { echo; echo "--- $1 ---"; }
note() { echo "[NOTE] $1"; }
warn() { echo "[WARN] $1"; }
blocker() { echo "[BLOCK] $1"; }

prompt_required() {
  local prompt="$1"
  local value=""
  while true; do
    read -r -p "$prompt: " value
    if [[ -n "${value// }" ]]; then
      printf "%s" "$value"
      return
    fi
    warn "Value is required."
  done
}

prompt_default() {
  local prompt="$1"
  local default_value="$2"
  local value=""
  read -r -p "$prompt [$default_value]: " value
  if [[ -z "${value// }" ]]; then
    printf "%s" "$default_value"
  else
    printf "%s" "$value"
  fi
}

prompt_yes_no() {
  local prompt="$1"
  local default_choice="$2" # y or n
  local value=""
  local suffix="[y/N]"
  [[ "$default_choice" == "y" ]] && suffix="[Y/n]"
  while true; do
    read -r -p "$prompt $suffix: " value
    value="${value,,}"
    if [[ -z "${value// }" ]]; then
      [[ "$default_choice" == "y" ]] && return 0 || return 1
    fi
    if [[ "$value" == "y" || "$value" == "yes" ]]; then
      return 0
    fi
    if [[ "$value" == "n" || "$value" == "no" ]]; then
      return 1
    fi
    warn "Please answer y or n."
  done
}

yaml_quote() {
  local v="$1"
  local escaped
  escaped="$(printf "%s" "$v" | sed "s/'/''/g")"
  printf "'%s'" "$escaped"
}

is_autopsy_install_candidate() {
  local p="$1"
  [[ -d "$p" ]] || return 1
  [[ -x "$p/bin/autopsy" ]] && return 0
  [[ -x "$p/autopsy" ]] && return 0
  [[ -f "$p/meta/snap.yaml" ]] && return 0
  [[ -f "$p/bin/autopsy64.exe" ]] && return 0
  [[ -f "$p/bin/autopsy.exe" ]] && return 0
  [[ "$p" == *autopsy* ]] && return 0
  return 1
}

detect_autopsy_install_candidates() {
  local p
  for p in \
    /opt/autopsy \
    /opt/autopsy-* \
    /usr/local/autopsy \
    /usr/local/autopsy-* \
    /usr/share/autopsy \
    /snap/autopsy/current \
    /var/lib/snapd/snap/autopsy/current \
    "$HOME/snap/autopsy/current"
  do
    [[ -d "$p" ]] || continue
    if is_autopsy_install_candidate "$p"; then
      printf "%s\n" "$p"
    fi
  done | awk '!seen[$0]++'
}

show_case_dir_hints() {
  local case_path="$1"
  if [[ ! -e "$case_path" ]]; then
    warn "case_dir path does not exist yet. Validation may fail until case is available."
    return
  fi

  local has_aut=false
  local has_log=false
  local has_db=false
  if compgen -G "$case_path/*.aut" >/dev/null; then
    has_aut=true
  fi
  [[ -d "$case_path/Log" ]] && has_log=true
  [[ -f "$case_path/autopsy.db" ]] && has_db=true

  if [[ "$has_aut" == "false" ]]; then
    warn "No .aut file found in case_dir (Autopsy case descriptor)."
  fi
  if [[ "$has_log" == "false" && "$has_db" == "false" ]]; then
    warn "Expected either Log/ directory or autopsy.db in case_dir."
  fi
}

is_placeholder_path() {
  local v="${1,,}"
  [[ "$v" == "c:\\path\\to\\your\\case" ]] && return 0
  [[ "$v" == "/path/to/your/case" ]] && return 0
  [[ "$v" == *"/path/"* ]] && return 0
  [[ "$v" == *"\\path\\"* ]] && return 0
  return 1
}

is_google_app_password_like() {
  local p="${1//[[:space:]]/}"
  [[ ${#p} -eq 16 ]] || return 1
  [[ "$p" =~ ^[A-Za-z]{16}$ ]] || return 1
  return 0
}

echo
echo "AutopsyGuard Setup Wizard (Linux/macOS)"
note "This wizard is security-first and optimized for production-safe defaults."
note "Gmail path is App Password-first."
note "Detailed guide: docs/setup-wizard-guide.md"

section "1) Prerequisites Check"
note "Why this matters: dependency/tooling gaps delay incident coverage."
if [[ "$SKIP_SYNC" == "false" ]]; then
  if command -v uv >/dev/null 2>&1; then
    if prompt_yes_no "Run 'uv sync' now?" "y"; then
      uv sync
    fi
  else
    warn "'uv' command not found. Install uv first, then run this wizard again."
  fi
fi

section "2) Case and Autopsy Paths"
note "Why this matters: monitor needs real case/log paths for accurate detection."
read -r -p "Autopsy case directory (case_dir): " case_dir
if [[ -z "${case_dir// }" ]]; then
  case_dir="/path/to/your/case"
fi
case_dir="${case_dir#"${case_dir%%[![:space:]]*}"}"
case_dir="${case_dir%"${case_dir##*[![:space:]]}"}"
if is_placeholder_path "$case_dir"; then
  blocker "You entered a placeholder case_dir."
  if ! prompt_yes_no "Proceed in DRAFT mode (must edit case_dir before run)?" "n"; then
    case_dir="$(prompt_required "Enter a real case_dir path")"
  fi
fi
if [[ ! -e "$case_dir" ]]; then
  warn "Path does not currently exist: $case_dir"
fi
show_case_dir_hints "$case_dir"

autopsy_install_dir=""
install_candidates_raw="$(detect_autopsy_install_candidates || true)"
if [[ -n "${install_candidates_raw// }" ]]; then
  note "Detected Autopsy install-dir candidates:"
  c=0
  shown=10
  while IFS= read -r line; do
    [[ -z "${line// }" ]] && continue
    c=$((c + 1))
    if [[ $c -le $shown ]]; then
      echo "  [$c] $line"
    fi
  done <<<"$install_candidates_raw"
  if [[ $c -gt $shown ]]; then
    echo "  ... plus $((c - shown)) more"
  fi

  while true; do
    read -r -p "Choose candidate number [1], M for manual, or S to skip: " selected_candidate
    selected_candidate="${selected_candidate// }"
    [[ -z "$selected_candidate" ]] && selected_candidate="1"
    lower_choice="${selected_candidate,,}"
    if [[ "$lower_choice" == "m" ]]; then
      read -r -p "Autopsy install directory (optional): " autopsy_install_dir
      break
    fi
    if [[ "$lower_choice" == "s" ]]; then
      autopsy_install_dir=""
      break
    fi
    if [[ "$selected_candidate" =~ ^[0-9]+$ ]] && ((selected_candidate >= 1 && selected_candidate <= c)); then
      autopsy_install_dir="$(printf "%s\n" "$install_candidates_raw" | sed -n "${selected_candidate}p")"
      break
    fi
    warn "Invalid selection. Choose valid number, M, or S."
  done
else
  warn "No install dir auto-detected. You can skip (optional)."
  read -r -p "Autopsy install directory (optional): " autopsy_install_dir
fi

section "3) Monitoring Performance"
note "Why this matters: affects detection latency and false-positive profile."
poll_interval="$(prompt_default "poll_interval (seconds)" "30.0")"
hang_timeout="$(prompt_default "hang_timeout (seconds)" "900.0")"
report_interval="$(prompt_default "report_interval_hours (example 12.0 or 0.5)" "12.0")"

section "4) Notifications Setup"
note "Why this matters: reliable alerting depends on secure/correct SMTP configuration."
note "Recommended production path: Gmail + Google App Password."

email_enabled=false
smtp_host=""
smtp_port="587"
smtp_use_ssl=false
smtp_async=true
smtp_user=""
smtp_password=""
email_sender="autopsyguard@example.com"
email_recipient=""
email_case_label=""

if prompt_yes_no "Configure email notifications?" "y"; then
  email_enabled=true
  note "Email mode is fixed to Gmail App Password."
  smtp_host="smtp.gmail.com"
  smtp_port="587"
  smtp_use_ssl=false

  if prompt_yes_no "Send email asynchronously (smtp_async)?" "y"; then
    smtp_async=true
  else
    smtp_async=false
  fi
  email_sender="$(prompt_default "Email sender (email_sender)" "autopsyguard@example.com")"
  email_recipient="$(prompt_required "Email recipient (email_recipient)")"
  read -r -p "Email case label (optional): " email_case_label

  note "Gmail App Password checklist:"
  note "  1) Enable 2-Step Verification."
  note "  2) Generate App Password for Mail."
  note "  3) Use app password below, never account password."
  smtp_user="$(prompt_required "SMTP user (your Gmail address)")"
  read -r -s -p "Google App Password: " smtp_password
  smtp_password="${smtp_password// /}"
  echo
  if ! is_google_app_password_like "$smtp_password"; then
    blocker "This does not look like a Google App Password (expected 16 letters)."
    if ! prompt_yes_no "Continue anyway with potentially unsafe/invalid password?" "n"; then
      blocker "Setup aborted to protect email reliability. Re-run with valid App Password."
      exit 1
    fi
  fi
fi

section "5) Optional Channels"
note "Why this matters: backup channels reduce single-point notification risk."
whatsapp_enabled=false
whatsapp_phone=""
whatsapp_apikey=""
if prompt_yes_no "Configure WhatsApp notifications (CallMeBot)?" "n"; then
  whatsapp_enabled=true
  whatsapp_phone="$(prompt_required "WhatsApp phone (+countrycode...)")"
  read -r -p "WhatsApp API key (optional): " whatsapp_apikey
  if [[ -z "${whatsapp_apikey// }" ]]; then
    warn "WhatsApp stays configured but disabled until AUTOPSYGUARD_WHATSAPP_APIKEY is set."
  fi
fi

telegram_enabled=false
telegram_user=""
if prompt_yes_no "Configure Telegram notifications (CallMeBot)?" "n"; then
  telegram_enabled=true
  telegram_user="$(prompt_required "Telegram user (example @myusername)")"
fi

section "6) Final Review and File Generation"
mkdir -p "$(dirname "$CONFIG_PATH")"
mkdir -p "$(dirname "$ENV_FILE_PATH")"

{
  echo "# Generated by scripts/setup-autopsyguard.sh"
  echo "# Security-first defaults. Review values before first production run."
  echo "case_dir: $(yaml_quote "$case_dir")"
  if [[ -n "${autopsy_install_dir// }" ]]; then
    echo "autopsy_install_dir: $(yaml_quote "$autopsy_install_dir")"
  fi
  echo "poll_interval: $poll_interval"
  echo "hang_timeout: $hang_timeout"
  echo "report_interval_hours: $report_interval"
  echo
  echo "# Localization and labels"
  echo "case_name_source: 'real'"
  echo
  echo "# Email (enabled when smtp_host + email_recipient are set)"
  echo "smtp_host: $(yaml_quote "$smtp_host")"
  echo "smtp_port: $smtp_port"
  echo "smtp_use_ssl: $smtp_use_ssl"
  echo "smtp_async: $smtp_async"
  echo "email_sender: $(yaml_quote "$email_sender")"
  echo "email_recipient: $(yaml_quote "$email_recipient")"
  echo "email_case_label: $(yaml_quote "$email_case_label")"
  echo
  echo "# WhatsApp (CallMeBot)"
  echo "whatsapp_enabled: $whatsapp_enabled"
  echo "whatsapp_phone: $(yaml_quote "$whatsapp_phone")"
  echo "whatsapp_apikey: ''"
  echo
  echo "# Telegram (CallMeBot)"
  echo "telegram_enabled: $telegram_enabled"
  echo "telegram_user: $(yaml_quote "$telegram_user")"
} >"$CONFIG_PATH"

{
  echo "# AutopsyGuard secrets - generated by scripts/setup-autopsyguard.sh"
  echo "# Loaded automatically by AutopsyGuard at startup."
  echo "# Do NOT commit this file to version control."
  if [[ -n "${smtp_user// }" ]]; then
    echo "AUTOPSYGUARD_SMTP_USER=${smtp_user}"
  fi
  if [[ -n "${smtp_password// }" ]]; then
    echo "AUTOPSYGUARD_SMTP_PASSWORD=${smtp_password}"
  fi
  if [[ -n "${whatsapp_apikey// }" ]]; then
    echo "AUTOPSYGUARD_WHATSAPP_APIKEY=${whatsapp_apikey}"
  fi
  if [[ -z "${smtp_user// }" && -z "${smtp_password// }" && -z "${whatsapp_apikey// }" ]]; then
    echo "# (No secrets provided.)"
    echo "# Example:"
    echo "#   AUTOPSYGUARD_SMTP_USER=your-user"
    echo "#   AUTOPSYGUARD_SMTP_PASSWORD=your-app-password"
    echo "#   AUTOPSYGUARD_WHATSAPP_APIKEY=your-callmebot-key"
  fi
} >"$ENV_FILE_PATH"

chmod 600 "$ENV_FILE_PATH" 2>/dev/null || true

echo
echo "Setup complete."
echo "Config file : $CONFIG_PATH"
echo "Secrets file: $ENV_FILE_PATH"
echo "Guide       : docs/setup-wizard-guide.md"

section "Operational Checklist"
echo "1) Review generated files:"
echo "   - $CONFIG_PATH"
echo "   - $ENV_FILE_PATH"
echo "2) Start monitor:"
echo "   uv run autopsyguard --config ./$CONFIG_PATH"
echo "3) Quick email channel smoke-check:"
echo "   uv run autopsyguard --config ./$CONFIG_PATH --verbose"
echo "   (Open Autopsy case and confirm startup notification arrives.)"
echo "4) Full setup guide:"
echo "   docs/setup-wizard-guide.md"

echo
echo "Top 5 common failures and fixes:"
echo "  - SMTP auth failed: verify App Password (not account password)."
echo "  - Gmail rejects login: verify 2-Step Verification is enabled."
echo "  - No email received: validate recipient, sender policy, spam folder."
echo "  - Case not detected: ensure case_dir points to real folder with .aut."
echo "  - WhatsApp not sending: set AUTOPSYGUARD_WHATSAPP_APIKEY in .env."

if [[ "$RUN_AFTER_SETUP" == "true" ]]; then
  uv run autopsyguard --config "./$CONFIG_PATH"
fi

