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

prompt_required() {
  local prompt="$1"
  local value=""
  while true; do
    read -r -p "$prompt: " value
    if [[ -n "${value// }" ]]; then
      printf "%s" "$value"
      return
    fi
    echo "Value is required."
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
    echo "Please answer y or n."
  done
}

yaml_quote() {
  local v="$1"
  local escaped
  escaped="$(printf "%s" "$v" | sed "s/'/''/g")"
  printf "'%s'" "$escaped"
}

shell_quote() {
  local v="$1"
  local escaped
  escaped="$(printf "%s" "$v" | sed "s/'/'\"'\"'/g")"
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
    echo "Hint: case_dir path does not exist yet. Validation may fail until the case is available."
    return
  fi

  local has_aut=false
  local has_log=false
  local has_db=false
  if compgen -G "$case_path/*.aut" > /dev/null; then
    has_aut=true
  fi
  [[ -d "$case_path/Log" ]] && has_log=true
  [[ -f "$case_path/autopsy.db" ]] && has_db=true

  if [[ "$has_aut" == "false" ]]; then
    echo "Hint: no .aut file found in case_dir (Autopsy case descriptor)."
  fi
  if [[ "$has_log" == "false" && "$has_db" == "false" ]]; then
    echo "Hint: expected either Log/ directory or autopsy.db in case_dir."
  fi
}

echo
echo "AutopsyGuard Setup Wizard (Linux/macOS)"
echo "This will generate a config file and a .env file for secrets."
echo "Secrets in .env are loaded automatically by AutopsyGuard at startup."
echo
echo "Quick guidance:"
echo "  - case_dir should contain *.aut and (Log/ or autopsy.db)"
echo "  - autopsy_install_dir is optional (mainly improves JVM crash file search)"
echo "  - SMTP 587 -> smtp_use_ssl=false (STARTTLS), SMTP 465 -> smtp_use_ssl=true"
echo "  - Install-dir lookup checks Linux defaults and Snap paths"
echo

if [[ "$SKIP_SYNC" == "false" ]]; then
  if command -v uv >/dev/null 2>&1; then
    if prompt_yes_no "Run 'uv sync' now?" "y"; then
      uv sync
    fi
  else
    echo "Warning: 'uv' command not found. Install uv first, then run this script again."
  fi
fi

case_dir="$(prompt_required "Autopsy case directory (case_dir)")"
if [[ ! -e "$case_dir" ]]; then
  echo "Warning: path does not currently exist: $case_dir"
fi
show_case_dir_hints "$case_dir"

autopsy_install_dir=""
install_candidates_raw="$(detect_autopsy_install_candidates || true)"
if [[ -n "${install_candidates_raw// }" ]]; then
  echo
  echo "Detected Autopsy install-dir candidates:"
  c=0
  first_candidate=""
  while IFS= read -r line; do
    [[ -z "${line// }" ]] && continue
    c=$((c + 1))
    [[ $c -eq 1 ]] && first_candidate="$line"
    if [[ $c -le 5 ]]; then
      echo "  [$c] $line"
    fi
  done <<< "$install_candidates_raw"
  if [[ $c -gt 5 ]]; then
    echo "  ... plus $((c - 5)) more"
  fi

  if prompt_yes_no "Use detected install dir '$first_candidate'?" "y"; then
    autopsy_install_dir="$first_candidate"
  else
    read -r -p "Autopsy install directory (optional, for hs_err_pid*.log search): " autopsy_install_dir
  fi
else
  echo "No install dir auto-detected. You can leave it blank (optional)."
  read -r -p "Autopsy install directory (optional, for hs_err_pid*.log search): " autopsy_install_dir
fi
poll_interval="$(prompt_default "poll_interval (seconds)" "30.0")"
hang_timeout="$(prompt_default "hang_timeout (seconds)" "900.0")"
report_interval="$(prompt_default "report_interval_hours" "12.0")"

email_enabled=false
smtp_host=""
smtp_port="587"
smtp_use_ssl=false
smtp_async=true
email_sender="autopsyguard@example.com"
email_recipient=""
email_case_label=""
smtp_user=""
smtp_password=""

if prompt_yes_no "Configure email notifications?" "y"; then
  email_enabled=true
  smtp_host="$(prompt_required "SMTP host (smtp_host)")"
  smtp_port="$(prompt_default "SMTP port (smtp_port)" "587")"
  if prompt_yes_no "Use SMTP SSL (smtp_use_ssl)? Use true for port 465, false for STARTTLS on 587" "n"; then
    smtp_use_ssl=true
  fi
  if prompt_yes_no "Send email asynchronously (smtp_async)?" "y"; then
    smtp_async=true
  else
    smtp_async=false
  fi
  email_sender="$(prompt_default "Email sender (email_sender)" "autopsyguard@example.com")"
  email_recipient="$(prompt_required "Email recipient (email_recipient)")"
  read -r -p "Email case label (email_case_label, optional): " email_case_label
  read -r -p "SMTP user (optional, stored in env script as AUTOPSYGUARD_SMTP_USER): " smtp_user
  read -r -s -p "SMTP password (optional, stored in env script as AUTOPSYGUARD_SMTP_PASSWORD): " smtp_password
  echo

  if [[ "$smtp_use_ssl" == "true" && "$smtp_port" == "587" ]]; then
    echo "Suggestion: SMTP port 587 usually uses STARTTLS (smtp_use_ssl=false)."
  fi
  if [[ "$smtp_use_ssl" == "false" && "$smtp_port" == "465" ]]; then
    echo "Suggestion: SMTP port 465 usually uses implicit SSL (smtp_use_ssl=true)."
  fi
fi

whatsapp_enabled=false
whatsapp_phone=""
whatsapp_apikey=""
if prompt_yes_no "Configure WhatsApp notifications?" "n"; then
  whatsapp_enabled=true
  whatsapp_phone="$(prompt_required "WhatsApp phone (+countrycode...)")"
  read -r -p "WhatsApp API key (optional; if blank, keep disabled until set): " whatsapp_apikey
  if [[ -z "${whatsapp_apikey// }" ]]; then
    echo "Note: WhatsApp requires AUTOPSYGUARD_WHATSAPP_APIKEY before alerts can be sent."
  fi
fi

telegram_enabled=false
telegram_user=""
if prompt_yes_no "Configure Telegram notifications?" "n"; then
  telegram_enabled=true
  telegram_user="$(prompt_required "Telegram user (e.g. @myusername)")"
fi

mkdir -p "$(dirname "$CONFIG_PATH")"
mkdir -p "$(dirname "$ENV_FILE_PATH")"

{
  echo "# Generated by scripts/setup-autopsyguard.sh"
  echo "# You can edit this file manually after setup."
  echo "case_dir: $(yaml_quote "$case_dir")"
  if [[ -n "${autopsy_install_dir// }" ]]; then
    echo "autopsy_install_dir: $(yaml_quote "$autopsy_install_dir")"
  fi
  echo "poll_interval: $poll_interval"
  echo "hang_timeout: $hang_timeout"
  echo "report_interval_hours: $report_interval"
  echo
  echo "# Email (enabled when smtp_host and email_recipient are set)"
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
} > "$CONFIG_PATH"

{
  echo "# AutopsyGuard secrets — generated by scripts/setup-autopsyguard.sh"
  echo "# This file is loaded automatically by AutopsyGuard at startup."
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
    echo "# (No secret env vars were provided.)"
    echo "# Example:"
    echo "#   AUTOPSYGUARD_SMTP_USER=your-user"
    echo "#   AUTOPSYGUARD_SMTP_PASSWORD=your-password"
    echo "#   AUTOPSYGUARD_WHATSAPP_APIKEY=your-callmebot-key"
  fi
} > "$ENV_FILE_PATH"

chmod 600 "$ENV_FILE_PATH" 2>/dev/null || true

echo
echo "Setup complete."
echo "Config file : $CONFIG_PATH"
echo "Secrets file: $ENV_FILE_PATH  (loaded automatically by AutopsyGuard)"
echo
echo "Next steps:"
echo "  1. uv run autopsyguard --config ./$CONFIG_PATH"
echo "  2. Optional debug run: uv run autopsyguard --config ./$CONFIG_PATH --verbose"
echo
echo "Configuration summary:"
echo "  - Email: $email_enabled"
echo "  - WhatsApp: $whatsapp_enabled"
echo "  - Telegram: $telegram_enabled"
echo "  - Polling: $poll_interval s"
echo "  - Hang timeout: $hang_timeout s"
echo

if [[ "$RUN_AFTER_SETUP" == "true" ]]; then
  uv run autopsyguard --config "./$CONFIG_PATH"
fi
