#!/bin/bash
# =============================================================================
# PQC Validator — Arc Custom Script Extension Bootstrap (Linux)
# =============================================================================
# Runs ONCE via the Arc CustomScript extension.
# Installs the PQC Compliance Validator and wires a daily systemd timer
# (cron fallback) to run the validator and stream results to Log Analytics
# via the Arc machine's System-Assigned Managed Identity.
#
# Required environment variables (set by CSE protectedSettings):
#   PQC_DCE_ENDPOINT        Data Collection Endpoint URL
#   PQC_DCR_IMMUTABLE_ID    DCR Immutable ID
#   PQC_PACKAGE_URL         SAS URL to pqc-validator.zip in blob storage
#
# Optional environment variables:
#   PQC_STREAM_NAME         Log Analytics stream name (default: Custom-PQCCompliance_CL)
#   PQC_SCHEDULE_TIME       Daily UTC run time HH:MM (default: 03:00)
#   PQC_INSTALL_DIR         Installation directory (default: /opt/pqc-validator)
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
INSTALL_DIR="${PQC_INSTALL_DIR:-/opt/pqc-validator}"
VENV_DIR="${INSTALL_DIR}/venv"
DAILY_SCRIPT="${INSTALL_DIR}/run-daily.sh"
SERVICE_NAME="pqc-validator"
STREAM_NAME="${PQC_STREAM_NAME:-Custom-PQCCompliance_CL}"
SCHEDULE_TIME="${PQC_SCHEDULE_TIME:-03:00}"
LOG_FILE="/var/log/pqc-cse-install.log"
LOG_DIR="/var/log/pqc-validator"
REPORT_DIR="/var/log/pqc-reports"

# ── Logging ───────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"; }

log "=========================================================="
log "PQC Validator CSE Install starting"log 'Version      : 3.0.0'log "=========================================================="

# ── Validate required parameters ──────────────────────────────────────────────
MISSING=""
for var in PQC_DCE_ENDPOINT PQC_DCR_IMMUTABLE_ID PQC_PACKAGE_URL; do
    if [ -z "${!var:-}" ]; then
        MISSING="$MISSING $var"
    fi
done
if [ -n "$MISSING" ]; then
    log "ERROR: Missing required environment variables:$MISSING"
    exit 1
fi

log "DCE Endpoint : $PQC_DCE_ENDPOINT"
log "DCR ID       : $PQC_DCR_IMMUTABLE_ID"
log "Stream Name  : $STREAM_NAME"
log "Schedule     : $SCHEDULE_TIME UTC"
log "Install Dir  : $INSTALL_DIR"

# ── Install Python 3 ─────────────────────────────────────────────────────────
log "--- Checking Python 3..."
if ! command -v python3 &>/dev/null; then
    log "Python 3 not found — installing..."
    if   command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq python3 python3-pip python3-venv curl unzip
    elif command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pip curl unzip
    elif command -v yum &>/dev/null; then
        yum install -y python3 python3-pip curl unzip
    elif command -v zypper &>/dev/null; then
        zypper install -y python3 python3-pip curl unzip
    else
        log "ERROR: No supported package manager (apt/dnf/yum/zypper) found"
        exit 1
    fi
fi

# ── Ensure curl and unzip are present (may be missing even when Python is) ────
log "--- Checking curl and unzip..."
MISSING_PKGS=""
command -v curl  &>/dev/null || MISSING_PKGS="$MISSING_PKGS curl"
command -v unzip &>/dev/null || MISSING_PKGS="$MISSING_PKGS unzip"

if [ -n "$MISSING_PKGS" ]; then
    log "Installing missing utilities:$MISSING_PKGS"
    if   command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq $MISSING_PKGS
    elif command -v dnf     &>/dev/null; then dnf install -y $MISSING_PKGS
    elif command -v yum     &>/dev/null; then yum install -y $MISSING_PKGS
    elif command -v zypper  &>/dev/null; then zypper install -y $MISSING_PKGS
    else
        log "ERROR: Cannot install $MISSING_PKGS — no supported package manager"
        exit 1
    fi
fi

PYTHON_BIN=$(command -v python3)
log "Python: $($PYTHON_BIN --version 2>&1)"

# Ensure pip and venv are available (some distros split them into extra packages)
# On Debian/Ubuntu, python3-venv installs the base module but ensurepip requires
# the version-specific package (e.g. python3.12-venv). Install both explicitly.
if ! $PYTHON_BIN -c "import ensurepip" &>/dev/null 2>&1; then
    log "ensurepip missing — installing version-specific venv package..."
    PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if   command -v apt-get &>/dev/null; then
        apt-get install -y -qq "python${PY_VER}-venv" python3-venv || true
    elif command -v dnf     &>/dev/null; then dnf  install -y python3-venv || true
    elif command -v yum     &>/dev/null; then yum  install -y python3-venv || true
    fi
fi

# ── Download & extract validator package ──────────────────────────────────────
log "--- Downloading PQC Validator package..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

curl -sSL --fail -o "$TMP_DIR/validator.zip" "$PQC_PACKAGE_URL" \
    || { log "ERROR: Failed to download package from PQC_PACKAGE_URL"; exit 1; }

log "--- Extracting to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
unzip -q -o "$TMP_DIR/validator.zip" -d "$INSTALL_DIR"

# ── Create Python virtual environment ─────────────────────────────────────────
log "--- Creating Python virtual environment..."
$PYTHON_BIN -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip

# Install only runtime requirements (no management-plane packages needed on Arc machines)
if [ -f "$INSTALL_DIR/requirements-arc.txt" ]; then
    "$VENV_DIR/bin/pip" install --quiet -r "$INSTALL_DIR/requirements-arc.txt"
else
    "$VENV_DIR/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
fi

# ── Create runtime directories ────────────────────────────────────────────────
mkdir -p "$LOG_DIR" "$REPORT_DIR"
chmod 755 "$LOG_DIR" "$REPORT_DIR"

# ── Write daily runner script ─────────────────────────────────────────────────
log "--- Writing daily runner: $DAILY_SCRIPT"
cat > "$DAILY_SCRIPT" <<RUNNER
#!/bin/bash
# PQC Validator daily runner — called by systemd timer or cron
# Streams validation results to Log Analytics via Arc Managed Identity.
set -uo pipefail

export PQC_DCE_ENDPOINT="${PQC_DCE_ENDPOINT}"
export PQC_DCR_IMMUTABLE_ID="${PQC_DCR_IMMUTABLE_ID}"
export PQC_STREAM_NAME="${STREAM_NAME}"

RUN_DATE=\$(date -u '+%Y%m%d')
RUN_LOG="${LOG_DIR}/run-\${RUN_DATE}.log"

echo "[run] PQC validation started: \$(date -u)" | tee -a "\$RUN_LOG"

cd "${INSTALL_DIR}"
"${VENV_DIR}/bin/python" main.py \
    --log-dir "${LOG_DIR}" \
    --report-dir "${REPORT_DIR}" \
    --no-reports \
    >> "\$RUN_LOG" 2>&1
EXIT_CODE=\$?

echo "[run] PQC validation finished: \$(date -u) exit=\$EXIT_CODE" | tee -a "\$RUN_LOG"

# Rotate logs older than 30 days
find "${LOG_DIR}" -name "run-*.log" -mtime +30 -delete 2>/dev/null || true

exit \$EXIT_CODE
RUNNER
chmod +x "$DAILY_SCRIPT"

# ── Set up daily scheduler ────────────────────────────────────────────────────
SCHEDULE_HOUR="${SCHEDULE_TIME%%:*}"
SCHEDULE_MIN="${SCHEDULE_TIME##*:}"

# Prefer systemd timer on modern systems
if command -v systemctl &>/dev/null && systemctl is-system-running --quiet 2>/dev/null; then

    log "--- Installing systemd service + timer..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=PQC Compliance Validator (daily)
Documentation=https://github.com/wayneme75/customer
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${DAILY_SCRIPT}
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pqc-validator
Environment=PQC_DCE_ENDPOINT=${PQC_DCE_ENDPOINT}
Environment=PQC_DCR_IMMUTABLE_ID=${PQC_DCR_IMMUTABLE_ID}
Environment=PQC_STREAM_NAME=${STREAM_NAME}
SERVICE

    cat > "/etc/systemd/system/${SERVICE_NAME}.timer" <<TIMER
[Unit]
Description=Daily PQC Compliance Validation
Requires=${SERVICE_NAME}.service

[Timer]
OnCalendar=*-*-* ${SCHEDULE_HOUR}:${SCHEDULE_MIN}:00 UTC
# Catch up if machine was off at scheduled time
Persistent=true
# Spread load — offset by up to 5 min across fleet
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
TIMER

    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}.timer"
    log "Systemd timer enabled: ${SERVICE_NAME}.timer (daily at ${SCHEDULE_TIME} UTC)"
    systemctl list-timers "${SERVICE_NAME}.timer" --no-pager || true

else
    # Fallback: /etc/cron.d entry
    log "--- Systemd not available — installing cron job..."
    CRON_FILE="/etc/cron.d/${SERVICE_NAME}"
    cat > "$CRON_FILE" <<CRON
# PQC Compliance Validator — daily execution
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
${SCHEDULE_MIN} ${SCHEDULE_HOUR} * * * root ${DAILY_SCRIPT} >> ${LOG_DIR}/cron.log 2>&1
CRON
    chmod 644 "$CRON_FILE"
    log "Cron job installed: $CRON_FILE (daily at ${SCHEDULE_TIME} UTC)"
fi

# ── Run immediately on first install ──────────────────────────────────────────
log "--- Running initial validation (this may take a few minutes)..."
"$DAILY_SCRIPT" \
    && log "Initial validation completed successfully" \
    || log "WARNING: Initial validation exited with errors — check $LOG_DIR"

log "=========================================================="
log "PQC Validator install complete"
log "  Validator  : $INSTALL_DIR"
log "  Daily log  : $LOG_DIR/run-YYYYMMDD.log"
log "  Schedule   : $SCHEDULE_TIME UTC"
log "  Install log: $LOG_FILE"
log "=========================================================="
