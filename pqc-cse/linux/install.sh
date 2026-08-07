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
#   PQC_PACKAGE_SHA256      Expected SHA-256 digest of pqc-validator.zip
#   PQC_PACKAGE_SIG_URL     SAS URL to detached signature for pqc-validator.zip
#   PQC_PACKAGE_PUBKEY_URL  URL to PEM public key used to verify signature
#
# Optional environment variables:
#   PQC_STREAM_NAME         Log Analytics stream name (default: Custom-PQCCompliance_CL)
#   PQC_SCHEDULE_TIME       Daily UTC run time HH:MM (default: 03:00)
#   PQC_INSTALL_DIR         Installation directory (default: /opt/pqc-validator)
#   PQC_ALLOW_ONLINE_BOOTSTRAP  Set to true to allow apt/dnf/yum/zypper installs
#                               when prerequisites are missing (default: false)
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
INSTALL_DIR="${PQC_INSTALL_DIR:-/opt/pqc-validator}"
VENV_DIR="${INSTALL_DIR}/venv"
DAILY_SCRIPT="${INSTALL_DIR}/run-daily.sh"
SERVICE_NAME="pqc-validator"
SERVICE_USER="pqc-validator"
SERVICE_GROUP="pqc-validator"
STREAM_NAME="${PQC_STREAM_NAME:-Custom-PQCCompliance_CL}"
SCHEDULE_TIME="${PQC_SCHEDULE_TIME:-03:00}"
LOG_FILE="/var/log/pqc-cse-install.log"
LOG_DIR="/var/log/pqc-validator"
REPORT_DIR="/var/log/pqc-reports"
ALLOW_ONLINE_BOOTSTRAP="${PQC_ALLOW_ONLINE_BOOTSTRAP:-false}"

# ── Logging ───────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"; }

log "=========================================================="
log "PQC Validator CSE Install starting"
log "Version      : 3.1.1"
log "=========================================================="

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log "ERROR: install.sh must run as root"
    exit 1
fi

# ── Validate required parameters ──────────────────────────────────────────────
MISSING=""
for var in PQC_DCE_ENDPOINT PQC_DCR_IMMUTABLE_ID PQC_PACKAGE_URL PQC_PACKAGE_SHA256 PQC_PACKAGE_SIG_URL PQC_PACKAGE_PUBKEY_URL; do
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
log "Package SHA  : $PQC_PACKAGE_SHA256"
log "Online bootstrap enabled: $ALLOW_ONLINE_BOOTSTRAP"

install_prereqs_online() {
    local packages="$1"
    if   command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq $packages
    elif command -v dnf     &>/dev/null; then
        dnf install -y $packages
    elif command -v yum     &>/dev/null; then
        yum install -y $packages
    elif command -v zypper  &>/dev/null; then
        zypper install -y $packages
    else
        log "ERROR: No supported package manager (apt/dnf/yum/zypper) found"
        exit 1
    fi
}

collect_missing_prereqs() {
    local missing=""
    command -v python3   &>/dev/null || missing="$missing python3"
    command -v curl      &>/dev/null || missing="$missing curl"
    command -v unzip     &>/dev/null || missing="$missing unzip"
    command -v openssl   &>/dev/null || missing="$missing openssl"
    command -v sha256sum &>/dev/null || missing="$missing coreutils"
    echo "$missing"
}

# ── Validate host prerequisites (offline-safe by default) ────────────────────
log "--- Checking host prerequisites..."
MISSING_PKGS="$(collect_missing_prereqs)"

if [ -n "$MISSING_PKGS" ]; then
    if [ "$ALLOW_ONLINE_BOOTSTRAP" = "true" ]; then
        log "Installing missing prerequisites via OS package manager:$MISSING_PKGS"
        install_prereqs_online "$MISSING_PKGS"
    else
        log "ERROR: Missing required host prerequisites:$MISSING_PKGS"
        log "Offline enclaves must pre-stage prerequisites in the base image or VM template."
        log "To permit installer-managed package installs, set PQC_ALLOW_ONLINE_BOOTSTRAP=true"
        exit 1
    fi
fi

MISSING_AFTER_BOOTSTRAP="$(collect_missing_prereqs)"
if [ -n "$MISSING_AFTER_BOOTSTRAP" ]; then
    log "ERROR: Required host prerequisites still missing:$MISSING_AFTER_BOOTSTRAP"
    exit 1
fi

PYTHON_BIN=$(command -v python3)
log "Python: $($PYTHON_BIN --version 2>&1)"

# Ensure pip and venv are available (some distros split them into extra packages)
# On Debian/Ubuntu, python3-venv installs the base module but ensurepip requires
# the version-specific package (e.g. python3.12-venv). Install both explicitly.
if ! $PYTHON_BIN -c "import ensurepip" &>/dev/null 2>&1; then
    if [ "$ALLOW_ONLINE_BOOTSTRAP" = "true" ]; then
        log "ensurepip missing — attempting to install venv packages via OS package manager..."
        PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if   command -v apt-get &>/dev/null; then
            apt-get install -y -qq "python${PY_VER}-venv" python3-venv || true
        elif command -v dnf     &>/dev/null; then dnf  install -y python3-venv || true
        elif command -v yum     &>/dev/null; then yum  install -y python3-venv || true
        elif command -v zypper  &>/dev/null; then zypper install -y python3-venv || true
        fi
    fi

    if ! $PYTHON_BIN -c "import ensurepip" &>/dev/null 2>&1; then
        log "ERROR: Python ensurepip/venv support is missing."
        log "Pre-stage python3-venv (or distro equivalent) in enclave images."
        exit 1
    fi
fi

# ── Download and verify signed validator package ─────────────────────────────
log "--- Downloading signed PQC Validator package..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

PACKAGE_ZIP="$TMP_DIR/validator.zip"
PACKAGE_SIG="$TMP_DIR/validator.zip.sig"
PACKAGE_PUBKEY="$TMP_DIR/pqc-signing-key.pem"

curl -sSL --fail -o "$PACKAGE_ZIP" "$PQC_PACKAGE_URL" \
    || { log "ERROR: Failed to download package from PQC_PACKAGE_URL"; exit 1; }
curl -sSL --fail -o "$PACKAGE_SIG" "$PQC_PACKAGE_SIG_URL" \
    || { log "ERROR: Failed to download signature from PQC_PACKAGE_SIG_URL"; exit 1; }
curl -sSL --fail -o "$PACKAGE_PUBKEY" "$PQC_PACKAGE_PUBKEY_URL" \
    || { log "ERROR: Failed to download public key from PQC_PACKAGE_PUBKEY_URL"; exit 1; }

log "--- Verifying package SHA-256..."
ACTUAL_SHA256=$(sha256sum "$PACKAGE_ZIP" | awk '{print $1}')
EXPECTED_SHA256=$(echo "$PQC_PACKAGE_SHA256" | tr '[:upper:]' '[:lower:]')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    log "ERROR: Package hash mismatch"
    log "  expected: $EXPECTED_SHA256"
    log "  actual  : $ACTUAL_SHA256"
    exit 1
fi

log "--- Verifying detached package signature..."
openssl dgst -sha256 -verify "$PACKAGE_PUBKEY" -signature "$PACKAGE_SIG" "$PACKAGE_ZIP" >/dev/null \
    || { log "ERROR: Signature verification failed"; exit 1; }
log "Package verification passed"

log "--- Extracting to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
unzip -q -o "$PACKAGE_ZIP" -d "$INSTALL_DIR"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        WHEELHOUSE_PATH="$INSTALL_DIR/wheelhouse/linux-x86_64"
        LOCK_PATH="$INSTALL_DIR/requirements-arc-lock-linux-x86_64.txt"
        ;;
    aarch64|arm64)
        WHEELHOUSE_PATH="$INSTALL_DIR/wheelhouse/linux-aarch64"
        LOCK_PATH="$INSTALL_DIR/requirements-arc-lock-linux-aarch64.txt"
        ;;
    *)
        log "ERROR: Unsupported Linux architecture: $ARCH"
        exit 1
        ;;
esac

if [ ! -d "$WHEELHOUSE_PATH" ] || [ ! -f "$LOCK_PATH" ]; then
    if [ -d "$INSTALL_DIR/wheelhouse" ] && [ -f "$INSTALL_DIR/requirements-arc-lock.txt" ]; then
        WHEELHOUSE_PATH="$INSTALL_DIR/wheelhouse"
        LOCK_PATH="$INSTALL_DIR/requirements-arc-lock.txt"
    else
        log "ERROR: Secure dependency bundle missing ($LOCK_PATH or $WHEELHOUSE_PATH)"
        exit 1
    fi
fi

log "Using wheelhouse: $WHEELHOUSE_PATH"
log "Using lock file  : $LOCK_PATH"

# ── Create least-privilege runtime account ───────────────────────────────────
if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    log "--- Creating service group: $SERVICE_GROUP"
    groupadd --system "$SERVICE_GROUP"
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "--- Creating service account: $SERVICE_USER"
    NOLOGIN_BIN=$(command -v nologin || echo "/sbin/nologin")
    useradd --system --home "$INSTALL_DIR" --shell "$NOLOGIN_BIN" --gid "$SERVICE_GROUP" "$SERVICE_USER"
fi

# Arc managed identity tokens are protected by the himds group on Linux Arc hosts.
# Add the validator service account so ManagedIdentityCredential can read token key files.
if getent group himds >/dev/null 2>&1; then
    if id -nG "$SERVICE_USER" | tr ' ' '\n' | grep -qx "himds"; then
        log "Service account already has Arc MI token access (group: himds)"
    else
        usermod -a -G himds "$SERVICE_USER"
        log "Granted Arc MI token access to service account via group: himds"
    fi
else
    log "WARNING: Arc group 'himds' not found; Managed Identity token access may fail"
fi

chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$INSTALL_DIR"

run_as_service() {
    if command -v runuser &>/dev/null; then
        runuser -u "$SERVICE_USER" -- "$@"
    else
        su -s /bin/bash "$SERVICE_USER" -c "$(printf '%q ' "$@")"
    fi
}

# ── Create Python virtual environment ─────────────────────────────────────────
log "--- Creating Python virtual environment..."
run_as_service "$PYTHON_BIN" -m venv "$VENV_DIR"

# Install runtime dependencies from offline wheelhouse with strict hash checking.
run_as_service "$VENV_DIR/bin/pip" install --quiet \
    --no-index \
    --find-links "$WHEELHOUSE_PATH" \
    --require-hashes \
    -r "$LOCK_PATH"

# ── Create runtime directories ────────────────────────────────────────────────
mkdir -p "$LOG_DIR" "$REPORT_DIR"
chmod 755 "$LOG_DIR" "$REPORT_DIR"
chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$LOG_DIR" "$REPORT_DIR"

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
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
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
${SCHEDULE_MIN} ${SCHEDULE_HOUR} * * * ${SERVICE_USER} ${DAILY_SCRIPT} >> ${LOG_DIR}/cron.log 2>&1
CRON
    chmod 644 "$CRON_FILE"
    log "Cron job installed: $CRON_FILE (daily at ${SCHEDULE_TIME} UTC)"
fi

# ── Run immediately on first install ──────────────────────────────────────────
log "--- Running initial validation (this may take a few minutes)..."
run_as_service "$DAILY_SCRIPT" \
    && log "Initial validation completed successfully" \
    || log "WARNING: Initial validation exited with errors — check $LOG_DIR"

log "=========================================================="
log "PQC Validator install complete"
log "  Validator  : $INSTALL_DIR"
log "  Daily log  : $LOG_DIR/run-YYYYMMDD.log"
log "  Schedule   : $SCHEDULE_TIME UTC"
log "  Install log: $LOG_FILE"
log "=========================================================="
