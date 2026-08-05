#!/bin/bash
# =============================================================================
# package-and-upload.sh  —  Package the PQC Validator and upload CSE artifacts
#                            to Azure Blob Storage
# =============================================================================
# Produces:
#   pqc-validator.zip          — validator source code + requirements
#   linux/install.sh           — Linux CSE bootstrap
#   windows/install.ps1        — Windows CSE bootstrap
#
# SAS URLs are written to .env.cse for use in main.bicepparam / policy params.
#
# Usage:
#   ./package-and-upload.sh \
#       --storage-account <name> \
#       --resource-group  <rg> \
#       --subscription    <sub-id>
#
#   Optional:
#     --container  <name>    (default: pqc-cse)
#     --sas-days   <n>       SAS token validity in days (default: 365)
#     --cloud      AzureCloud | AzureUSGovernment  (default: auto-detected)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR_DIR="$(cd "$SCRIPT_DIR/../pqc-validator" && pwd)"
CSE_DIR="$SCRIPT_DIR"

# ── Defaults ──────────────────────────────────────────────────────────────────
CONTAINER="pqc-cse"
SAS_DAYS=365
CLOUD=""
STORAGE_ACCOUNT=""
RESOURCE_GROUP=""
SUBSCRIPTION=""

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --storage-account) STORAGE_ACCOUNT="$2"; shift 2 ;;
        --resource-group)  RESOURCE_GROUP="$2";  shift 2 ;;
        --subscription)    SUBSCRIPTION="$2";    shift 2 ;;
        --container)       CONTAINER="$2";       shift 2 ;;
        --sas-days)        SAS_DAYS="$2";        shift 2 ;;
        --cloud)           CLOUD="$2";           shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

for var in STORAGE_ACCOUNT RESOURCE_GROUP SUBSCRIPTION; do
    if [ -z "${!var}" ]; then
        echo "ERROR: --${var//_/-} is required"
        exit 1
    fi
done

log() { echo "[$(date -u '+%H:%M:%S')] $*"; }

# ── Set Azure cloud if specified ──────────────────────────────────────────────
if [ -n "$CLOUD" ]; then
    az cloud set --name "$CLOUD"
fi

az account set --subscription "$SUBSCRIPTION"

# ── Auto-detect cloud for endpoints ───────────────────────────────────────────
CURRENT_CLOUD=$(az cloud show --query name -o tsv 2>/dev/null || echo "AzureCloud")
if [[ "$CURRENT_CLOUD" == *"Government"* ]]; then
    BLOB_SUFFIX="blob.core.usgovcloudapi.net"
else
    BLOB_SUFFIX="blob.core.windows.net"
fi
log "Cloud: $CURRENT_CLOUD | Blob suffix: $BLOB_SUFFIX"

# ── Create storage container (public read for scripts, private for package) ───
log "Ensuring storage container '$CONTAINER' exists..."
az storage container create \
    --name "$CONTAINER" \
    --account-name "$STORAGE_ACCOUNT" \
    --resource-group "$RESOURCE_GROUP" \
    --public-access off \
    --output none 2>/dev/null || true

# ── Build validator zip ───────────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

ZIP_PATH="$TMP_DIR/pqc-validator.zip"
log "Building pqc-validator.zip..."

(
  cd "$VALIDATOR_DIR"
  zip -r "$ZIP_PATH" . \
      --exclude "venv/*" \
      --exclude "*.pyc" \
      --exclude "__pycache__/*" \
      --exclude "*.egg-info/*" \
      --exclude "logs/*" \
      --exclude "reports/*" \
      --exclude ".git/*" \
      --exclude ".gitignore" \
      --exclude "tests/*" \
      --exclude "*.log"
)

# Bundle the Windows PowerShell module so install.ps1 can find it after extraction
(cd "$CSE_DIR/windows" && zip "$ZIP_PATH" PQCValidator.psm1)
log "Bundled PQCValidator.psm1 into package zip"

log "Package size: $(du -sh "$ZIP_PATH" | cut -f1)"

# ── Upload artifacts ──────────────────────────────────────────────────────────
upload_blob() {
    local local_path="$1"
    local blob_name="$2"
    az storage blob upload \
        --account-name "$STORAGE_ACCOUNT" \
        --container-name "$CONTAINER" \
        --file "$local_path" \
        --name "$blob_name" \
        --overwrite \
        --output none
    log "Uploaded: $blob_name"
}

log "--- Uploading CSE artifacts..."
upload_blob "$ZIP_PATH"                              "pqc-validator.zip"
upload_blob "$CSE_DIR/linux/install.sh"              "linux/install.sh"
upload_blob "$CSE_DIR/windows/install.ps1"           "windows/install.ps1"
upload_blob "$CSE_DIR/windows/PQCValidator.psm1"     "windows/PQCValidator.psm1"

# ── Generate SAS tokens ───────────────────────────────────────────────────────
log "--- Generating SAS tokens (valid for ${SAS_DAYS} days)..."
EXPIRY=$(date -u -d "+${SAS_DAYS} days" '+%Y-%m-%dT%H:%MZ' 2>/dev/null \
         || date -u -v "+${SAS_DAYS}d" '+%Y-%m-%dT%H:%MZ')

make_sas() {
    local blob_name="$1"
    az storage blob generate-sas \
        --account-name "$STORAGE_ACCOUNT" \
        --container-name "$CONTAINER" \
        --name "$blob_name" \
        --permissions r \
        --expiry "$EXPIRY" \
        --https-only \
        --output tsv
}

PKG_SAS=$(make_sas "pqc-validator.zip")
LINUX_SAS=$(make_sas "linux/install.sh")
WIN_SAS=$(make_sas "windows/install.ps1")
WIN_MOD_SAS=$(make_sas "windows/PQCValidator.psm1")

PKG_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/pqc-validator.zip?${PKG_SAS}"
LINUX_SCRIPT_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/linux/install.sh?${LINUX_SAS}"
WIN_SCRIPT_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/windows/install.ps1?${WIN_SAS}"
WIN_MODULE_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/windows/PQCValidator.psm1?${WIN_MOD_SAS}"

# ── Write .env.cse ────────────────────────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env.cse"
cat > "$ENV_FILE" <<ENV
# PQC CSE artifact URLs — generated $(date -u)
# Source: ${STORAGE_ACCOUNT}/${CONTAINER}
# SAS expiry: ${EXPIRY}
#
# WARNING: these URLs contain SAS tokens. Do NOT commit to git.

PQC_PACKAGE_URL="${PKG_URL}"
PQC_LINUX_INSTALL_SCRIPT_URL="${LINUX_SCRIPT_URL}"
PQC_WINDOWS_INSTALL_SCRIPT_URL="${WIN_SCRIPT_URL}"
PQC_WINDOWS_MODULE_URL="${WIN_MODULE_URL}"
ENV
chmod 600 "$ENV_FILE"

log ""
log "============================================================"
log "Upload complete. Artifact URLs written to: $ENV_FILE"
log ""
log "Next steps:"
log "  1. Copy values from $ENV_FILE into:"
log "       pqc-cse/bicep/main.bicepparam"
log "     or supply as policy assignment parameters."
log ""
log "  2. Deploy via Bicep (targeted):"
log "       az deployment group create \\"
log "         --resource-group <rg> \\"
log "         --template-file pqc-cse/bicep/main.bicep \\"
log "         --parameters pqc-cse/bicep/main.bicepparam"
log ""
log "  3. Or deploy via Policy (at scale):"
log "       ./deploy-policy.sh  (see pqc-cse/policy/)"
log "============================================================"
