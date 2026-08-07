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
#     --signing-key <path>   PEM private key used to sign pqc-validator.zip (required)
#     --public-key  <path>   PEM public key to publish (optional; auto-derived if omitted)
#     --pip-index-url <url>  Private Python package index (e.g., Azure Artifacts)
#     --pip-extra-index-url <url> Secondary package index (optional)
#     --pip-trusted-host <h> Trusted host for private index TLS interception scenarios
#     --pip-find-links <dir-or-url> Local wheelhouse or mirror endpoint for offline builds
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
SIGNING_KEY=""
PUBLIC_KEY=""
PIP_INDEX_URL=""
PIP_EXTRA_INDEX_URL=""
PIP_TRUSTED_HOST=""
PIP_FIND_LINKS=""

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --storage-account) STORAGE_ACCOUNT="$2"; shift 2 ;;
        --resource-group)  RESOURCE_GROUP="$2";  shift 2 ;;
        --subscription)    SUBSCRIPTION="$2";    shift 2 ;;
        --container)       CONTAINER="$2";       shift 2 ;;
        --sas-days)        SAS_DAYS="$2";        shift 2 ;;
        --cloud)           CLOUD="$2";           shift 2 ;;
        --signing-key)     SIGNING_KEY="$2";     shift 2 ;;
        --public-key)      PUBLIC_KEY="$2";      shift 2 ;;
        --pip-index-url)       PIP_INDEX_URL="$2";       shift 2 ;;
        --pip-extra-index-url) PIP_EXTRA_INDEX_URL="$2"; shift 2 ;;
        --pip-trusted-host)    PIP_TRUSTED_HOST="$2";    shift 2 ;;
        --pip-find-links)      PIP_FIND_LINKS="$2";      shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

for var in STORAGE_ACCOUNT RESOURCE_GROUP SUBSCRIPTION; do
    if [ -z "${!var}" ]; then
        echo "ERROR: --${var//_/-} is required"
        exit 1
    fi
done

if [ -z "$SIGNING_KEY" ]; then
    echo "ERROR: --signing-key is required"
    exit 1
fi
if [ ! -f "$SIGNING_KEY" ]; then
    echo "ERROR: Signing key not found: $SIGNING_KEY"
    exit 1
fi

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
WHEELHOUSE_DIR="$TMP_DIR/wheelhouse"
LOCK_PATH_X86="$TMP_DIR/requirements-arc-lock-linux-x86_64.txt"
LOCK_PATH_ARM="$TMP_DIR/requirements-arc-lock-linux-aarch64.txt"
SIG_PATH="$TMP_DIR/pqc-validator.zip.sig"
SHA_PATH="$TMP_DIR/pqc-validator.zip.sha256"
PUBKEY_PATH="$TMP_DIR/pqc-signing-key.pem"
CERT_PEM_PATH="$TMP_DIR/pqc-signing-cert.pem"
CERT_DER_PATH="$TMP_DIR/pqc-signing-cert.cer"
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

# ── Build offline wheelhouses + hash-locked requirements ────────────────────
log "Building offline wheelhouses from requirements-arc.txt..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to build wheelhouse"
    exit 1
fi

build_wheelhouse() {
    local platform_tag="$1"
    local wheel_dir="$2"
    local lock_path="$3"

    rm -rf "$wheel_dir"
    mkdir -p "$wheel_dir"

    local pip_cmd=(
        python3 -m pip download
        --disable-pip-version-check
        --only-binary=:all:
        --platform "$platform_tag"
        --implementation cp
        --python-version 3.12
        --abi cp312
        --dest "$wheel_dir"
        -r "$VALIDATOR_DIR/requirements-arc.txt"
    )

    if [ -n "$PIP_FIND_LINKS" ]; then
        pip_cmd+=(--no-index --find-links "$PIP_FIND_LINKS")
    fi
    if [ -n "$PIP_INDEX_URL" ]; then
        pip_cmd+=(--index-url "$PIP_INDEX_URL")
    fi
    if [ -n "$PIP_EXTRA_INDEX_URL" ]; then
        pip_cmd+=(--extra-index-url "$PIP_EXTRA_INDEX_URL")
    fi
    if [ -n "$PIP_TRUSTED_HOST" ]; then
        pip_cmd+=(--trusted-host "$PIP_TRUSTED_HOST")
    fi

    "${pip_cmd[@]}"

    python3 - <<'PY' "$wheel_dir" "$lock_path"
import hashlib
import pathlib
import re
import sys

wheelhouse = pathlib.Path(sys.argv[1])
lock_file = pathlib.Path(sys.argv[2])

entries = []
for wheel in sorted(wheelhouse.glob("*.whl")):
    m = re.match(r"(?P<name>.+?)-(?P<version>[^-]+)-", wheel.name)
    if not m:
        raise SystemExit(f"Unable to parse wheel filename: {wheel.name}")
    name = m.group("name").replace("_", "-")
    version = m.group("version")
    sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    entries.append((name.lower(), f"{name}=={version} --hash=sha256:{sha}"))

entries.sort(key=lambda x: x[0])
with lock_file.open("w", encoding="utf-8") as f:
    f.write("# Auto-generated by package-and-upload.sh for Arc runtime installs\n")
    f.write("# Uses --require-hashes and offline wheelhouse installation\n")
    for _, line in entries:
        f.write(line + "\n")
PY
}

build_wheelhouse "manylinux2014_x86_64" "$WHEELHOUSE_DIR/linux-x86_64" "$LOCK_PATH_X86"
build_wheelhouse "manylinux2014_aarch64" "$WHEELHOUSE_DIR/linux-aarch64" "$LOCK_PATH_ARM"

log "Adding wheelhouse and hash-locked requirements to package zip..."
(
  cd "$TMP_DIR"
    zip -r "$ZIP_PATH" wheelhouse requirements-arc-lock-linux-x86_64.txt requirements-arc-lock-linux-aarch64.txt >/dev/null
)

# ── Create detached signature and digest ─────────────────────────────────────
if [ -n "$PUBLIC_KEY" ]; then
    cp "$PUBLIC_KEY" "$PUBKEY_PATH"
else
    openssl pkey -in "$SIGNING_KEY" -pubout -out "$PUBKEY_PATH"
fi

# Create a certificate that carries the signing public key for Windows-native verification.
openssl req -new -x509 \
    -key "$SIGNING_KEY" \
    -out "$CERT_PEM_PATH" \
    -subj "/CN=PQC Validator Artifact Signing/" \
    -days 3650 >/dev/null 2>&1
openssl x509 -in "$CERT_PEM_PATH" -outform der -out "$CERT_DER_PATH"

openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$SIG_PATH" "$ZIP_PATH"
PKG_SHA256=$(sha256sum "$ZIP_PATH" | awk '{print $1}')
echo "$PKG_SHA256  pqc-validator.zip" > "$SHA_PATH"
log "Package SHA-256: $PKG_SHA256"

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
upload_blob "$SIG_PATH"                              "pqc-validator.zip.sig"
upload_blob "$SHA_PATH"                              "pqc-validator.zip.sha256"
upload_blob "$PUBKEY_PATH"                           "pqc-signing-key.pem"
upload_blob "$CERT_DER_PATH"                         "pqc-signing-cert.cer"
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
PKG_SIG_SAS=$(make_sas "pqc-validator.zip.sig")
PKG_SHA_SAS=$(make_sas "pqc-validator.zip.sha256")
PKG_PUBKEY_SAS=$(make_sas "pqc-signing-key.pem")
PKG_CERT_SAS=$(make_sas "pqc-signing-cert.cer")
LINUX_SAS=$(make_sas "linux/install.sh")
WIN_SAS=$(make_sas "windows/install.ps1")
WIN_MOD_SAS=$(make_sas "windows/PQCValidator.psm1")

PKG_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/pqc-validator.zip?${PKG_SAS}"
PKG_SIG_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/pqc-validator.zip.sig?${PKG_SIG_SAS}"
PKG_SHA_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/pqc-validator.zip.sha256?${PKG_SHA_SAS}"
PKG_PUBKEY_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/pqc-signing-key.pem?${PKG_PUBKEY_SAS}"
PKG_CERT_URL="https://${STORAGE_ACCOUNT}.${BLOB_SUFFIX}/${CONTAINER}/pqc-signing-cert.cer?${PKG_CERT_SAS}"
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
PQC_PACKAGE_SHA256="${PKG_SHA256}"
PQC_PACKAGE_SIG_URL="${PKG_SIG_URL}"
PQC_PACKAGE_SHA256_URL="${PKG_SHA_URL}"
PQC_PACKAGE_PUBKEY_URL="${PKG_PUBKEY_URL}"
PQC_PACKAGE_CERT_URL="${PKG_CERT_URL}"
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
