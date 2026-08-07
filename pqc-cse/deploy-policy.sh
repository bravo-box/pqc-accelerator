#!/bin/bash
# =============================================================================
# deploy-policy.sh  —  Register PQC policy definitions, create an initiative,
#                       and assign it at subscription scope
# =============================================================================
# Prerequisites:
#   - az cli logged in with Owner or Policy Contributor + User Access Administrator
#   - package-and-upload.sh already run (.env.cse exists)
#   - setup_azure.py already run (.env.pqc exists)
#
# Usage:
#   ./deploy-policy.sh \
#       --subscription <sub-id> \
#       [--management-group <mg-id>]   # optional: assign at MG scope
#       [--scope-rg <rg>]              # optional: limit assignment to one RG
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$SCRIPT_DIR/policy"

SUBSCRIPTION=""
MGMT_GROUP=""
SCOPE_RG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --subscription)     SUBSCRIPTION="$2";  shift 2 ;;
        --management-group) MGMT_GROUP="$2";    shift 2 ;;
        --scope-rg)         SCOPE_RG="$2";      shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ -z "$SUBSCRIPTION" ]; then
    echo "ERROR: --subscription is required"
    exit 1
fi

log() { echo "[$(date -u '+%H:%M:%S')] $*"; }

# ── Load environment files ────────────────────────────────────────────────────
ENV_PQC="$SCRIPT_DIR/../.env.pqc"
if [ ! -f "$ENV_PQC" ] && [ -f "$SCRIPT_DIR/../pqc-validator/deploy/.env.pqc" ]; then
    ENV_PQC="$SCRIPT_DIR/../pqc-validator/deploy/.env.pqc"
fi
ENV_CSE="$SCRIPT_DIR/.env.cse"

for f in "$ENV_PQC" "$ENV_CSE"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: Required env file not found: $f"
        echo "  Run setup_azure.py and package-and-upload.sh first."
        exit 1
    fi
done

# shellcheck source=/dev/null
source "$ENV_PQC"
source "$ENV_CSE"

for var in PQC_PACKAGE_URL PQC_PACKAGE_SHA256 PQC_PACKAGE_SIG_URL PQC_PACKAGE_PUBKEY_URL PQC_PACKAGE_CERT_URL PQC_LINUX_INSTALL_SCRIPT_URL PQC_WINDOWS_INSTALL_SCRIPT_URL; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: Missing required variable '$var' in $ENV_CSE"
        echo "  Re-run package-and-upload.sh to regenerate secure artifact URLs."
        exit 1
    fi
done

az account set --subscription "$SUBSCRIPTION"
SUB_SCOPE="/subscriptions/$SUBSCRIPTION"

# ── Detect cloud and pick a valid MI location for the policy assignment ────────
# Azure Government: policy assignment identity only works in gov regions.
# "global" is accepted by all clouds and avoids any region-specific restriction.
CURRENT_CLOUD=$(az cloud show --query name -o tsv 2>/dev/null || echo "AzureCloud")
if [[ "$CURRENT_CLOUD" == *"Government"* || "$CURRENT_CLOUD" == *"Dod"* || "$CURRENT_CLOUD" == *"USGov"* ]]; then
    MI_LOCATION="usgovvirginia"
else
    MI_LOCATION="eastus"
fi
log "Cloud: $CURRENT_CLOUD | MI location: $MI_LOCATION"

# ── Verify jq is available ────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
    log "ERROR: 'jq' is required but not installed. Install with: brew install jq"
    exit 1
fi

# Helper: register a single policy definition from a full policy JSON file.
# az policy definition create --rules expects ONLY the policyRule object (if/then),
# and --params expects ONLY the parameters object — not the full properties wrapper.
register_policy() {
    local name="$1"
    local display_name="$2"
    local description="$3"
    local json_file="$4"

    local tmp_rules tmp_params
    tmp_rules=$(mktemp)
    tmp_params=$(mktemp)

    jq '.properties.policyRule'   "$json_file" > "$tmp_rules"
    jq '.properties.parameters'  "$json_file" > "$tmp_params"

    local policy_id
    local scope_args=()
    if [ -n "$MGMT_GROUP" ]; then
        scope_args+=(--management-group "$MGMT_GROUP")
    else
        scope_args+=(--subscription "$SUBSCRIPTION")
    fi

    policy_id=$(az policy definition create \
        --name         "$name" \
        --display-name "$display_name" \
        --description  "$description" \
        --rules        "$tmp_rules" \
        --params       "$tmp_params" \
        --mode         Indexed \
        "${scope_args[@]}" \
        --query id --output tsv)

    rm -f "$tmp_rules" "$tmp_params"
    echo "$policy_id"
}

# ── Register policy definitions ───────────────────────────────────────────────
log "--- Registering Linux policy definition..."
LINUX_POLICY_ID=$(register_policy \
    "pqc-validator-linux-arc-cse" \
    "[PQC] Deploy PQC Validator CSE to Linux Arc machines" \
    "Deploys PQC Compliance Validator via Custom Script Extension to Linux Arc machines" \
    "$POLICY_DIR/pqc-linux-policy.json")
log "Linux policy: $LINUX_POLICY_ID"

log "--- Registering Windows policy definition..."
WIN_POLICY_ID=$(register_policy \
    "pqc-validator-windows-arc-cse" \
    "[PQC] Deploy PQC Validator CSE to Windows Arc machines" \
    "Deploys PQC Compliance Validator via Custom Script Extension to Windows Arc machines" \
    "$POLICY_DIR/pqc-windows-policy.json")
log "Windows policy: $WIN_POLICY_ID"

# ── Patch initiative with real policy IDs and extract sub-objects ─────────────
INITIATIVE_FILE="$POLICY_DIR/pqc-initiative.json"

TMP_DEFS=$(mktemp)
TMP_PARAMS=$(mktemp)

# Substitute placeholder IDs, then extract just the arrays az CLI needs
jq --arg linux  "$LINUX_POLICY_ID" \
   --arg windows "$WIN_POLICY_ID" \
   '.properties.policyDefinitions |
    map(if .policyDefinitionId == "<LINUX-POLICY-DEFINITION-ID>"  then .policyDefinitionId = $linux
        elif .policyDefinitionId == "<WINDOWS-POLICY-DEFINITION-ID>" then .policyDefinitionId = $windows
        else . end)' \
   "$INITIATIVE_FILE" > "$TMP_DEFS"

jq '.properties.parameters' "$INITIATIVE_FILE" > "$TMP_PARAMS"

log "--- Creating policy initiative..."
SCOPE_ARGS=()
if [ -n "$MGMT_GROUP" ]; then
    SCOPE_ARGS+=(--management-group "$MGMT_GROUP")
else
    SCOPE_ARGS+=(--subscription "$SUBSCRIPTION")
fi

INITIATIVE_ID=$(az policy set-definition create \
    --name         "pqc-validator-arc-initiative" \
    --display-name "[PQC] Deploy PQC Compliance Validator to Arc machines" \
    --definitions  "$TMP_DEFS" \
    --params       "$TMP_PARAMS" \
    "${SCOPE_ARGS[@]}" \
    --query id --output tsv)

rm -f "$TMP_DEFS" "$TMP_PARAMS"
log "Initiative: $INITIATIVE_ID"

# ── Determine assignment scope ────────────────────────────────────────────────
if [ -n "$MGMT_GROUP" ]; then
    ASSIGN_SCOPE="/providers/Microsoft.Management/managementGroups/$MGMT_GROUP"
    REMEDIATION_DISCOVERY_MODE="ExistingNonCompliant"
elif [ -n "$SCOPE_RG" ]; then
    ASSIGN_SCOPE="$SUB_SCOPE/resourceGroups/$SCOPE_RG"
    REMEDIATION_DISCOVERY_MODE="ReEvaluateCompliance"
else
    ASSIGN_SCOPE="$SUB_SCOPE"
    REMEDIATION_DISCOVERY_MODE="ReEvaluateCompliance"
fi
log "Assignment scope: $ASSIGN_SCOPE"

# ── Assign initiative ─────────────────────────────────────────────────────────
log "--- Assigning initiative..."
ASSIGNMENT_JSON=$(az policy assignment create \
    --name "pqc-validator-arc" \
    --display-name "[PQC] PQC Validator — Arc fleet" \
    --policy-set-definition "$INITIATIVE_ID" \
    --scope "$ASSIGN_SCOPE" \
    --location "$MI_LOCATION" \
    --mi-system-assigned \
        --params "{
            \"dceEndpoint\":             {\"value\": \"$PQC_DCE_ENDPOINT\"},
            \"dcrImmutableId\":          {\"value\": \"$PQC_DCR_IMMUTABLE_ID\"},
            \"streamName\":              {\"value\": \"${PQC_STREAM_NAME:-Custom-PQCCompliance_CL}\"},
            \"linuxInstallScriptUrl\":   {\"value\": \"$PQC_LINUX_INSTALL_SCRIPT_URL\"},
            \"windowsInstallScriptUrl\": {\"value\": \"$PQC_WINDOWS_INSTALL_SCRIPT_URL\"},
            \"packageUrl\":              {\"value\": \"$PQC_PACKAGE_URL\"},
            \"packageSha256\":           {\"value\": \"$PQC_PACKAGE_SHA256\"},
            \"packageSigUrl\":           {\"value\": \"$PQC_PACKAGE_SIG_URL\"},
            \"packagePubkeyUrl\":        {\"value\": \"$PQC_PACKAGE_PUBKEY_URL\"},
            \"packageCertUrl\":          {\"value\": \"$PQC_PACKAGE_CERT_URL\"},
            \"scheduleTime\":            {\"value\": \"03:00\"},
            \"forceUpdateTag\":          {\"value\": \"v4\"},
            \"linuxEffect\":             {\"value\": \"DeployIfNotExists\"},
            \"windowsEffect\":           {\"value\": \"DeployIfNotExists\"}
        }" \
    --output json)
ASSIGNMENT_ID=$(echo "$ASSIGNMENT_JSON"  | jq -r '.id')
ASSIGNMENT_MI=$(echo "$ASSIGNMENT_JSON"  | jq -r '.identity.principalId')
log "Assignment: $ASSIGNMENT_ID"
log "Assignment MI principal: $ASSIGNMENT_MI"

# ── Grant remediation identity the Arc Connected Machine Resource Administrator role ──
# Role: Azure Connected Machine Resource Administrator
# GUID:  cd570a14-e51a-42ad-bac8-bafd67325302
log "--- Granting policy MI the Arc resource administrator role..."
EXISTING_ROLE_ASSIGNMENT_ID=$(az role assignment list \
    --assignee-object-id "$ASSIGNMENT_MI" \
    --scope "$ASSIGN_SCOPE" \
    --query "[?roleDefinitionId && contains(roleDefinitionId, 'cd570a14-e51a-42ad-bac8-bafd67325302')].id | [0]" \
    --output tsv 2>/dev/null || true)

if [ -n "$EXISTING_ROLE_ASSIGNMENT_ID" ]; then
    log "Role assignment already exists for policy MI: $EXISTING_ROLE_ASSIGNMENT_ID"
else
    az role assignment create \
        --role "cd570a14-e51a-42ad-bac8-bafd67325302" \
        --assignee-object-id "$ASSIGNMENT_MI" \
        --assignee-principal-type ServicePrincipal \
        --scope "$ASSIGN_SCOPE" \
        --output none
    log "Role granted to assignment MI: $ASSIGNMENT_MI"
fi

# ── Create remediation tasks for existing machines ────────────────────────────
# For initiative (policy set) assignments, a separate remediation task is required
# for each member policy definition, identified by --definition-reference-id.
# --policy-assignment takes the assignment NAME (not resource ID).
# --scope must match the assignment scope.
log "--- Creating remediation task for Linux Arc machines..."
LINUX_REMEDIATION_STATE=$(az policy remediation show \
    --name "pqc-remediation-linux" \
    --management-group "$MGMT_GROUP" \
    --query "properties.provisioningState" \
    --output tsv 2>/dev/null || true)

if [ -n "$LINUX_REMEDIATION_STATE" ] && [ "$LINUX_REMEDIATION_STATE" != "Failed" ]; then
    log "Linux remediation already exists (state: $LINUX_REMEDIATION_STATE); skipping create"
else
    set +e
    LINUX_REMEDIATION_CREATE_OUTPUT=$(az policy remediation create \
        --name "pqc-remediation-linux" \
        --policy-assignment "pqc-validator-arc" \
        --definition-reference-id "pqc-linux-arc-cse" \
        --subscription "$SUBSCRIPTION" \
        --resource-discovery-mode "$REMEDIATION_DISCOVERY_MODE" \
        --output none 2>&1)
    LINUX_REMEDIATION_CREATE_EXIT=$?
    set -e

    if [ $LINUX_REMEDIATION_CREATE_EXIT -ne 0 ]; then
        if echo "$LINUX_REMEDIATION_CREATE_OUTPUT" | grep -q "InvalidUpdateRemediationRequest"; then
            log "Linux remediation already active; skipping create"
        else
            echo "$LINUX_REMEDIATION_CREATE_OUTPUT"
            exit $LINUX_REMEDIATION_CREATE_EXIT
        fi
    fi
fi

log "--- Creating remediation task for Windows Arc machines..."
WINDOWS_REMEDIATION_STATE=$(az policy remediation show \
    --name "pqc-remediation-windows" \
    --management-group "$MGMT_GROUP" \
    --query "properties.provisioningState" \
    --output tsv 2>/dev/null || true)

if [ -n "$WINDOWS_REMEDIATION_STATE" ] && [ "$WINDOWS_REMEDIATION_STATE" != "Failed" ]; then
    log "Windows remediation already exists (state: $WINDOWS_REMEDIATION_STATE); skipping create"
else
    set +e
    WINDOWS_REMEDIATION_CREATE_OUTPUT=$(az policy remediation create \
        --name "pqc-remediation-windows" \
        --policy-assignment "pqc-validator-arc" \
        --definition-reference-id "pqc-windows-arc-cse" \
        --subscription "$SUBSCRIPTION" \
        --resource-discovery-mode "$REMEDIATION_DISCOVERY_MODE" \
        --output none 2>&1)
    WINDOWS_REMEDIATION_CREATE_EXIT=$?
    set -e

    if [ $WINDOWS_REMEDIATION_CREATE_EXIT -ne 0 ]; then
        if echo "$WINDOWS_REMEDIATION_CREATE_OUTPUT" | grep -q "InvalidUpdateRemediationRequest"; then
            log "Windows remediation already active; skipping create"
        else
            echo "$WINDOWS_REMEDIATION_CREATE_OUTPUT"
            exit $WINDOWS_REMEDIATION_CREATE_EXIT
        fi
    fi
fi

log ""
log "============================================================"
log "Policy deployment complete"
log ""
log "  Linux policy  : $LINUX_POLICY_ID"
log "  Windows policy: $WIN_POLICY_ID"
log "  Initiative    : $INITIATIVE_ID"
log "  Assignment    : $ASSIGNMENT_ID"
log "  Scope         : $ASSIGN_SCOPE"
log ""
log "New Arc machines will automatically receive the CSE extension"
log "within the policy evaluation cycle (every 24h)."
log ""
log "Monitor compliance:"
log "  az policy state list --policy-assignment pqc-validator-arc \\"
log "      --subscription $SUBSCRIPTION --output table"
log "============================================================"
