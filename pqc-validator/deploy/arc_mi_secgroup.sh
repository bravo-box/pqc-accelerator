#!/bin/bash

set -euo pipefail

# ==============================
# Configuration
# ==============================
GROUP_ID=""

# ==============================
# Validate Azure login
# ==============================
echo "Checking Azure login..."
az account show >/dev/null

# ==============================
# Validate security group
# ==============================
echo "Validating security group..."
az ad group show --group "$GROUP_ID" >/dev/null

# ==============================
# Get current group members
# ==============================
echo "Retrieving current group members..."

GROUP_MEMBERS=$(az ad group member list \
    --group "$GROUP_ID" \
    --query "[].id" \
    -o tsv)

echo "Retrieving Arc-enabled machine identities..."

IDENTITIES=$(az resource list \
    --resource-type Microsoft.HybridCompute/machines \
    --query "[?identity.type=='SystemAssigned'].identity.principalId" \
    -o tsv)

if [[ -z "$IDENTITIES" ]]; then
    echo "No Arc-enabled machines with system-assigned identities were found."
    exit 0
fi

echo "Found identities:"
echo "$IDENTITIES"

PROCESSED=0
ADDED=0
SKIPPED=0

ADDED_IDS=()
EXISTING_IDS=()

while IFS= read -r ID; do
    [[ -z "$ID" ]] && continue

    ((++PROCESSED))

    # Check if already a member
    if grep -Fxq "$ID" <<< "$GROUP_MEMBERS"; then
        echo "✓ Already a member: $ID"
        EXISTING_IDS+=("$ID")
        ((++SKIPPED))
        continue
    fi

    echo "Adding: $ID"

    az ad group member add \
        --group "$GROUP_ID" \
        --member-id "$ID"

    echo "  ✓ Added"
    ADDED_IDS+=("$ID")
    ((++ADDED))

done <<< "$IDENTITIES"

echo
echo "=============================="
echo "Summary"
echo "=============================="
echo "Processed : $PROCESSED"
echo "Added     : $ADDED"
echo "Skipped   : $SKIPPED"

echo
echo "Identities already in the group:"
if (( ${#EXISTING_IDS[@]} == 0 )); then
    echo "  None"
else
    printf '  %s\n' "${EXISTING_IDS[@]}"
fi

echo
echo "Identities added:"
if (( ${#ADDED_IDS[@]} == 0 )); then
    echo "  None"
else
    printf '  %s\n' "${ADDED_IDS[@]}"
fi

echo
echo "Done."