"""
One-time Azure setup for PQC compliance validation.

Creates:
  1. Resource Group (if needed)
  2. Log Analytics Workspace
  3. Custom Table  PQCCompliance_CL
  4. Data Collection Endpoint (DCE)
  5. Data Collection Rule (DCR) wired to the table
    6. Operator follow-up: create a Microsoft Entra security group for
         Arc machine identities, assign the required DCR ingestion role to
         that group once, and add all Arc machine system-assigned identities
         to the group

Run once per environment. Outputs a .env file with the values
to set on each Arc machine (or store in Key Vault).

This script does not manage Microsoft Entra group membership. In production,
use a dedicated security group for PQC ingestion and add every Arc machine
identity to that group as part of onboarding.

Usage:
    python deploy/setup_azure.py \
        --subscription <sub-id> \
        --resource-group pqc-compliance-rg \
        --location eastus \
        --workspace-name pqc-law
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import os
import tempfile

# Monitoring Metrics Publisher role ID (built-in, fixed GUID)
# Recommended usage: assign once to a dedicated Microsoft Entra security
# group that contains all Arc machine system-assigned identities.
MONITORING_METRICS_PUBLISHER_ROLE = "3913510d-42f4-4e42-8a64-420c390055eb"


def get_azure_cloud_config() -> dict:
    """
    Detect the current Azure cloud from az CLI context.
    Returns config dict with endpoints for cloud-specific SDK initialization.
    """
    try:
        result = subprocess.run(
            ["az", "cloud", "show", "-o", "json"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            cloud_info = json.loads(result.stdout)
            return {
                "name": cloud_info.get("name", "AzureCloud"),
                "endpoints": cloud_info.get("endpoints", {}),
                "suffixes": cloud_info.get("suffixes", {})
            }
    except Exception:
        pass
    
    # Default to public Azure
    return {
        "name": "AzureCloud",
        "endpoints": {
            "resourceManager": "https://management.azure.com",
            "activeDirectory": "https://login.microsoftonline.com"
        },
        "suffixes": {
            "resourceManager": ".azure.com"
        }
    }

# PQC custom table schema — mirrors the JSONL record structure
PQC_COLUMNS = [
    {"name": "TimeGenerated", "type": "datetime"},
    {"name": "ingestion_time", "type": "datetime"},
    {"name": "hostname", "type": "string"},
    {"name": "platform", "type": "string"},
    {"name": "os_version", "type": "string"},
    {"name": "record_type", "type": "string"},   # scan_result | compliance_gap | error
    {"name": "check_name", "type": "string"},
    {"name": "category", "type": "string"},
    {"name": "status", "type": "string"},   # COMPLIANT | DEPRECATED | etc.
    {"name": "details", "type": "string"},
    {"name": "gap_type", "type": "string"},
    {"name": "severity", "type": "string"},   # CRITICAL | HIGH | MEDIUM | LOW
    {"name": "affected_component", "type": "string"},
    {"name": "recommendation", "type": "string"},
    {"name": "priority_score", "type": "real"},
    {"name": "algorithm", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "error_type", "type": "string"},
    {"name": "scan_run_id", "type": "string"},
    {"name": "record_hash", "type": "string"},
    {"name": "raw_record", "type": "string"},   # full JSON for audit
]


def ensure_resource_group(rg_client, subscription_id: str, rg_name: str, location: str):
    print(f"  Ensuring resource group '{rg_name}'...")
    rg_client.resource_groups.create_or_update(
        rg_name,
        {"location": location}
    )
    print(f"  ✓ Resource group ready")


def create_log_analytics_workspace(law_client, rg_name: str, workspace_name: str,
                                    location: str) -> dict:
    print(f"  Creating Log Analytics workspace '{workspace_name}'...")
    poller = law_client.workspaces.begin_create_or_update(
        rg_name,
        workspace_name,
        {
            "location": location,
            "sku": {"name": "PerGB2018"},
            "retention_in_days": 90,
            "properties": {
                "features": {"enableLogAccessUsingOnlyResourcePermissions": True}
            }
        }
    )
    workspace = poller.result()
    print(f"  ✓ Workspace ready: {workspace.customer_id}")
    return {
        "id": workspace.id,
        "customer_id": workspace.customer_id,
        "location": workspace.location
    }


def ensure_custom_table_schema(
    subscription_id: str,
    rg_name: str,
    workspace_name: str,
    table_plan: str,
    table_retention_days: int,
    table_total_retention_days: int,
) -> bool:
    """
    Ensure PQCCompliance_CL exists and contains all required columns.

    If the table already exists, missing columns are added in place using ARM REST.
    Existing columns are preserved.
    """
    table_name = "PQCCompliance_CL"
    desired_plan_lower = str(table_plan).lower()
    retention_mutable = desired_plan_lower == "analytics"
    print(f"  Ensuring custom table '{table_name}' schema...")

    desired_columns = list(PQC_COLUMNS)
    desired_map = {c["name"]: c["type"] for c in desired_columns}
    column_args = [f"{c['name']}={c['type']}" for c in desired_columns]

    # Step 1: Check whether table already exists
    show_result = subprocess.run(
        [
            "az", "monitor", "log-analytics", "workspace", "table", "show",
            "--subscription", subscription_id,
            "--resource-group", rg_name,
            "--workspace-name", workspace_name,
            "--name", table_name,
            "-o", "json"
        ],
        capture_output=True,
        text=True
    )

    if show_result.returncode != 0:
        # Table does not exist: create with full desired schema
        create_cmd = [
            "az", "monitor", "log-analytics", "workspace", "table", "create",
            "--subscription", subscription_id,
            "--resource-group", rg_name,
            "--workspace-name", workspace_name,
            "--name", table_name,
            "--columns",
            *column_args,
            "--plan", table_plan,
        ]
        if retention_mutable:
            create_cmd.extend(["--retention-time", str(table_retention_days)])
        create_result = subprocess.run(
            create_cmd,
            capture_output=True,
            text=True
        )
        if create_result.returncode != 0:
            print(f"  ✗ Failed to create table: {create_result.stderr.strip()}")
            return False

        print(f"  ✓ Custom table '{table_name}' created")
        return True

    # Step 2: Table exists — reconcile schema
    table = json.loads(show_result.stdout)
    # az CLI may return table fields either top-level or under "properties".
    properties = table.get("properties", {}) if isinstance(table.get("properties"), dict) else {}
    schema = properties.get("schema") if isinstance(properties.get("schema"), dict) else None
    if not isinstance(schema, dict):
        schema = table.get("schema", {}) if isinstance(table.get("schema"), dict) else {}
    existing_columns = schema.get("columns", [])
    existing_map = {c.get("name"): c.get("type") for c in existing_columns if c.get("name")}

    missing_columns = [c for c in desired_columns if c["name"] not in existing_map]
    conflicting_columns = [
        name for name, dtype in desired_map.items()
        if name in existing_map and existing_map[name] != dtype
    ]
    current_plan = str(properties.get("plan", table.get("plan", "Analytics")))
    current_retention = int(
        properties.get("retentionInDays", table.get("retentionInDays", table_retention_days))
        or table_retention_days
    )
    current_total_retention = int(
        properties.get("totalRetentionInDays", table.get("totalRetentionInDays", table_total_retention_days))
        or table_total_retention_days
    )
    plan_changed = current_plan.lower() != str(table_plan).lower()
    retention_changed = (
        current_retention != table_retention_days
        or current_total_retention != table_total_retention_days
    )
    # Basic/Auxiliary plans do not support mutable table retention settings.
    plan_or_retention_changed = plan_changed or (retention_mutable and retention_changed)

    if not missing_columns and not conflicting_columns and not plan_or_retention_changed:
        print(f"  ✓ Custom table '{table_name}' already matches required schema")
        return True

    table_subtype = str(schema.get("tableSubType", table.get("tableSubType", "")))
    table_type = str(schema.get("tableType", table.get("tableType", "")))
    is_classic_table = table_subtype.lower() == "classic" or table_type.lower() == "customlog"

    if is_classic_table:
        print("  ℹ  Detected Classic custom table. Schema mutation via DCR table API is not supported.")
        if plan_or_retention_changed:
            print(
                "  ⚠  Classic table settings differ from requested values; "
                "automatic plan/retention updates are skipped."
            )
            print(
                "     Current values are kept. To enforce new values, migrate to a DCR-based table first."
            )

        if missing_columns:
            print(
                "  ⚠  Classic table is missing the new normalized columns; "
                "schema updates are blocked for this table type."
            )
            print(
                "     Keep using compatibility queries or migrate to a DCR-based table "
                "before enforcing normalized schema."
            )

        return True

    if conflicting_columns:
        print("  ⚠  Existing columns with incompatible types detected:")
        for name in conflicting_columns:
            print(f"     - {name}: existing={existing_map[name]}, required={desired_map[name]}")
        print("     Type changes are not applied automatically; add new compatible columns instead.")

    if plan_or_retention_changed:
        print(
            "  ℹ  Updating table plan/retention: "
            f"plan {current_plan}->{table_plan}, "
            f"retention {current_retention}->{table_retention_days}, "
            f"totalRetention {current_total_retention}->{table_total_retention_days}"
        )
    elif not retention_mutable and retention_changed:
        print(
            "  ℹ  Table plan is Basic/Auxiliary; retention arguments are ignored for this plan."
        )

    if not missing_columns and not plan_or_retention_changed:
        return True

    update_cmd = [
        "az", "monitor", "log-analytics", "workspace", "table", "update",
        "--subscription", subscription_id,
        "--resource-group", rg_name,
        "--workspace-name", workspace_name,
        "--name", table_name,
        "--plan", table_plan,
        "-o", "none",
    ]

    if retention_mutable:
        update_cmd.extend([
            "--retention-time", str(table_retention_days),
            "--total-retention-time", str(table_total_retention_days),
        ])

    if missing_columns:
        update_cmd.extend(["--columns", *column_args])

    update_result = subprocess.run(update_cmd, capture_output=True, text=True)

    if update_result.returncode != 0:
        print(f"  ✗ Failed to update schema in place: {update_result.stderr.strip()}")
        print("     You can retry after validating RBAC and API permissions for table updates.")
        return False

    if missing_columns:
        print(f"  ✓ Added missing columns to '{table_name}': {', '.join(c['name'] for c in missing_columns)}")
    else:
        print(f"  ✓ Updated table plan/retention on '{table_name}'")
    return True


def create_dce(monitor_client, rg_name: str, dce_name: str, location: str) -> dict:
    print(f"  Creating Data Collection Endpoint '{dce_name}'...")
    poller = monitor_client.data_collection_endpoints.create(
        rg_name,
        dce_name,
        DataCollectionEndpointResource(
            location=location,
            network_acls={"public_network_access": "Enabled"}
        )
    )
    dce = poller if hasattr(poller, 'logs_ingestion') else monitor_client.data_collection_endpoints.get(rg_name, dce_name)
    print(f"  ✓ DCE ready")
    return {"id": dce.id, "endpoint": dce.logs_ingestion.endpoint if dce.logs_ingestion else ""}


def create_dcr(monitor_client, rg_name: str, dcr_name: str, location: str,
               workspace_id: str, dce_id: str) -> dict:
    print(f"  Creating Data Collection Rule '{dcr_name}'...")

    dcr = monitor_client.data_collection_rules.create(
        rg_name,
        dcr_name,
        DataCollectionRuleResource(
            location=location,
            data_collection_endpoint_id=dce_id,
            stream_declarations={
                "Custom-PQCCompliance_CL": StreamDeclaration(
                    columns=PQC_COLUMNS
                )
            },
            destinations=DataCollectionRuleDestinations(
                log_analytics=[
                    LogAnalyticsDestination(
                        workspace_resource_id=workspace_id,
                        name="pqc-law-destination"
                    )
                ]
            ),
            data_flows=[
                DataFlow(
                    streams=["Custom-PQCCompliance_CL"],
                    destinations=["pqc-law-destination"],
                    output_stream="Custom-PQCCompliance_CL",
                    # Preserve machine event timestamps while also stamping ingest time.
                    transform_kql="source | extend ingestion_time = now()"
                )
            ]
        )
    )

    print(f"  ✓ DCR ready: {dcr.immutable_id}")
    return {"id": dcr.id, "immutable_id": dcr.immutable_id}


def assign_monitoring_publisher_role(auth_client, dce_id: str, arc_machine_ids: list):
    """
    Grant 'Monitoring Metrics Publisher' to Arc machine system-assigned identities
    on the DCE scope so they can ingest data.
    """
    if not arc_machine_ids:
        print("  ℹ  No Arc machine IDs provided — skipping role assignment.")
        print("     After onboarding machines, run: python deploy/setup_azure.py --assign-roles")
        return

    print(f"  Assigning 'Monitoring Metrics Publisher' role to {len(arc_machine_ids)} machine(s)...")
    for machine_id in arc_machine_ids:
        try:
            auth_client.role_assignments.create(
                scope=dce_id,
                role_assignment_name=machine_id.split("/")[-1],  # use machine name as suffix
                parameters=RoleAssignmentCreateParameters(
                    role_definition_id=f"/providers/Microsoft.Authorization/roleDefinitions/{MONITORING_METRICS_PUBLISHER_ROLE}",
                    principal_id=machine_id,
                    principal_type="ServicePrincipal"
                )
            )
            print(f"    ✓ {machine_id}")
        except Exception as e:
            print(f"    ⚠  {machine_id}: {e}")


def write_env_file(config: dict, output_path: str = ".env.pqc"):
    with open(output_path, "w") as f:
        f.write("# PQC Validator — Azure Monitor configuration\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        f.write(f"PQC_DCE_ENDPOINT={config['dce_endpoint']}\n")
        f.write(f"PQC_DCR_IMMUTABLE_ID={config['dcr_immutable_id']}\n")
        f.write(f"PQC_STREAM_NAME=Custom-PQCCompliance_CL\n")
    print(f"\n  ✓ Environment config written to {output_path}")
    print(f"    Distribute this file to Arc machines or store values in Key Vault.")


def main():
    parser = argparse.ArgumentParser(
        description="One-time Azure setup for PQC compliance validation"
    )
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--resource-group", default="pqc-compliance-rg")
    parser.add_argument("--location", default="usgovvirginia")
    parser.add_argument("--workspace-name", default="pqc-law")
    parser.add_argument("--dce-name", default="pqc-dce")
    parser.add_argument("--dcr-name", default="pqc-dcr")
    parser.add_argument(
        "--workspace-sku",
        default="PerGB2018",
        choices=["PerGB2018", "CapacityReservation"],
        help="Workspace billing SKU. Default: PerGB2018"
    )
    parser.add_argument(
        "--workspace-retention-days",
        type=int,
        default=90,
        help="Workspace retention in days (default: 90)"
    )
    parser.add_argument(
        "--table-plan",
        default="Analytics",
        choices=["Analytics", "Basic", "Auxiliary"],
        help="Log Analytics table plan for PQCCompliance_CL (default: Analytics)"
    )
    parser.add_argument(
        "--table-retention-days",
        type=int,
        default=30,
        help="Interactive retention days for PQCCompliance_CL (default: 30)"
    )
    parser.add_argument(
        "--table-total-retention-days",
        type=int,
        default=365,
        help="Total retention days (hot + archive) for PQCCompliance_CL (default: 365)"
    )
    parser.add_argument("--output-env", default=".env.pqc",
                        help="Path to write the .env config file")
    args = parser.parse_args()

    if args.table_total_retention_days < args.table_retention_days:
        print("  ✗ table-total-retention-days must be >= table-retention-days")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("PQC Compliance — Azure Infrastructure Setup (via Azure CLI)")
    print(f"{'='*60}")
    print(f"Subscription:    {args.subscription}")
    print(f"Resource Group:  {args.resource_group}")
    print(f"Location:        {args.location}")
    print(f"Workspace SKU:   {args.workspace_sku}")
    print(f"Workspace Retention Days: {args.workspace_retention_days}")
    print(f"Table Plan:      {args.table_plan}")
    print(f"Table Retention Days: {args.table_retention_days}")
    print(f"Table Total Retention Days: {args.table_total_retention_days}")
    print()

    # Detect Azure cloud environment
    cloud_config = get_azure_cloud_config()
    print(f"Detected Cloud:  {cloud_config['name']}")
    print()

    # Use az CLI for all operations (respects current cloud context)
    
    # 1. Create or verify resource group
    print("1. Ensuring resource group...")
    result = subprocess.run(
        ["az", "group", "create", 
         "--subscription", args.subscription,
         "--name", args.resource_group, 
         "--location", args.location],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ✗ Failed: {result.stderr.strip()}")
        sys.exit(1)
    print(f"  ✓ Resource group ready")

    # 2. Create Log Analytics workspace
    print("2. Creating Log Analytics workspace...")
    result = subprocess.run(
        ["az", "monitor", "log-analytics", "workspace", "create",
         "--subscription", args.subscription,
         "--resource-group", args.resource_group,
         "--workspace-name", args.workspace_name,
         "--location", args.location,
         "--sku", args.workspace_sku,
         "--retention-time", str(args.workspace_retention_days)],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ⚠  {result.stderr.strip()}")
    else:
        print(f"  ✓ Workspace ready")

    # 3. Get workspace ID
    print("3. Retrieving workspace configuration...")
    result = subprocess.run(
        ["az", "monitor", "log-analytics", "workspace", "show",
         "--subscription", args.subscription,
         "--resource-group", args.resource_group,
         "--workspace-name", args.workspace_name,
         "-o", "json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ✗ Failed to get workspace: {result.stderr.strip()}")
        sys.exit(1)
    
    workspace = json.loads(result.stdout)
    workspace_id = workspace["id"]
    print(f"  ✓ Workspace ID: {workspace_id}")

    # 4. Ensure custom table schema (create or patch in place)
    print("4. Ensuring custom table schema for 'PQCCompliance_CL'...")
    if not ensure_custom_table_schema(
        subscription_id=args.subscription,
        rg_name=args.resource_group,
        workspace_name=args.workspace_name,
        table_plan=args.table_plan,
        table_retention_days=args.table_retention_days,
        table_total_retention_days=args.table_total_retention_days,
    ):
        sys.exit(1)

    # 5. Create Data Collection Endpoint
    print("5. Creating Data Collection Endpoint...")
    result = subprocess.run(
        ["az", "monitor", "data-collection", "endpoint", "create",
         "--subscription", args.subscription,
         "--resource-group", args.resource_group,
         "--name", args.dce_name,
         "--location", args.location,
         "--public-network-access", "Enabled"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ✗ Failed: {result.stderr.strip()}")
        sys.exit(1)
    print(f"  ✓ DCE ready")

    # 6. Get DCE details
    print("6. Retrieving DCE configuration...")
    result = subprocess.run(
        ["az", "monitor", "data-collection", "endpoint", "show",
         "--subscription", args.subscription,
         "--resource-group", args.resource_group,
         "--name", args.dce_name,
         "-o", "json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ✗ Failed: {result.stderr.strip()}")
        sys.exit(1)
    
    dce = json.loads(result.stdout)
    dce_id = dce["id"]
    dce_endpoint = dce.get("logsIngestion", {}).get("endpoint", "")
    if not dce_endpoint and "properties" in dce:
        dce_endpoint = dce["properties"].get("logsIngestion", {}).get("endpoint", "")
    print(f"  ✓ DCE ID: {dce_id}")
    print(f"  ✓ DCE Endpoint: {dce_endpoint}")

    # 7. Create Data Collection Rule with full payload
    print("7. Creating Data Collection Rule...")
    dcr_payload = {
        "properties": {
            "dataCollectionEndpointId": dce_id,
            "streamDeclarations": {
                "Custom-PQCCompliance_CL": {
                    "columns": PQC_COLUMNS
                }
            },
            "destinations": {
                "logAnalytics": [
                    {
                        "name": "pqc-law-destination",
                        "workspaceResourceId": workspace_id
                    }
                ]
            },
            "dataFlows": [
                {
                    "streams": ["Custom-PQCCompliance_CL"],
                    "destinations": ["pqc-law-destination"],
                    "outputStream": "Custom-PQCCompliance_CL",
                    "transformKql": "source | extend ingestion_time = now()"
                }
            ]
        }
    }

    dcr_rule_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(dcr_payload, tmp)
            dcr_rule_file = tmp.name

        result = subprocess.run(
            ["az", "monitor", "data-collection", "rule", "create",
             "--subscription", args.subscription,
             "--resource-group", args.resource_group,
             "--name", args.dcr_name,
             "--location", args.location,
             "--rule-file", dcr_rule_file],
            capture_output=True,
            text=True
        )
    finally:
        if dcr_rule_file and os.path.exists(dcr_rule_file):
            os.remove(dcr_rule_file)

    if result.returncode != 0:
        print(f"  ⚠  {result.stderr.strip()}")
    else:
        print(f"  ✓ DCR ready")

    # 8. Get DCR Immutable ID
    print("8. Retrieving DCR configuration...")
    result = subprocess.run(
        ["az", "monitor", "data-collection", "rule", "show",
         "--subscription", args.subscription,
         "--resource-group", args.resource_group,
         "--name", args.dcr_name,
         "-o", "json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ⚠  Could not retrieve DCR: {result.stderr.strip()}")
        dcr_immutable_id = "dcr-xxxxxxxxxxxxxxxx"  # Placeholder
    else:
        dcr_info = json.loads(result.stdout)
        dcr_immutable_id = dcr_info.get("immutableId", dcr_info.get("id", "").split("/")[-1])
        print(f"  ✓ DCR Immutable ID: {dcr_immutable_id}")

    # 9. Write config file
    print("\n9. Writing configuration...")
    config = {
        "dce_endpoint":      dce_endpoint,
        "dcr_immutable_id":  dcr_immutable_id
    }
    write_env_file(config, args.output_env)

    print(f"\n{'='*60}")
    print("✓ Infrastructure setup complete!")
    print(f"{'='*60}")
    print(f"\nConfiguration saved to: {args.output_env}")
    print("\nNext steps:")
    print(f"1. Create or identify the Microsoft Entra security group used for PQC DCR ingestion")
    print(f"2. Assign the DCR ingestion role to that group at the DCR scope")
    print(f"3. Add all Arc machine system-assigned identities to that group")
    print(f"4. Make group membership part of Arc machine onboarding automation")
    print(f"5. Deploy pqc-validator to your Arc machines")
    print(f"6. Set environment variables on each machine:")
    print(f"   export PQC_DCE_ENDPOINT='{dce_endpoint}'")
    print(f"   export PQC_DCR_IMMUTABLE_ID='{dcr_immutable_id}'")
    print(f"7. Or run the Arc orchestrator:")
    print(f"   python deploy/arc_orchestrator.py \\")
    print(f"     --subscription {args.subscription} \\")
    print(f"     --dce-endpoint '{dce_endpoint}' \\")
    print(f"     --dcr-immutable-id '{dcr_immutable_id}'")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
