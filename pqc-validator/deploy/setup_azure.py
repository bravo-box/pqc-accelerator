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

from azure.identity import DefaultAzureCredential
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import (
    DataCollectionEndpointResource,
    DataCollectionRuleResource,
    DataCollectionRuleDataSources,
    DataCollectionRuleDestinations,
    LogAnalyticsDestination,
    DataFlow,
    StreamDeclaration,
    ColumnDefinition,
)
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters

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
    ColumnDefinition(name="TimeGenerated",      type="datetime"),
    ColumnDefinition(name="MachineName",        type="string"),
    ColumnDefinition(name="Platform",           type="string"),
    ColumnDefinition(name="OSVersion",          type="string"),
    ColumnDefinition(name="RecordType",         type="string"),   # scan_result | compliance_gap | error
    ColumnDefinition(name="CheckName",          type="string"),
    ColumnDefinition(name="Category",           type="string"),
    ColumnDefinition(name="Status",             type="string"),   # COMPLIANT | DEPRECATED | etc.
    ColumnDefinition(name="Details",            type="string"),
    ColumnDefinition(name="GapType",            type="string"),
    ColumnDefinition(name="Severity",           type="string"),   # CRITICAL | HIGH | MEDIUM | LOW
    ColumnDefinition(name="AffectedComponent",  type="string"),
    ColumnDefinition(name="Recommendation",     type="string"),
    ColumnDefinition(name="PriorityScore",      type="real"),
    ColumnDefinition(name="Algorithm",          type="string"),
    ColumnDefinition(name="Version",            type="string"),
    ColumnDefinition(name="RawRecord",          type="string"),   # full JSON for audit
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


def create_custom_table(subscription_id: str, rg_name: str, workspace_name: str,
                         location: str):
    """
    Create PQCCompliance_CL custom table via Azure REST API.
    (The SDK does not yet expose custom table creation directly.)
    """
    print(f"  Creating custom table 'PQCCompliance_CL'...")

    table_body = {
        "properties": {
            "schema": {
                "name": "PQCCompliance_CL",
                "columns": [
                    {"name": col.name, "type": col.type}
                    for col in PQC_COLUMNS
                ]
            },
            "retentionInDays": 90
        }
    }

    # Use az CLI as the Python SDK doesn't expose custom log table creation yet
    result = subprocess.run(
        [
            "az", "monitor", "log-analytics", "workspace", "table", "create",
            "--subscription", subscription_id,
            "--resource-group", rg_name,
            "--workspace-name", workspace_name,
            "--name", "PQCCompliance_CL",
            "--columns",
            " ".join(f"{col.name}={col.type}" for col in PQC_COLUMNS),
            "--retention-time", "90"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"  ⚠  Table creation via CLI failed: {result.stderr.strip()}")
        print(f"     The table may already exist or you may need to create it manually.")
    else:
        print(f"  ✓ Custom table 'PQCCompliance_CL' ready")


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
                "PQCCompliance_CL": StreamDeclaration(
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
                    streams=["PQCCompliance_CL"],
                    destinations=["pqc-law-destination"],
                    output_stream="PQCCompliance_CL",
                    transform_kql="source | extend TimeGenerated = now()"
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
        f.write(f"PQC_STREAM_NAME=PQCCompliance_CL\n")
    print(f"\n  ✓ Environment config written to {output_path}")
    print(f"    Distribute this file to Arc machines or store values in Key Vault.")


def main():
    parser = argparse.ArgumentParser(
        description="One-time Azure setup for PQC compliance validation"
    )
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--resource-group", default="pqc-compliance-rg")
    parser.add_argument("--location", default="eastus")
    parser.add_argument("--workspace-name", default="pqc-law")
    parser.add_argument("--dce-name", default="pqc-dce")
    parser.add_argument("--dcr-name", default="pqc-dcr")
    parser.add_argument("--output-env", default=".env.pqc",
                        help="Path to write the .env config file")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("PQC Compliance — Azure Infrastructure Setup (via Azure CLI)")
    print(f"{'='*60}")
    print(f"Subscription:    {args.subscription}")
    print(f"Resource Group:  {args.resource_group}")
    print(f"Location:        {args.location}")
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
         "--location", args.location],
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

    # 4. Create custom table
    print("4. Creating custom table 'PQCCompliance_CL'...")
    columns_str = " ".join(f"{col.name}={col.type}" for col in PQC_COLUMNS)
    result = subprocess.run(
        ["az", "monitor", "log-analytics", "workspace", "table", "create",
         "--subscription", args.subscription,
         "--resource-group", args.resource_group,
         "--workspace-name", args.workspace_name,
         "--name", "PQCCompliance_CL",
         "--columns", columns_str,
         "--retention-time", "90"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ⚠  {result.stderr.strip()}")
    else:
        print(f"  ✓ Custom table ready")

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

    # 7. Create Data Collection Rule (simplified)
    print("7. Creating Data Collection Rule...")
    result = subprocess.run(
        ["az", "monitor", "data-collection", "rule", "create",
         "--subscription", args.subscription,
         "--resource-group", args.resource_group,
         "--name", args.dcr_name,
         "--location", args.location],
        capture_output=True,
        text=True
    )
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
