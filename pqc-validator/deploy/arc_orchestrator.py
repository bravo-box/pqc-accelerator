"""
Arc Orchestrator — dispatches the PQC validator to every Arc-connected machine
in a subscription using Azure Arc Run Command.

No host list required. Machine inventory comes from Azure Resource Graph.
Results flow directly from each machine to Log Analytics via Managed Identity.

Usage:
    python deploy/arc_orchestrator.py \
        --subscription <sub-id> \
        [--resource-group <rg>] \
        [--os-filter Windows|Linux] \
        [--tag Environment=Production]

Prerequisites on each Arc machine:
    - Azure Arc Connected Machine Agent installed and Connected
    - Python 3.8+ installed
    - pqc-validator deployed to a known path (default: /opt/pqc-validator or C:\\pqc-validator)
    - System-assigned Managed Identity enabled on the Arc machine
    - Managed Identity has 'Monitoring Metrics Publisher' on the DCE/DCR
"""

import argparse
import json
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# Add parent directory to path so we can import src/
sys.path.insert(0, str(Path(__file__).parent.parent))

from azure.identity import DefaultAzureCredential
from azure.mgmt.hybridcompute import HybridComputeManagementClient
from azure.mgmt.hybridcompute.models import MachineRunCommand, MachineRunCommandScriptSource

from src.integrations.arc_inventory import get_arc_machines, get_arc_machine_count


# Default install path on Arc machines (adjust to your deployment)
LINUX_VALIDATOR_PATH = "/opt/pqc-validator"
WINDOWS_VALIDATOR_PATH = "C:\\pqc-validator"


def build_linux_script(dce_endpoint: str, dcr_immutable_id: str,
                        stream_name: str = "Custom-PQCCompliance_CL") -> str:
    """Shell script injected via Arc Run Command on Linux/macOS machines."""
    return f"""#!/bin/bash
set -e

export PQC_DCE_ENDPOINT="{dce_endpoint}"
export PQC_DCR_IMMUTABLE_ID="{dcr_immutable_id}"
export PQC_STREAM_NAME="{stream_name}"

VALIDATOR_PATH="{LINUX_VALIDATOR_PATH}"

if [ ! -f "$VALIDATOR_PATH/main.py" ]; then
    echo "ERROR: PQC validator not found at $VALIDATOR_PATH"
    exit 1
fi

cd "$VALIDATOR_PATH"

# Activate venv if present
if [ -f "$VALIDATOR_PATH/venv/bin/activate" ]; then
    source "$VALIDATOR_PATH/venv/bin/activate"
fi

python3 main.py \
    --log-dir /var/log/pqc-validator \
    --report-dir /var/log/pqc-reports \
    --no-reports

echo "PQC validation complete on $(hostname)"
"""


def build_windows_script(dce_endpoint: str, dcr_immutable_id: str,
                          stream_name: str = "Custom-PQCCompliance_CL") -> str:
    """PowerShell script injected via Arc Run Command on Windows machines."""
    return f"""
$env:PQC_DCE_ENDPOINT = "{dce_endpoint}"
$env:PQC_DCR_IMMUTABLE_ID = "{dcr_immutable_id}"
$env:PQC_STREAM_NAME = "{stream_name}"

$ValidatorPath = "{WINDOWS_VALIDATOR_PATH}"

if (-not (Test-Path "$ValidatorPath\\main.py")) {{
    Write-Error "PQC validator not found at $ValidatorPath"
    exit 1
}}

Set-Location $ValidatorPath

# Use venv if present
$python = if (Test-Path "$ValidatorPath\\venv\\Scripts\\python.exe") {{
    "$ValidatorPath\\venv\\Scripts\\python.exe"
}} else {{
    "python"
}}

& $python main.py `
    --log-dir "C:\\ProgramData\\pqc-validator\\logs" `
    --report-dir "C:\\ProgramData\\pqc-validator\\reports" `
    --no-reports

Write-Host "PQC validation complete on $env:COMPUTERNAME"
"""


def dispatch_to_machine(
    machine: Dict,
    subscription_id: str,
    dce_endpoint: str,
    dcr_immutable_id: str,
    stream_name: str,
    credential
) -> Tuple[str, bool, str]:
    """
    Issue an Arc Run Command to a single machine.

    Returns:
        (machine_name, success, message)
    """
    name = machine["name"]
    rg = machine["resource_group"]
    os_name = machine.get("os_name", "").lower()

    is_windows = "windows" in os_name

    script = (
        build_windows_script(dce_endpoint, dcr_immutable_id, stream_name)
        if is_windows
        else build_linux_script(dce_endpoint, dcr_immutable_id, stream_name)
    )

    client = HybridComputeManagementClient(credential, subscription_id)

    run_command_name = f"pqc-validate-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    run_command = MachineRunCommand(
        location=machine["location"],
        source=MachineRunCommandScriptSource(
            script=script
        ),
        async_execution=False,
        timeout_in_seconds=300,
        run_as_system=True
    )

    try:
        poller = client.machine_run_commands.begin_create_or_update(
            resource_group_name=rg,
            machine_name=name,
            run_command_name=run_command_name,
            run_command_properties=run_command
        )

        result = poller.result(timeout=360)

        exit_code = result.instance_view.exit_code if result.instance_view else None
        output = result.instance_view.output if result.instance_view else ""
        error = result.instance_view.error if result.instance_view else ""

        if exit_code == 0:
            return (name, True, output.strip())
        else:
            return (name, False, f"Exit {exit_code}: {error.strip()}")

    except Exception as exc:
        return (name, False, str(exc))
    finally:
        # Clean up the run command resource
        try:
            client.machine_run_commands.begin_delete(rg, name, run_command_name).result(timeout=60)
        except Exception:
            pass


def run_fleet_validation(
    subscription_id: str,
    dce_endpoint: str,
    dcr_immutable_id: str,
    stream_name: str = "Custom-PQCCompliance_CL",
    resource_group: Optional[str] = None,
    os_filter: Optional[str] = None,
    tag_filter: Optional[Dict[str, str]] = None,
    max_parallel: int = 10
) -> Dict:
    """
    Discover all Arc-connected machines and run PQC validation on each.

    Args:
        subscription_id:   Azure subscription ID
        dce_endpoint:      Data Collection Endpoint URL
        dcr_immutable_id:  DCR Immutable ID
        stream_name:       Log Analytics custom stream name
        resource_group:    Optional: scope to one resource group
        os_filter:         Optional: 'Windows' or 'Linux'
        tag_filter:        Optional: tag key/value filter
        max_parallel:      Max concurrent Arc Run Commands (be mindful of API limits)

    Returns:
        Summary dict with per-machine results
    """
    print(f"\n{'='*60}")
    print("PQC Fleet Validation via Azure Arc")
    print(f"{'='*60}")
    print(f"Subscription: {subscription_id}")
    print(f"Time: {datetime.now().isoformat()}")

    credential = DefaultAzureCredential()

    # Step 1: Inventory Arc machines
    print("\nQuerying Arc machine inventory...")
    machines = get_arc_machines(
        subscription_ids=[subscription_id],
        resource_group=resource_group,
        os_filter=os_filter,
        tag_filter=tag_filter
    )

    if not machines:
        print("No connected Arc machines found matching the criteria.")
        return {"total": 0, "results": []}

    print(f"Found {len(machines)} connected Arc machine(s):")
    for m in machines:
        print(f"  {m['name']:30s} {m['os_name']:20s} {m['resource_group']}")

    print(f"\nDispatching validator to {len(machines)} machine(s) "
          f"(max {max_parallel} parallel)...")
    print("Results will stream to Log Analytics as each machine completes.\n")

    # Step 2: Dispatch in parallel
    results = []
    success_count = 0
    fail_count = 0

    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        futures = {
            executor.submit(
                dispatch_to_machine,
                machine=m,
                subscription_id=subscription_id,
                dce_endpoint=dce_endpoint,
                dcr_immutable_id=dcr_immutable_id,
                stream_name=stream_name,
                credential=credential
            ): m
            for m in machines
        }

        for future in as_completed(futures):
            machine_name, success, message = future.result()
            status_icon = "✓" if success else "✗"
            print(f"  {status_icon} {machine_name}: {message[:100]}")

            results.append({
                "machine": machine_name,
                "success": success,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            if success:
                success_count += 1
            else:
                fail_count += 1

    # Step 3: Summary
    print(f"\n{'='*60}")
    print(f"Fleet validation complete.")
    print(f"  Succeeded: {success_count}")
    print(f"  Failed:    {fail_count}")
    print(f"\nResults are available in Log Analytics.")
    print(f"Query with: PQCCompliance_CL | summarize count() by status_s, hostname_s")
    print(f"{'='*60}\n")

    return {
        "total": len(machines),
        "succeeded": success_count,
        "failed": fail_count,
        "results": results
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run PQC validation across all Arc-connected machines in a subscription"
    )

    parser.add_argument("--subscription", required=True,
                        help="Azure subscription ID")
    parser.add_argument("--dce-endpoint", required=True,
                        help="Data Collection Endpoint URL")
    parser.add_argument("--dcr-immutable-id", required=True,
                        help="DCR Immutable ID (dcr-xxxx...)")
    parser.add_argument("--stream-name", default="Custom-PQCCompliance_CL",
                        help="Log Analytics custom stream name")
    parser.add_argument("--resource-group",
                        help="Scope to a specific resource group")
    parser.add_argument("--os-filter", choices=["Windows", "Linux"],
                        help="Filter by OS type")
    parser.add_argument("--tag", action="append", metavar="KEY=VALUE",
                        help="Filter machines by tag (repeatable)")
    parser.add_argument("--parallel", type=int, default=10,
                        help="Max parallel Arc Run Commands (default: 10)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show discovered machines but do not run validation")

    args = parser.parse_args()

    # Parse tag filters
    tag_filter = {}
    if args.tag:
        for t in args.tag:
            if "=" in t:
                k, v = t.split("=", 1)
                tag_filter[k] = v
            else:
                print(f"Warning: ignoring malformed tag '{t}' (expected KEY=VALUE)")

    if args.dry_run:
        print("Dry run — querying Arc inventory only...")
        credential = DefaultAzureCredential()
        machines = get_arc_machines(
            subscription_ids=[args.subscription],
            resource_group=args.resource_group,
            os_filter=args.os_filter,
            tag_filter=tag_filter or None
        )
        print(f"\nWould validate {len(machines)} machine(s):")
        for m in machines:
            print(f"  {m['name']:30s} {m['os_name']:20s} {m['status']}")
        sys.exit(0)

    result = run_fleet_validation(
        subscription_id=args.subscription,
        dce_endpoint=args.dce_endpoint,
        dcr_immutable_id=args.dcr_immutable_id,
        stream_name=args.stream_name,
        resource_group=args.resource_group,
        os_filter=args.os_filter,
        tag_filter=tag_filter or None,
        max_parallel=args.parallel
    )

    sys.exit(0 if result["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
