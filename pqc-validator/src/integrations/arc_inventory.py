"""
Azure Arc machine inventory via Azure Resource Graph.

Queries all Arc-connected machines in a subscription/resource group
without maintaining a static host list.
"""

import json
from typing import List, Dict, Any, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest


def get_arc_machines(
    subscription_ids: List[str],
    resource_group: Optional[str] = None,
    os_filter: Optional[str] = None,
    tag_filter: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """
    Query Azure Resource Graph for all Arc-connected machines.

    Args:
        subscription_ids:   List of subscription IDs to scope the query
        resource_group:     Optional: limit to a specific resource group
        os_filter:          Optional: 'Windows' or 'Linux'
        tag_filter:         Optional: dict of tags to filter on
                            e.g. {"Environment": "Production"}

    Returns:
        List of machine dicts with id, name, location, osName, status, resourceGroup
    """
    credential = DefaultAzureCredential()
    client = ResourceGraphClient(credential)

    # Base query - Arc Connected Machines
    query = """
        Resources
        | where type =~ 'microsoft.hybridcompute/machines'
        | where properties.status =~ 'Connected'
        | project
            id,
            name,
            location,
            resourceGroup,
            osName    = tostring(properties.osName),
            osVersion = tostring(properties.osVersion),
            osSku     = tostring(properties.osSku),
            status    = tostring(properties.status),
            lastStatusChange = tostring(properties.lastStatusChange),
            agentVersion = tostring(properties.agentVersion),
            tags
    """

    if resource_group:
        query += f"\n| where resourceGroup =~ '{resource_group}'"

    if os_filter:
        query += f"\n| where osName has '{os_filter}'"

    if tag_filter:
        for key, value in tag_filter.items():
            query += f"\n| where tags['{key}'] =~ '{value}'"

    query += "\n| order by name asc"

    request = QueryRequest(
        subscriptions=subscription_ids,
        query=query
    )

    response = client.resources(request)

    machines = []
    for row in response.data:
        machines.append({
            "id":               row.get("id"),
            "name":             row.get("name"),
            "location":         row.get("location"),
            "resource_group":   row.get("resourceGroup"),
            "os_name":          row.get("osName"),
            "os_version":       row.get("osVersion"),
            "os_sku":           row.get("osSku"),
            "status":           row.get("status"),
            "last_status":      row.get("lastStatusChange"),
            "agent_version":    row.get("agentVersion"),
            "tags":             row.get("tags", {})
        })

    return machines


def get_arc_machine_count(subscription_ids: List[str]) -> Dict[str, int]:
    """
    Return a quick count summary of Arc machines by OS and status.
    Useful for validating inventory before a scan run.
    """
    credential = DefaultAzureCredential()
    client = ResourceGraphClient(credential)

    query = """
        Resources
        | where type =~ 'microsoft.hybridcompute/machines'
        | summarize
            total     = count(),
            connected = countif(properties.status =~ 'Connected'),
            windows   = countif(properties.osName has 'Windows'),
            linux     = countif(not (properties.osName has 'Windows'))
          by status = tostring(properties.status)
    """

    request = QueryRequest(subscriptions=subscription_ids, query=query)
    response = client.resources(request)

    summary = {"total": 0, "connected": 0, "windows": 0, "linux": 0}
    for row in response.data:
        summary["total"] += row.get("total", 0)
        summary["connected"] += row.get("connected", 0)
        summary["windows"] += row.get("windows", 0)
        summary["linux"] += row.get("linux", 0)

    return summary
