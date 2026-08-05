"""Azure Arc integrations for PQC validator"""

# Only import the runtime sink here.
# arc_inventory requires azure-mgmt-resourcegraph (management-plane) and is only
# used by deploy/arc_orchestrator.py on the management workstation — never on an
# Arc machine. Import it directly where needed rather than via this package.
from .azure_monitor import AzureMonitorSink, sink_from_env

__all__ = [
    "AzureMonitorSink",
    "sink_from_env",
]
