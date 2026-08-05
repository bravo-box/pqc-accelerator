"""
Azure Monitor Logs Ingestion API client.

Sends PQC validation results directly to a Log Analytics custom table
using the machine's Arc Managed Identity — no hardcoded credentials needed.

Supports both Azure Public Cloud and Azure Government Cloud.
Uses REST API directly for better control over Azure Government authentication.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AzureMonitorSink:
    """
    Streams PQC validation records to Azure Monitor Log Analytics.

    Auth priority:
      1. Arc Managed Identity (on Arc-connected machines)
      2. DefaultAzureCredential fallback (dev/service principal)
    """

    def __init__(
        self,
        dce_endpoint: str,
        dcr_immutable_id: str,
        stream_name: str,
        use_managed_identity: bool = True,
        client_id: Optional[str] = None
    ):
        """
        Args:
            dce_endpoint:       Data Collection Endpoint URL
                                e.g. https://<dce-name>.<region>.ingest.monitor.azure.com
                                or https://<dce-name>.<region>.ingest.monitor.azure.us (Gov)
            dcr_immutable_id:   Immutable ID of the Data Collection Rule
                                e.g. dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
            stream_name:        Custom stream name matching the DCR definition
                                e.g. PQCCompliance_CL
            use_managed_identity: Use Arc/VM Managed Identity (recommended on Arc machines)
            client_id:          Optional: specific managed identity client ID
        """
        self.dce_endpoint = dce_endpoint
        self.dcr_immutable_id = dcr_immutable_id
        self.stream_name = stream_name
        self.use_managed_identity = use_managed_identity
        self.client_id = client_id

        # Determine if this is Azure Government based on DCE endpoint
        self.is_government = "azure.us" in dce_endpoint.lower()
        
        if self.is_government:
            print("[AzureMonitorSink] Configured for Azure Government Cloud")
            self.authority = "https://login.microsoftonline.us"
            self.resource = "https://monitor.azure.us"
        else:
            print("[AzureMonitorSink] Configured for Azure Public Cloud")
            self.authority = "https://login.microsoftonline.com"
            self.resource = "https://monitor.azure.com"

        if use_managed_identity:
            print("[AzureMonitorSink] Using Arc Managed Identity")
        else:
            print("[AzureMonitorSink] Using Azure CLI credentials")

        self._buffer: List[Dict[str, Any]] = []
        self._buffer_size = 50  # flush every N records
        self._token_cache: Optional[str] = None
        self._token_expires: Optional[float] = None

    def send(self, record: Dict[str, Any]) -> None:
        """
        Buffer a single log record and flush when buffer is full.

        Args:
            record: A JSONL-style record from PQCLogger
        """
        # Ensure TimeGenerated is present (required by Log Analytics)
        if "TimeGenerated" not in record:
            record["TimeGenerated"] = datetime.now(timezone.utc).isoformat()

        self._buffer.append(record)

        if len(self._buffer) >= self._buffer_size:
            self.flush()

    def _get_token(self) -> Optional[str]:
        """
        Get an authentication token for Monitor Logs Ingestion API.

        Uses azure-identity ManagedIdentityCredential which automatically handles
        both standard Azure VM IMDS and Arc-connected machine endpoints.
        On Arc machines the agent sets IDENTITY_ENDPOINT + IMDS_ENDPOINT env vars
        which ManagedIdentityCredential reads — the direct IMDS call at
        169.254.169.254 does NOT work on Arc.

        Returns:
            Bearer token or None if authentication fails
        """
        import time

        # Return cached token if still valid (60s buffer before expiry)
        if self._token_cache and self._token_expires and time.time() < self._token_expires - 60:
            return self._token_cache

        if self.use_managed_identity:
            try:
                from azure.identity import ManagedIdentityCredential
                kwargs = {"client_id": self.client_id} if self.client_id else {}
                credential = ManagedIdentityCredential(**kwargs)
                # azure-identity uses scope format: <resource>/.default
                scope = f"{self.resource.rstrip('/')}/.default"
                token_obj = credential.get_token(scope)
                self._token_cache = token_obj.token
                self._token_expires = token_obj.expires_on
                return self._token_cache
            except Exception as e:
                print(f"[AzureMonitorSink] ManagedIdentityCredential failed: {e}")
                return None
        else:
            # Fallback: Azure CLI credentials (dev/testing only)
            try:
                result = subprocess.run(
                    ["az", "account", "get-access-token", "--resource", self.resource],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    self._token_cache = data["accessToken"]
                    self._token_expires = time.time() + 3600
                    return self._token_cache
                else:
                    print(f"[AzureMonitorSink] Azure CLI token failed: {result.stderr}")
                    return None
            except Exception as e:
                print(f"[AzureMonitorSink] Failed to get token: {e}")
                return None

    def send_batch(self, records: List[Dict[str, Any]]) -> bool:
        """
        Send a batch of records via REST API.

        Args:
            records: List of log records

        Returns:
            True on success
        """
        if not records:
            return True

        # Inject TimeGenerated if missing
        for r in records:
            if "TimeGenerated" not in r:
                r["TimeGenerated"] = datetime.now(timezone.utc).isoformat()

        # Get authentication token
        token = self._get_token()
        if not token:
            print("[AzureMonitorSink] Failed to acquire token for Log Analytics upload")
            return False

        # Prepare the REST API request
        # Format: https://<dce-name>.<region>.ingest.monitor.azure.us/dataCollectionRules/<dcr-id>/streams/<stream>?api-version=2023-01-01
        base_url = self.dce_endpoint.rstrip('/')
        url = f"{base_url}/dataCollectionRules/{self.dcr_immutable_id}/streams/{self.stream_name}?api-version=2023-01-01"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        payload = records
        
        try:
            if not REQUESTS_AVAILABLE:
                print("[AzureMonitorSink] requests library not available, falling back to curl")
                return self._send_batch_curl(records, token, url, headers)
            
            resp = requests.post(url, json=payload, headers=headers, timeout=30)
            
            if resp.status_code in (200, 204):
                print(f"[AzureMonitorSink] Successfully uploaded {len(records)} records")
                return True
            else:
                print(f"[AzureMonitorSink] Upload failed: HTTP {resp.status_code}")
                print(f"[AzureMonitorSink] URL: {url}")
                print(f"[AzureMonitorSink] Response: {resp.text[:500]}")
                print(f"[AzureMonitorSink] DCE endpoint: {self.dce_endpoint}")
                print(f"[AzureMonitorSink] DCR ID: {self.dcr_immutable_id}")
                print(f"[AzureMonitorSink] Stream name: {self.stream_name}")
                print(f"[AzureMonitorSink] Resource URL: {self.resource}")
                
                if "InvalidAudience" in resp.text or "401" in str(resp.status_code):
                    print("[AzureMonitorSink] Authentication error - check token audience")
                
                return False
        except Exception as e:
            print(f"[AzureMonitorSink] Unexpected error: {type(e).__name__}: {e}")
            return False

    def _send_batch_curl(self, records: List[Dict[str, Any]], token: str, url: str, headers: Dict[str, str]) -> bool:
        """Fallback method using curl for REST API upload."""
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(records, f)
                payload_file = f.name
            
            cmd = ["curl", "-X", "POST", url, "-H", f"Authorization: Bearer {token}"]
            for k, v in headers.items():
                if k != "Authorization":
                    cmd.extend(["-H", f"{k}: {v}"])
            cmd.extend(["--data", "@" + payload_file])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            os.unlink(payload_file)
            
            if result.returncode == 0:
                return True
            else:
                print(f"[AzureMonitorSink] curl upload failed: {result.stderr}")
                return False
        except Exception as e:
            print(f"[AzureMonitorSink] curl fallback error: {e}")
            return False

    def flush(self) -> bool:
        """Send all buffered records."""
        if not self._buffer:
            return True

        success = self.send_batch(self._buffer)
        self._buffer = []
        return success

    def upload_jsonl_file(self, jsonl_path: str) -> int:
        """
        Upload an entire local scans.jsonl file to Azure Monitor.
        Useful for backfill or when connectivity was not available during scan.

        Args:
            jsonl_path: Path to the JSONL log file

        Returns:
            Number of records uploaded
        """
        records = []
        try:
            with open(jsonl_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except FileNotFoundError:
            print(f"[AzureMonitorSink] File not found: {jsonl_path}")
            return 0

        if not records:
            return 0

        # Upload in chunks of 500 (API limit)
        chunk_size = 500
        uploaded = 0
        for i in range(0, len(records), chunk_size):
            chunk = records[i:i + chunk_size]
            if self.send_batch(chunk):
                uploaded += len(chunk)

        print(f"[AzureMonitorSink] Uploaded {uploaded}/{len(records)} records from {jsonl_path}")
        return uploaded


def sink_from_env() -> Optional["AzureMonitorSink"]:
    """
    Build an AzureMonitorSink from environment variables.
    
    Tries two methods in priority order:
    
    Method 1: Data Collector API (Preferred - simpler, more reliable)
        Required env vars:
            LOG_ANALYTICS_WORKSPACE_ID
            LOG_ANALYTICS_WORKSPACE_KEY
        Optional:
            LOG_ANALYTICS_TABLE_NAME (defaults to "PQCCompliance")
    
    Method 2: DCR-based Logs Ingestion API (Legacy)
        Required env vars:
            PQC_DCE_ENDPOINT
            PQC_DCR_IMMUTABLE_ID
            PQC_STREAM_NAME
        Optional:
            PQC_MANAGED_IDENTITY_CLIENT_ID
    """
    
    # Try Data Collector API first (preferred method)
    workspace_id = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID")
    workspace_key = os.environ.get("LOG_ANALYTICS_WORKSPACE_KEY")
    
    if workspace_id and workspace_key:
        # Create a wrapper that uses Data Collector API
        return _create_datacollector_sink(workspace_id, workspace_key)
    
    # Fallback to DCR method
    dce = os.environ.get("PQC_DCE_ENDPOINT")
    dcr = os.environ.get("PQC_DCR_IMMUTABLE_ID")
    stream = os.environ.get("PQC_STREAM_NAME", "Custom-Json-PQCCompliance")

    if not dce or not dcr:
        return None

    return AzureMonitorSink(
        dce_endpoint=dce,
        dcr_immutable_id=dcr,
        stream_name=stream,
        use_managed_identity=True,
        client_id=os.environ.get("PQC_MANAGED_IDENTITY_CLIENT_ID")
    )


def _create_datacollector_sink(workspace_id: str, workspace_key: str) -> "AzureMonitorSink":
    """
    Create an AzureMonitorSink adapter that uses the Log Analytics Data Collector API.
    This is a wrapper that makes the Data Collector API compatible with the existing
    AzureMonitorSink interface.
    """
    # Import here to avoid circular imports
    from .azure_datacollector_api import AzureDataCollectorSink
    
    table_name = os.environ.get("LOG_ANALYTICS_TABLE_NAME", "PQCCompliance")
    
    # Create the Data Collector sink
    dc_sink = AzureDataCollectorSink(workspace_id, workspace_key, log_type=table_name)
    
    # Wrap it in an adapter that implements the AzureMonitorSink interface
    return _DataCollectorAdapter(dc_sink)


class _DataCollectorAdapter(AzureMonitorSink):
    """
    Adapter that wraps AzureDataCollectorSink to be compatible with AzureMonitorSink interface.
    This allows existing code to use either DCR or Data Collector API transparently.
    """
    
    def __init__(self, dc_sink):
        """Initialize adapter with a Data Collector sink."""
        self.dc_sink = dc_sink
        self._buffer: List[Dict[str, Any]] = []
        self._buffer_size = 50
        self.is_government = dc_sink.is_government
        print(f"[AzureMonitorSink] Using Log Analytics Data Collector API")
        print(f"[AzureMonitorSink] Workspace: {dc_sink.workspace_id[:8]}...")
        print(f"[AzureMonitorSink] Cloud: {'Azure Government' if self.is_government else 'Azure Public'}")
    
    def send(self, record: Dict[str, Any]) -> None:
        """Buffer a record and flush when buffer is full."""
        if "TimeGenerated" not in record:
            record["TimeGenerated"] = datetime.now(timezone.utc).isoformat()
        
        self._buffer.append(record)
        
        if len(self._buffer) >= self._buffer_size:
            self.flush()
    
    def flush(self) -> bool:
        """Send all buffered records."""
        if not self._buffer:
            return True
        
        success = self.dc_sink.send_batch(self._buffer)
        self._buffer = []
        return success
    
    def send_batch(self, records: List[Dict[str, Any]]) -> bool:
        """Send a batch directly to Log Analytics."""
        return self.dc_sink.send_batch(records)
    
    def upload_jsonl_file(self, jsonl_path: str) -> int:
        """Upload a JSONL file to Log Analytics."""
        self.dc_sink.upload_jsonl_file(jsonl_path)
        # Count lines in file for return value
        try:
            with open(jsonl_path) as f:
                return sum(1 for line in f if line.strip())
        except:
            return 0
