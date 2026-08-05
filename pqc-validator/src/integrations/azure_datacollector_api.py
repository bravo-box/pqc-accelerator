"""
Azure Log Analytics Data Collector API client.

Alternative to DCR-based ingestion for sending PQC validation results.
Uses the Log Analytics Data Collector REST API directly.

Supports both Azure Public Cloud and Azure Government Cloud.
Simpler than DCR approach - no need to create/configure Data Collection Rules.
"""

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
import subprocess

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AzureDataCollectorSink:
    """
    Streams PQC validation records to Azure Log Analytics using Data Collector API.
    
    This API accepts JSON POST requests and stores data in a custom table.
    No DCR or Logs Ingestion API complexity - just send JSON to Log Analytics workspace directly.
    
    Supports:
    - Azure Public Cloud (monitor.azure.com)
    - Azure Government Cloud (monitor.azure.us)
    """

    def __init__(
        self,
        workspace_id: str,
        workspace_key: str,
        log_type: str = "PQCCompliance_CL"
    ):
        """
        Args:
            workspace_id:   Log Analytics workspace ID (found in workspace settings)
            workspace_key:  Workspace primary/secondary key (found in workspace settings)
            log_type:       Custom log table name (without _CL suffix, system adds it)
                           e.g. 'PQCCompliance' → stores in 'PQCCompliance_CL'
        """
        self.workspace_id = workspace_id
        self.workspace_key = workspace_key
        self.log_type = log_type
        
        # Detect cloud (public vs government)
        self.is_government = self._detect_government_cloud()
        self.api_version = "2016-04-01"  # Data Collector API version
        self.api_endpoint = self._get_api_endpoint()

    def _detect_government_cloud(self) -> bool:
        """Check if running in Azure Government cloud via environment."""
        cloud_env = os.environ.get("AZURE_CLOUD_ENV", "").lower()
        if "gov" in cloud_env or "usgovcloud" in cloud_env:
            return True
        # Check for Gov-specific hostnames in other env vars
        for key, value in os.environ.items():
            if value and "usgovcloud" in str(value).lower() or "monitor.azure.us" in str(value).lower():
                return True
        return False

    def _get_api_endpoint(self) -> str:
        """Get the correct Log Analytics API endpoint for the cloud."""
        if self.is_government:
            return f"https://{self.workspace_id}.ods.opinsights.azure.us"
        else:
            return f"https://{self.workspace_id}.ods.opinsights.azure.com"

    def _build_signature(self, date: str, content_length: int) -> str:
        """
        Build the authorization signature for Log Analytics API.
        
        Signature = HMAC-SHA256(StringToSign, base64DecodedKey)
        StringToSign = Method + Content Length + Content Type + RFC 7231 Date + Resource Path
        """
        string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
        
        # Decode the workspace key (it's base64 encoded)
        import base64
        try:
            key_bytes = base64.b64decode(self.workspace_key)
        except Exception as e:
            raise ValueError(f"Invalid workspace key (must be base64 encoded): {e}")
        
        # Create HMAC-SHA256 signature
        signature = hmac.new(
            key_bytes,
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Base64 encode the signature
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        return signature_b64

    def send_batch(self, records: List[Dict[str, Any]]) -> bool:
        """
        Send a batch of records to Log Analytics.
        
        Args:
            records: List of dict records to send
            
        Returns:
            True if successful, False otherwise
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required - install with: pip install requests")
        
        if not records:
            return True

        # Sanitize reserved field names - Log Analytics rejects certain column names
        # 'type' and 'timestamp' are reserved; rename them before sending
        RESERVED_FIELDS = {"type": "record_type", "timestamp": "record_timestamp"}
        sanitized = []
        for rec in records:
            new_rec = {}
            for k, v in rec.items():
                new_key = RESERVED_FIELDS.get(k, k)
                if isinstance(v, dict):
                    new_rec[new_key] = json.dumps(v)  # flatten nested objects to string
                else:
                    new_rec[new_key] = v
            sanitized.append(new_rec)
        records = sanitized

        try:
            # Serialize records to JSON
            json_data = json.dumps(records)
            content_length = len(json_data)
            
            # Create authorization header
            # Format: SharedKey <WorkspaceId>:<Signature>
            date_rfc7231 = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            signature = self._build_signature(date_rfc7231, content_length)
            
            authorization = f"SharedKey {self.workspace_id}:{signature}"
            
            # Build headers
            headers = {
                "Content-Type": "application/json",
                "Authorization": authorization,
                "Log-Type": self.log_type,
                "x-ms-date": date_rfc7231
            }
            
            # Send POST request to Log Analytics
            url = f"{self.api_endpoint}/api/logs?api-version={self.api_version}"
            
            response = requests.post(url, data=json_data, headers=headers, timeout=30)
            
            if response.status_code in [200, 202]:
                print(f"✓ Sent {len(records)} records to Log Analytics ({self.log_type}_CL)")
                return True
            else:
                print(f"✗ Log Analytics ingestion failed: HTTP {response.status_code}")
                print(f"  Response: {response.text[:200]}")
                return False
                
        except Exception as e:
            print(f"✗ Error sending to Log Analytics: {e}")
            return False

    def upload_jsonl_file(self, filepath: str, batch_size: int = 500) -> bool:
        """
        Upload records from a JSONL file to Log Analytics.
        
        Args:
            filepath:    Path to JSONL file (one JSON record per line)
            batch_size:  Records to send per API call
            
        Returns:
            True if all batches successful, False if any failed
        """
        if not os.path.exists(filepath):
            print(f"✗ File not found: {filepath}")
            return False
        
        try:
            records = []
            success = True
            batch_count = 0
            
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        record = json.loads(line)
                        records.append(record)
                        
                        # Send batch when size reached
                        if len(records) >= batch_size:
                            if not self.send_batch(records):
                                success = False
                            batch_count += 1
                            records = []
                            time.sleep(0.5)  # Brief delay between batches
                            
                    except json.JSONDecodeError as e:
                        print(f"⚠ Skipping invalid JSON line: {e}")
                        continue
            
            # Send remaining records
            if records:
                if not self.send_batch(records):
                    success = False
                batch_count += 1
            
            if success:
                print(f"✓ Successfully uploaded file ({batch_count} batches)")
            else:
                print(f"⚠ Some batches failed during upload")
            
            return success
            
        except Exception as e:
            print(f"✗ Error uploading file: {e}")
            return False


def get_workspace_credentials() -> tuple[str, str]:
    """
    Retrieve Log Analytics workspace ID and key from environment or Azure CLI.
    
    Returns:
        (workspace_id, workspace_key)
    """
    # Try environment variables first
    workspace_id = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID")
    workspace_key = os.environ.get("LOG_ANALYTICS_WORKSPACE_KEY")
    
    if workspace_id and workspace_key:
        return workspace_id, workspace_key
    
    # Try Azure CLI as fallback
    try:
        # This requires the user to have logged in via Azure CLI
        result = subprocess.run(
            ["az", "monitor", "log-analytics", "workspace", "show",
             "--resource-group", os.environ.get("AZURE_RESOURCE_GROUP", ""),
             "--workspace-name", os.environ.get("LOG_ANALYTICS_WORKSPACE_NAME", ""),
             "--query", "customerId", "-o", "tsv"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            workspace_id = result.stdout.strip()
        
        # Get workspace key
        result = subprocess.run(
            ["az", "monitor", "log-analytics", "workspace", "get-shared-keys",
             "--resource-group", os.environ.get("AZURE_RESOURCE_GROUP", ""),
             "--workspace-name", os.environ.get("LOG_ANALYTICS_WORKSPACE_NAME", ""),
             "--query", "primarySharedKey", "-o", "tsv"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            workspace_key = result.stdout.strip()
        
        if workspace_id and workspace_key:
            return workspace_id, workspace_key
    except Exception as e:
        print(f"Note: Could not retrieve credentials from Azure CLI: {e}")
    
    raise ValueError(
        "Log Analytics credentials not found. "
        "Set LOG_ANALYTICS_WORKSPACE_ID and LOG_ANALYTICS_WORKSPACE_KEY environment variables, "
        "or configure via Azure CLI: az configure"
    )


if __name__ == "__main__":
    # Test usage
    print("Azure Log Analytics Data Collector API - Test")
    print("=" * 50)
    
    try:
        workspace_id, workspace_key = get_workspace_credentials()
        print(f"✓ Found workspace: {workspace_id[:8]}...")
        
        sink = AzureDataCollectorSink(workspace_id, workspace_key)
        print(f"✓ Connected to {'Azure Government' if sink.is_government else 'Azure Public'} cloud")
        print(f"  Endpoint: {sink.api_endpoint}")
        
        # Test with sample record
        test_records = [{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "compliance_check",
            "gap_type": "MISSING_PATCH",
            "severity": "HIGH",
            "description": "Critical security updates available",
            "affected_component": "System Libraries",
            "recommendation": "Apply latest patches"
        }]
        
        if sink.send_batch(test_records):
            print("✓ Test message sent successfully")
        else:
            print("✗ Test message failed")
            
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
