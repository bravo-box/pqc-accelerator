"""
Centralized logging module for PQC validation framework.
Captures all validation activities for audit trails and reporting.
"""

import logging
import json
import os
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from src.integrations.azure_monitor import AzureMonitorSink


class PQCLogger:
    """Centralized logger for PQC compliance validation."""

    def __init__(self, log_dir: str = "logs", azure_sink: Optional["AzureMonitorSink"] = None):
        """
        Initialize PQC Logger.

        Args:
            log_dir:      Directory where logs will be stored
            azure_sink:   Optional AzureMonitorSink — when provided every JSONL
                          record is streamed to Log Analytics in real time.
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Optional Azure Monitor sink (Arc Managed Identity auth)
        self._azure_sink = azure_sink

        # Create loggers for different purposes
        self.general_logger = self._setup_logger("pqc_validation", "validation.log")
        self.compliance_logger = self._setup_logger("pqc_compliance", "compliance.log")
        self.error_logger = self._setup_logger("pqc_errors", "errors.log")
        self.scan_logger = self._setup_logger("pqc_scan", "scans.json")
        
        # Structured log file for machine parsing
        self.scan_file = self.log_dir / "scans.jsonl"
        self.host_info = {}
        self.scan_run_id = str(uuid.uuid4())

    def _build_record_hash(self, normalized: Dict[str, Any]) -> str:
        """
        Build a deterministic hash for idempotent deduplication across reruns.
        Excludes run-local and timestamp fields so identical findings hash the same.
        """
        stable_view = {
            "record_type": normalized.get("record_type", ""),
            "hostname": normalized.get("hostname", ""),
            "platform": normalized.get("platform", ""),
            "os_version": normalized.get("os_version", ""),
            "check_name": normalized.get("check_name", ""),
            "category": normalized.get("category", ""),
            "status": normalized.get("status", ""),
            "details": normalized.get("details", ""),
            "algorithm": normalized.get("algorithm", ""),
            "version": normalized.get("version", ""),
            "gap_type": normalized.get("gap_type", ""),
            "severity": normalized.get("severity", ""),
            "affected_component": normalized.get("affected_component", ""),
            "recommendation": normalized.get("recommendation", ""),
            "priority_score": normalized.get("priority_score", 0.0),
            "error_type": normalized.get("error_type", ""),
        }
        payload = json.dumps(stable_view, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
        
    def _setup_logger(self, name: str, filename: str) -> logging.Logger:
        """Create a configured logger instance."""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.log_dir / filename)
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)

        return logger

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize an internal record for Log Analytics ingestion via the
        Data Collector API.  Field names are snake_case; the API appends _s
        (string), _d (numeric), _t (datetime) automatically so the column
        names in the workspace will be e.g. record_type_s, hostname_s, etc.

        Four record shapes:
          scan_result        — from log_scan_result / record_result
          cryptography_check — from log_cryptography_check
          compliance_gap     — from log_gap / identify_gap
          error              — from log_error
        """
        raw_type = record.get("type", "")
        if not raw_type and "check" in record:
            raw_type = "scan_result"

        result    = record.get("result", {}) or {}
        host_info = record.get("host_info", {}) or {}
        effective_host = host_info or self.host_info
        event_timestamp = record.get("timestamp") or datetime.now().isoformat()

        details = (
            record.get("details")
            or result.get("details")
            or record.get("description")
            or record.get("message")
            or ""
        )

        normalized = {
            # Preserve machine-side event time for evidence-quality timelines.
            "TimeGenerated":      event_timestamp,
            "record_timestamp":   event_timestamp,
            "scan_started_at":    effective_host.get("scan_timestamp", ""),
            "scan_run_id":        self.scan_run_id,
            "record_type":        raw_type,
            "hostname":           effective_host.get("hostname", ""),
            "platform":           effective_host.get("platform", ""),
            "os_version":         effective_host.get("version", ""),
            # Check / scan fields
            "check_name":         record.get("check", result.get("check_name", "")),
            "category":           record.get("category", result.get("category", "")),
            "status":             record.get("status", result.get("status", "")),
            "details":            details,
            "algorithm":          record.get("algorithm", result.get("algorithm", "")),
            "version":            record.get("version", result.get("version", "")),
            # Compliance gap fields
            "gap_type":           record.get("gap_type", ""),
            "severity":           record.get("severity", ""),
            "affected_component": record.get("affected_component", ""),
            "recommendation":     record.get("recommendation", ""),
            "priority_score":     float(record.get("priority_score", 0.0)),
            # Error fields
            "error_type":         record.get("error_type", ""),
            # Full source record payload for audit/replay provenance.
            "raw_record":         json.dumps(record, default=str),
        }

        normalized["record_hash"] = self._build_record_hash(normalized)
        return normalized

    def _emit(self, record: Dict[str, Any]) -> None:
        """Write one record to local JSONL and (optionally) to Azure Monitor."""
        with open(self.scan_file, 'a') as f:
            f.write(json.dumps(record) + '\n')

        if self._azure_sink:
            try:
                # Normalize record for consistent Log Analytics schema
                normalized = self._normalize_record(record)
                self._azure_sink.send(normalized)
            except Exception as exc:  # never let telemetry break the scan
                self.error_logger.warning(f"Azure Monitor send failed: {exc}")

    def flush_azure(self) -> bool:
        """Flush any buffered records to Azure Monitor."""
        if self._azure_sink:
            return self._azure_sink.flush()
        return True

    def set_host_info(self, hostname: str, platform: str, version: str):
        """Record host information for this validation session."""
        self.host_info = {
            "hostname": hostname,
            "platform": platform,
            "version": version,
            "scan_timestamp": datetime.now().isoformat()
        }
        self.general_logger.info(
            f"Scan initialized - Host: {hostname}, Platform: {platform} {version}"
        )
    
    def log_scan_result(self, check_name: str, category: str, result: Dict[str, Any]):
        """
        Log a scan result in structured format (JSONL).
        
        Args:
            check_name: Name of the check performed
            category: Category of the check (crypto, certificate, library, etc.)
            result: Dictionary containing check results
        """
        record = {
            "timestamp": datetime.now().isoformat(),
            "host_info": self.host_info,
            "check": check_name,
            "category": category,
            "result": result
        }

        self._emit(record)

        status = result.get("status", "UNKNOWN")
        self.compliance_logger.info(
            f"[{category}] {check_name}: {status}"
        )
    
    def log_cryptography_check(self, component: str, check: str, 
                               algorithm: str, status: str, details: str):
        """Log cryptography-specific checks."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "type": "cryptography_check",
            "component": component,
            "check": check,
            "algorithm": algorithm,
            "status": status,  # COMPLIANT, DEPRECATED, NOT_FOUND, RISK
            "details": details
        }
        
        self._emit(record)

        self.compliance_logger.info(
            f"[CRYPTO] {component}/{algorithm}: {status} - {details}"
        )
    
    def log_gap(self, gap_type: str, severity: str, description: str, 
                affected_component: str, recommendation: str):
        """Log identified compliance gaps."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "type": "compliance_gap",
            "gap_type": gap_type,
            "severity": severity,  # CRITICAL, HIGH, MEDIUM, LOW
            "description": description,
            "affected_component": affected_component,
            "recommendation": recommendation
        }
        
        self._emit(record)

        self.compliance_logger.warning(
            f"[{severity}] {gap_type}: {description}"
        )
    
    def log_error(self, error_type: str, message: str, context: Dict[str, Any] = None):
        """Log validation errors."""
        self.error_logger.error(f"[{error_type}] {message}")

        record = {
            "timestamp": datetime.now().isoformat(),
            "type": "error",
            "error_type": error_type,
            "message": message,
            "context": context or {}
        }

        self._emit(record)
    
    def get_log_files(self) -> Dict[str, str]:
        """Return paths to all log files."""
        return {
            "validation": str(self.log_dir / "validation.log"),
            "compliance": str(self.log_dir / "compliance.log"),
            "errors": str(self.log_dir / "errors.log"),
            "structured": str(self.scan_file)
        }
