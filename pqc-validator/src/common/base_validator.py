"""
Base validator class that all platform-specific validators inherit from.
Provides common validation patterns and interfaces.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from .logger import PQCLogger


class CheckStatus(Enum):
    """Status of a compliance check."""
    COMPLIANT = "COMPLIANT"
    DEPRECATED = "DEPRECATED"
    NOT_FOUND = "NOT_FOUND"
    REQUIRES_UPDATE = "REQUIRES_UPDATE"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class SeverityLevel(Enum):
    """Severity level for identified gaps."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ValidationResult:
    """Standard validation result format."""
    check_name: str
    category: str
    status: CheckStatus
    details: str
    algorithm: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, handling enums."""
        result = asdict(self)
        result['status'] = self.status.value
        return result


@dataclass
class ComplianceGap:
    """Identified compliance gap or vulnerability."""
    gap_type: str
    severity: SeverityLevel
    description: str
    affected_component: str
    recommendation: str
    priority_score: float = 0.0  # For ranking remediation efforts


class BaseValidator(ABC):
    """Abstract base class for all platform validators."""
    
    def __init__(self, logger: PQCLogger):
        """
        Initialize base validator.
        
        Args:
            logger: PQCLogger instance for recording results
        """
        self.logger = logger
        self.validation_results: List[ValidationResult] = []
        self.identified_gaps: List[ComplianceGap] = []
    
    @abstractmethod
    def validate_crypto_libraries(self) -> List[ValidationResult]:
        """
        Validate installed cryptographic libraries.
        
        Returns:
            List of validation results
        """
        pass
    
    @abstractmethod
    def validate_certificate_store(self) -> List[ValidationResult]:
        """
        Validate system certificate store for weak algorithms.
        
        Returns:
            List of validation results
        """
        pass
    
    @abstractmethod
    def validate_openssl_configuration(self) -> List[ValidationResult]:
        """
        Validate OpenSSL/TLS configuration.
        
        Returns:
            List of validation results
        """
        pass
    
    @abstractmethod
    def validate_system_algorithms(self) -> List[ValidationResult]:
        """
        Validate system-wide cryptographic algorithm usage.
        
        Returns:
            List of validation results
        """
        pass
    
    def identify_gap(self, gap_type: str, severity: SeverityLevel, 
                    description: str, component: str, recommendation: str,
                    priority: float = 0.0) -> ComplianceGap:
        """
        Identify and record a compliance gap.
        
        Args:
            gap_type: Type of gap (e.g., "weak_algorithm", "missing_pqc_support")
            severity: Severity level
            description: Detailed description
            component: Affected component
            recommendation: Remediation recommendation
            priority: Priority score for ranking (0.0-1.0)
        
        Returns:
            ComplianceGap instance
        """
        gap = ComplianceGap(
            gap_type=gap_type,
            severity=severity,
            description=description,
            affected_component=component,
            recommendation=recommendation,
            priority_score=priority
        )
        self.identified_gaps.append(gap)
        
        self.logger.log_gap(
            gap_type=gap_type,
            severity=severity.value,
            description=description,
            affected_component=component,
            recommendation=recommendation
        )
        
        return gap
    
    def record_result(self, result: ValidationResult):
        """Record a validation result."""
        self.validation_results.append(result)
        self.logger.log_scan_result(
            check_name=result.check_name,
            category=result.category,
            result=result.to_dict()
        )
    
    def run_full_validation(self) -> Dict[str, Any]:
        """
        Run all validation checks.
        
        Returns:
            Summary of validation results
        """
        # Run all validators
        self.logger.general_logger.info("Starting full PQC compliance validation...")
        
        self.validation_results = []
        self.identified_gaps = []
        
        try:
            self.validate_crypto_libraries()
            self.validate_certificate_store()
            self.validate_openssl_configuration()
            self.validate_system_algorithms()
        except Exception as e:
            self.logger.log_error(
                error_type="validation_error",
                message=f"Error during validation: {str(e)}"
            )
        
        self.logger.general_logger.info(
            f"Validation complete. Found {len(self.identified_gaps)} gaps."
        )
        
        return self.get_validation_summary()
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of validation results."""
        compliant_count = sum(
            1 for r in self.validation_results 
            if r.status == CheckStatus.COMPLIANT
        )
        
        gaps_by_severity = {}
        for gap in self.identified_gaps:
            severity = gap.severity.value
            gaps_by_severity[severity] = gaps_by_severity.get(severity, 0) + 1
        
        return {
            "total_checks": len(self.validation_results),
            "compliant_checks": compliant_count,
            "non_compliant_checks": len(self.validation_results) - compliant_count,
            "total_gaps": len(self.identified_gaps),
            "gaps_by_severity": gaps_by_severity,
            "validation_results": [r.to_dict() for r in self.validation_results],
            "identified_gaps": [
                {
                    "gap_type": g.gap_type,
                    "severity": g.severity.value,
                    "description": g.description,
                    "affected_component": g.affected_component,
                    "recommendation": g.recommendation,
                    "priority_score": g.priority_score
                }
                for g in self.identified_gaps
            ]
        }
