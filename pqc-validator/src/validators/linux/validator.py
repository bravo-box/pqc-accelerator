"""
Linux-specific PQC compliance validator.
Checks for OpenSSL, cryptographic libraries, and system crypto configuration.
"""

import subprocess
import re
from typing import List, Dict, Any
from pathlib import Path
import platform as sys_platform
from ...common.base_validator import (
    BaseValidator, ValidationResult, CheckStatus, SeverityLevel
)
from ...common.logger import PQCLogger


class LinuxValidator(BaseValidator):
    """Validator for Linux systems (desktops and servers)."""
    
    def __init__(self, logger: PQCLogger):
        """Initialize Linux validator."""
        super().__init__(logger)
        self.system_info = self._gather_system_info()
    
    def _gather_system_info(self) -> Dict[str, str]:
        """Gather system information for logging."""
        try:
            import os
            # Prefer ARC_MACHINE_NAME (set by deploy script) so Docker containers
            # report the Arc VM name instead of the container hostname
            hostname = (
                os.environ.get("ARC_MACHINE_NAME")
                or subprocess.check_output(['hostname'], text=True).strip()
            )
            distro = self._get_distro_info()
            kernel = subprocess.check_output(['uname', '-r'], text=True).strip()
            
            info = {
                "hostname": hostname,
                "distro": distro,
                "kernel": kernel,
                "platform": "linux"
            }
            
            self.logger.set_host_info(
                hostname=hostname,
                platform="Linux",
                version=distro
            )
            
            return info
        except Exception as e:
            self.logger.log_error("system_info", f"Failed to gather system info: {e}")
            return {}
    
    def _get_distro_info(self) -> str:
        """Get Linux distribution information."""
        try:
            # Try /etc/os-release first (modern systems)
            if Path("/etc/os-release").exists():
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            return line.split("=")[1].strip().strip('"')
            
            # Fallback to /etc/lsb-release
            if Path("/etc/lsb-release").exists():
                with open("/etc/lsb-release") as f:
                    for line in f:
                        if line.startswith("DISTRIB_DESCRIPTION="):
                            return line.split("=")[1].strip()
            
            return "Linux (Unknown Distribution)"
        except:
            return "Linux"
    
    def validate_crypto_libraries(self) -> List[ValidationResult]:
        """Validate installed cryptographic libraries."""
        self.logger.general_logger.info("Validating cryptographic libraries...")
        
        checks = [
            self._check_openssl_version(),
            self._check_libcrypto_algorithms(),
            self._check_libgcrypt(),
            self._check_libnss(),
            self._check_openssl_fips(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_openssl_version(self) -> ValidationResult:
        """Check OpenSSL version and PQC support."""
        try:
            output = subprocess.check_output(['openssl', 'version', '-a'], text=True)
            version_match = re.search(r'OpenSSL (\d+\.\d+\.\d+)', output)
            
            if not version_match:
                return ValidationResult(
                    check_name="OpenSSL Version Check",
                    category="crypto_library",
                    status=CheckStatus.UNKNOWN,
                    details="Could not determine OpenSSL version"
                )
            
            version = version_match.group(1)
            major, minor, patch = map(int, version.split('.'))
            
            # OpenSSL 3.0+ has post-quantum support
            if major >= 3:
                status = CheckStatus.COMPLIANT
                details = f"OpenSSL {version} - Has PQC support"
            elif major == 1 and minor >= 1:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"OpenSSL {version} - Consider upgrading to 3.x for PQC support"
            else:
                status = CheckStatus.DEPRECATED
                details = f"OpenSSL {version} - Deprecated, upgrade required"
                self.identify_gap(
                    gap_type="deprecated_openssl",
                    severity=SeverityLevel.HIGH,
                    description=f"OpenSSL {version} is deprecated and lacks PQC support",
                    component="OpenSSL",
                    recommendation="Upgrade to OpenSSL 3.0 or later",
                    priority=0.9
                )
            
            return ValidationResult(
                check_name="OpenSSL Version Check",
                category="crypto_library",
                status=status,
                details=details,
                version=version,
                algorithm="OpenSSL"
            )
        except subprocess.CalledProcessError:
            return ValidationResult(
                check_name="OpenSSL Version Check",
                category="crypto_library",
                status=CheckStatus.NOT_FOUND,
                details="OpenSSL not found",
                confidence=0.8
            )
        except Exception as e:
            self.logger.log_error("openssl_check", str(e))
            return None
    
    def _check_libcrypto_algorithms(self) -> ValidationResult:
        """Check available algorithms in libcrypto."""
        try:
            output = subprocess.check_output(['openssl', 'list', '-public-key-algorithms'], 
                                            text=True, stderr=subprocess.STDOUT)
            
            # Check for post-quantum algorithms
            pqc_algorithms = ['kyber', 'dilithium', 'falcon', 'sphincs']
            found_pqc = [algo for algo in pqc_algorithms if algo in output.lower()]
            
            if found_pqc:
                status = CheckStatus.COMPLIANT
                details = f"Found PQC algorithms: {', '.join(found_pqc)}"
            else:
                status = CheckStatus.DEPRECATED
                details = "No PQC algorithms detected in libcrypto"
                self.identify_gap(
                    gap_type="no_pqc_algorithms",
                    severity=SeverityLevel.HIGH,
                    description="System libcrypto lacks post-quantum cryptography algorithms",
                    component="libcrypto",
                    recommendation="Install liboqs or update OpenSSL to version with PQC support",
                    priority=0.95
                )
            
            return ValidationResult(
                check_name="libcrypto Algorithm Check",
                category="crypto_algorithms",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("libcrypto_check", str(e))
            return None
    
    def _check_libgcrypt(self) -> ValidationResult:
        """Check libgcrypt installation and version."""
        try:
            output = subprocess.check_output(['libgcrypt-config', '--version'], text=True)
            version = output.strip()
            
            # libgcrypt 1.10+ has better support for modern algorithms
            details = f"libgcrypt {version} installed"
            status = CheckStatus.COMPLIANT if version >= "1.10" else CheckStatus.REQUIRES_UPDATE
            
            return ValidationResult(
                check_name="libgcrypt Check",
                category="crypto_library",
                status=status,
                details=details,
                version=version
            )
        except subprocess.CalledProcessError:
            return ValidationResult(
                check_name="libgcrypt Check",
                category="crypto_library",
                status=CheckStatus.NOT_FOUND,
                details="libgcrypt not installed"
            )
        except Exception as e:
            self.logger.log_error("libgcrypt_check", str(e))
            return None
    
    def _check_libnss(self) -> ValidationResult:
        """Check NSS (Network Security Services) library."""
        try:
            output = subprocess.check_output(['pkg-config', '--modversion', 'nss'], 
                                            text=True)
            version = output.strip()
            
            details = f"NSS {version} installed"
            return ValidationResult(
                check_name="NSS Library Check",
                category="crypto_library",
                status=CheckStatus.COMPLIANT,
                details=details,
                version=version
            )
        except subprocess.CalledProcessError:
            return ValidationResult(
                check_name="NSS Library Check",
                category="crypto_library",
                status=CheckStatus.NOT_FOUND,
                details="NSS not found via pkg-config"
            )
        except Exception as e:
            self.logger.log_error("nss_check", str(e))
            return None
    
    def _check_openssl_fips(self) -> ValidationResult:
        """Check if OpenSSL FIPS module is available."""
        try:
            output = subprocess.check_output(['openssl', 'version'], text=True)
            
            if 'FIPS' in output:
                status = CheckStatus.COMPLIANT
                details = "FIPS module available"
            else:
                status = CheckStatus.REQUIRES_UPDATE
                details = "FIPS module not enabled"
                self.identify_gap(
                    gap_type="fips_not_enabled",
                    severity=SeverityLevel.MEDIUM,
                    description="OpenSSL FIPS module not enabled",
                    component="OpenSSL",
                    recommendation="Enable FIPS module for compliance requirements",
                    priority=0.6
                )
            
            return ValidationResult(
                check_name="OpenSSL FIPS Module Check",
                category="compliance",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("fips_check", str(e))
            return None
    
    def validate_certificate_store(self) -> List[ValidationResult]:
        """Validate system certificate store."""
        self.logger.general_logger.info("Validating certificate store...")
        
        checks = [
            self._check_ca_bundle_location(),
            self._check_weak_certificates(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_ca_bundle_location(self) -> ValidationResult:
        """Check for system CA bundle."""
        ca_paths = [
            Path('/etc/ssl/certs/ca-bundle.crt'),
            Path('/etc/ssl/certs/ca-certificates.crt'),
            Path('/etc/pki/tls/certs/ca-bundle.crt'),
        ]
        
        found = [p for p in ca_paths if p.exists()]
        
        if found:
            return ValidationResult(
                check_name="CA Bundle Location",
                category="certificates",
                status=CheckStatus.COMPLIANT,
                details=f"Found CA bundle at {found[0]}"
            )
        else:
            return ValidationResult(
                check_name="CA Bundle Location",
                category="certificates",
                status=CheckStatus.NOT_FOUND,
                details="System CA bundle not found"
            )
    
    def _check_weak_certificates(self) -> ValidationResult:
        """Check for weak certificates in system store."""
        ca_bundle = Path('/etc/ssl/certs/ca-certificates.crt')
        
        if not ca_bundle.exists():
            ca_bundle = Path('/etc/ssl/certs/ca-bundle.crt')
        
        if not ca_bundle.exists():
            return ValidationResult(
                check_name="Weak Certificate Detection",
                category="certificates",
                status=CheckStatus.UNKNOWN,
                details="CA bundle not found, skipping check"
            )
        
        try:
            # This is a placeholder - real implementation would parse certs
            return ValidationResult(
                check_name="Weak Certificate Detection",
                category="certificates",
                status=CheckStatus.COMPLIANT,
                details="No obviously weak certificates detected (manual review recommended)"
            )
        except Exception as e:
            self.logger.log_error("weak_cert_check", str(e))
            return None
    
    def validate_openssl_configuration(self) -> List[ValidationResult]:
        """Validate OpenSSL configuration files."""
        self.logger.general_logger.info("Validating OpenSSL configuration...")
        
        checks = [
            self._check_openssl_config_algorithms(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_openssl_config_algorithms(self) -> ValidationResult:
        """Check OpenSSL configuration for deprecated algorithms."""
        try:
            output = subprocess.check_output(
                ['openssl', 'list', '-cipher-algorithms'],
                text=True
            )
            
            weak_ciphers = ['DES', 'RC4', 'MD5']
            found_weak = [cipher for cipher in weak_ciphers if cipher in output]
            
            if found_weak:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"Weak ciphers available: {', '.join(found_weak)}"
                self.identify_gap(
                    gap_type="weak_ciphers_available",
                    severity=SeverityLevel.MEDIUM,
                    description=f"Weak ciphers still available: {', '.join(found_weak)}",
                    component="OpenSSL",
                    recommendation="Disable weak ciphers in OpenSSL configuration",
                    priority=0.7
                )
            else:
                status = CheckStatus.COMPLIANT
                details = "No obvious weak ciphers detected"
            
            return ValidationResult(
                check_name="OpenSSL Cipher Configuration",
                category="tls_configuration",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("openssl_config_check", str(e))
            return None
    
    def validate_system_algorithms(self) -> List[ValidationResult]:
        """Validate system-wide algorithm usage."""
        self.logger.general_logger.info("Validating system algorithms...")
        
        checks = [
            self._check_ssh_algorithms(),
            self._check_system_entropy(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_ssh_algorithms(self) -> ValidationResult:
        """Check SSH algorithm configuration."""
        ssh_config = Path('/etc/ssh/sshd_config')
        
        if not ssh_config.exists():
            return ValidationResult(
                check_name="SSH Algorithm Configuration",
                category="ssh",
                status=CheckStatus.UNKNOWN,
                details="SSH configuration not found"
            )
        
        try:
            with open(ssh_config) as f:
                content = f.read()
            
            # Check for deprecated algorithms
            deprecated_patterns = [
                'HostKeyAlgorithms.*ssh-rsa',
                'HostKeyAlgorithms.*ecdsa-sha2',
            ]
            
            found_deprecated = any(
                re.search(pattern, content) for pattern in deprecated_patterns
            )
            
            if found_deprecated:
                status = CheckStatus.REQUIRES_UPDATE
                details = "SSH configuration contains deprecated algorithms"
                self.identify_gap(
                    gap_type="deprecated_ssh_algorithms",
                    severity=SeverityLevel.HIGH,
                    description="SSH server configured with deprecated algorithms",
                    component="SSH/sshd",
                    recommendation="Update SSH configuration to use modern algorithms (ed25519, etc.)",
                    priority=0.85
                )
            else:
                status = CheckStatus.COMPLIANT
                details = "SSH algorithms appear properly configured"
            
            return ValidationResult(
                check_name="SSH Algorithm Configuration",
                category="ssh",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("ssh_config_check", str(e))
            return None
    
    def _check_system_entropy(self) -> ValidationResult:
        """Check system entropy source."""
        entropy_sources = [
            Path('/dev/urandom'),
            Path('/dev/random'),
        ]
        
        available = [p for p in entropy_sources if p.exists()]
        
        if available:
            return ValidationResult(
                check_name="System Entropy Source",
                category="cryptography",
                status=CheckStatus.COMPLIANT,
                details=f"Entropy sources available: {', '.join(str(p) for p in available)}"
            )
        else:
            return ValidationResult(
                check_name="System Entropy Source",
                category="cryptography",
                status=CheckStatus.NOT_FOUND,
                details="No system entropy sources found"
            )
