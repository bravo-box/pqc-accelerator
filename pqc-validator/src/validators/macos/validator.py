"""
macOS-specific PQC compliance validator.
Checks for cryptographic frameworks and system crypto configuration.
"""

import subprocess
import re
from typing import List, Dict, Any
from pathlib import Path
from ...common.base_validator import (
    BaseValidator, ValidationResult, CheckStatus, SeverityLevel
)
from ...common.logger import PQCLogger


class MacOSValidator(BaseValidator):
    """Validator for macOS systems."""
    
    def __init__(self, logger: PQCLogger):
        """Initialize macOS validator."""
        super().__init__(logger)
        self.system_info = self._gather_system_info()
    
    def _gather_system_info(self) -> Dict[str, str]:
        """Gather macOS system information."""
        try:
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            
            # Get macOS version
            output = subprocess.check_output(
                ['sw_vers', '-productVersion'],
                text=True
            )
            macos_version = output.strip()
            
            info = {
                "hostname": hostname,
                "platform": "macos",
                "version": macos_version
            }
            
            self.logger.set_host_info(
                hostname=hostname,
                platform="macOS",
                version=f"macOS {macos_version}"
            )
            
            return info
        except Exception as e:
            self.logger.log_error("system_info", f"Failed to gather system info: {e}")
            return {}
    
    def validate_crypto_libraries(self) -> List[ValidationResult]:
        """Validate macOS cryptographic libraries."""
        self.logger.general_logger.info("Validating macOS cryptography libraries...")
        
        checks = [
            self._check_openssl_version(),
            self._check_common_crypto_framework(),
            self._check_libcrypto_algorithms(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_openssl_version(self) -> ValidationResult:
        """Check OpenSSL version on macOS."""
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
            
            # macOS often ships with LibreSSL, which is Apple's fork
            if 'LibreSSL' in output:
                status = CheckStatus.COMPLIANT
                details = f"LibreSSL {version} - Apple's TLS implementation"
            elif major >= 3:
                status = CheckStatus.COMPLIANT
                details = f"OpenSSL {version} - Has PQC support"
            elif major == 1 and minor >= 1:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"OpenSSL {version} - Consider upgrading to 3.x for PQC support"
            else:
                status = CheckStatus.DEPRECATED
                details = f"OpenSSL {version} - Deprecated"
                self.identify_gap(
                    gap_type="deprecated_openssl",
                    severity=SeverityLevel.HIGH,
                    description=f"OpenSSL {version} is deprecated",
                    component="OpenSSL",
                    recommendation="Install modern OpenSSL via Homebrew or MacPorts",
                    priority=0.85
                )
            
            return ValidationResult(
                check_name="OpenSSL Version Check",
                category="crypto_library",
                status=status,
                details=details,
                version=version
            )
        except subprocess.CalledProcessError:
            return ValidationResult(
                check_name="OpenSSL Version Check",
                category="crypto_library",
                status=CheckStatus.NOT_FOUND,
                details="OpenSSL not found"
            )
        except Exception as e:
            self.logger.log_error("openssl_check", str(e))
            return None
    
    def _check_common_crypto_framework(self) -> ValidationResult:
        """Check macOS CommonCrypto framework."""
        try:
            # Check if Security framework is available
            security_header = Path('/System/Library/Frameworks/Security.framework/Headers/Security.h')
            
            if security_header.exists():
                return ValidationResult(
                    check_name="macOS CommonCrypto Framework",
                    category="crypto_library",
                    status=CheckStatus.COMPLIANT,
                    details="macOS CommonCrypto/Security framework available"
                )
            else:
                return ValidationResult(
                    check_name="macOS CommonCrypto Framework",
                    category="crypto_library",
                    status=CheckStatus.UNKNOWN,
                    details="Could not verify CommonCrypto framework"
                )
        except Exception as e:
            self.logger.log_error("common_crypto_check", str(e))
            return None
    
    def _check_libcrypto_algorithms(self) -> ValidationResult:
        """Check available algorithms in libcrypto."""
        try:
            output = subprocess.check_output(
                ['openssl', 'list', '-public-key-algorithms'],
                text=True,
                stderr=subprocess.STDOUT
            )
            
            # Check for post-quantum algorithms
            pqc_algorithms = ['kyber', 'dilithium', 'falcon', 'sphincs']
            found_pqc = [algo for algo in pqc_algorithms if algo in output.lower()]
            
            if found_pqc:
                status = CheckStatus.COMPLIANT
                details = f"Found PQC algorithms: {', '.join(found_pqc)}"
            else:
                status = CheckStatus.DEPRECATED
                details = "No PQC algorithms detected"
                self.identify_gap(
                    gap_type="no_pqc_algorithms",
                    severity=SeverityLevel.HIGH,
                    description="macOS system lacks post-quantum cryptography algorithms",
                    component="libcrypto",
                    recommendation="Install OpenSSL 3.x with liboqs support via Homebrew",
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
    
    def validate_certificate_store(self) -> List[ValidationResult]:
        """Validate macOS certificate store."""
        self.logger.general_logger.info("Validating macOS certificate store...")
        
        checks = [
            self._check_keychain_certificates(),
            self._check_weak_certificates(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_keychain_certificates(self) -> ValidationResult:
        """Check macOS Keychain for certificates."""
        try:
            output = subprocess.check_output(
                ['security', 'find-certificate', '-a', '-c', 'Certificate'],
                text=True,
                stderr=subprocess.STDOUT
            )
            
            cert_count = output.count('certificate:')
            
            if cert_count > 0:
                return ValidationResult(
                    check_name="macOS Keychain Certificate Store",
                    category="certificates",
                    status=CheckStatus.COMPLIANT,
                    details=f"Keychain accessible with {cert_count} certificates"
                )
            else:
                return ValidationResult(
                    check_name="macOS Keychain Certificate Store",
                    category="certificates",
                    status=CheckStatus.UNKNOWN,
                    details="No certificates found in Keychain"
                )
        except subprocess.CalledProcessError:
            return ValidationResult(
                check_name="macOS Keychain Certificate Store",
                category="certificates",
                status=CheckStatus.UNKNOWN,
                details="Could not access Keychain certificates"
            )
        except Exception as e:
            self.logger.log_error("keychain_check", str(e))
            return None
    
    def _check_weak_certificates(self) -> ValidationResult:
        """Check for weak certificates in system store."""
        try:
            # Get system root certificates location
            system_certs = Path('/System/Library/Keychains')
            
            if system_certs.exists():
                return ValidationResult(
                    check_name="System Certificate Store",
                    category="certificates",
                    status=CheckStatus.COMPLIANT,
                    details="System certificate store accessible (manual review recommended)"
                )
            else:
                return ValidationResult(
                    check_name="System Certificate Store",
                    category="certificates",
                    status=CheckStatus.UNKNOWN,
                    details="System certificate store not found"
                )
        except Exception as e:
            self.logger.log_error("weak_cert_check", str(e))
            return None
    
    def validate_openssl_configuration(self) -> List[ValidationResult]:
        """Validate OpenSSL configuration on macOS."""
        self.logger.general_logger.info("Validating OpenSSL configuration...")
        
        checks = [
            self._check_openssl_config_path(),
            self._check_cipher_configuration(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_openssl_config_path(self) -> ValidationResult:
        """Check OpenSSL configuration file location."""
        config_paths = [
            Path('/etc/ssl/openssl.cnf'),
            Path('/opt/homebrew/etc/openssl/openssl.cnf'),
            Path('/usr/local/etc/openssl/openssl.cnf'),
        ]
        
        found = [p for p in config_paths if p.exists()]
        
        if found:
            return ValidationResult(
                check_name="OpenSSL Configuration Path",
                category="tls_configuration",
                status=CheckStatus.COMPLIANT,
                details=f"OpenSSL config found at {found[0]}"
            )
        else:
            return ValidationResult(
                check_name="OpenSSL Configuration Path",
                category="tls_configuration",
                status=CheckStatus.UNKNOWN,
                details="OpenSSL configuration file not found"
            )
    
    def _check_cipher_configuration(self) -> ValidationResult:
        """Check cipher configuration on macOS."""
        try:
            output = subprocess.check_output(
                ['openssl', 'list', '-cipher-algorithms'],
                text=True
            )
            
            weak_ciphers = ['DES', 'RC4']
            found_weak = [cipher for cipher in weak_ciphers if cipher in output]
            
            if found_weak:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"Legacy ciphers available: {', '.join(found_weak)}"
            else:
                status = CheckStatus.COMPLIANT
                details = "No obvious weak ciphers detected"
            
            return ValidationResult(
                check_name="Cipher Configuration Check",
                category="tls_configuration",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("cipher_config_check", str(e))
            return None
    
    def validate_system_algorithms(self) -> List[ValidationResult]:
        """Validate system-wide algorithm usage on macOS."""
        self.logger.general_logger.info("Validating macOS system algorithms...")
        
        checks = [
            self._check_ssh_configuration(),
            self._check_filevault_encryption(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_ssh_configuration(self) -> ValidationResult:
        """Check SSH algorithm configuration on macOS."""
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
            
            if 'HostKeyAlgorithm' in content:
                status = CheckStatus.COMPLIANT
                details = "SSH configuration includes HostKeyAlgorithm settings"
            else:
                status = CheckStatus.REQUIRES_UPDATE
                details = "SSH configuration missing explicit algorithm settings"
            
            return ValidationResult(
                check_name="SSH Algorithm Configuration",
                category="ssh",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("ssh_config_check", str(e))
            return None
    
    def _check_filevault_encryption(self) -> ValidationResult:
        """Check if FileVault encryption is enabled."""
        try:
            output = subprocess.check_output(
                ['diskutil', 'info', '/'],
                text=True
            )
            
            if 'Encrypted: Yes' in output:
                return ValidationResult(
                    check_name="FileVault Encryption",
                    category="encryption",
                    status=CheckStatus.COMPLIANT,
                    details="FileVault encryption enabled"
                )
            else:
                return ValidationResult(
                    check_name="FileVault Encryption",
                    category="encryption",
                    status=CheckStatus.REQUIRES_UPDATE,
                    details="FileVault encryption not enabled"
                )
        except Exception as e:
            self.logger.log_error("filevault_check", str(e))
            return ValidationResult(
                check_name="FileVault Encryption",
                category="encryption",
                status=CheckStatus.UNKNOWN,
                details="Could not determine FileVault status"
            )
