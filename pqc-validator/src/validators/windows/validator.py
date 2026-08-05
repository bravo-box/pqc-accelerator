"""
Windows-specific PQC compliance validator.
Checks for CNG, cryptography APIs, and Windows crypto configuration.
"""

import subprocess
import re
from typing import List, Dict, Any
from pathlib import Path
from ...common.base_validator import (
    BaseValidator, ValidationResult, CheckStatus, SeverityLevel
)
from ...common.logger import PQCLogger


class WindowsValidator(BaseValidator):
    """Validator for Windows systems (desktops and servers)."""
    
    def __init__(self, logger: PQCLogger):
        """Initialize Windows validator."""
        super().__init__(logger)
        self.system_info = self._gather_system_info()
    
    def _gather_system_info(self) -> Dict[str, str]:
        """Gather Windows system information."""
        try:
            # Get Windows version
            output = subprocess.check_output(
                ['powershell', '-Command', 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version'],
                text=True
            )
            
            # Get hostname
            hostname = subprocess.check_output(
                ['powershell', '-Command', 'Get-CimInstance Win32_ComputerSystem | Select-Object Name'],
                text=True
            ).strip()
            
            info = {
                "hostname": hostname,
                "platform": "windows"
            }
            
            self.logger.set_host_info(
                hostname=hostname,
                platform="Windows",
                version="Windows Server/Desktop"
            )
            
            return info
        except Exception as e:
            self.logger.log_error("system_info", f"Failed to gather system info: {e}")
            return {}
    
    def _run_powershell(self, command: str) -> str:
        """Execute a PowerShell command."""
        try:
            return subprocess.check_output(
                ['powershell', '-Command', command],
                text=True,
                stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError as e:
            raise Exception(f"PowerShell command failed: {e.output}")
    
    def validate_crypto_libraries(self) -> List[ValidationResult]:
        """Validate Windows cryptographic libraries (CNG, CAPI)."""
        self.logger.general_logger.info("Validating Windows cryptography libraries...")
        
        checks = [
            self._check_cng_support(),
            self._check_bcryptography_dll(),
            self._check_schannel_protocols(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_cng_support(self) -> ValidationResult:
        """Check Windows CNG (Cryptography Next Generation) support."""
        try:
            # Check if CNG providers are registered
            output = self._run_powershell(
                'Get-Item -Path HKLM:\\Software\\Microsoft\\Cryptography\\Providers | Select-Object -ExpandProperty Name'
            )
            
            if 'Microsoft' in output:
                return ValidationResult(
                    check_name="Windows CNG Support",
                    category="crypto_library",
                    status=CheckStatus.COMPLIANT,
                    details="CNG (Cryptography Next Generation) is available"
                )
            else:
                return ValidationResult(
                    check_name="Windows CNG Support",
                    category="crypto_library",
                    status=CheckStatus.REQUIRES_UPDATE,
                    details="CNG not properly configured"
                )
        except Exception as e:
            self.logger.log_error("cng_check", str(e))
            return ValidationResult(
                check_name="Windows CNG Support",
                category="crypto_library",
                status=CheckStatus.UNKNOWN,
                details=f"Could not verify CNG: {str(e)}"
            )
    
    def _check_bcryptography_dll(self) -> ValidationResult:
        """Check for BCrypt library availability."""
        try:
            # Check Windows\System32 for bcrypt.dll
            bcrypt_path = Path('C:\\Windows\\System32\\bcrypt.dll')
            
            if bcrypt_path.exists():
                # Try to get file version
                output = self._run_powershell(
                    f'[System.Diagnostics.FileVersionInfo]::GetVersionInfo("{bcrypt_path}").FileVersion'
                )
                version = output.strip()
                
                return ValidationResult(
                    check_name="BCrypt Library Check",
                    category="crypto_library",
                    status=CheckStatus.COMPLIANT,
                    details=f"BCrypt.dll available (version: {version})",
                    version=version
                )
            else:
                return ValidationResult(
                    check_name="BCrypt Library Check",
                    category="crypto_library",
                    status=CheckStatus.NOT_FOUND,
                    details="BCrypt.dll not found"
                )
        except Exception as e:
            self.logger.log_error("bcrypt_check", str(e))
            return None
    
    def _check_schannel_protocols(self) -> ValidationResult:
        """Check SChannel (Windows TLS) protocol configuration."""
        try:
            # Check registry for enabled/disabled protocols
            output = self._run_powershell('''
                $protocols = Get-Item -Path "HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols" | 
                    Get-ChildItem | Select-Object -ExpandProperty Name
                $protocols | ForEach-Object { Split-Path $_ -Leaf }
            ''')
            
            protocols = output.strip().split('\n')
            deprecated = ['SSL 2.0', 'SSL 3.0', 'TLS 1.0']
            found_deprecated = [p for p in protocols if any(d in p for d in deprecated)]
            
            if found_deprecated:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"Deprecated protocols detected: {', '.join(found_deprecated)}"
                self.identify_gap(
                    gap_type="deprecated_protocols",
                    severity=SeverityLevel.HIGH,
                    description=f"Windows SChannel has deprecated protocols enabled: {', '.join(found_deprecated)}",
                    component="SChannel/TLS",
                    recommendation="Disable deprecated protocols in Windows Registry",
                    priority=0.9
                )
            else:
                status = CheckStatus.COMPLIANT
                details = "No obviously deprecated protocols detected"
            
            return ValidationResult(
                check_name="SChannel Protocol Configuration",
                category="tls_configuration",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("schannel_check", str(e))
            return None
    
    def validate_certificate_store(self) -> List[ValidationResult]:
        """Validate Windows certificate store."""
        self.logger.general_logger.info("Validating Windows certificate store...")
        
        checks = [
            self._check_certificate_store_health(),
            self._check_weak_root_certificates(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_certificate_store_health(self) -> ValidationResult:
        """Check Windows certificate store accessibility."""
        try:
            # Check if we can access the local machine certificate store
            output = self._run_powershell(
                'Get-ChildItem -Path Cert:\\LocalMachine\\Root | Measure-Object | Select-Object -ExpandProperty Count'
            )
            
            cert_count = int(output.strip())
            
            if cert_count > 0:
                return ValidationResult(
                    check_name="Certificate Store Health",
                    category="certificates",
                    status=CheckStatus.COMPLIANT,
                    details=f"Windows certificate store accessible ({cert_count} root certificates)"
                )
            else:
                return ValidationResult(
                    check_name="Certificate Store Health",
                    category="certificates",
                    status=CheckStatus.UNKNOWN,
                    details="Certificate store appears empty"
                )
        except Exception as e:
            self.logger.log_error("cert_store_check", str(e))
            return None
    
    def _check_weak_root_certificates(self) -> ValidationResult:
        """Check for weak root certificates using deprecated algorithms."""
        try:
            # Get certificates with weak algorithms (SHA1)
            output = self._run_powershell('''
                $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root
                $weak = $certs | Where-Object { $_.SignatureAlgorithm.FriendlyName -match 'sha1|md5|dsa' }
                $weak | Measure-Object | Select-Object -ExpandProperty Count
            ''')
            
            weak_count = int(output.strip())
            
            if weak_count > 0:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"Found {weak_count} root certificates using weak algorithms"
                self.identify_gap(
                    gap_type="weak_root_certificates",
                    severity=SeverityLevel.MEDIUM,
                    description=f"{weak_count} root certificates using weak algorithms",
                    component="Windows Certificate Store",
                    recommendation="Update or remove certificates using weak algorithms",
                    priority=0.7
                )
            else:
                status = CheckStatus.COMPLIANT
                details = "No weak root certificates detected"
            
            return ValidationResult(
                check_name="Root Certificate Algorithm Check",
                category="certificates",
                status=status,
                details=details
            )
        except Exception as e:
            self.logger.log_error("weak_root_cert_check", str(e))
            return None
    
    def validate_openssl_configuration(self) -> List[ValidationResult]:
        """Validate OpenSSL if installed on Windows."""
        self.logger.general_logger.info("Validating OpenSSL configuration (if present)...")
        
        checks = [
            self._check_windows_openssl(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_windows_openssl(self) -> ValidationResult:
        """Check if OpenSSL is installed on Windows."""
        try:
            output = subprocess.check_output(['openssl', 'version'], text=True)
            version_match = re.search(r'OpenSSL (\d+\.\d+\.\d+)', output)
            
            if version_match:
                version = version_match.group(1)
                major, minor, _ = map(int, version.split('.'))
                
                if major >= 3:
                    status = CheckStatus.COMPLIANT
                    details = f"OpenSSL {version} (Windows) - Has PQC support"
                else:
                    status = CheckStatus.REQUIRES_UPDATE
                    details = f"OpenSSL {version} (Windows) - Consider upgrading to 3.x"
                
                return ValidationResult(
                    check_name="Windows OpenSSL Check",
                    category="crypto_library",
                    status=status,
                    details=details,
                    version=version
                )
            else:
                return ValidationResult(
                    check_name="Windows OpenSSL Check",
                    category="crypto_library",
                    status=CheckStatus.UNKNOWN,
                    details="OpenSSL version could not be determined"
                )
        except subprocess.CalledProcessError:
            return ValidationResult(
                check_name="Windows OpenSSL Check",
                category="crypto_library",
                status=CheckStatus.NOT_FOUND,
                details="OpenSSL not installed on Windows"
            )
        except Exception as e:
            self.logger.log_error("windows_openssl_check", str(e))
            return None
    
    def validate_system_algorithms(self) -> List[ValidationResult]:
        """Validate system-wide algorithm usage on Windows."""
        self.logger.general_logger.info("Validating Windows system algorithms...")
        
        checks = [
            self._check_windows_update_status(),
            self._check_bitlocker_encryption(),
        ]
        
        results = [c for c in checks if c]
        for result in results:
            if result:
                self.record_result(result)
        
        return results
    
    def _check_windows_update_status(self) -> ValidationResult:
        """Check Windows Update status for security patches."""
        try:
            # Check if Windows is up to date
            output = self._run_powershell(
                'Get-WmiObject -Query "select * from Win32_QuickFixEngineering" | Measure-Object | Select-Object -ExpandProperty Count'
            )
            
            patch_count = int(output.strip())
            
            if patch_count > 0:
                return ValidationResult(
                    check_name="Windows Security Patches",
                    category="system_security",
                    status=CheckStatus.COMPLIANT,
                    details=f"Windows has {patch_count} security patches installed"
                )
            else:
                return ValidationResult(
                    check_name="Windows Security Patches",
                    category="system_security",
                    status=CheckStatus.REQUIRES_UPDATE,
                    details="No security patches detected - system may be out of date"
                )
        except Exception as e:
            self.logger.log_error("windows_update_check", str(e))
            return None
    
    def _check_bitlocker_encryption(self) -> ValidationResult:
        """Check if BitLocker is enabled for encryption."""
        try:
            output = self._run_powershell(
                'Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty EncryptionPercentage'
            )
            
            if output.strip() == '100':
                return ValidationResult(
                    check_name="BitLocker Encryption",
                    category="encryption",
                    status=CheckStatus.COMPLIANT,
                    details="BitLocker encryption enabled and complete"
                )
            else:
                return ValidationResult(
                    check_name="BitLocker Encryption",
                    category="encryption",
                    status=CheckStatus.REQUIRES_UPDATE,
                    details="BitLocker encryption not fully enabled"
                )
        except Exception as e:
            self.logger.log_error("bitlocker_check", str(e))
            return ValidationResult(
                check_name="BitLocker Encryption",
                category="encryption",
                status=CheckStatus.UNKNOWN,
                details="Could not determine BitLocker status"
            )
