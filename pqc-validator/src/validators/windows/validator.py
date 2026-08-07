"""
Windows-specific PQC compliance validator.
Checks for CNG, cryptography APIs, PQC algorithm availability,
and Windows crypto configuration.
"""

import subprocess
import re
import yaml
import json
import os
import socket
import ssl
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
        self.pqc_requirements = self._load_pqc_requirements()
        self.system_info = self._gather_system_info()

    def _load_pqc_requirements(self) -> Dict[str, Any]:
        """Load PQC requirements from config file when available."""
        try:
            requirements_path = Path(__file__).resolve().parents[3] / 'config' / 'pqc_requirements.yaml'
            if requirements_path.exists():
                with open(requirements_path, 'r', encoding='utf-8') as req_file:
                    data = yaml.safe_load(req_file) or {}
                    return data.get('pqc_requirements', {})
        except Exception as e:
            self.logger.log_error("pqc_requirements_load", str(e))
        return {}

    def _normalize_pqc_algorithm_name(self, algo_name: str) -> str:
        """Normalize PQC algorithm aliases to canonical names for comparison."""
        normalized = algo_name.strip().lower().replace('_', '-').replace(' ', '-')
        alias_map = {
            'kyber-512': 'ml-kem-512',
            'kyber512': 'ml-kem-512',
            'ml-kem-512': 'ml-kem-512',
            'kyber-768': 'ml-kem-768',
            'kyber768': 'ml-kem-768',
            'ml-kem-768': 'ml-kem-768',
            'kyber-1024': 'ml-kem-1024',
            'kyber1024': 'ml-kem-1024',
            'ml-kem-1024': 'ml-kem-1024',
            'dilithium2': 'ml-dsa-44',
            'dilithium-2': 'ml-dsa-44',
            'ml-dsa-44': 'ml-dsa-44',
            'dilithium3': 'ml-dsa-65',
            'dilithium-3': 'ml-dsa-65',
            'ml-dsa-65': 'ml-dsa-65',
            'dilithium5': 'ml-dsa-87',
            'dilithium-5': 'ml-dsa-87',
            'ml-dsa-87': 'ml-dsa-87',
        }
        return alias_map.get(normalized, normalized)

    def _get_required_pqc_algorithms(self) -> List[str]:
        """Return required PQC algorithms from config or secure defaults."""
        reqs = self.pqc_requirements.get('required_pqc_algorithms', {})
        kem = reqs.get('key_encapsulation', [])
        sig = reqs.get('digital_signature', [])
        required = kem + sig

        if not required:
            required = [
                'ml-kem-512',
                'ml-kem-768',
                'ml-kem-1024',
                'ml-dsa-44',
                'ml-dsa-65',
                'ml-dsa-87',
            ]

        return sorted({self._normalize_pqc_algorithm_name(name) for name in required})

    def _extract_detected_pqc_algorithms(self, raw_output: str) -> List[str]:
        """Extract detected PQC algorithms from command output."""
        output = raw_output.lower()
        candidate_aliases = [
            'ml-kem-512', 'ml-kem-768', 'ml-kem-1024',
            'kyber-512', 'kyber-768', 'kyber-1024',
            'kyber512', 'kyber768', 'kyber1024',
            'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87',
            'dilithium2', 'dilithium3', 'dilithium5',
            'dilithium-2', 'dilithium-3', 'dilithium-5',
        ]

        detected = {
            self._normalize_pqc_algorithm_name(alias)
            for alias in candidate_aliases
            if alias in output
        }
        return sorted(detected)

    def _collect_windows_pqc_algorithms(self) -> Dict[str, List[str]]:
        """Collect PQC algorithms from available Windows crypto stacks."""
        detected: Dict[str, List[str]] = {}

        # OpenSSL may expose PQC algorithm names when using OQS or recent providers.
        openssl_commands = [
            ['openssl', 'list', '-public-key-algorithms'],
            ['openssl', 'list', '-kem-algorithms'],
            ['openssl', 'list', '-signature-algorithms'],
        ]
        for cmd in openssl_commands:
            try:
                output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
                found = self._extract_detected_pqc_algorithms(output)
                if found:
                    detected[f"openssl:{' '.join(cmd[2:])}"] = found
            except Exception:
                continue

        # CNG algorithm list is available on systems with newer PKI cmdlets.
        try:
            cng_output = self._run_powershell('''
                if (Get-Command Get-CngAlgorithm -ErrorAction SilentlyContinue) {
                    Get-CngAlgorithm | Select-Object -ExpandProperty Name
                }
            ''')
            cng_found = self._extract_detected_pqc_algorithms(cng_output)
            if cng_found:
                detected['cng'] = cng_found
        except Exception:
            pass

        # certutil can expose available providers and OIDs on many Windows builds.
        try:
            certutil_output = subprocess.check_output(
                ['certutil', '-csplist'],
                text=True,
                stderr=subprocess.STDOUT
            )
            certutil_found = self._extract_detected_pqc_algorithms(certutil_output)
            if certutil_found:
                detected['certutil'] = certutil_found
        except Exception:
            pass

        return detected
    
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
            self._check_cng_pqc_algorithm_enumeration(),
            self._check_bcryptography_dll(),
            self._check_windows_pqc_algorithms(),
            self._check_schannel_protocols(),
            self._check_schannel_pq_cipher_suites(),
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

    def _check_cng_pqc_algorithm_enumeration(self) -> ValidationResult:
        """Enumerate CNG algorithms and detect ML-KEM/ML-DSA aliases."""
        try:
            output = self._run_powershell('''
                if (Get-Command Get-CngAlgorithm -ErrorAction SilentlyContinue) {
                    Get-CngAlgorithm | Select-Object -ExpandProperty Name
                }
            ''')

            if not output.strip():
                return ValidationResult(
                    check_name="Windows CNG PQC Algorithm Enumeration",
                    category="crypto_algorithms",
                    status=CheckStatus.UNKNOWN,
                    details="Get-CngAlgorithm is unavailable or returned no algorithms"
                )

            detected = self._extract_detected_pqc_algorithms(output)
            if detected:
                return ValidationResult(
                    check_name="Windows CNG PQC Algorithm Enumeration",
                    category="crypto_algorithms",
                    status=CheckStatus.COMPLIANT,
                    details=f"CNG algorithm inventory includes PQC aliases: {', '.join(detected)}"
                )

            self.identify_gap(
                gap_type="cng_no_pqc_algorithms",
                severity=SeverityLevel.HIGH,
                description="CNG algorithm enumeration found no ML-KEM/ML-DSA or Kyber/Dilithium aliases",
                component="Windows CNG",
                recommendation="Install/enable CNG providers that expose ML-KEM/ML-DSA algorithms",
                priority=0.9
            )
            return ValidationResult(
                check_name="Windows CNG PQC Algorithm Enumeration",
                category="crypto_algorithms",
                status=CheckStatus.REQUIRES_UPDATE,
                details="CNG algorithm inventory found no detectable PQC aliases"
            )
        except Exception as e:
            self.logger.log_error("cng_pqc_enumeration", str(e))
            return ValidationResult(
                check_name="Windows CNG PQC Algorithm Enumeration",
                category="crypto_algorithms",
                status=CheckStatus.UNKNOWN,
                details=f"Could not enumerate CNG algorithms: {str(e)}"
            )

    def _check_windows_pqc_algorithms(self) -> ValidationResult:
        """Check for required PQC algorithms on Windows crypto stacks."""
        required = self._get_required_pqc_algorithms()
        sources = self._collect_windows_pqc_algorithms()

        detected = sorted({algo for values in sources.values() for algo in values})
        missing = [algo for algo in required if algo not in detected]

        if not detected:
            status = CheckStatus.DEPRECATED
            details = (
                "No PQC algorithms detected (ML-KEM/ML-DSA or Kyber/Dilithium aliases) "
                "in OpenSSL, CNG, or certutil outputs"
            )
            self.identify_gap(
                gap_type="no_pqc_algorithms",
                severity=SeverityLevel.HIGH,
                description="Windows host does not expose detectable PQC algorithms",
                component="Windows Cryptography Stack",
                recommendation="Install or enable crypto providers exposing ML-KEM/ML-DSA support",
                priority=0.95
            )
        elif missing:
            status = CheckStatus.REQUIRES_UPDATE
            details = (
                f"Detected PQC algorithms: {', '.join(detected)}; "
                f"missing required: {', '.join(missing)}"
            )
            self.identify_gap(
                gap_type="no_pqc_algorithms",
                severity=SeverityLevel.HIGH,
                description=f"Windows host is missing required PQC algorithms: {', '.join(missing)}",
                component="Windows Cryptography Stack",
                recommendation="Enable/install providers that add the missing ML-KEM/ML-DSA algorithms",
                priority=0.9
            )
        else:
            status = CheckStatus.COMPLIANT
            details = f"Detected required PQC algorithms: {', '.join(detected)}"

        source_summary = (
            "; sources=" + ", ".join(sorted(sources.keys()))
            if sources else
            "; sources=none"
        )

        return ValidationResult(
            check_name="Windows PQC Algorithm Detection",
            category="crypto_algorithms",
            status=status,
            details=details + source_summary
        )
    
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

    def _check_schannel_pq_cipher_suites(self) -> ValidationResult:
        """Detect Schannel cipher suites that appear to provide PQC/hybrid key exchange."""
        try:
            output = self._run_powershell('''
                if (Get-Command Get-TlsCipherSuite -ErrorAction SilentlyContinue) {
                    Get-TlsCipherSuite | Select-Object -ExpandProperty Name
                }
            ''')

            if not output.strip():
                return ValidationResult(
                    check_name="SChannel Post-Quantum Cipher Suite Detection",
                    category="tls_configuration",
                    status=CheckStatus.UNKNOWN,
                    details="Get-TlsCipherSuite is unavailable or returned no suites"
                )

            suites = [line.strip() for line in output.splitlines() if line.strip()]
            pq_patterns = ['MLKEM', 'KYBER', 'KEM', 'HYBRID', 'PQ']
            pq_suites = [suite for suite in suites if any(p in suite.upper() for p in pq_patterns)]

            if pq_suites:
                return ValidationResult(
                    check_name="SChannel Post-Quantum Cipher Suite Detection",
                    category="tls_configuration",
                    status=CheckStatus.COMPLIANT,
                    details=f"Detected Schannel PQ/hybrid suites: {', '.join(pq_suites[:8])}"
                )

            self.identify_gap(
                gap_type="schannel_no_pq_cipher_suites",
                severity=SeverityLevel.HIGH,
                description="No Schannel post-quantum or hybrid cipher suites detected",
                component="Windows SChannel",
                recommendation="Enable Schannel builds/policies that expose post-quantum or hybrid cipher suites",
                priority=0.9
            )
            return ValidationResult(
                check_name="SChannel Post-Quantum Cipher Suite Detection",
                category="tls_configuration",
                status=CheckStatus.REQUIRES_UPDATE,
                details="No Schannel PQ/hybrid cipher suites detected"
            )
        except Exception as e:
            self.logger.log_error("schannel_pq_suites", str(e))
            return ValidationResult(
                check_name="SChannel Post-Quantum Cipher Suite Detection",
                category="tls_configuration",
                status=CheckStatus.UNKNOWN,
                details=f"Could not enumerate Schannel cipher suites: {str(e)}"
            )
    
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
        """Inventory weak and quantum-vulnerable root certificate algorithms."""
        try:
            # Weak signature roots
            output = self._run_powershell('''
                $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root
                $weak = $certs | Where-Object { $_.SignatureAlgorithm.FriendlyName -match 'sha1|md5|dsa' }
                $weak | Measure-Object | Select-Object -ExpandProperty Count
            ''')
            
            weak_count = int(output.strip())

            # RSA-2048 roots (quantum migration exposure)
            rsa_output = self._run_powershell('''
                $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root
                $rsa2048 = $certs | Where-Object {
                    $_.PublicKey -and
                    $_.PublicKey.Oid -and
                    $_.PublicKey.Oid.FriendlyName -match 'RSA' -and
                    $_.PublicKey.Key -and
                    $_.PublicKey.Key.KeySize -eq 2048
                }
                $rsa2048 | Measure-Object | Select-Object -ExpandProperty Count
            ''')

            rsa3072_output = self._run_powershell('''
                $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root
                $rsa3072 = $certs | Where-Object {
                    $_.PublicKey -and
                    $_.PublicKey.Oid -and
                    $_.PublicKey.Oid.FriendlyName -match 'RSA' -and
                    $_.PublicKey.Key -and
                    $_.PublicKey.Key.KeySize -eq 3072
                }
                $rsa3072 | Measure-Object | Select-Object -ExpandProperty Count
            ''')

            ecdsa_p256_output = self._run_powershell('''
                $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root
                $p256 = $certs | Where-Object {
                    $_.PublicKey -and
                    $_.PublicKey.Oid -and
                    $_.PublicKey.Oid.FriendlyName -match 'ECC|ECDSA' -and
                    $_.PublicKey.Key -and
                    $_.PublicKey.Key.KeySize -eq 256
                }
                $p256 | Measure-Object | Select-Object -ExpandProperty Count
            ''')

            ecdsa_p384_output = self._run_powershell('''
                $certs = Get-ChildItem -Path Cert:\\LocalMachine\\Root
                $p384 = $certs | Where-Object {
                    $_.PublicKey -and
                    $_.PublicKey.Oid -and
                    $_.PublicKey.Oid.FriendlyName -match 'ECC|ECDSA' -and
                    $_.PublicKey.Key -and
                    $_.PublicKey.Key.KeySize -eq 384
                }
                $p384 | Measure-Object | Select-Object -ExpandProperty Count
            ''')

            rsa_2048_count = int(rsa_output.strip())
            rsa_3072_count = int(rsa3072_output.strip())
            ecdsa_p256_count = int(ecdsa_p256_output.strip())
            ecdsa_p384_count = int(ecdsa_p384_output.strip())
            issues = []
            
            if weak_count > 0:
                issues.append(f"{weak_count} weak-signature root certificates (SHA1/MD5/DSA)")
                self.identify_gap(
                    gap_type="weak_root_certificates",
                    severity=SeverityLevel.MEDIUM,
                    description=f"{weak_count} root certificates using weak algorithms",
                    component="Windows Certificate Store",
                    recommendation="Update or remove certificates using weak algorithms",
                    priority=0.7
                )

            if rsa_2048_count > 0:
                issues.append(f"{rsa_2048_count} RSA-2048 root certificates")
                self.identify_gap(
                    gap_type="rsa_2048_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"{rsa_2048_count} root certificates use RSA-2048 keys",
                    component="Windows Certificate Store",
                    recommendation="Prioritize migration from RSA-2048 trust anchors to quantum-resistant alternatives per policy",
                    priority=0.9
                )

            if rsa_3072_count > 0:
                issues.append(f"{rsa_3072_count} RSA-3072 root certificates")
                self.identify_gap(
                    gap_type="rsa_3072_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"{rsa_3072_count} root certificates use RSA-3072 keys",
                    component="Windows Certificate Store",
                    recommendation="Plan migration from RSA-3072 trust anchors to quantum-resistant alternatives",
                    priority=0.8
                )

            if ecdsa_p256_count > 0:
                issues.append(f"{ecdsa_p256_count} ECDSA P-256 root certificates")
                self.identify_gap(
                    gap_type="ecdsa_p256_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"{ecdsa_p256_count} root certificates use ECDSA P-256 keys",
                    component="Windows Certificate Store",
                    recommendation="Prioritize migration from ECDSA P-256 trust anchors to quantum-resistant alternatives",
                    priority=0.8
                )

            if ecdsa_p384_count > 0:
                issues.append(f"{ecdsa_p384_count} ECDSA P-384 root certificates")
                self.identify_gap(
                    gap_type="ecdsa_p384_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"{ecdsa_p384_count} root certificates use ECDSA P-384 keys",
                    component="Windows Certificate Store",
                    recommendation="Prioritize migration from ECDSA P-384 trust anchors to quantum-resistant alternatives",
                    priority=0.75
                )

            if issues:
                status = CheckStatus.REQUIRES_UPDATE
                details = "; ".join(issues)
            else:
                status = CheckStatus.COMPLIANT
                details = "No weak signatures or quantum-vulnerable root certificates detected"
            
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
                major, minor, patch = map(int, version.split('.'))
                
                if (major, minor, patch) >= (3, 5, 0):
                    status = CheckStatus.COMPLIANT
                    details = f"OpenSSL {version} (Windows) - Meets native PQC baseline (3.5.0+)"
                elif major >= 3:
                    status = CheckStatus.REQUIRES_UPDATE
                    details = f"OpenSSL {version} (Windows) - Below native PQC baseline; upgrade to 3.5.0+"
                else:
                    status = CheckStatus.REQUIRES_UPDATE
                    details = f"OpenSSL {version} (Windows) - Upgrade to 3.5.0+ for native PQC support"
                
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
            self._check_quantum_vulnerable_ssh_keys(),
            self._check_quantum_vulnerable_tls_endpoints(),
            self._check_sp800_208_firmware_signing(),
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

    def _check_quantum_vulnerable_ssh_keys(self) -> ValidationResult:
        """Inventory RSA/ECDSA host and user SSH keys vulnerable to quantum attacks."""
        key_files = set()
        key_files.update(Path('C:/ProgramData/ssh').glob('*.pub'))
        key_files.update(Path.home().joinpath('.ssh').glob('*.pub'))
        key_files.update(Path('C:/Users').glob('*/.ssh/*.pub'))

        if not key_files:
            return ValidationResult(
                check_name="SSH Quantum-Vulnerable Key Inventory",
                category="ssh",
                status=CheckStatus.UNKNOWN,
                details="No SSH host/user public keys found for inventory"
            )

        rsa_2048 = 0
        rsa_3072 = 0
        ecdsa_p256 = 0
        ecdsa_p384 = 0

        for key_path in sorted(key_files):
            try:
                content = key_path.read_text(encoding='utf-8', errors='ignore').strip().lower()
                first_token = content.split()[0] if content else ''
                if first_token == 'ssh-rsa':
                    try:
                        out = subprocess.check_output(['ssh-keygen', '-lf', str(key_path)], text=True, stderr=subprocess.STDOUT)
                        bits = int(out.split()[0])
                        if bits == 2048:
                            rsa_2048 += 1
                        elif bits == 3072:
                            rsa_3072 += 1
                    except Exception:
                        continue
                elif first_token.startswith('ecdsa-sha2-'):
                    if 'nistp256' in first_token:
                        ecdsa_p256 += 1
                    elif 'nistp384' in first_token:
                        ecdsa_p384 += 1
            except Exception:
                continue

        issues = []
        if rsa_2048:
            issues.append(f"{rsa_2048} RSA-2048 keys")
        if rsa_3072:
            issues.append(f"{rsa_3072} RSA-3072 keys")
        if ecdsa_p256:
            issues.append(f"{ecdsa_p256} ECDSA P-256 keys")
        if ecdsa_p384:
            issues.append(f"{ecdsa_p384} ECDSA P-384 keys")

        if issues:
            details = f"Quantum-vulnerable SSH keys detected across host/user inventory: {', '.join(issues)}"
            self.identify_gap(
                gap_type="quantum_vulnerable_ssh_keys",
                severity=SeverityLevel.HIGH,
                description=details,
                component="SSH Host/User Keys",
                recommendation="Rotate SSH keys to quantum-resistant or approved hybrid key types",
                priority=0.9
            )
            return ValidationResult(
                check_name="SSH Quantum-Vulnerable Key Inventory",
                category="ssh",
                status=CheckStatus.REQUIRES_UPDATE,
                details=details
            )

        return ValidationResult(
            check_name="SSH Quantum-Vulnerable Key Inventory",
            category="ssh",
            status=CheckStatus.COMPLIANT,
            details=f"No RSA-2048/3072 or ECDSA P-256/P-384 keys detected across {len(key_files)} SSH key files"
        )

    def _check_quantum_vulnerable_tls_endpoints(self) -> ValidationResult:
        """Inventory quantum-vulnerable key algorithms from configured/local TLS endpoints."""
        configured = os.environ.get('PQC_TLS_ENDPOINTS', '')
        endpoints = []
        if configured:
            for item in configured.split(','):
                item = item.strip()
                if not item:
                    continue
                host, _, port = item.partition(':')
                if host and port.isdigit():
                    endpoints.append((host, int(port)))
        else:
            for port in (443, 8443, 9443):
                endpoints.append(('localhost', port))

        vulnerable = []
        reachable = 0

        for host, port in endpoints:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=2.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                        reachable += 1
                        der = tls_sock.getpeercert(binary_form=True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                cert_text = subprocess.check_output(
                    ['openssl', 'x509', '-noout', '-text'],
                    input=pem,
                    text=True,
                    stderr=subprocess.STDOUT
                )
                algo_match = re.search(r'Public Key Algorithm:\s*([^\n]+)', cert_text)
                keysize_match = re.search(r'Public-Key:\s*\((\d+) bit\)', cert_text)
                curve_match = re.search(r'ASN1 OID:\s*([^\n]+)', cert_text)
                algo_name = algo_match.group(1).strip().lower() if algo_match else ''
                key_size = int(keysize_match.group(1)) if keysize_match else None
                curve = curve_match.group(1).strip().lower() if curve_match else ''

                if ('rsa' in algo_name and key_size in (2048, 3072)) or (
                    ('id-ecpublickey' in algo_name or 'ecdsa' in algo_name)
                    and curve in ('prime256v1', 'secp384r1')
                ):
                    vulnerable.append(f"{host}:{port}")
            except Exception:
                continue

        if reachable == 0:
            return ValidationResult(
                check_name="TLS Endpoint Quantum-Vulnerable Inventory",
                category="tls_configuration",
                status=CheckStatus.UNKNOWN,
                details="No reachable TLS endpoints for inventory; set PQC_TLS_ENDPOINTS for explicit endpoint coverage"
            )

        if vulnerable:
            details = f"Quantum-vulnerable TLS endpoint certificates detected: {', '.join(vulnerable)}"
            self.identify_gap(
                gap_type="quantum_vulnerable_tls_endpoints",
                severity=SeverityLevel.HIGH,
                description=details,
                component="TLS Endpoints",
                recommendation="Replace endpoint certificates that use RSA-2048/3072 or ECDSA P-256/P-384 with quantum-resistant alternatives",
                priority=0.9
            )
            return ValidationResult(
                check_name="TLS Endpoint Quantum-Vulnerable Inventory",
                category="tls_configuration",
                status=CheckStatus.REQUIRES_UPDATE,
                details=details
            )

        return ValidationResult(
            check_name="TLS Endpoint Quantum-Vulnerable Inventory",
            category="tls_configuration",
            status=CheckStatus.COMPLIANT,
            details=f"No quantum-vulnerable endpoint certificates detected across {reachable} reachable TLS endpoints"
        )

    def _check_sp800_208_firmware_signing(self) -> ValidationResult:
        """Verify LMS/XMSS firmware-signing evidence for SP 800-208."""
        manifest_paths = []
        env_paths = os.environ.get('PQC_FIRMWARE_MANIFEST', '').strip()
        if env_paths:
            manifest_paths.extend(Path(p) for p in env_paths.split(os.pathsep) if p)
        manifest_paths.extend([
            Path('C:/ProgramData/pqc-validator/firmware-signing.json'),
            Path('C:/ProgramData/pqc-validator/firmware_signing.json'),
            Path('C:/pqc-validator/config/firmware-signing.json'),
        ])

        found_manifest = None
        evidence_text = ""
        for manifest in manifest_paths:
            if not manifest.exists():
                continue
            found_manifest = manifest
            raw = ""
            try:
                raw = manifest.read_text(encoding='utf-8', errors='ignore')
                if manifest.suffix.lower() == '.json':
                    evidence_text = json.dumps(json.loads(raw)).lower()
                else:
                    evidence_text = raw.lower()
                break
            except Exception:
                evidence_text = raw.lower()
                break

        has_lms_or_xmss = ('lms' in evidence_text) or ('xmss' in evidence_text)
        if has_lms_or_xmss:
            return ValidationResult(
                check_name="SP 800-208 Firmware Signing Check",
                category="compliance",
                status=CheckStatus.COMPLIANT,
                details=f"Firmware-signing evidence includes LMS/XMSS in {found_manifest}"
            )

        details = (
            "No LMS/XMSS firmware-signing evidence found"
            if not found_manifest
            else f"Firmware manifest found at {found_manifest}, but no LMS/XMSS algorithms declared"
        )
        self.identify_gap(
            gap_type="missing_sp800_208_firmware_signing",
            severity=SeverityLevel.HIGH,
            description=details,
            component="Firmware Signing",
            recommendation="Adopt LMS/XMSS firmware-signing controls and record evidence in PQC_FIRMWARE_MANIFEST",
            priority=0.9
        )
        return ValidationResult(
            check_name="SP 800-208 Firmware Signing Check",
            category="compliance",
            status=CheckStatus.REQUIRES_UPDATE,
            details=details
        )
