"""
macOS-specific PQC compliance validator.
Checks for cryptographic frameworks and system crypto configuration.
"""

import subprocess
import re
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
            elif (major, minor, patch) >= (3, 5, 0):
                status = CheckStatus.COMPLIANT
                details = f"OpenSSL {version} - Meets native PQC baseline (3.5.0+)"
            elif major >= 3:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"OpenSSL {version} - Below native PQC baseline; upgrade to 3.5.0+"
            elif major == 1 and minor >= 1:
                status = CheckStatus.REQUIRES_UPDATE
                details = f"OpenSSL {version} - Upgrade to 3.5.0+ for native PQC support"
            else:
                status = CheckStatus.DEPRECATED
                details = f"OpenSSL {version} - Deprecated"
                self.identify_gap(
                    gap_type="deprecated_openssl",
                    severity=SeverityLevel.HIGH,
                    description=f"OpenSSL {version} is deprecated",
                    component="OpenSSL",
                    recommendation="Install OpenSSL 3.5.0+ via Homebrew or MacPorts",
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
            pqc_algorithms = [
                'kyber', 'dilithium', 'falcon', 'sphincs',
                'ml-kem', 'ml-dsa'
            ]
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
        """Inventory weak and quantum-vulnerable certificate algorithms."""
        try:
            root_keychain = Path('/System/Library/Keychains/SystemRootCertificates.keychain')
            if not root_keychain.exists():
                return ValidationResult(
                    check_name="System Certificate Store",
                    category="certificates",
                    status=CheckStatus.NOT_FOUND,
                    details="System root keychain not found"
                )

            pem_bundle = subprocess.check_output(
                ['security', 'find-certificate', '-a', '-p', str(root_keychain)],
                text=True,
                stderr=subprocess.STDOUT
            )
            bundle_text = subprocess.check_output(
                ['openssl', 'crl2pkcs7', '-nocrl', '-certfile', '/dev/stdin'],
                input=pem_bundle,
                text=True,
                stderr=subprocess.STDOUT
            )
            cert_text = subprocess.check_output(
                ['openssl', 'pkcs7', '-print_certs', '-text', '-noout'],
                input=bundle_text,
                text=True,
                stderr=subprocess.STDOUT
            )

            rsa_2048_count = 0
            rsa_3072_count = 0
            ecdsa_p256_count = 0
            ecdsa_p384_count = 0

            cert_blocks = cert_text.split("Certificate:")
            for block in cert_blocks:
                algo_match = re.search(r'Public Key Algorithm:\s*([^\n]+)', block)
                keysize_match = re.search(r'Public-Key:\s*\((\d+) bit\)', block)
                curve_match = re.search(r'ASN1 OID:\s*([^\n]+)', block)
                if not algo_match:
                    continue

                algo_name = algo_match.group(1).strip().lower()
                key_size = int(keysize_match.group(1)) if keysize_match else None
                curve = curve_match.group(1).strip().lower() if curve_match else ""

                if 'rsa' in algo_name and key_size == 2048:
                    rsa_2048_count += 1
                if 'rsa' in algo_name and key_size == 3072:
                    rsa_3072_count += 1
                if ('id-ecpublickey' in algo_name or 'ecdsa' in algo_name) and curve == 'prime256v1':
                    ecdsa_p256_count += 1
                if ('id-ecpublickey' in algo_name or 'ecdsa' in algo_name) and curve == 'secp384r1':
                    ecdsa_p384_count += 1

            weak_sig_count = len(re.findall(r'Signature Algorithm:\s*(?:sha1|md5|dsa)', cert_text, flags=re.IGNORECASE))

            issues = []
            if rsa_2048_count > 0:
                issues.append(f"{rsa_2048_count} RSA-2048 root certificates")
                self.identify_gap(
                    gap_type="rsa_2048_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"Detected {rsa_2048_count} RSA-2048 root certificates in trust store",
                    component="macOS System Root Keychain",
                    recommendation="Prioritize migration from RSA-2048 trust anchors to quantum-resistant alternatives per policy",
                    priority=0.9
                )

            if rsa_3072_count > 0:
                issues.append(f"{rsa_3072_count} RSA-3072 root certificates")
                self.identify_gap(
                    gap_type="rsa_3072_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"Detected {rsa_3072_count} RSA-3072 root certificates in trust store",
                    component="macOS System Root Keychain",
                    recommendation="Plan migration from RSA-3072 trust anchors to quantum-resistant alternatives",
                    priority=0.8
                )

            if ecdsa_p256_count > 0:
                issues.append(f"{ecdsa_p256_count} ECDSA P-256 root certificates")
                self.identify_gap(
                    gap_type="ecdsa_p256_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"Detected {ecdsa_p256_count} ECDSA P-256 root certificates in trust store",
                    component="macOS System Root Keychain",
                    recommendation="Prioritize migration from ECDSA P-256 trust anchors to quantum-resistant alternatives",
                    priority=0.8
                )

            if ecdsa_p384_count > 0:
                issues.append(f"{ecdsa_p384_count} ECDSA P-384 root certificates")
                self.identify_gap(
                    gap_type="ecdsa_p384_certificates",
                    severity=SeverityLevel.HIGH,
                    description=f"Detected {ecdsa_p384_count} ECDSA P-384 root certificates in trust store",
                    component="macOS System Root Keychain",
                    recommendation="Prioritize migration from ECDSA P-384 trust anchors to quantum-resistant alternatives",
                    priority=0.75
                )

            if weak_sig_count > 0:
                issues.append(f"{weak_sig_count} weak-signature certificates (SHA1/MD5/DSA)")
                self.identify_gap(
                    gap_type="weak_root_certificates",
                    severity=SeverityLevel.MEDIUM,
                    description=f"Detected {weak_sig_count} root certificates using weak signature algorithms",
                    component="macOS System Root Keychain",
                    recommendation="Remove or replace certificates signed with SHA1/MD5/DSA",
                    priority=0.7
                )

            if issues:
                status = CheckStatus.REQUIRES_UPDATE
                details = "; ".join(issues)
            else:
                status = CheckStatus.COMPLIANT
                details = "No weak signatures or quantum-vulnerable root certificates detected"

            return ValidationResult(
                check_name="System Certificate Store",
                category="certificates",
                status=status,
                details=details
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
            self._check_quantum_vulnerable_ssh_keys(),
            self._check_quantum_vulnerable_tls_endpoints(),
            self._check_sp800_208_firmware_signing(),
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

    def _check_quantum_vulnerable_ssh_keys(self) -> ValidationResult:
        """Inventory RSA/ECDSA host and user SSH keys vulnerable to quantum attacks."""
        key_files = set()
        key_files.update(Path('/etc/ssh').glob('ssh_host_*_key.pub'))
        key_files.update(Path.home().joinpath('.ssh').glob('*.pub'))
        key_files.update(Path('/Users').glob('*/.ssh/*.pub'))

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
            Path('/etc/pqc/firmware-signing.json'),
            Path('/etc/pqc/firmware_signing.json'),
            Path('/Library/Application Support/pqc-validator/firmware-signing.json'),
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
