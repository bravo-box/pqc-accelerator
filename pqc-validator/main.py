"""
Main entry point for PQC compliance validator.
Orchestrates validation across platforms and generates reports.
"""

import sys
import platform as sys_platform
import argparse
from typing import Optional

from src.common.logger import PQCLogger
from src.validators.linux.validator import LinuxValidator
from src.validators.windows.validator import WindowsValidator
from src.validators.macos.validator import MacOSValidator
from src.reporting.report_generator import ReportGenerator
from src.integrations.azure_monitor import sink_from_env, AzureMonitorSink


def get_sink():
    """
    Build the Azure Monitor sink using managed identity Logs Ingestion.
    Returns None when DCR/DCE environment variables are not configured.
    """
    return sink_from_env()


def get_validator_for_platform(logger: PQCLogger):
    """
    Get the appropriate validator for the current platform.
    
    Returns:
        Platform-specific validator instance
    """
    system = sys_platform.system()
    
    if system == "Linux":
        return LinuxValidator(logger)
    elif system == "Windows":
        return WindowsValidator(logger)
    elif system == "Darwin":  # macOS
        return MacOSValidator(logger)
    else:
        raise Exception(f"Unsupported platform: {system}")


def run_validation(
    log_dir: str = "logs",
    report_dir: str = "reports",
    generate_reports: bool = True,
    verbose: bool = False,
    azure_sink: Optional[AzureMonitorSink] = None
) -> dict:
    """
    Run full PQC compliance validation.

    Args:
        log_dir:          Directory for logs
        report_dir:       Directory for reports
        generate_reports: Whether to generate reports after validation
        verbose:          Verbose output
        azure_sink:       Optional Azure Monitor sink — when provided all results
                          are streamed to Log Analytics in real time via Managed Identity.
                          If None, checks environment variables PQC_DCE_ENDPOINT and
                          PQC_DCR_IMMUTABLE_ID and auto-configures if present.
    """
    # Auto-detect Azure Monitor config from environment if not explicitly passed
    if azure_sink is None:
        azure_sink = get_sink()
        if azure_sink:
            print("Azure Monitor sink configured — streaming to Log Analytics.")

    # Initialize logger
    logger = PQCLogger(log_dir, azure_sink=azure_sink)
    
    print(f"PQC Compliance Validator")
    print(f"Platform: {sys_platform.system()}")
    print(f"Log Directory: {log_dir}")
    print("-" * 60)
    
    # Get platform-specific validator
    validator = get_validator_for_platform(logger)
    
    # Run validation
    print("Starting compliance validation...")
    summary = validator.run_full_validation()
    
    # Print summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total Checks: {summary['total_checks']}")
    print(f"Compliant: {summary['compliant_checks']}")
    print(f"Non-Compliant: {summary['non_compliant_checks']}")
    print(f"Total Gaps: {summary['total_gaps']}")
    
    if summary.get('gaps_by_severity'):
        print("\nGaps by Severity:")
        for severity, count in summary['gaps_by_severity'].items():
            print(f"  {severity}: {count}")
    
    print(f"\nLog files generated:")
    for name, path in logger.get_log_files().items():
        print(f"  {name}: {path}")

    # Flush any remaining buffered records to Azure Monitor
    azure_flush_ok = logger.flush_azure()
    if azure_sink:
        if azure_flush_ok:
            print("  azure_monitor: streamed to Log Analytics (Log Analytics Workspace)")
        else:
            print("  azure_monitor: upload failed (check Managed Identity/token access)")

    # Generate reports
    if generate_reports:
        print("\n" + "=" * 60)
        print("GENERATING REPORTS")
        print("=" * 60)
        
        report_gen = ReportGenerator(log_dir, report_dir)
        reports = report_gen.generate_all_reports()
        
        for report_type, report_path in reports.items():
            print(f"✓ {report_type.upper()} Report: {report_path}")
        
        summary['reports'] = reports
    
    print("\n" + "=" * 60)
    print("Validation complete!")
    
    return summary


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Post-Quantum Cryptography Compliance Validator'
    )
    
    parser.add_argument(
        '--log-dir',
        default='logs',
        help='Directory for validation logs (default: logs)'
    )
    
    parser.add_argument(
        '--report-dir',
        default='reports',
        help='Directory for generated reports (default: reports)'
    )
    
    parser.add_argument(
        '--no-reports',
        action='store_true',
        help='Skip report generation'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    try:
        summary = run_validation(
            log_dir=args.log_dir,
            report_dir=args.report_dir,
            generate_reports=not args.no_reports,
            verbose=args.verbose
        )
        
        # Return appropriate exit code
        if summary['total_gaps'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
