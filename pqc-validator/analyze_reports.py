"""
Utility script to analyze and aggregate PQC validator reports.
Useful for cross-system compliance tracking.
"""

import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict


def aggregate_reports(report_dir: str) -> Dict[str, Any]:
    """
    Aggregate multiple JSON reports for comparative analysis.
    
    Args:
        report_dir: Directory containing compliance reports
    
    Returns:
        Aggregated report data
    """
    report_path = Path(report_dir)
    json_reports = list(report_path.glob('compliance_report_*.json'))
    
    if not json_reports:
        print(f"No reports found in {report_dir}")
        return {}
    
    aggregated = {
        'total_systems': 0,
        'systems': [],
        'total_gaps': 0,
        'gaps_by_severity': defaultdict(int),
        'gaps_by_type': defaultdict(int),
        'gaps_by_component': defaultdict(list),
        'critical_systems': [],
        'compliant_systems': []
    }
    
    for report_file in json_reports:
        try:
            with open(report_file) as f:
                report = json.load(f)
            
            host = report.get('host_info', {})
            summary = report.get('summary', {})
            
            system_info = {
                'hostname': host.get('hostname', 'Unknown'),
                'platform': host.get('platform', 'Unknown'),
                'total_gaps': summary.get('total_gaps', 0),
                'total_checks': summary.get('total_checks', 0),
                'compliance_score': (
                    (summary.get('total_checks', 0) - summary.get('total_gaps', 0)) / 
                    max(1, summary.get('total_checks', 0))
                ) * 100
            }
            
            aggregated['systems'].append(system_info)
            aggregated['total_systems'] += 1
            aggregated['total_gaps'] += summary.get('total_gaps', 0)
            
            # Aggregate severity counts
            for severity, count in summary.get('gaps_by_severity', {}).items():
                aggregated['gaps_by_severity'][severity] += count
            
            # Track critical and compliant systems
            if summary.get('total_gaps', 0) > 0:
                if any(summary.get('gaps_by_severity', {}).get(s, 0) > 0 
                       for s in ['CRITICAL', 'HIGH']):
                    aggregated['critical_systems'].append(system_info)
            else:
                aggregated['compliant_systems'].append(system_info)
            
            # Aggregate gap types
            gaps = report.get('compliance_gaps', {})
            for severity_gaps in gaps.values():
                for gap in severity_gaps:
                    gap_type = gap.get('gap_type', 'unknown')
                    aggregated['gaps_by_type'][gap_type] += 1
                    
                    component = gap.get('affected_component', 'unknown')
                    if component not in aggregated['gaps_by_component']:
                        aggregated['gaps_by_component'][component] = []
                    aggregated['gaps_by_component'][component].append({
                        'gap_type': gap_type,
                        'hostname': system_info['hostname']
                    })
        
        except Exception as e:
            print(f"Error processing {report_file}: {e}")
    
    # Convert defaultdicts to regular dicts for JSON serialization
    aggregated['gaps_by_severity'] = dict(aggregated['gaps_by_severity'])
    aggregated['gaps_by_type'] = dict(aggregated['gaps_by_type'])
    aggregated['gaps_by_component'] = dict(aggregated['gaps_by_component'])
    
    return aggregated


def print_summary(aggregated: Dict[str, Any]):
    """Print a text summary of aggregated reports."""
    print("\n" + "="*70)
    print("PQC COMPLIANCE AGGREGATED REPORT")
    print("="*70)
    
    print(f"\nTotal Systems Scanned: {aggregated['total_systems']}")
    print(f"Total Compliance Gaps: {aggregated['total_gaps']}")
    
    if aggregated['systems']:
        avg_compliance = sum(s['compliance_score'] for s in aggregated['systems']) / len(aggregated['systems'])
        print(f"Average Compliance Score: {avg_compliance:.1f}%")
    
    print("\n--- Systems by Status ---")
    print(f"Compliant: {len(aggregated['compliant_systems'])}")
    print(f"Critical Issues: {len(aggregated['critical_systems'])}")
    
    if aggregated['critical_systems']:
        print("\nCritical Systems:")
        for system in aggregated['critical_systems']:
            print(f"  • {system['hostname']} ({system['platform']}): {system['total_gaps']} gaps")
    
    print("\n--- Gaps by Severity ---")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = aggregated['gaps_by_severity'].get(severity, 0)
        print(f"  {severity}: {count}")
    
    print("\n--- Top Gap Types ---")
    sorted_gaps = sorted(
        aggregated['gaps_by_type'].items(),
        key=lambda x: x[1],
        reverse=True
    )
    for gap_type, count in sorted_gaps[:5]:
        print(f"  {gap_type}: {count}")
    
    print("\n--- Most Affected Components ---")
    sorted_components = sorted(
        [(c, len(v)) for c, v in aggregated['gaps_by_component'].items()],
        key=lambda x: x[1],
        reverse=True
    )
    for component, count in sorted_components[:5]:
        print(f"  {component}: {count}")
    
    print("\n" + "="*70 + "\n")


def export_aggregated_report(aggregated: Dict[str, Any], output_file: str):
    """Export aggregated report to JSON."""
    with open(output_file, 'w') as f:
        json.dump(aggregated, f, indent=2)
    print(f"Aggregated report exported to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze and aggregate PQC validator reports'
    )
    
    parser.add_argument(
        'report_dir',
        help='Directory containing compliance reports'
    )
    
    parser.add_argument(
        '--output',
        help='Export aggregated report to file (JSON)'
    )
    
    args = parser.parse_args()
    
    # Aggregate reports
    aggregated = aggregate_reports(args.report_dir)
    
    if aggregated:
        # Print summary
        print_summary(aggregated)
        
        # Export if requested
        if args.output:
            export_aggregated_report(aggregated, args.output)


if __name__ == '__main__':
    main()
