"""
Report generation from validation logs and scan results.
Generates HTML, JSON, and CSV reports for compliance tracking.
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from collections import defaultdict


class ReportGenerator:
    """Generate compliance reports from validation logs."""
    
    def __init__(self, log_dir: str = "logs", report_dir: str = "reports"):
        """
        Initialize report generator.
        
        Args:
            log_dir: Directory containing JSONL logs
            report_dir: Directory where reports will be written
        """
        self.log_dir = Path(log_dir)
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.scan_file = self.log_dir / "scans.jsonl"
    
    def load_scan_data(self) -> List[Dict[str, Any]]:
        """Load all scan records from JSONL file."""
        records = []
        
        if not self.scan_file.exists():
            return records
        
        try:
            with open(self.scan_file, 'r') as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))
        except Exception as e:
            print(f"Error loading scan data: {e}")
        
        return records
    
    def analyze_compliance_gaps(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze and categorize compliance gaps."""
        gaps_by_type = defaultdict(list)
        gaps_by_severity = defaultdict(list)
        gaps_by_component = defaultdict(list)
        
        for record in records:
            if record.get('type') == 'compliance_gap':
                gap_type = record.get('gap_type', 'unknown')
                severity = record.get('severity', 'unknown')
                component = record.get('affected_component', 'unknown')
                
                gaps_by_type[gap_type].append(record)
                gaps_by_severity[severity].append(record)
                gaps_by_component[component].append(record)
        
        return {
            'by_type': dict(gaps_by_type),
            'by_severity': dict(gaps_by_severity),
            'by_component': dict(gaps_by_component),
            'total': sum(len(v) for v in gaps_by_type.values())
        }
    
    def analyze_checks(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze validation check results."""
        checks = [r for r in records if r.get('type') != 'compliance_gap' and r.get('type') != 'error']
        
        by_status = defaultdict(int)
        by_category = defaultdict(int)
        
        for check in checks:
            if 'result' in check and 'status' in check['result']:
                status = check['result'].get('status', 'unknown')
                by_status[status] += 1
            
            if 'result' in check and 'category' in check['result']:
                category = check['result'].get('category', 'unknown')
                by_category[category] += 1
        
        return {
            'by_status': dict(by_status),
            'by_category': dict(by_category),
            'total_checks': len(checks)
        }
    
    def generate_json_report(self) -> str:
        """Generate comprehensive JSON report."""
        records = self.load_scan_data()
        
        gaps = self.analyze_compliance_gaps(records)
        checks = self.analyze_checks(records)
        
        # Extract host info from first record
        host_info = {}
        for record in records:
            if 'host_info' in record:
                host_info = record['host_info']
                break
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'host_info': host_info,
            'summary': {
                'total_checks': checks.get('total_checks', 0),
                'total_gaps': gaps.get('total', 0),
                'checks_by_status': checks.get('by_status', {}),
                'gaps_by_severity': {
                    severity: len(items) 
                    for severity, items in gaps.get('by_severity', {}).items()
                }
            },
            'compliance_gaps': gaps.get('by_severity', {}),
            'checks_by_category': checks.get('by_category', {}),
            'raw_records': records
        }
        
        # Write report
        report_file = self.report_dir / f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return str(report_file)
    
    def generate_html_report(self) -> str:
        """Generate HTML report for visualization."""
        records = self.load_scan_data()
        gaps = self.analyze_compliance_gaps(records)
        checks = self.analyze_checks(records)
        
        # Extract host info
        host_info = {}
        for record in records:
            if 'host_info' in record:
                host_info = record['host_info']
                break
        
        # Build HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PQC Compliance Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .card {{
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            margin-top: 0;
            color: #2c3e50;
        }}
        .critical {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .high {{
            color: #f57c00;
            font-weight: bold;
        }}
        .medium {{
            color: #fbc02d;
        }}
        .low {{
            color: #388e3c;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            margin: 20px 0;
            border-radius: 5px;
            overflow: hidden;
        }}
        th {{
            background-color: #2c3e50;
            color: white;
            padding: 10px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .section {{
            margin: 30px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Post-Quantum Cryptography Compliance Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <div class="card">
            <h3>Host Information</h3>
            <p><strong>Hostname:</strong> {host_info.get('hostname', 'Unknown')}</p>
            <p><strong>Platform:</strong> {host_info.get('platform', 'Unknown')}</p>
            <p><strong>Version:</strong> {host_info.get('version', 'Unknown')}</p>
        </div>
        
        <div class="card">
            <h3>Checks Summary</h3>
            <p>Total Checks: {checks.get('total_checks', 0)}</p>
            <p>Compliant: {checks.get('by_status', {}).get('COMPLIANT', 0)}</p>
            <p>Non-Compliant: {checks.get('by_status', {}).get('DEPRECATED', 0) + checks.get('by_status', {}).get('REQUIRES_UPDATE', 0)}</p>
        </div>
        
        <div class="card">
            <h3>Compliance Gaps</h3>
            <p>Total Gaps: {gaps.get('total', 0)}</p>
            <p class="critical">Critical: {len(gaps.get('by_severity', {}).get('CRITICAL', []))}</p>
            <p class="high">High: {len(gaps.get('by_severity', {}).get('HIGH', []))}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Compliance Gaps by Severity</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Affected Component</th>
                <th>Recommendation</th>
            </tr>
"""
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            gap_list = gaps.get('by_severity', {}).get(severity, [])
            for gap in gap_list:
                html += f"""
            <tr>
                <td>{gap.get('gap_type', 'Unknown')}</td>
                <td class="{severity.lower()}">{severity}</td>
                <td>{gap.get('description', '')}</td>
                <td>{gap.get('affected_component', '')}</td>
                <td>{gap.get('recommendation', '')}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Checks by Category</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Count</th>
            </tr>
"""
        
        for category, count in checks.get('by_category', {}).items():
            html += f"<tr><td>{category}</td><td>{count}</td></tr>"
        
        html += """
        </table>
    </div>
    
</body>
</html>
"""
        
        report_file = self.report_dir / f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_file, 'w') as f:
            f.write(html)
        
        return str(report_file)
    
    def generate_csv_report(self) -> str:
        """Generate CSV report for gap analysis."""
        import csv
        
        records = self.load_scan_data()
        gaps = [r for r in records if r.get('type') == 'compliance_gap']
        
        report_file = self.report_dir / f"compliance_gaps_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(report_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'Gap Type', 'Severity', 'Description',
                'Affected Component', 'Recommendation', 'Priority Score'
            ])
            
            for gap in gaps:
                writer.writerow([
                    gap.get('timestamp', ''),
                    gap.get('gap_type', ''),
                    gap.get('severity', ''),
                    gap.get('description', ''),
                    gap.get('affected_component', ''),
                    gap.get('recommendation', ''),
                    gap.get('priority_score', '')
                ])
        
        return str(report_file)
    
    def generate_all_reports(self) -> Dict[str, str]:
        """Generate all report types."""
        print("Generating compliance reports...")
        
        json_report = self.generate_json_report()
        html_report = self.generate_html_report()
        csv_report = self.generate_csv_report()
        
        return {
            'json': json_report,
            'html': html_report,
            'csv': csv_report
        }
