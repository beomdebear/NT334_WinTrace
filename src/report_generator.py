"""
WinTrace - Report Generation Module (Fixed for Dicts)
Author: Quyen (Validation & Visualization Engineer)
"""

from datetime import datetime
from typing import List, Dict, Any
from src.schema import ForensicEvent

class ReportGenerator:
    @staticmethod
    def generate_html_report(events: List[ForensicEvent], findings: List[Dict[str, Any]], case_id: str = "CASE01") -> str:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        high_conf_findings = [f for f in findings if f.get("confidence_level") == "HIGH"]
        verified_events = [e for e in events if e.validation_status == "verified"]

        html_content = f"""
        <html>
        <head>
            <title>WinTrace Investigation Report - {case_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .high-conf {{ color: #d35400; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>WinTrace Investigation Report</h1>
            <p><strong>Case ID:</strong> {case_id}</p>
            <p><strong>Generated on:</strong> {now_str}</p>
            
            <h2>1. Executive Summary</h2>
            <ul>
                <li>Total Events Filtered/Analyzed: {len(events)} ({len(verified_events)} verified)</li>
                <li>Total Candidate Findings: {len(findings)}</li>
                <li><span class="high-conf">High Confidence Findings: {len(high_conf_findings)}</span></li>
            </ul>

            <h2>2. Key Correlation Findings</h2>
            <table>
                <tr>
                    <th>Finding ID</th>
                    <th>Time Delta (min)</th>
                    <th>Rules</th>
                    <th>Confidence</th>
                    <th>Explanation</th>
                </tr>
        """
        
        for f in findings:
            rules = ", ".join(f.get("matched_rules", []))
            html_content += f"""
                <tr>
                    <td>{f.get('finding_id')}</td>
                    <td>{f.get('time_delta_minutes')}</td>
                    <td>{rules}</td>
                    <td>{f.get('confidence_level')} ({f.get('confidence_score')})</td>
                    <td>{f.get('explanation')}</td>
                </tr>
            """
            
        html_content += """
            </table>
            <h2>3. Timeline Events (Sample - Top 50)</h2>
            <table>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Artifact</th>
                    <th>Message / Target Path</th>
                    <th>Evidence Ref</th>
                </tr>
        """
        
        for e in events[:50]:
            ref = e.evidence_reference if e.evidence_reference else "N/A"
            html_content += f"""
                <tr>
                    <td>{e.timestamp}</td>
                    <td>{e.artifact_source}</td>
                    <td>{e.message}<br/><small>{e.target_path}</small></td>
                    <td>{ref}</td>
                </tr>
            """
            
        html_content += """
            </table>
        </body>
        </html>
        """
        return html_content