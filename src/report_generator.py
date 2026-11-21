"""
WinTrace - Report Generation Module
Author: Quyen (Validation & Visualization Engineer)
"""

from datetime import datetime
from html import escape
from typing import List, Dict, Any, Optional
from src.schema import ForensicEvent

class ReportGenerator:
    @staticmethod
    def generate_html_report(events: List[ForensicEvent], findings: List[Dict[str, Any]],
                             case_id: Optional[str] = None) -> str:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        case_ids = sorted({event.case_id for event in events if event.case_id})
        if case_ids and any(not event.case_id for event in events):
            case_ids.append("Unspecified")
        case_label = escape(", ".join(case_ids) or case_id or "Unspecified")
        
        high_conf_findings = [f for f in findings if f.get("confidence_level") == "HIGH"]
        verified_events = [e for e in events if e.validation_status == "verified"]

        html_content = f"""
        <html>
        <head>
            <title>WinTrace Investigation Report - {case_label}</title>
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
            <p><strong>Case ID:</strong> {case_label}</p>
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
                    <td>{escape(str(f.get('finding_id')))}</td>
                    <td>{escape(str(f.get('time_delta_minutes')))}</td>
                    <td>{escape(rules)}</td>
                    <td>{escape(str(f.get('confidence_level')))} ({escape(str(f.get('confidence_score')))})</td>
                    <td>{escape(str(f.get('explanation')))}</td>
                </tr>
            """
            
        html_content += """
            </table>
            <h2>3. Timeline Events (Sample - Top 50)</h2>
            <table>
                <tr>
                    <th>Case ID</th>
                    <th>Timestamp (UTC)</th>
                    <th>Artifact</th>
                    <th>Message / Target Path</th>
                    <th>Evidence Ref</th>
                    <th>Validation Status</th>
                </tr>
        """
        
        for e in events[:50]:
            ref = e.evidence_reference if e.evidence_reference else "N/A"
            html_content += f"""
                <tr>
                    <td>{escape(e.case_id or "Unspecified")}</td>
                    <td>{escape(e.timestamp)}<br/><small>{escape(e.timestamp_type or "Unspecified")}</small></td>
                    <td>{escape(e.artifact_source)}</td>
                    <td>{escape(e.message)}<br/><small>{escape(e.target_path)}</small></td>
                    <td>{escape(ref)}</td>
                    <td>{escape(e.validation_status or "Unspecified")}</td>
                </tr>
            """
            
        html_content += """
            </table>
        </body>
        </html>
        """
        return html_content
