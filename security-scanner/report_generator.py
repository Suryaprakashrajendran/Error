import json
from pathlib import Path
from utils import safe_serialize
from vulnerability_analysis import analyze_port_vulnerabilities, analyze_ssl_vulnerabilities, analyze_header_vulnerabilities

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
except Exception:
    colors = A4 = SimpleDocTemplate = Table = TableStyle = Paragraph = Spacer = getSampleStyleSheet = None


def html_escape(s):
    """Escape HTML special characters"""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def build_vulnerability_summary_html(port_analysis, ssl_analysis, header_analysis):
    """Build HTML vulnerability summary section"""
    all_vulnerabilities = []
    all_recommendations = []
    all_vulnerabilities.extend(port_analysis.get('vulnerabilities', []))
    all_vulnerabilities.extend(ssl_analysis.get('vulnerabilities', []))
    all_vulnerabilities.extend(header_analysis.get('vulnerabilities', []))
    all_recommendations.extend(port_analysis.get('recommendations', []))
    all_recommendations.extend(ssl_analysis.get('recommendations', []))
    all_recommendations.extend(header_analysis.get('recommendations', []))
    all_recommendations = list(set(all_recommendations))

    overall_risk = port_analysis.get('risk_level', 'UNKNOWN')
    risk_color = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
        'INFORMATIONAL': '#17a2b8',
        'UNKNOWN': '#6c757d'
    }.get(overall_risk, '#6c757d')

    vuln_summary = f"""
    <div class="vulnerability-summary">
        <h2>Security Assessment</h2>
        <div class="risk-level" style="background-color: {risk_color}; color: white; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <strong>Overall Risk Level: {overall_risk}</strong>
            <span style="margin-left: 20px;">Risk Score: {port_analysis.get('risk_score', 0)}/10</span>
        </div>
        <div class="risk-breakdown">
            <h3>Risk Breakdown:</h3>
            <ul>
                <li>Critical: {port_analysis.get('risk_breakdown', {}).get('CRITICAL', 0)} issues</li>
                <li>High: {port_analysis.get('risk_breakdown', {}).get('HIGH', 0)} issues</li>
                <li>Medium: {port_analysis.get('risk_breakdown', {}).get('MEDIUM', 0)} issues</li>
                <li>Low: {port_analysis.get('risk_breakdown', {}).get('LOW', 0)} issues</li>
            </ul>
        </div>
        <div class="vulnerabilities">
            <h3>Identified Vulnerabilities:</h3>
            <ul>
    """
    
    for vuln in all_vulnerabilities:
        if isinstance(vuln, dict):
            vuln_summary += f"<li><strong>Port {vuln['port']} ({vuln['service']}) - {vuln['risk']} RISK:</strong><ul>"
            for issue in vuln['issues']:
                vuln_summary += f"<li>{html_escape(issue)}</li>"
            vuln_summary += "</ul></li>"
        else:
            vuln_summary += f"<li>{html_escape(str(vuln))}</li>"

    vuln_summary += """
            </ul>
        </div>
        <div class="recommendations">
            <h3>🔧 Security Recommendations:</h3>
            <ol>
    """
    for rec in all_recommendations:
        vuln_summary += f"<li>{html_escape(str(rec))}</li>"
    
    vuln_summary += """
            </ol>
        </div>
    </div>
    """
    
    return vuln_summary


def build_port_analysis_html(results):
    """Build detailed port analysis HTML table"""
    port_data = results.get("Port Scan Results")
    if not isinstance(port_data, dict) or 'open_ports' not in port_data:
        return ""

    port_info_html = """
    <div class="port-analysis">
        <h3>Detailed Port Analysis:</h3>
        <table class="port-table">
            <thead>
                <tr><th>Port</th><th>Service</th><th>Risk Level</th><th>Common Vulnerabilities</th></tr>
            </thead>
            <tbody>
    """
    
    vulnerable_ports = {
        21: {'service': 'FTP', 'risk': 'HIGH'},
        22: {'service': 'SSH', 'risk': 'MEDIUM'},
        23: {'service': 'Telnet', 'risk': 'CRITICAL'},
        25: {'service': 'SMTP', 'risk': 'MEDIUM'},
        53: {'service': 'DNS', 'risk': 'MEDIUM'},
        80: {'service': 'HTTP', 'risk': 'MEDIUM'},
        110: {'service': 'POP3', 'risk': 'HIGH'},
        143: {'service': 'IMAP', 'risk': 'MEDIUM'},
        443: {'service': 'HTTPS', 'risk': 'LOW'},
        445: {'service': 'SMB', 'risk': 'HIGH'},
        1433: {'service': 'MSSQL', 'risk': 'CRITICAL'},
        3389: {'service': 'RDP', 'risk': 'CRITICAL'},
        3306: {'service': 'MySQL', 'risk': 'HIGH'},
        5432: {'service': 'PostgreSQL', 'risk': 'HIGH'},
    }
    
    common_vulns_map = {
        21: "Anonymous access, brute force, plaintext",
        22: "Brute force, weak passwords",
        23: "Unencrypted, no security",
        25: "Open relay, spoofing",
        80: "Unencrypted data, session hijacking",
        443: "Weak SSL/TLS config",
        445: "EternalBlue, credential relay",
        1433: "SQL injection, brute force",
        3389: "BlueKeep, brute force, RCE"
    }
    
    for port in port_data['open_ports']:
        p = port['port'] if isinstance(port, dict) else (int(port) if str(port).isdigit() else 0)
        if p in vulnerable_ports:
            service = vulnerable_ports[p]['service']
            risk = vulnerable_ports[p]['risk']
            common_v = common_vulns_map.get(p, "Various security issues")
            port_info_html += f"""
            <tr>
                <td>{p}</td>
                <td>{service}</td>
                <td>{risk}</td>
                <td>{common_v}</td>
            </tr>
            """
        else:
            port_info_html += f"""
            <tr>
                <td>{p}</td>
                <td>Unknown</td>
                <td>UNKNOWN</td>
                <td>Requires manual analysis</td>
            </tr>
            """
    
    port_info_html += """
            </tbody>
        </table>
    </div>
    """
    
    return port_info_html


def build_html_report(target, timestamp, results: dict) -> str:
    """Generate complete HTML report"""
    port_analysis = analyze_port_vulnerabilities(results.get("Port Scan Results", {}))
    ssl_analysis = analyze_ssl_vulnerabilities(results.get("SSL Certificate Info", {}))
    header_analysis = analyze_header_vulnerabilities(results.get("HTTP Headers", {}))

    vuln_summary = build_vulnerability_summary_html(port_analysis, ssl_analysis, header_analysis)
    port_info_html = build_port_analysis_html(results)

    # Build detailed results table
    rows_html = ""
    for section, data in results.items():
        if section != "_meta":
            pretty_data = json.dumps(data, indent=2, default=safe_serialize, ensure_ascii=False)
            rows_html += f"<tr><td class='section'>{html_escape(section)}</td><td><pre>{html_escape(pretty_data)}</pre></td></tr>"

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Security Report - {html_escape(target)}</title>
  <style>
    body {{
        font-family: Arial, sans-serif;
        padding: 20px;
        background-color: #f8f9fa;
        line-height: 1.6;
    }}
    .header {{
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        text-align: center;
    }}
    .header h1 {{ margin: 0; font-size: 2.0em; }}
    .vulnerability-summary, .port-analysis, .main-data {{
        background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }}
    .port-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    .port-table th, .port-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    .port-table th {{ background-color: #f2f2f2; font-weight: bold; }}
    h2, h3 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 5px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    table, th, td {{ border: 1px solid #ddd; }}
    th, td {{ padding: 12px; vertical-align: top; }}
    tr:nth-child(even){{ background-color: #f9f9f9; }}
    .section {{ width: 220px; font-weight: bold; background: #e9ecef; }}
    pre {{ margin: 0; font-family: 'Courier New', monospace; font-size: 12px; white-space: pre-wrap; word-wrap: break-word; }}
    ul, ol {{ margin: 10px 0; padding-left: 20px; }}
    .risk-breakdown ul {{ display: flex; flex-wrap: wrap; list-style: none; padding: 0; }}
    .risk-breakdown li {{ margin: 5px 15px 5px 0; padding: 5px 10px; background: #f8f9fa; border-radius: 5px; border-left: 4px solid #667eea; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <h2>{html_escape(target)}</h2>
    <p>Generated: {html_escape(timestamp)}</p>
  </div>

  {vuln_summary}

  {port_info_html}

  <div class="main-data">
    <h2>Detailed Scan Results</h2>
    <table>
      <thead>
        <tr><th>Section</th><th>Data</th></tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

  <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 10px;">
    <h3>Important Notes:</h3>
    <ul>
      <li>This report is for educational and authorized security testing purposes only</li>
      <li>Always obtain proper authorization before conducting security assessments</li>
      <li>Vulnerabilities identified require manual verification and testing</li>
      <li>Implement security measures in a test environment before production deployment</li>
      <li>Regular security assessments and updates are recommended</li>
    </ul>
  </div>
</body>
</html>"""
    return html


def generate_pdf_report(target: str, timestamp: str, results: dict, pdf_path: Path):
    """Generate PDF report using ReportLab"""
    if not SimpleDocTemplate:
        raise RuntimeError("ReportLab is not installed. Cannot generate PDF.")

    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"Security Report: {target}", styles["Title"]))
    elements.append(Paragraph(f"Generated: {timestamp}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # Add vulnerability analysis to PDF
    port_analysis = analyze_port_vulnerabilities(results.get("Port Scan Results", {}))
    elements.append(Paragraph("Security Assessment Summary", styles["Heading2"]))
    elements.append(Paragraph(f"Overall Risk Level: {port_analysis.get('risk_level', 'UNKNOWN')}", styles["Normal"]))
    elements.append(Paragraph(f"Risk Score: {port_analysis.get('risk_score', 0)}/10", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["Section", "Data"]]
    for section, data in results.items():
        pretty_data = json.dumps(data, indent=2, default=safe_serialize, ensure_ascii=False)
        table_data.append([section, pretty_data])

    table = Table(table_data, colWidths=[150, 350])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f0f4f8")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))

    elements.append(table)
    doc.build(elements)