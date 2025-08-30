import argparse
import datetime
from pathlib import Path

# Import all modules
from config import DEFAULT_OUTPUT_DIR
from utils import ensure_output_dir, print_json_pretty, write_json_file, write_html_file
from reconnaissance import (
    ip_lookup, whois_lookup, dns_info, subdomain_enum, port_scan,
    geolocation_info, ssl_info, tech_detect, http_headers, dir_bruteforce
)
from vulnerability_analysis import (
    analyze_port_vulnerabilities, analyze_ssl_vulnerabilities, analyze_header_vulnerabilities
)
from report_generator import build_html_report, generate_pdf_report


def run_reconnaissance_phase(target: str):
    """Execute all reconnaissance modules and return results"""
    print("Running reconnaissance modules...")
    results = {}
    
    # IP Address Lookup
    try:
        print("  → IP Address Lookup")
        ip_result = ip_lookup(target)
        results["IP Address"] = ip_result
        print_json_pretty(ip_result, "IP Address Lookup")
    except Exception as e:
        results["IP Address"] = f"ERROR: {e}"
        print(f"IP Address Lookup ERROR: {e}")

    # WHOIS Information
    try:
        print("  → WHOIS Information")
        whois_result = whois_lookup(target)
        results["WHOIS Information"] = whois_result
        print_json_pretty(whois_result, "WHOIS Information")
    except Exception as e:
        results["WHOIS Information"] = f"ERROR: {e}"
        print(f"WHOIS Information ERROR: {e}")

    # DNS Records
    try:
        print("  → DNS Records")
        dns_result = dns_info(target)
        results["DNS Records"] = dns_result
        print_json_pretty(dns_result, "DNS Records")
    except Exception as e:
        results["DNS Records"] = f"ERROR: {e}"
        print(f"DNS Records ERROR: {e}")

    # Subdomain Enumeration
    try:
        print("  → Subdomain Enumeration")
        subdomain_result = subdomain_enum(target)
        results["Subdomain Enumeration"] = subdomain_result
        print_json_pretty(subdomain_result, "Subdomain Enumeration")
    except Exception as e:
        results["Subdomain Enumeration"] = f"ERROR: {e}"
        print(f"Subdomain Enumeration ERROR: {e}")

    # Port Scanning
    try:
        print("  → Port Scanning")
        port_result = port_scan(target)
        results["Port Scan Results"] = port_result
        print_json_pretty(port_result, "Port Scan Results")
    except Exception as e:
        results["Port Scan Results"] = f"ERROR: {e}"
        print(f"Port Scan Results ERROR: {e}")

    # IP Geolocation
    try:
        print("  → IP Geolocation")
        geo_result = geolocation_info(target)
        results["IP Geolocation Info"] = geo_result
        print_json_pretty(geo_result, "IP Geolocation Info")
    except Exception as e:
        results["IP Geolocation Info"] = f"ERROR: {e}"
        print(f"IP Geolocation Info ERROR: {e}")

    # SSL Certificate Analysis
    try:
        print("  → SSL Certificate Analysis")
        ssl_result = ssl_info(target)
        results["SSL Certificate Info"] = ssl_result
        print_json_pretty(ssl_result, "SSL Certificate Info")
    except Exception as e:
        results["SSL Certificate Info"] = f"ERROR: {e}"
        print(f"SSL Certificate Info ERROR: {e}")

    # Technology Detection
    try:
        print("  → Technology Detection")
        tech_result = tech_detect(target)
        results["Technology Detection"] = tech_result
        print_json_pretty(tech_result, "Technology Detection")
    except Exception as e:
        results["Technology Detection"] = f"ERROR: {e}"
        print(f"Technology Detection ERROR: {e}")

    # HTTP Headers Analysis
    try:
        print("  → HTTP Headers Analysis")
        headers_result = http_headers(target)
        results["HTTP Headers"] = headers_result
        print_json_pretty(headers_result, "HTTP Headers Analysis")
    except Exception as e:
        results["HTTP Headers"] = f"ERROR: {e}"
        print(f"HTTP Headers Analysis ERROR: {e}")

    # Directory Bruteforcing
    try:
        print("  → Directory Bruteforcing")
        dir_result = dir_bruteforce(target)
        results["Directory Bruteforce Results"] = dir_result
        print_json_pretty(dir_result, "Directory Bruteforce Results")
    except Exception as e:
        results["Directory Bruteforce Results"] = f"ERROR: {e}"
        print(f"Directory Bruteforce Results ERROR: {e}")

    return results


def run_vulnerability_analysis(results: dict):
    """Analyze reconnaissance results for vulnerabilities"""
    print("\nAnalyzing security vulnerabilities...")
    
    port_analysis = analyze_port_vulnerabilities(results.get("Port Scan Results", {}))
    ssl_analysis = analyze_ssl_vulnerabilities(results.get("SSL Certificate Info", {}))
    header_analysis = analyze_header_vulnerabilities(results.get("HTTP Headers", {}))

    # Print security analysis in JSON format
    print_json_pretty(port_analysis, "Port Vulnerability Analysis")
    print_json_pretty(ssl_analysis, "SSL Vulnerability Analysis") 
    print_json_pretty(header_analysis, "HTTP Headers Vulnerability Analysis")

    return port_analysis, ssl_analysis, header_analysis


def generate_reports(target: str, timestamp: str, results: dict, output_dir: Path, port_analysis: dict):
    """Generate all report formats"""
    safe_target = "".join(ch for ch in target if ch.isalnum() or ch in ("-", "_", "."))
    
    json_file = output_dir / f"security_report_{safe_target}_{timestamp}.json"
    html_file = output_dir / f"security_report_{safe_target}_{timestamp}.html"
    pdf_file = output_dir / f"security_report_{safe_target}_{timestamp}.pdf"

    print(f"\nGenerating reports...")
    
    # JSON Report
    print(f"   JSON: {json_file}")
    write_json_file(results, json_file)

    # HTML Report
    print(f"   HTML: {html_file}")
    html = build_html_report(target, timestamp, results)
    write_html_file(html, html_file)

    # PDF Report
    try:
        print(f"   PDF: {pdf_file}")
        generate_pdf_report(target, timestamp, results, pdf_file)
    except Exception as e:
        print(f"   PDF generation skipped: {e}")

    return json_file, html_file, pdf_file


def print_summary(target: str, port_analysis: dict, json_file: Path, html_file: Path, pdf_file: Path):
    """Print assessment summary"""
    print("\nAssessment Complete!")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Risk Level: {port_analysis.get('risk_level', 'UNKNOWN')}")
    print(f"Risk Score: {port_analysis.get('risk_score', 0)}/10")
    print("=" * 60)
    print("Generated Files:")
    print(f"JSON Report: {json_file}")
    print(f"HTML Report: {html_file}")
    if pdf_file.exists():
        print(f"PDF Report: {pdf_file}")
    print("=" * 60)

    # Show critical issues
    vulnerabilities = port_analysis.get('vulnerabilities', [])
    if vulnerabilities:
        print("Critical Issues Found:")
        critical_count = sum(1 for v in vulnerabilities if isinstance(v, dict) and v.get('risk') == 'CRITICAL')
        if critical_count > 0:
            for v in vulnerabilities:
                if isinstance(v, dict) and v.get('risk') == 'CRITICAL':
                    print(f"Port {v['port']} ({v['service']}) - CRITICAL RISK")
        else:
            high_count = sum(1 for v in vulnerabilities if isinstance(v, dict) and v.get('risk') == 'HIGH')
            if high_count > 0:
                print(f"{high_count} HIGH RISK issues found")
            else:
                print("No critical issues found")
    else:
        print("No major vulnerabilities detected")

    print("\nIMPORTANT: This tool is for authorized security testing only!")
    print("   Always obtain proper permission before testing any system.")


def run_assessment(target: str, output_dir: Path):
    """Main assessment function"""
    print("Starting Enhanced Security Assessment...")
    ensure_output_dir(output_dir)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Phase 1: Reconnaissance
    results = run_reconnaissance_phase(target)
    results["_meta"] = {"target": target, "generated_at": timestamp}

    # Phase 2: Vulnerability Analysis
    port_analysis, ssl_analysis, header_analysis = run_vulnerability_analysis(results)

    # Print complete results summary in JSON
    print_json_pretty(results, "COMPLETE SCAN RESULTS - FULL JSON OUTPUT")

    print(f"\n   Security Assessment Complete!")
    print(f"   Risk Level: {port_analysis.get('risk_level', 'UNKNOWN')}")
    print(f"   Risk Score: {port_analysis.get('risk_score', 0)}/10")
    print(f"   Vulnerabilities Found: {len(port_analysis.get('vulnerabilities', []))}")
    print(f"   Recommendations: {len(port_analysis.get('recommendations', []))}")

    # Phase 3: Report Generation
    json_file, html_file, pdf_file = generate_reports(target, timestamp, results, output_dir, port_analysis)

    # Phase 4: Summary
    print_summary(target, port_analysis, json_file, html_file, pdf_file)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Enhanced Security Scanner - Comprehensive security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_scanner.py --target example.com
  python security_scanner.py --target 192.168.1.1 --out /tmp/security_reports
  python security_scanner.py -t subdomain.example.com -o ./reports

IMPORTANT: This tool is for authorized security testing only!
Always obtain proper permission before testing any system.
        """
    )
    
    parser.add_argument(
        "--target", "-t", 
        required=True, 
        help="Domain or IP address to assess (e.g., example.com, 192.168.1.1)"
    )
    
    parser.add_argument(
        "--out", "-o", 
        default=str(DEFAULT_OUTPUT_DIR), 
        help=f"Output directory for reports (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    try:
        args = parse_arguments()
        output_directory = Path(args.out).expanduser().resolve()
        target_domain = args.target.strip()
        
        print(f"Target: {target_domain}")
        print(f"Output Directory: {output_directory}")
        print()
        
        run_assessment(target_domain, output_directory)
        
    except KeyboardInterrupt:
        print("\n\nAssessment interrupted by user.")
        print("Partial results may have been saved.")
    except Exception as e:
        print(f"\nError during assessment: {e}")
        print("Check your target format and network connectivity.")


if __name__ == "__main__":
    main()