# Security Scanner

A comprehensive security assessment tool for authorized penetration testing and vulnerability analysis.

## Features

- **Reconnaissance**: IP lookup, WHOIS, DNS records, subdomain enumeration
- **Port Scanning**: Identifies open ports and running services
- **SSL Analysis**: Certificate information and configuration assessment
- **HTTP Security**: Header analysis and directory bruteforcing
- **Vulnerability Assessment**: Automated risk analysis with scoring
- **Multiple Report Formats**: JSON, HTML, and PDF reports
- **Modular Architecture**: Easy to extend and maintain

## Project Structure

```
security-scanner/
├── security_scanner.py      # Main application entry point
├── config.py               # Configuration settings
├── utils.py                # Utility functions
├── reconnaissance.py       # Reconnaissance modules
├── vulnerability_analysis.py # Vulnerability analysis
├── report_generator.py     # Report generation
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Installation

1. **Clone or download the project files**
2. **Create a virtual environment (recommended)**:
   ```bash
   python -m venv security_scanner_env
   source security_scanner_env/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage
```bash
python security_scanner.py --target example.com
```

### Command Line Options
- `--target, -t`: Target domain or IP address (required)
- `--out, -o`: Output directory for reports (default: C:\dumps on Windows, ./dumps on Unix)


## Configuration

Edit `config.py` to customize:

- Default output directory
- Request timeouts
- Port scan lists
- Wordlists for directory bruteforcing
- Subdomain lists

## Dependencies

**Required:**
- `requests`: HTTP requests
- `python-whois`: WHOIS lookups
- `dnspython`: DNS queries
- `reportlab`: PDF generation

**Optional modules installed automatically:**
- Standard library modules for networking and SSL

## Security Features

### Reconnaissance
- IP address resolution
- WHOIS information gathering
- DNS record enumeration (A, MX, NS, TXT)
- Basic subdomain discovery
- Geolocation information

### Port Scanning
- Common port identification
- Service detection
- Risk assessment for open ports

### Web Analysis
- HTTP security header analysis
- SSL certificate examination
- Basic directory enumeration

### Vulnerability Assessment
- Automated risk scoring
- Service-specific vulnerability identification
- Security recommendations
- Risk level categorization (CRITICAL, HIGH, MEDIUM, LOW)

## Risk Assessment

The tool provides automated vulnerability analysis with:

- **Port-based vulnerabilities**: Known security issues for common services
- **Missing security headers**: HTTP security configuration problems  
- **SSL/TLS issues**: Certificate and encryption problems
- **Overall risk scoring**: Numerical and categorical risk assessment

## Important Notes

### Legal and Ethical Use
- **AUTHORIZATION REQUIRED**: Only use on systems you own or have explicit permission to test
- **Educational Purpose**: This tool is designed for learning and authorized security testing
- **Responsibility**: Users are responsible for complying with all applicable laws and regulations

### Technical Limitations
- **Basic Scanning**: This is not a professional-grade vulnerability scanner
- **False Positives**: Manual verification of findings is recommended  
- **Network Dependencies**: Requires internet connectivity for external lookups
- **Performance**: Scanning speed limited by network conditions and timeouts


## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations.
