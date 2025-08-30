import socket
import ssl
from config import REQUEST_TIMEOUT, PORT_SCAN_TIMEOUT, SCAN_PORTS, DEFAULT_SUBDOMAINS, WORDLIST_PATH, DEFAULT_DIRECTORIES

try:
    import requests
except Exception:
    requests = None

try:
    import whois as python_whois
except Exception:
    python_whois = None

try:
    import dns.resolver
except Exception:
    dns = None


def ip_lookup(domain: str):
    """Get IP address for domain"""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"IP lookup failed: {e}"


def whois_lookup(domain: str):
    """Perform WHOIS lookup on domain"""
    if not python_whois:
        return "WHOIS module not installed"
    try:
        w = python_whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0] if expiration_date else None
        return {
            "Domain": domain,
            "Registrar": getattr(w, "registrar", None) or "N/A",
            "Creation Date": str(creation_date) if creation_date else "N/A",
            "Expiration Date": str(expiration_date) if expiration_date else "N/A",
            "Name Servers": list(getattr(w, "name_servers", []) or []) or "N/A",
            "Status": getattr(w, "status", None) or "N/A",
        }
    except Exception as e:
        return f"WHOIS lookup failed: {e}"


def dns_info(domain: str):
    """Get DNS record information"""
    out = {}
    if not dns:
        return "dnspython module not installed"
    try:
        for record_type in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                out[record_type] = [r.to_text() for r in answers]
            except Exception:
                out[record_type] = []
        return out
    except Exception as e:
        return f"DNS fetch failed: {e}"


def subdomain_enum(domain: str):
    """Light subdomain enumeration using HTTP GET; success (<400) recorded."""
    if not requests:
        return "requests module not installed"
    subdomains = []
    for sub in DEFAULT_SUBDOMAINS:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                subdomains.append(f"{sub}.{domain}")
        except Exception:
            continue
    return subdomains


def port_scan(domain: str):
    """Scan common ports on the target domain"""
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        for port in SCAN_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                sock.close()
        return {"open_ports": open_ports}
    except Exception as e:
        return f"Port scan failed: {e}"


def geolocation_info(domain: str):
    """Get geolocation information for domain IP"""
    if not requests:
        return "requests module not installed"
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=REQUEST_TIMEOUT)
        return resp.json() if resp.ok else f"Geolocation fetch failed: HTTP {resp.status_code}"
    except Exception as e:
        return f"Geolocation fetch failed: {e}"


def ssl_info(domain: str):
    """Fetch SSL certificate information presented by the domain on :443."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "Valid From": cert.get("notBefore"),
                    "Valid To": cert.get("notAfter"),
                    "Subject": cert.get("subject"),
                    "Issuer": cert.get("issuer"),
                }
    except Exception as e:
        return f"SSL info fetch failed: {e}"


def tech_detect(domain: str):
    """Technology detection placeholder"""
    return "Technology detection not implemented (suggest Wappalyzer / whatweb API)"


def http_headers(domain: str):
    """Get HTTP headers from domain"""
    if not requests:
        return "requests module not installed"
    try:
        if not domain.startswith("http"):
            domain = "https://" + domain
        r = requests.get(domain, timeout=REQUEST_TIMEOUT)
        return dict(r.headers)
    except Exception as e:
        return f"HTTP headers fetch failed: {e}"


def dir_bruteforce(domain: str):
    """Basic directory bruteforce using wordlist"""
    if not requests:
        return "requests module not installed"
    found = []
    if not domain.startswith("http"):
        domain = "http://" + domain
    
    # Load wordlist or use defaults
    if WORDLIST_PATH.exists():
        try:
            with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception:
            words = DEFAULT_DIRECTORIES
    else:
        words = DEFAULT_DIRECTORIES
    
    for word in words:
        url = f"{domain.rstrip('/')}/{word}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code in (200, 301, 302):
                found.append(url)
        except Exception:
            continue
    return found