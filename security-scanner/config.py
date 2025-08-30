import os
from pathlib import Path

# Output configuration
DEFAULT_OUTPUT_DIR = Path(r"C:\dumps") if os.name == "nt" else Path("./dumps")

WORDLIST_PATH = Path("common.txt")

REQUEST_TIMEOUT = 5
PORT_SCAN_TIMEOUT = 0.5

#ports
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5672, 5900, 
    6379, 8080, 8081, 9200, 11211
]

#subdomain
DEFAULT_SUBDOMAINS = ["www", "mail", "ftp", "test", "dev", "api"]

#wordlist
DEFAULT_DIRECTORIES = ["admin", "login", "uploads", "backup", "config", ".git"]