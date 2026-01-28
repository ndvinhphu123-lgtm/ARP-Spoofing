from dataclasses import dataclass, field
from typing import Optional, Set, List

@dataclass
class ScanConfig:
    target_domain: str
    max_workers: int = 50
    timeout: float = 5.0
    max_retries: int = 3
    rate_limit: float = 5.0
    dry_run: bool = True
    allowed_targets: Optional[Set[str]] = None
    output_dir: str = "./recon_output"
    scan_id: str = None
    verbose: bool = False
    proxies: List[str] = field(default_factory=list)
    tor_control_port: int = 9051
    renew_tor_every: int = 10
    subdomain_wordlist: str = "subdomains.txt"
    path_wordlist: str = "paths.txt"
    enable_cve_scan: bool = True
    enable_waf_detection: bool = True
    cve_api_key: Optional[str] = None  # For NVD API
    use_cache: bool = True

# Common data
COMMON_SUBDOMAINS = [
    "www", "api", "dev", "test", "mail", "admin", "blog", "app", 
    "ftp", "staging", "beta", "vpn", "portal", "m", "mobile", "shop"
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 3000, 5000, 8000, 8888, 9000]

COMMON_PATHS = [
    "/admin/", "/login/", "/phpmyadmin/", "/backup/", "/.env", 
    "/.git/config", "/robots.txt", "/db_backup.sql", "/.DS_Store",
    "/wp-admin/", "/wp-login.php", "/config.php", "/admin.php",
    "/uploads/", "/private/", "/test/", "/api/", "/swagger.json"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

WAF_SIGNATURES = {
    "Cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
    "Akamai": ["akamai", "akamaighost"],
    "AWS WAF": ["x-amz-", "awselb"],
    "Imperva": ["incap_ses", "visid_incap"],
    "ModSecurity": ["mod_security", "NOYB"],
    "F5 BIG-IP": ["BigIP", "F5-TrafficShield", "BIGipServer"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Wordfence": ["wordfence"],
    "Fortinet": ["fortigate", "fortigate-waf"]
}

CDN_SIGNATURES = {
    "Cloudflare": {"asn": [13335], "servers": ["cloudflare"]},
    "Akamai": {"asn": [20940, 16625, 16702], "servers": ["akamai"]},
    "Fastly": {"asn": [54113], "servers": ["fastly"]},
    "CloudFront": {"asn": [16509], "servers": ["cloudfront"]},
    "MaxCDN": {"asn": [36610], "servers": ["maxcdn"]},
}


# ==================== FILE: models.py ====================
"""Data models for scan results"""
from dataclasses import dataclass, field
from typing import Dict, Set, Any, List, Optional
import time

@dataclass
class VulnerabilityInfo:
    cve_id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    score: float
    description: str
    references: List[str]
    published_date: str
    
@dataclass
class WAFInfo:
    detected: bool
    waf_name: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)

@dataclass
class CDNInfo:
    detected: bool
    cdn_name: Optional[str] = None
    asn: Optional[int] = None
    ip_range: Optional[str] = None

@dataclass
class Asset:
    ip: str
    domains: Set[str] = field(default_factory=set)
    ports: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    http_info: Dict[str, Any] = field(default_factory=dict)
    tls_info: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    waf_info: Optional[WAFInfo] = None
    cdn_info: Optional[CDNInfo] = None
    timestamp: float = field(default_factory=time.time)

@dataclass
class ScanResult:
    scan_id: str
    config: Any  # ScanConfig
    assets: Dict[str, Asset]
    metrics: Dict[str, int]
    timestamp: float