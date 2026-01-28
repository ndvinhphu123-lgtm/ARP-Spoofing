from dataclasses import dataclass, field
from typing import Dict, Set, Any, List, Optional
import time

@dataclass
class VulnerabilityInfo:
    cve_id: str
    severity: str
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
    config: Any
    assets: Dict[str, Asset]
    metrics: Dict[str, int]
    timestamp: float