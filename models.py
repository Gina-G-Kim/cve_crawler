"""
CVE Data Models based on CWE export format
Reference: https://cwe.mitre.org/data/csv/
"""
from dataclasses import dataclass, asdict, field
from typing import List, Optional
from datetime import datetime


@dataclass
class CVERecord:
    """
    CVE Record following CWE-inspired format for space security vulnerabilities
    Fields align with standard CVE/CWE export formats
    """
    cve_id: str  # CVE ID (e.g., CVE-2023-12345)
    description: str  # Vulnerability description
    product: str  # Affected product name
    vendor: Optional[str] = None  # Vendor name
    affected_versions: Optional[str] = None  # Version range or list
    severity: Optional[str] = None  # CVSS severity (Critical, High, Medium, Low)
    cvss_score: Optional[float] = None  # CVSS Score (0.0-10.0)
    cvss_vector: Optional[str] = None  # CVSS Vector string
    cwe_ids: Optional[str] = None  # Associated CWE IDs (comma-separated)
    published_date: Optional[str] = None  # Publication date
    last_updated: Optional[str] = None  # Last update date
    references: Optional[str] = None  # Reference URLs (semicolon-separated)
    source_url: Optional[str] = None  # URL where data was crawled from
    mitigation: Optional[str] = None  # Mitigation steps
    impact: Optional[str] = None  # Impact description
    is_space_related: bool = True  # Flag for space/satellite systems
    discovery_date: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)
    
    @staticmethod
    def get_csv_headers() -> List[str]:
        """Return CSV headers in CWE-like format"""
        return [
            'CVE ID',
            'Description',
            'Product',
            'Vendor',
            'Affected Versions',
            'Severity',
            'CVSS Score',
            'CVSS Vector',
            'CWE IDs',
            'Published Date',
            'Last Updated',
            'References',
            'Source URL',
            'Mitigation',
            'Impact',
            'Space Related',
            'Discovery Date'
        ]
    
    def to_csv_row(self) -> dict:
        """Convert to CSV row format"""
        return {
            'CVE ID': self.cve_id,
            'Description': self.description or '',
            'Product': self.product,
            'Vendor': self.vendor or '',
            'Affected Versions': self.affected_versions or '',
            'Severity': self.severity or '',
            'CVSS Score': self.cvss_score or '',
            'CVSS Vector': self.cvss_vector or '',
            'CWE IDs': self.cwe_ids or '',
            'Published Date': self.published_date or '',
            'Last Updated': self.last_updated or '',
            'References': self.references or '',
            'Source URL': self.source_url or '',
            'Mitigation': self.mitigation or '',
            'Impact': self.impact or '',
            'Space Related': 'Yes' if self.is_space_related else 'No',
            'Discovery Date': self.discovery_date
        }


@dataclass
class CrawlSession:
    """Track crawling session metadata"""
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    sources_crawled: List[str] = field(default_factory=list)
    total_cves_found: int = 0
    total_links_followed: int = 0
    end_time: Optional[str] = None
    
    def finalize(self):
        """Mark session as complete"""
        self.end_time = datetime.now().isoformat()
