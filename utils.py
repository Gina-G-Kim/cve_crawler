"""
Utility functions for CVE crawler
"""
import json
import csv
import os
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
from models import CVERecord
import logging

logger = logging.getLogger(__name__)


class DataExporter:
    """Export CVE data to CSV and JSON formats"""
    
    @staticmethod
    def export_json(cve_records: List[CVERecord], output_path: str) -> bool:
        """
        Export CVE records to JSON file in CWE-inspired format
        """
        try:
            data = {
                'format': 'CVE_Export_CWE_Style',
                'version': '1.0',
                'export_date': cve_records[0].discovery_date if cve_records else '',
                'total_records': len(cve_records),
                'records': [record.to_dict() for record in cve_records]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Exported {len(cve_records)} records to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")
            return False
    
    @staticmethod
    def export_csv(cve_records: List[CVERecord], output_path: str) -> bool:
        """
        Export CVE records to CSV file in CWE format
        """
        try:
            if not cve_records:
                logger.warning("No records to export to CSV")
                return False
            
            headers = CVERecord.get_csv_headers()
            rows = [record.to_csv_row() for record in cve_records]
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
            
            logger.info(f"Exported {len(cve_records)} records to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting CSV: {e}")
            return False


class URLProcessor:
    """Handle URL operations like filtering and normalization"""
    
    SKIP_DOMAINS = {
        'twitter.com', 'facebook.com', 'linkedin.com', 'instagram.com',
        'youtube.com', 'reddit.com', 'pinterest.com'
    }
    
    SPACE_KEYWORDS = {
        'satellite', 'space', 'orbital', 'leo', 'geo', 'earth observation',
        'communication satellite', 'gps', 'gnss', 'spacescraft', 'rocket',
        'launch', 'constellation', 'iss', 'cubesat', 'aerospace'
    }
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for comparison"""
        url = url.strip()
        if url.startswith('//'):
            url = 'https:' + url
        return url.rstrip('/')
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid for crawling"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Skip social media and irrelevant domains
            for skip_domain in URLProcessor.SKIP_DOMAINS:
                if skip_domain in domain:
                    return False
            
            return parsed.scheme in ['http', 'https']
        except:
            return False
    
    @staticmethod
    def is_space_related(text: str) -> bool:
        """Check if text contains space-related keywords"""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in URLProcessor.SPACE_KEYWORDS)
    
    @staticmethod
    def get_base_domain(url: str) -> str:
        """Extract base domain from URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"


class SessionManager:
    """Manage crawling sessions and state"""
    
    def __init__(self, session_dir: str = "sessions"):
        self.session_dir = session_dir
        os.makedirs(session_dir, exist_ok=True)
    
    def save_visited_urls(self, visited: Set[str], filename: str = "visited_urls.json"):
        """Save visited URLs to file to avoid duplicates"""
        try:
            path = os.path.join(self.session_dir, filename)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(list(visited), f, indent=2)
        except Exception as e:
            logger.error(f"Error saving visited URLs: {e}")
    
    def load_visited_urls(self, filename: str = "visited_urls.json") -> Set[str]:
        """Load previously visited URLs"""
        try:
            path = os.path.join(self.session_dir, filename)
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    return set(json.load(f))
        except Exception as e:
            logger.error(f"Error loading visited URLs: {e}")
        return set()
