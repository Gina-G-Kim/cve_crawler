"""
Scrapers for different CVE sources
Each scraper handles a specific data source
"""
import requests
from bs4 import BeautifulSoup
from typing import List, Set, Optional
from urllib.parse import urljoin, urlparse
from models import CVERecord
from utils import URLProcessor
import logging
import re
import json
import time

logger = logging.getLogger(__name__)


class BaseScraper:
    """Base class for all scrapers"""
    
    def __init__(self, max_retries: int = 3, timeout: int = 10):
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.visited_urls = set()
    
    def fetch_url(self, url: str) -> Optional[str]:
        """Fetch URL content with retry logic"""
        if not URLProcessor.is_valid_url(url):
            return None
        
        if url in self.visited_urls:
            return None
        
        self.visited_urls.add(url)
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                return response.text
            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed for {url}: {e}")
                time.sleep(2 ** attempt)  # Exponential backoff
        
        logger.error(f"Failed to fetch {url} after {self.max_retries} attempts")
        return None
    
    def extract_links(self, html: str, base_url: str, max_links: int = 50) -> Set[str]:
        """Extract links from HTML"""
        try:
            soup = BeautifulSoup(html, 'lxml')
            links = set()
            
            for link in soup.find_all('a', href=True)[:max_links]:
                url = urljoin(base_url, link['href'])
                if URLProcessor.is_valid_url(url):
                    links.add(URLProcessor.normalize_url(url))
            
            return links
        except Exception as e:
            logger.error(f"Error extracting links: {e}")
            return set()
    
    def scrape(self, url: str) -> List[CVERecord]:
        """Main scrape method - to be implemented by subclasses"""
        raise NotImplementedError


class GitHubScraper(BaseScraper):
    """Scraper for GitHub repositories"""
    
    def scrape(self, url: str) -> List[CVERecord]:
        """Scrape GitHub repo for CVE information"""
        cves = []
        try:
            logger.info(f"Scraping GitHub: {url}")
            
            # Get raw content from GitHub
            if 'github.com' in url and not url.endswith('/raw'):
                # Try to get README
                parts = url.rstrip('/').split('/')
                if len(parts) >= 5:
                    owner, repo = parts[3], parts[4]
                    readme_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.md"
                    content = self.fetch_url(readme_url)
                    
                    if not content:
                        readme_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/README.md"
                        content = self.fetch_url(readme_url)
                    
                    if content:
                        cves.extend(self._parse_cve_from_text(content, url))
        except Exception as e:
            logger.error(f"Error scraping GitHub {url}: {e}")
        
        return cves
    
    def _parse_cve_from_text(self, text: str, source_url: str) -> List[CVERecord]:
        """Extract CVE information from text content"""
        cves = []
        
        # Find CVE IDs using regex
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_matches = set(re.findall(cve_pattern, text))
        
        for cve_id in cve_matches:
            # Extract surrounding context
            idx = text.find(cve_id)
            context = text[max(0, idx-200):min(len(text), idx+200)]
            
            cve = CVERecord(
                cve_id=cve_id,
                description=context.strip(),
                product='Satellite/Space System (GitHub)',
                vendor=source_url.split('/')[-2] if '/' in source_url else 'Unknown',
                source_url=source_url,
                is_space_related=URLProcessor.is_space_related(text)
            )
            cves.append(cve)
        
        return cves


class OpenCVEScraper(BaseScraper):
    """Scraper for OpenCVE (https://app.opencve.io)"""
    
    def scrape(self, url: str, depth: int = 0, max_depth: int = 2) -> List[CVERecord]:
        """Scrape OpenCVE for satellite-related CVEs"""
        cves = []
        
        # Limit depth to prevent excessive recursion
        if depth > max_depth:
            return cves
        
        try:
            logger.info(f"Scraping OpenCVE (depth {depth}): {url}")
            
            html = self.fetch_url(url)
            if not html:
                return cves
            
            soup = BeautifulSoup(html, 'lxml')
            
            # Find CVE entries (structure may vary)
            cve_rows = soup.find_all('tr') or soup.find_all('div', class_=re.compile('cve', re.I))
            
            for row in cve_rows:
                cve_record = self._parse_cve_row(row, url)
                if cve_record:
                    cves.append(cve_record)
            
            # Follow pagination links (but limit depth)
            if depth < max_depth:
                next_links = self._find_next_pages(html, url, max_pages=2)
                for next_url in list(next_links)[:2]:  # Only follow first 2 pagination links
                    logger.info(f"Following OpenCVE page: {next_url}")
                    time.sleep(1)  # Be respectful with requests
                    cves.extend(self.scrape(next_url, depth + 1, max_depth))
        
        except Exception as e:
            logger.error(f"Error scraping OpenCVE {url}: {e}")
        
        return cves
    
    def _parse_cve_row(self, row, source_url: str) -> Optional[CVERecord]:
        """Parse individual CVE row"""
        try:
            # Extract CVE ID
            cve_id = None
            cve_match = re.search(r'CVE-\d{4}-\d{4,}', row.get_text())
            if not cve_match:
                return None
            
            cve_id = cve_match.group()
            
            text_content = row.get_text(strip=True)
            
            return CVERecord(
                cve_id=cve_id,
                description=text_content[:500],
                product='Satellite',
                source_url=source_url,
                is_space_related=True
            )
        except Exception as e:
            logger.warning(f"Error parsing CVE row: {e}")
            return None
    
    def _find_next_pages(self, html: str, base_url: str, max_pages: int = 3) -> Set[str]:
        """Find pagination links (limit to reduce crawl time)"""
        try:
            soup = BeautifulSoup(html, 'lxml')
            next_links = set()
            page_count = 0
            
            # Look for next/pagination links
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if any(keyword in href.lower() for keyword in ['next', 'page', 'offset']):
                    if page_count < max_pages:  # Limit pagination depth
                        full_url = urljoin(base_url, href)
                        if URLProcessor.is_valid_url(full_url):
                            next_links.add(URLProcessor.normalize_url(full_url))
                            page_count += 1
            
            return next_links
        except Exception as e:
            logger.warning(f"Error finding next pages: {e}")
            return set()


class VulnersScraper(BaseScraper):
    """Scraper for Vulners vulnerability database"""
    
    def scrape(self, url: str) -> List[CVERecord]:
        """Scrape Vulners for Red Hat Satellite vulnerabilities"""
        cves = []
        try:
            logger.info(f"Scraping Vulners: {url}")
            
            html = self.fetch_url(url)
            if not html:
                return cves
            
            soup = BeautifulSoup(html, 'lxml')
            
            # Find vulnerability entries
            vuln_rows = soup.find_all('div', class_=re.compile('vuln|row', re.I))
            
            for row in vuln_rows:
                cve_record = self._parse_vuln_entry(row, url)
                if cve_record:
                    cves.append(cve_record)
            
            # Extract links to follow
            related_links = self.extract_links(html, url)
            for link in list(related_links)[:5]:  # Limit to 5 related links
                if 'vulners.com' in link and link not in self.visited_urls:
                    logger.info(f"Following Vulners link: {link}")
                    time.sleep(1)
                    cves.extend(self.scrape(link))
        
        except Exception as e:
            logger.error(f"Error scraping Vulners {url}: {e}")
        
        return cves
    
    def _parse_vuln_entry(self, entry, source_url: str) -> Optional[CVERecord]:
        """Parse vulnerability entry"""
        try:
            text = entry.get_text(strip=True)
            
            # Extract CVE ID
            cve_match = re.search(r'CVE-\d{4}-\d{4,}', text)
            if not cve_match:
                return None
            
            cve_id = cve_match.group()
            
            # Extract severity if present
            severity = None
            for sev in ['Critical', 'High', 'Medium', 'Low']:
                if sev.lower() in text.lower():
                    severity = sev
                    break
            
            # Extract CVSS score if present
            cvss_match = re.search(r'CVSS[:\s]+(\d+\.?\d*)', text)
            cvss_score = float(cvss_match.group(1)) if cvss_match else None
            
            return CVERecord(
                cve_id=cve_id,
                description=text[:500],
                product='Red Hat Satellite',
                vendor='Red Hat',
                severity=severity,
                cvss_score=cvss_score,
                source_url=source_url,
                is_space_related=True
            )
        except Exception as e:
            logger.warning(f"Error parsing Vulners entry: {e}")
            return None


class ENISAEU_Scraper(BaseScraper):
    """Scraper for ENISA EU Space Threat Landscape"""
    
    def scrape(self, url: str) -> List[CVERecord]:
        """Scrape ENISA space threat landscape"""
        cves = []
        try:
            logger.info(f"Scraping ENISA: {url}")
            
            html = self.fetch_url(url)
            if not html:
                return cves
            
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract text content
            text_content = soup.get_text()
            
            # Find all CVE IDs
            cve_pattern = r'CVE-\d{4}-\d{4,}'
            cve_matches = set(re.findall(cve_pattern, text_content))
            
            for cve_id in cve_matches:
                idx = text_content.find(cve_id)
                context = text_content[max(0, idx-300):min(len(text_content), idx+300)]
                
                cve = CVERecord(
                    cve_id=cve_id,
                    description=context.strip(),
                    product='Space Threat (ENISA)',
                    vendor='ENISA',
                    source_url=url,
                    is_space_related=True
                )
                cves.append(cve)
            
            # Find related links
            related_links = self.extract_links(html, url, max_links=10)
            for link in list(related_links)[:3]:  # Follow max 3 links
                if link not in self.visited_urls:
                    logger.info(f"Following ENISA link: {link}")
                    time.sleep(1)
                    cves.extend(self.scrape(link))
        
        except Exception as e:
            logger.error(f"Error scraping ENISA {url}: {e}")
        
        return cves
