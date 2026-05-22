"""
Configuration settings for CVE Crawler
"""

# Crawler settings
CRAWLER_CONFIG = {
    'max_retries': 3,
    'timeout': 10,
    'request_delay': 1,  # seconds between requests
    'follow_links_depth': 2,  # how deep to follow linked pages
}

# Scraper-specific settings
SCRAPER_CONFIG = {
    'github': {
        'max_links_per_page': 50,
        'follow_related': True,
    },
    'opencve': {
        'max_pagination_pages': 5,
        'follow_related': True,
    },
    'vulners': {
        'max_related_links': 5,
        'follow_related': True,
    },
    'enisa': {
        'max_related_links': 3,
        'follow_related': True,
    }
}

# Output settings
OUTPUT_CONFIG = {
    'output_directory': 'output',
    'json_filename': 'space_cves_cwe_format.json',
    'csv_filename': 'space_cves_cwe_format.csv',
    'report_filename': 'crawl_report.txt',
    'session_directory': 'sessions',
}

# CVE source URLs
CVE_SOURCES = {
    'github_poc': 'https://github.com/ericyoc/prob_vuln_assess_space_iot_sys_poc',
    'github_enisa': 'https://github.com/enisaeu/Space-Threat-Landscape',
    'opencve_satellite': 'https://app.opencve.io/cve/?q=product%3Asatellite',
    'vulners_redhat': 'https://vulners.com/search/vendors/redhat/products/satellite/versions',
}

# Space-related keywords for filtering
SPACE_KEYWORDS = [
    'satellite', 'space', 'orbital', 'leo', 'geo', 'earth observation',
    'communication satellite', 'gps', 'gnss', 'spacecraft', 'rocket',
    'launch', 'constellation', 'iss', 'cubesat', 'aerospace',
    'spacetime', 'orbital mechanics', 'telemetry', 'payload',
    'ground station', 'uplink', 'downlink'
]

# Logging configuration
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'crawler.log',
    'console': True,
}

# Data export fields (in order)
EXPORT_FIELDS = [
    'cve_id',
    'description',
    'product',
    'vendor',
    'affected_versions',
    'severity',
    'cvss_score',
    'cvss_vector',
    'cwe_ids',
    'published_date',
    'last_updated',
    'references',
    'source_url',
    'mitigation',
    'impact',
    'is_space_related',
    'discovery_date',
]
