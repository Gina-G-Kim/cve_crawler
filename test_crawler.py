#!/usr/bin/env python3
"""
Test script for CVE Crawler - verify basic functionality
"""
import sys
import os
from models import CVERecord, CrawlSession
from utils import DataExporter, URLProcessor
import json
import csv
from datetime import datetime

def test_models():
    """Test data model creation and conversion"""
    print("\n" + "="*60)
    print("TEST 1: Data Models")
    print("="*60)
    
    # Create sample CVE record
    cve = CVERecord(
        cve_id='CVE-2023-12345',
        description='Test vulnerability in satellite communication system',
        product='Satellite Comm',
        vendor='TestVendor',
        affected_versions='1.0-2.0',
        severity='High',
        cvss_score=7.5,
        cvss_vector='AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        cwe_ids='CWE-123;CWE-456',
        published_date='2023-01-15',
        references='https://example.com',
        source_url='https://github.com/test',
        is_space_related=True
    )
    
    print(f"✓ Created CVE record: {cve.cve_id}")
    print(f"  - Description: {cve.description[:50]}...")
    print(f"  - Severity: {cve.severity}")
    print(f"  - CVSS Score: {cve.cvss_score}")
    
    # Test CSV conversion
    csv_row = cve.to_csv_row()
    print(f"✓ Converted to CSV row with {len(csv_row)} fields")
    
    # Test JSON conversion
    json_data = cve.to_dict()
    print(f"✓ Converted to JSON with {len(json_data)} fields")
    
    return True


def test_url_processor():
    """Test URL processing utilities"""
    print("\n" + "="*60)
    print("TEST 2: URL Processor")
    print("="*60)
    
    test_urls = [
        ('https://github.com/user/repo', True),
        ('https://twitter.com/user', False),
        ('//example.com/path', True),
        ('ftp://invalid.com', False),
    ]
    
    for url, expected_valid in test_urls:
        result = URLProcessor.is_valid_url(url)
        status = "✓" if result == expected_valid else "✗"
        print(f"{status} {url}: valid={result}")
    
    # Test space keyword detection
    texts = [
        ('satellite communication system', True),
        ('weather monitoring', False),
        ('GPS constellation', True),
    ]
    
    print("\nSpace keyword detection:")
    for text, expected in texts:
        result = URLProcessor.is_space_related(text)
        status = "✓" if result == expected else "✗"
        print(f"{status} '{text}': space_related={result}")
    
    return True


def test_export():
    """Test data export functionality"""
    print("\n" + "="*60)
    print("TEST 3: Data Export")
    print("="*60)
    
    # Create test data
    cves = [
        CVERecord(
            cve_id='CVE-2023-00001',
            description='Test CVE 1',
            product='Satellite',
            vendor='TestVendor',
            severity='High',
            source_url='https://test.com/1'
        ),
        CVERecord(
            cve_id='CVE-2023-00002',
            description='Test CVE 2',
            product='Space System',
            vendor='TestVendor2',
            severity='Medium',
            source_url='https://test.com/2'
        ),
    ]
    
    # Create test output directory
    test_output_dir = 'test_output'
    os.makedirs(test_output_dir, exist_ok=True)
    
    # Test JSON export
    json_path = os.path.join(test_output_dir, 'test_export.json')
    result = DataExporter.export_json(cves, json_path)
    if result and os.path.exists(json_path):
        print(f"✓ JSON export successful: {json_path}")
        file_size = os.path.getsize(json_path)
        print(f"  File size: {file_size} bytes")
    else:
        print(f"✗ JSON export failed")
        return False
    
    # Test CSV export
    csv_path = os.path.join(test_output_dir, 'test_export.csv')
    result = DataExporter.export_csv(cves, csv_path)
    if result and os.path.exists(csv_path):
        print(f"✓ CSV export successful: {csv_path}")
        file_size = os.path.getsize(csv_path)
        print(f"  File size: {file_size} bytes")
        
        # Verify CSV content
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            print(f"  Records in CSV: {len(rows)}")
    else:
        print(f"✗ CSV export failed")
        return False
    
    # Cleanup
    import shutil
    shutil.rmtree(test_output_dir)
    print("✓ Test files cleaned up")
    
    return True


def test_crawl_session():
    """Test crawl session tracking"""
    print("\n" + "="*60)
    print("TEST 4: Crawl Session")
    print("="*60)
    
    session = CrawlSession()
    session.sources_crawled.append('https://example.com/1')
    session.sources_crawled.append('https://example.com/2')
    session.total_cves_found = 25
    session.total_links_followed = 100
    
    print(f"✓ Created session at: {session.start_time}")
    print(f"  Sources crawled: {len(session.sources_crawled)}")
    print(f"  Total CVEs: {session.total_cves_found}")
    print(f"  Total links: {session.total_links_followed}")
    
    session.finalize()
    print(f"✓ Session finalized at: {session.end_time}")
    
    return True


def run_all_tests():
    """Run all tests"""
    print("\n" + "🔍 " + "="*56)
    print("CVE CRAWLER - SYSTEM TEST SUITE")
    print("="*60 + "\n")
    
    tests = [
        ("Data Models", test_models),
        ("URL Processor", test_url_processor),
        ("Data Export", test_export),
        ("Crawl Session", test_crawl_session),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ {test_name} FAILED: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print("="*60 + "\n")
    
    return passed == total


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
