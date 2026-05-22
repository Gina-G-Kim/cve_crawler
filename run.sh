#!/bin/bash
# Quick Start Guide for CVE Crawler

echo "=========================================="
echo "Space Security CVE Crawler - Quick Start"
echo "=========================================="
echo ""

# Check if in correct directory
if [ ! -f "main.py" ]; then
    echo "Error: Please run from cve_crawler directory"
    exit 1
fi

# Check dependencies
echo "Checking dependencies..."
python3 -c "import requests, bs4" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing dependencies..."
    pip3 install -q requests beautifulsoup4 lxml python-dateutil pandas
fi

echo "Dependencies ready"
echo ""

# Run crawler
echo "Starting CVE crawler..."
echo "This will scrape space security vulnerabilities from:"
echo "  1. GitHub POC repositories"
echo "  2. OpenCVE satellite database"
echo "  3. Vulners Red Hat Satellite CVEs"
echo "  4. ENISA space threat landscape"
echo ""

python3 main.py

echo ""
echo "=========================================="
echo "Crawl Complete!"
echo "=========================================="
echo ""
echo "Output files generated:"
echo "  output/space_cves.json  (JSON format - CWE style)"
echo "  output/space_cves.csv   (CSV format - CWE compatible)"
echo "  output/crawl_report.txt            (Summary report)"
echo ""
