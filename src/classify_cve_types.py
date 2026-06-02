#!/usr/bin/env python3
"""
🛰️ CVE Product Type Classification - Taxonomy-First Strategy

Classify each CVE into a 3-level type hierarchy (Category | Type | Sub-Type).

SATELLITE-FIRST CLASSIFICATION STRATEGY

Supports both Hardware and Software products through a two-tier classification system:

1️⃣ TAXONOMY-BASED (Primary - 🛰️ CHECKED FIRST)
   Source: config/satellite_asset_taxonomy.json
   Strategy: Match CVE products to satellite-specific assets
   Output Format: Category | Type > Sub-Type | Asset Name
   Examples:
     - Hardware | System > Flight Computer | OBC(On-Board Computer)
     - Software | Module > Service | Message Transfer
     - Software | Func > Executive Service | Software Bus Service (SB)
     - Application | Module > Data Management | Memory Access Manager
   Priority: HIGH (checked first)

2️⃣ LEGACY KEYWORD RULES (Fallback)
   Source: CATEGORY_RULES in this script
   Strategy: Match CVE products to generic software/hardware categories
   Output Format: Category | Type | Product Name
   Examples:
     - Software | Operating System | ubuntu_linux
     - Software | Library | struts
     - Hardware | Firmware | ios_xe
   Priority: MEDIUM (checked after Taxonomy fails)

3️⃣ VENDOR-BASED RULES (Fallback)
   Strategy: Detect known hardware vendors
   Priority: LOW

4️⃣ CATCH-ALL (Default)
   Output: Software | Application

Classification Priority (first match wins):
  ⭐ 1. Taxonomy Rules (satellite_asset_taxonomy.json) - SATELLITE-SPECIFIC
  🔧 2. Legacy Keyword Rules (CATEGORY_RULES) - GENERIC
  🏢 3. Vendor Rules (HW_VENDORS) - VENDOR-BASED
  🎯 4. Catch-all (Software | Application) - DEFAULT

Key Improvements:
  - Taxonomy rules checked FIRST for domain-specific accuracy
  - Relaxed keyword filtering (>= 3 chars instead of >= 5)
  - Proper handling of acronyms (OBC, CAN, RTC, OSAL, etc.)
  - Clear separation between satellite-specific and generic classification

Output:
  - output/space_cves_with_type.csv
  - output/space_cves_with_type.json
  - output/cve_type_taxonomy.txt
"""

import csv
import json
import os
import re
import sys
from dataclasses import dataclass
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_CSV = os.path.join(BASE_DIR, "data", "output", "space_cves.csv")
INPUT_JSON = os.path.join(BASE_DIR, "data", "output", "space_cves.json")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "output", "space_cves_with_type.csv")
OUTPUT_JSON = os.path.join(BASE_DIR, "data", "output", "space_cves_with_type.json")
OUTPUT_TXT = os.path.join(BASE_DIR, "data", "output", "cve_type_taxonomy.txt")

def get_taxonomy_path():
    """Get taxonomy path from CLI arg or default."""
    if len(sys.argv) > 1:
        path = sys.argv[1]
        # Convert relative path to absolute if needed
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        return path
    return os.path.join(BASE_DIR, "config", "satellite_asset_taxonomy.json")

TAXONOMY_JSON = get_taxonomy_path()


@dataclass
class TypeRule:
    """A single classification rule."""
    category: str
    type_level: str
    keywords: list  # list of lower-case keywords (substring match)
    priority: int


@dataclass
class TaxonomyRule:
    """A taxonomy-derived classification rule (Category > Type > Sub-Type > Asset)."""
    category: str
    type_level: str
    sub_type: str
    asset_name: str
    traceability: str
    keywords: list


# Vendors whose products are primarily hardware (for vendor-based classification)
HW_VENDORS = {
    "amd", "cisco", "dell", "hpe", "hewlett packard", "hewlett-packard",
    "hitachi", "honeywell", "fortinet", "juniper", "checkpoint",
    "zte", "huawei", "ericsson", "nokia", "avaya", "mitel",
    "dahua", "hikvision", "samsung", "xerox", "fujitsu",
    "siemens", "rockwell", "microchip", "delta", "almac",
    "avtech", "tvtech", "totolink", "tenda", "cayin",
    "hms", "ge", "general electric", "omron", "abb",
    "schneider", "pfeiffer", "tesla", "vnetsecurity",
    "b&r", "b&", "firewalla", "alarm.com", "d-link",
    "gl-inet", "lore", "annke", "d3dsecurity", "thermo",
    "palo alto", "omnivise", "skysea", "motorola",
}


CATEGORY_RULES: list[TypeRule] = [
    # ==== 1. Software | Operating System (priority 1) ====
    # OS rules are checked first so OS products are correctly classified
    # regardless of vendor. Network device OSes (fortios, ios_xe, etc.)
    # are explicitly listed in the Firmware rule below and matched there.
    TypeRule(
        "Software", "Operating System",
        [
            # Generic OS indicators
            "linux", "windows", "solaris", "freebsd", "macos",
            "tvos", "watchos", "visionos", "android",
            # Mobile OS
            "iphone_os", "ipados",
            # HarmonyOS (Huawei)
            "harmonyos",
            # ChromeOS
            "chromeos",
            # Distro-specific
            "ubuntu_linux", "enterprise_linux", "suse_linux_enterprise",
            "amazon_linux", "red_hat_enterprise_linux", "rhel",
            "fedora", "centos", "debian", "arch", "alpine",
            "openwrt", "kali", "coreos", "raspberry_pi",
            # Windows specific
            "windows_10", "windows_11", "windows_2000", "windows_2003",
            "windows_server", "windows_vista", "windows_xp",
            "windows_2012", "windows_2016", "windows_2019", "windows_2022",
        ],
        1,
    ),

    # ==== 2. Hardware | Firmware (priority 2) ====
    # Network device OS and embedded firmware keywords
    TypeRule(
        "Hardware", "Firmware",
        [
            # Embedded firmware
            "firmware",
            "bios",
            "uefi",
            "bootloader",
            # Network device OS / firmware
            "fortios", "arubaos", "instantos", "pan-os", "nx-os",
            "ios_xe", "ios_xr", "mellanox_os",
        ],
        2,
    ),

    # ==== 3. Hardware | Hardware (priority 20) ====
    # Products whose name indicates physical hardware components
    # Keywords are chosen to be SPECIFIC enough to avoid false positives
    TypeRule(
        "Hardware", "Hardware",
        [
            # CPU / GPU / SoC
            "processor", "epyc", "ryzen", "instinct", "radeon",
            "xeon", "threadripper", "gpu", "max_series",
            # Industrial automation
            "simatic", "siemens_logo", "siplus", "plc",
            "micro850", "micro870", "st7_scadaconnect", "scada",
            # Networking devices (use specific model names to avoid false positives)
            # NOTE: modem, access_point, router, switch removed — false positives
            "ethernet_network_controllers", "ethernet_adapters",
            # Specific networking hardware (Siemens)
            "scalancem812",
            # Specific hardware models (Syrotech)
            "syrotech",
            # Specific networking hardware (Cisco, Arista, etc.)
            "catalyst_sd_wan", "asa", "adaptive_security",
            "cisco_small_business",
            # Specific hardware models (Arista)
            "arista",
            # Specific hardware models (Extreme)
            "extreme_networks",
            # Visual / sensor devices
            "telepresence", "camera", "dvr", "cctv",
            # "scanner" and "printer" removed — no products match in the dataset
            # "display" and "monitor" removed — too broad, matches apps/libraries
            # Cameras (Cisco)
            "wvc200", "wvc210", "wvc2300", "wvc2400",
            "rvs4000", "pvc2300",
            # IP Phones (Cisco)
            "ip phones",
            # Specific hardware models (Oracle storage)
            "solidfire", "santricity", "storagegrid",
            "data_manager_appliance",
            # Specific hardware models (Mitel)
            "6863i", "6865i", "6867i", "6869i", "6873i",
            "6905", "6910", "6915", "6920w", "6920",
            "6930w", "6930", "6940w", "6940", "6970", "9700",
            # Specific hardware models (GL-iNet)
            "a1300", "a3002r", "a3100r", "a3700r", "ax1800",
            "b1300", "b2200", "e750", "mt1300", "mt2500",
            "mt3000", "mt300n", "mv1000", "n300", "x3000",
            "x300b", "x5000r", "x750", "xe3000", "xe300",
            "usb150", "sf1200", "sft1200",
            # Specific hardware models (Honeywell)
            "pc42",
            # Specific hardware models (Motorola)
            "q14_mesh",
            # Specific hardware models (HMS)
            "ewon_cosy",
            # Specific hardware models (D-Link)
            "dsr-1000", "dsr-150", "dsr-250", "dsr-500",
            # Specific hardware models (Thermo Fisher)
            "dt80_dex",
            # Specific hardware models (Lorex)
            "edge2_lh330", "edge3_lh340", "edge+_lh320",
            "edge_lh310",
            # Specific hardware models (Siemens)
            "ruggedcom_ape1808", "simatic_s7", "siplus_s7",
            # Specific hardware models (Oracle/Sparc)
            "sparc_enterprise_m", "sparc_enterprise_e",
            # Specific hardware models (Oracle/Networking)
            "s12700", "s1300", "s2700", "s2750", "s3700",
            "s5700", "s5710", "s5720", "s6700", "s7700",
            # Specific hardware models (Cisco)
            "big-ip",
            # Specific hardware models (Avtech)
            "avm1203",
            # Specific hardware models (Tenda)
            "ac10", "ac18", "fh1201",
            # Specific hardware models (D-Link)
            "dir-300", "dir-820", "dir-823", "dir-860",
            # Specific hardware models (Annke)
            "crater_2",
            # Specific hardware models (D3D Security)
            "d8801",
            # Specific hardware models (GL-inet)
            "ar300m", "ar750", "ar750s",
            # Specific hardware models (Omnivise)
            "t3000",
            # Specific hardware models (Rockwell)
            "1756",
            # Specific hardware models (Dell EMC)
            "insightiq",
            "bigiq",
        ],
        20,
    ),

    # ==== 4. Software | Library (priority 30) ====
    # Programming language libraries, frameworks, packages
    TypeRule(
        "Software", "Library",
        [
            # Language runtimes / standard libraries
            "java", "php", "python", "ruby", "go", "perl", "rust",
            "dotnet", ".net", "csharp", "scala", "jvm", "j2ee",
            "django", "spring_boot", "nodejs", "javascript",
            # Specific libraries / frameworks
            "twisted", "telejson", "sshj", "sshlib", "zlib",
            "streamlit", "streamlit-geospatial", "socialdriver-framework",
            "struts", "xwork", "dojo", "celery", "pillow", "flask",
            "fastapi", "numpy", "pandas", "scipy", "scikit-learn",
            "keras", "matplotlib", "plotly",
            # Package managers / build tools
            "pypi", "npm", "composer", "maven", "gradle", "pip",
            "gem", "cocoapods", "carthage",
            # CSS / JS frameworks
            "bootstrap", "tailwindcss", "jquery",
            "angular", "react", "vue", "svelte", "ember",
            "nextjs", "nuxtjs", "laravel",
            # CMS / CMS frameworks
            "wordpress", "drupal", "joomla", "magento",
            "concrete_cms", "xwiki-platform", "xwiki-pro-macros",
            "shopware",
            # ML / Data
            "tensorflow",
            # Dev tools
            "visual_studio",
            # Protocol / serialization
            "protobuf", "grpc",
        ],
        30,
    ),

    # ==== 5. Software | Application (priority 100, catch-all) ====
    # Default fallback: any product not matched by higher-priority rules
    # This ensures all products get a classification
    TypeRule(
        "Software", "Application",
        [],  # Empty keyword list: matches everything (catch-all)
        100,
    ),

]


def normalize_text(value: str) -> str:
    """Normalize text for robust substring matching."""
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def keyword_variants(value: str) -> list:
    """Generate keyword variants for tolerant matching."""
    base = normalize_text(value)
    if not base:
        return []

    variants = {base, base.replace(" ", "")}

    # Keep short acronym in parentheses, e.g., "OS(Operating System)" -> "os"
    acronyms = re.findall(r"\(([^)]+)\)", value)
    for acronym in acronyms:
        acronym_norm = normalize_text(acronym)
        if acronym_norm:
            variants.add(acronym_norm)
            variants.add(acronym_norm.replace(" ", ""))

    return sorted(v for v in variants if v)


def load_taxonomy_rules() -> list[TaxonomyRule]:
    """Load taxonomy JSON and flatten it into matching rules."""
    if not os.path.exists(TAXONOMY_JSON):
        return []

    with open(TAXONOMY_JSON, encoding="utf-8") as f:
        data = json.load(f)

    root = data.get("satellite_asset_taxonomy", {})
    categories = root.get("categories", [])
    rules: list[TaxonomyRule] = []

    for category_obj in categories:
        category = (category_obj.get("category") or "").strip()
        for type_obj in category_obj.get("types", []):
            type_level = (type_obj.get("type") or "").strip()
            for sub_type_obj in type_obj.get("sub_types", []):
                sub_type = (sub_type_obj.get("sub_type") or "").strip()
                for asset in sub_type_obj.get("assets", []):
                    asset_name = (asset.get("name") or "").strip()
                    if not asset_name:
                        continue
                    traceability = (asset.get("traceability") or "").strip()

                    # Match by asset name primarily, but also allow sub-type hints.
                    keywords = keyword_variants(asset_name) + keyword_variants(sub_type)
                    keywords = sorted(set(k for k in keywords if k))

                    # 🛰️ IMPROVED: Relaxed keyword filtering for satellite asset classification
                    # Previously: Only kept keywords >= 5 chars (too restrictive)
                    # Now: Keep keywords >= 3 chars OR acronyms from parentheses
                    # This allows matching common satellite components like "CAN Bus", "RTC", "OBC", etc.
                    
                    acronyms = set()
                    # Collect acronyms from the original asset name
                    for m in re.finditer(r"\(([A-Za-z]+)\)", asset_name):
                        acronyms.add(m.group(1).lower())
                    # Also from sub_type
                    for m in re.finditer(r"\(([A-Za-z]+)\)", sub_type):
                        acronyms.add(m.group(1).lower())

                    # CHANGE: Relax filter from >= 5 to >= 3 for better satellite asset matching
                    keywords = [k for k in keywords if len(k) >= 3 or k in acronyms]
                    
                    # Ensure acronyms are included even if filtered
                    keywords.extend(list(acronyms))
                    keywords = sorted(set(keywords))

                    rules.append(
                        TaxonomyRule(
                            category=category or "Software",
                            type_level=type_level or "Application",
                            sub_type=sub_type or "General",
                            asset_name=asset_name,
                            traceability=traceability,
                            keywords=keywords,
                        )
                    )

    return rules


TAXONOMY_RULES = None  # Loaded dynamically in main()


# ==== Helper functions ====

def get_primary_vendor(vendor_str: str) -> str:
    """Return the first vendor from semicolon-separated list."""
    return vendor_str.split(";")[0].strip() if vendor_str.strip() else ""


def get_primary_product(product_str: str) -> str:
    """Return the first product from semicolon-separated list."""
    return product_str.split(";")[0].strip() if product_str.strip() else ""


def get_all_products(product_str: str) -> list:
    """Return all products from semicolon-separated list."""
    return [p.strip() for p in product_str.split(";") if p.strip()]


def classify_product(product_str: str, vendor_str: str = "") -> tuple:
    """
    Classify product with Taxonomy-First strategy.
    
    ⭐ TAXONOMY-FIRST STRATEGY (Satellite-specific classification prioritized)
    
    Priority order:
    1. 🛰️ Taxonomy rules (satellite_asset_taxonomy.json) - **SATELLITE-SPECIFIC** 
       Output: Category | Type > Sub-Type | Asset Name
       Examples: Software | Module > Service | Message Transfer
    
    2. 🔧 Legacy keyword rules (CATEGORY_RULES) - Generic fallback
       Output: Category | Type | Product Name  
       Examples: Software | Operating System | ubuntu_linux
    
    3. 🏢 Vendor-based rules - Known hardware vendors
    
    4. 🎯 Catch-all - Software | Application (default)
    
    This ensures satellite-specific classification takes precedence over
    generic rules, maintaining domain-specific accuracy.
    """
    all_prods = get_all_products(product_str)
    if not all_prods:
        return ("Software", "Application", "Unknown")

    # 1️⃣ TAXONOMY RULES FIRST (🛰️ Satellite-specific, HIGH priority)
    for prod in all_prods:
        prod_lower = prod.lower()
        prod_compact = prod_lower.replace("_", "").replace("-", "").replace(" ", "")
        
        for rule in TAXONOMY_RULES:
            for keyword in rule.keywords:
                # Check both normalized and compact versions
                if keyword in prod_lower or keyword in prod_compact:
                    mapped_type = f"{rule.type_level} > {rule.sub_type}"
                    return (rule.category, mapped_type, rule.asset_name)

    # 2️⃣ LEGACY KEYWORD RULES (🔧 Generic, FALLBACK)
    for rule in CATEGORY_RULES:
        if not rule.keywords:  # Skip catch-all rule for now
            continue
        for prod in all_prods:
            prod_lower = prod.lower()
            for keyword in rule.keywords:
                if keyword in prod_lower:
                    return (rule.category, rule.type_level, prod)

    # 3️⃣ VENDOR-BASED RULES (🏢 Known hardware vendors)
    if vendor_str:
        for vendor in vendor_str.split(";"):
            vendor_lower = vendor.strip().lower()
            # Skip vendors that make both HW and SW
            if "github" in vendor_lower:
                continue
            matched_hw_vendor = None
            for hw_vendor in HW_VENDORS:
                # Use word boundary matching to avoid false positives
                # (e.g., "naturalintelligence" should NOT match "intel")
                if re.search(rf'\b{re.escape(hw_vendor)}\b', vendor_lower):
                    matched_hw_vendor = hw_vendor
                    break

            if not matched_hw_vendor:
                continue

            # Known HW vendor: classify based on product keywords
            for prod in all_prods:
                prod_lower = prod.lower()
                # Firmware keywords
                if any(kw in prod_lower for kw in ["firmware", "bios", "uefi", "bootloader"]):
                    return ("Hardware", "Firmware", prod)
                # Network device OS
                if any(kw in prod_lower for kw in ["fortios", "arubaos", "instantos", "pan-os", "nx-os", "ios_xe", "ios_xr", "mellanox_os"]):
                    return ("Hardware", "Firmware", prod)
                # CPU/GPU keywords
                if any(kw in prod_lower for kw in ["processor", "epyc", "ryzen", "instinct", "radeon", "xeon", "threadripper", "gpu", "max_series"]):
                    return ("Hardware", "Hardware", prod)
                # Other HW keywords
                if any(kw in prod_lower for kw in ["solidfire", "santricity", "storagegrid", "big-ip", "data_manager_appliance", "insightiq", "bigiq", "sparc_enterprise", "simatic_s7", "ruggedcom", "q14_mesh", "ewon_cosy", "dt80_dex", "pc42", "avm1203", "1756"]):
                    return ("Hardware", "Hardware", prod)

            # Default to Hardware for known HW vendors with no matching keywords
            return ("Hardware", "Hardware", all_prods[0])

    # 4️⃣ CATCH-ALL (🎯 Default fallback)
    return ("Software", "Application", all_prods[0])


def build_product_info(vendor_str: str, product_str: str) -> str:
    """Build human-readable product info: Vendor — Product."""
    vendor = get_primary_vendor(vendor_str)
    product = get_primary_product(product_str)
    if vendor and product:
        # Replace underscores with spaces, title-case
        return f"{vendor} — {product.replace('_', ' ')}"
    return ""


def write_taxonomy(type_counts: dict, type_desc: dict) -> list:
    """Build taxonomy text content."""
    lines = [
        "CVE Product Type Taxonomy",
        "=" * 40,
        "",
        "Structure: Category | Type | (Sub-Type if applicable)",
        "",
        "Primary Source: CATEGORY_RULES (legacy keyword rules)",
        "Secondary Source: config/satellite_asset_taxonomy.json",
        "Tertiary Source: Hardware Vendor Detection (HW_VENDORS)",
        "Fallback: Software | Application (catch-all)",
        "",
        "Level 1 — Category:",
        "  Hardware  : Physical devices, chips, sensors, controllers, etc.",
        "  Software  : Programs, libraries, services, OS, etc.",
        "",
        "Level 2 — Type (from CATEGORY_RULES):",
        "  Operating System     : OS-level software (Linux, Windows, etc.)",
        "  Firmware             : Firmware/BIOS embedded in hardware",
        "  Hardware             : Physical hardware components",
        "  Library              : Libraries, frameworks, language runtimes",
        "  Application          : Standalone applications and services (default)",
        "",
        "Level 2+ — Type (from Taxonomy, optional):",
        "  Taxonomy > Sub-Type  : Detailed satellite asset classification",
        "                         e.g., 'Software | Func > Platform Support'",
        "",
        "Classification Priority (first match wins):",
        "  1. ⭐ Taxonomy Rules (satellite_asset_taxonomy.json) - SATELLITE-SPECIFIC",
        "  2. 🔧 Legacy Keyword Rules (CATEGORY_RULES) - GENERIC",
        "  3. 🏢 Vendor Rules (HW_VENDORS) - VENDOR-BASED",
        "  4. 🎯 Catch-all: Software | Application - DEFAULT",
        "",
        "-" * 40,
        "Type Distribution",
        "-" * 40,
        "",
    ]

    for key in sorted(type_counts, key=lambda k: type_counts[k], reverse=True):
        lines.append(f"  {key}")
        lines.append(f"    Count: {type_counts[key]}")
        # Convert set to sorted list and take first 3 examples
        examples = sorted(type_desc.get(key, set()))[:3]
        lines.append(f"    Examples: {', '.join(examples)}")
        lines.append("")

    return lines


def main():
    global TAXONOMY_RULES
    
    print("=" * 60)

    TAXONOMY_RULES = load_taxonomy_rules()
    print(f"Loaded {len(TAXONOMY_RULES)} taxonomy rules from {TAXONOMY_JSON}")
    print("CVE Product Type Classification")
    print("=" * 60)

    # --- Load CSV ---
    with open(INPUT_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        csv_headers = list(reader.fieldnames)
        rows = list(reader)

    print(f"\nLoaded {len(rows)} CVE records from CSV")

    # --- Classify each row ---
    type_counts: dict[str, int] = defaultdict(int)
    type_desc: dict[str, set] = defaultdict(set)  # type -> set of unique example products (no duplicates)

    for row in rows:
        category, type_level, product_name = classify_product(row["x_cve_product"], row["x_cve_vendor"])
        product_info = build_product_info(row["x_cve_vendor"], row["x_cve_product"])

        row["CVE_type"] = f"{category} | {type_level} | {product_name}"
        row["CVE_product_info"] = product_info

        key = f"{category} | {type_level}"
        type_counts[key] += 1
        # Use set to collect unique products, collect up to 10 then sample
        if len(type_desc[key]) < 10:
            type_desc[key].add(product_name)

    # --- Write CSV ---
    out_headers = csv_headers + ["CVE_type", "CVE_product_info"]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=out_headers)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {OUTPUT_CSV}")

    # --- Load & update JSON ---
    with open(INPUT_JSON, encoding="utf-8") as f:
        json_data = json.load(f)

    for obj in json_data.get("objects", []):
        if obj.get("type") == "vulnerability":
            cve_id = obj.get("x_cve_id", "")
            matching_row = next(
                (r for r in rows if r["x_cve_id"] == cve_id), None
            )
            if matching_row:
                obj["cve_type"] = matching_row["CVE_type"]
                obj["cve_product_info"] = matching_row["CVE_product_info"]

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"Wrote JSON to {OUTPUT_JSON}")

    # --- Write taxonomy ---
    taxonomy_lines = write_taxonomy(type_counts, type_desc)
    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(taxonomy_lines))
    print(f"Wrote taxonomy to {OUTPUT_TXT}")

    # --- Summary ---
    print("\n" + "-" * 40)
    print("Classification Summary")
    print("-" * 40)
    for key in sorted(type_counts, key=lambda k: type_counts[k], reverse=True):
        print(f"  {key}: {type_counts[key]}")
    total = sum(type_counts.values())
    print(f"\nTotal: {total} CVEs classified")

    # Show HW vs SW summary
    hw_total = sum(v for k, v in type_counts.items() if k.startswith("Hardware"))
    sw_total = sum(v for k, v in type_counts.items() if k.startswith("Software"))
    print(f"  Hardware total: {hw_total}")
    print(f"  Software total: {sw_total}")
    print("=" * 60)


if __name__ == "__main__":
    main()
