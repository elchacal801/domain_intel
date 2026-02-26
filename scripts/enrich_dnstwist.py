#!/usr/bin/env python3
"""
enrich_dnstwist.py

Cross-references pipeline domains against dnstwist output to identify
potential typosquat domains. Adds 6 enrichment columns:
  - dnstwist_match: whether the domain was found in the dnstwist output
  - dnstwist_fuzzer: the fuzzer technique used (e.g., homoglyph, addition)
  - dnstwist_target: the brand domain being impersonated
  - redirects_to_brand: whether the domain redirects to the brand
  - registrant_mismatch: whether the registrant differs from the brand
  - ssl_present: whether the domain has an HTTPS response
"""

import argparse
import csv
import logging
import os
from typing import Dict

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Configuration ---

DEFAULT_INPUT = "data/dea_domains_probed.csv"
DEFAULT_OUTPUT = "data/dea_domains_probed.csv"  # in-place enrichment
DEFAULT_DNSTWIST = "data/potential_typosquats.csv"
NEW_COLUMNS = [
    "dnstwist_match",
    "dnstwist_fuzzer",
    "dnstwist_target",
    "redirects_to_brand",
    "registrant_mismatch",
    "ssl_present",
]

# Two-part TLD suffixes where the SLD is part of the TLD structure
TWO_PART_TLDS = frozenset({
    "co.uk", "com.au", "co.nz", "co.za", "co.in", "co.jp", "co.kr",
    "com.br", "com.mx", "com.ar", "com.cn", "com.tw", "com.sg",
    "com.hk", "com.my", "com.pk", "com.ng", "com.eg", "com.tr",
    "com.ua", "com.co", "com.pe", "com.ve", "com.ec", "com.ph",
    "org.uk", "org.au", "net.au", "net.uk", "ac.uk", "gov.uk",
    "gov.au", "edu.au", "co.id", "co.il", "co.th",
})


# --- Core Functions ---


def load_dnstwist_lookup(dnstwist_file: str) -> Dict[str, dict]:
    """Load dnstwist CSV into a domain -> record lookup dict.

    Args:
        dnstwist_file: Path to the dnstwist CSV file.

    Returns:
        Dict mapping lowercase domain -> {"fuzzer": str, "source_target": str}.
        Returns empty dict on missing or empty file.
    """
    lookup: Dict[str, dict] = {}

    if not os.path.isfile(dnstwist_file):
        logger.warning("dnstwist file not found: %s", dnstwist_file)
        return lookup

    try:
        with open(dnstwist_file, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain", "").strip().lower()
                if not domain:
                    continue
                lookup[domain] = {
                    "fuzzer": row.get("fuzzer", "").strip(),
                    "source_target": row.get("source_target", "").strip(),
                }
    except Exception as exc:
        logger.error("Failed to load dnstwist file: %s", exc)

    logger.info("Loaded %d dnstwist entries from %s", len(lookup), dnstwist_file)
    return lookup


def extract_brand_name(domain: str) -> str:
    """Extract the brand label from a domain name.

    Handles two-part TLDs (e.g., co.uk, com.au) and subdomains.

    Examples:
        "amazon.com"       -> "amazon"
        "www.google.com"   -> "google"
        "barclays.co.uk"   -> "barclays"
        ""                 -> ""
    """
    if not domain or not domain.strip():
        return ""

    domain = domain.strip().lower()
    parts = domain.split(".")

    if len(parts) < 2:
        return ""

    # Check if the last two parts form a two-part TLD
    if len(parts) >= 3:
        candidate_tld = ".".join(parts[-2:])
        if candidate_tld in TWO_PART_TLDS:
            # Brand is the part just before the two-part TLD
            # e.g., barclays.co.uk -> parts = [barclays, co, uk]
            # e.g., www.barclays.co.uk -> parts = [www, barclays, co, uk]
            brand_index = len(parts) - 3
            return parts[brand_index] if brand_index >= 0 else ""

    # Standard TLD: brand is the second-to-last part
    # e.g., amazon.com -> parts = [amazon, com]
    # e.g., www.google.com -> parts = [www, google, com]
    return parts[-2]


def check_redirects_to_brand(redirect_target: str, brand_domain: str) -> bool:
    """Check if the redirect target contains the brand domain (case-insensitive).

    Args:
        redirect_target: The URL the domain redirects to.
        brand_domain: The brand domain to look for (e.g., "amazon.com").

    Returns:
        True if brand_domain appears in redirect_target.
    """
    if not redirect_target or not redirect_target.strip():
        return False
    if not brand_domain or not brand_domain.strip():
        return False

    return brand_domain.strip().lower() in redirect_target.strip().lower()


def check_registrant_mismatch(registrant_org: str, brand_domain: str) -> bool:
    """Check if the registrant organization does NOT match the brand.

    Extracts the brand name from brand_domain and checks if it appears
    in registrant_org (case-insensitive). Empty registrant_org defaults
    to True (unknown = suspicious).

    Args:
        registrant_org: The WHOIS registrant organization string.
        brand_domain: The brand domain (e.g., "amazon.com").

    Returns:
        True if there is a mismatch (registrant does not match brand).
    """
    if not registrant_org or not registrant_org.strip():
        return True  # Unknown registrant is suspicious

    brand_name = extract_brand_name(brand_domain)
    if not brand_name:
        return True

    return brand_name.lower() not in registrant_org.strip().lower()


def enrich_row(row: dict, lookup: Dict[str, dict]) -> None:
    """Enrich a single pipeline row in place with dnstwist cross-reference data.

    Args:
        row: A dict representing a CSV row (modified in place).
        lookup: The dnstwist domain -> record lookup dict.
    """
    domain = row.get("domain", "").strip().lower()
    entry = lookup.get(domain)

    if entry:
        brand_domain = entry["source_target"]

        row["dnstwist_match"] = "True"
        row["dnstwist_fuzzer"] = entry["fuzzer"]
        row["dnstwist_target"] = brand_domain

        # Check if domain redirects to the brand
        redirect_target = row.get("http_redirect_target", "")
        row["redirects_to_brand"] = (
            "True" if check_redirects_to_brand(redirect_target, brand_domain) else "False"
        )

        # Check registrant mismatch
        registrant_org = row.get("registrant_org", "")
        row["registrant_mismatch"] = (
            "True" if check_registrant_mismatch(registrant_org, brand_domain) else "False"
        )

        # Check SSL presence (any non-empty https_status)
        https_status = row.get("https_status", "").strip()
        row["ssl_present"] = "True" if https_status else "False"
    else:
        row["dnstwist_match"] = "False"
        row["dnstwist_fuzzer"] = ""
        row["dnstwist_target"] = ""
        row["redirects_to_brand"] = "False"
        row["registrant_mismatch"] = "False"
        row["ssl_present"] = "False"


def run(input_file: str, output_file: str, dnstwist_file: str) -> int:
    """Run the dnstwist cross-reference enrichment pipeline.

    Args:
        input_file: Path to the pipeline CSV (must have a 'domain' column).
        output_file: Path for the enriched output CSV.
        dnstwist_file: Path to the dnstwist potential_typosquats.csv.

    Returns:
        Number of domains that matched dnstwist entries.
    """
    if not os.path.isfile(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    # Load dnstwist lookup
    lookup = load_dnstwist_lookup(dnstwist_file)
    logger.info("dnstwist lookup: %d entries", len(lookup))

    # Read input CSV
    with open(input_file, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) if reader.fieldnames else []
        rows = list(reader)

    if not rows:
        logger.warning("No rows found in input file: %s", input_file)
        return 0

    # Add new columns to fieldnames
    for col in NEW_COLUMNS:
        if col not in fieldnames:
            fieldnames.append(col)

    # Enrich each row
    match_count = 0
    for row in rows:
        enrich_row(row, lookup)
        if row.get("dnstwist_match") == "True":
            match_count += 1

    # Write output
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info(
        "Enriched %d rows, %d dnstwist matches. Output: %s",
        len(rows),
        match_count,
        output_file,
    )
    return match_count


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Cross-reference pipeline domains against dnstwist output"
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV file")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file")
    parser.add_argument(
        "--dnstwist-file",
        default=DEFAULT_DNSTWIST,
        help="dnstwist potential_typosquats.csv file",
    )
    args = parser.parse_args()

    count = run(args.input, args.output, args.dnstwist_file)
    logger.info("Done. %d dnstwist matches found.", count)


if __name__ == "__main__":
    main()
