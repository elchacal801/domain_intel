#!/usr/bin/env python3
"""
match_fingerprints.py

Infrastructure fingerprint matching engine for domain_intel.
Loads YAML fingerprint definitions and matches them against enriched domain
CSV data, producing scored match results.
"""

import argparse
import csv
import glob
import logging
import os
import re
from typing import Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIELD_ALIASES: Dict[str, str] = {
    "ns": "nameservers",
    "mx": "primary_mx",
    "registrar": "registry",
    "country": "cc",
    "title": "http_title",
}

VALID_MATCH_TYPES = {"exact", "contains", "regex", "range"}

REQUIRED_FP_KEYS = {"id", "name", "indicators", "confidence_base"}

REQUIRED_INDICATOR_KEYS = {"field", "match_type", "value"}

OUTPUT_FIELDS = ["domain", "fp_id", "fp_name", "confidence", "flame_tp_ids", "evidence"]

FINGERPRINT_DIR = "config/fingerprints"
DEFAULT_INPUT = "data/dea_domains_probed.csv"
DEFAULT_OUTPUT = "data/fingerprint_matches.csv"


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------

def resolve_field(field: str) -> str:
    """Resolve a field alias to the canonical CSV column name.

    If *field* is a known alias, return the mapped column name; otherwise
    return *field* unchanged (pass-through).
    """
    return FIELD_ALIASES.get(field, field)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def validate_fingerprint(fp: dict, source: str = "<unknown>") -> dict:
    """Validate a fingerprint dict against the required schema.

    Checks that all REQUIRED_FP_KEYS are present, each indicator has the
    required keys and a valid match_type, and pre-compiles any regex
    patterns.  Sets defaults for optional keys.

    Returns the (possibly mutated) fingerprint dict on success.
    Raises ``ValueError`` if validation fails.
    """
    # --- required top-level keys ---
    missing = REQUIRED_FP_KEYS - set(fp.keys())
    if missing:
        raise ValueError(
            f"Fingerprint from {source} missing required key(s): "
            f"{', '.join(sorted(missing))}"
        )

    # --- indicators ---
    indicators = fp.get("indicators", [])
    if not indicators and not fp.get("any_of"):
        raise ValueError(
            f"Fingerprint {fp.get('id', '?')} from {source} has no indicators"
        )

    for idx, ind in enumerate(indicators):
        ind_missing = REQUIRED_INDICATOR_KEYS - set(ind.keys())
        if ind_missing:
            raise ValueError(
                f"Indicator {idx} in {fp['id']} from {source} missing key(s): "
                f"{', '.join(sorted(ind_missing))}"
            )

        if ind["match_type"] not in VALID_MATCH_TYPES:
            raise ValueError(
                f"Indicator {idx} in {fp['id']} from {source} has invalid "
                f"match_type '{ind['match_type']}' "
                f"(valid: {', '.join(sorted(VALID_MATCH_TYPES))})"
            )

        # Resolve field aliases in-place
        ind["field"] = resolve_field(ind["field"])

        # Default 'required' to True if not specified
        ind.setdefault("required", True)

        # Pre-compile regex patterns (guard against excessively long patterns
        # that could cause catastrophic backtracking / ReDoS)
        MAX_REGEX_LEN = 200
        if ind["match_type"] == "regex":
            if len(ind["value"]) > MAX_REGEX_LEN:
                raise ValueError(
                    f"Indicator {idx} in {fp['id']} from {source} has regex "
                    f"exceeding {MAX_REGEX_LEN} chars (length {len(ind['value'])})"
                )
            try:
                ind["_compiled"] = re.compile(ind["value"], re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"Indicator {idx} in {fp['id']} from {source} has invalid "
                    f"regex '{ind['value']}': {exc}"
                )

    # --- any_of: OR semantics, at least one member must match ---
    any_of = fp.get("any_of") or []
    for idx, ind in enumerate(any_of):
        missing_keys = REQUIRED_INDICATOR_KEYS - set(ind.keys())
        if missing_keys:
            raise ValueError(
                f"any_of entry {idx} in {fp.get('id','?')} from {source} missing "
                f"key(s): {', '.join(sorted(missing_keys))}"
            )
        if ind["match_type"] not in VALID_MATCH_TYPES:
            raise ValueError(
                f"any_of entry {idx} in {fp.get('id','?')} from {source} has "
                f"invalid match_type '{ind['match_type']}'"
            )
        ind["field"] = resolve_field(ind["field"])
        if ind["match_type"] == "regex":
            try:
                ind["_compiled"] = re.compile(ind["value"], re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"any_of entry {idx} in {fp.get('id','?')} from {source} has "
                    f"invalid regex '{ind['value']}': {exc}"
                )
    fp["any_of"] = any_of

    # --- refuse fingerprints that gate nothing ---
    # With no required indicator and no any_of, all_required_pass is vacuously
    # true and the fingerprint matches EVERY row. Four shipped in that state,
    # producing ~990k junk match rows and pushing fingerprint_matches.csv past
    # GitHub's 100 MB limit, which broke the daily push. Authors used
    # required:false because the engine had no OR semantics; any_of supplies it.
    if not [i for i in indicators if i.get("required", True)] and not any_of:
        raise ValueError(
            f"Fingerprint {fp.get('id','?')} from {source} has no required "
            f"indicator and no any_of group, so it would match every row. "
            f"Mark an indicator required, or express alternatives as any_of."
        )

    # --- optional key defaults ---
    fp.setdefault("description", "")
    fp.setdefault("version", 1)
    fp.setdefault("confidence_modifiers", [])
    fp.setdefault("flame_tp_ids", [])
    fp.setdefault("ttl_days", 30)

    return fp


# ---------------------------------------------------------------------------
# Indicator matching
# ---------------------------------------------------------------------------

def check_indicator(field_data: str, match_type: str, value: str,
                    compiled_re: Optional[re.Pattern] = None) -> bool:
    """Check whether *field_data* satisfies the indicator condition.

    Supports match types: exact, contains, regex, range.
    Returns ``False`` for empty *field_data* unless match_type is
    ``"exact"`` and *value* is also empty (empty-to-empty match).
    """
    if not field_data:
        return match_type == "exact" and value.strip() == ""

    if match_type == "exact":
        return field_data.strip().lower() == value.strip().lower()

    if match_type == "contains":
        return value.lower() in field_data.lower()

    if match_type == "regex":
        pattern = compiled_re or re.compile(value, re.IGNORECASE)
        return bool(pattern.search(field_data))

    if match_type == "range":
        try:
            lo_str, hi_str = value.split("-", 1)
            lo, hi = int(lo_str), int(hi_str)
            num = int(field_data)
            return lo <= num <= hi
        except (ValueError, TypeError):
            return False

    return False


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def calculate_confidence(fp: dict, row: dict) -> int:
    """Calculate the confidence score for a fingerprint match.

    Starts at ``confidence_base``, then applies each modifier whose
    condition matches the row data.  The final value is clamped to [0, 100].
    """
    score = fp["confidence_base"]

    for mod in fp.get("confidence_modifiers", []):
        field = resolve_field(mod.get("field", ""))
        field_data = row.get(field, "")
        match_type = mod.get("match_type", "exact")
        mod_value = mod.get("value", "")

        if check_indicator(str(field_data), match_type, str(mod_value)):
            score += mod.get("delta", 0)

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Fingerprint evaluation
# ---------------------------------------------------------------------------

def evaluate_fingerprint(fp: dict, row: dict) -> Optional[dict]:
    """Evaluate a single fingerprint against a domain row.

    All required indicators must match (AND logic).  If any required
    indicator fails, returns ``None``.

    Returns a match dict with keys matching OUTPUT_FIELDS on success.
    """
    evidence_parts = []
    all_required_pass = True

    for ind in fp["indicators"]:
        field = ind["field"]
        field_data = str(row.get(field, ""))
        match_type = ind["match_type"]
        value = ind["value"]
        required = ind.get("required", True)

        compiled_re = ind.get("_compiled")
        matched = check_indicator(field_data, match_type, value, compiled_re)

        if matched:
            sep = "~" if match_type == "contains" else "="
            evidence_parts.append(f"{field}{sep}{value}")

        if required and not matched:
            all_required_pass = False
            break  # short-circuit: no need to check further

    if not all_required_pass:
        return None

    # any_of: at least one member must match
    any_of = fp.get("any_of") or []
    if any_of:
        hit = False
        for ind in any_of:
            if check_indicator(str(row.get(ind["field"], "")), ind["match_type"],
                               ind["value"], ind.get("_compiled")):
                hit = True
                sep = "~" if ind["match_type"] == "contains" else "="
                evidence_parts.append(f"{ind['field']}{sep}{ind['value']}")
                break
        if not hit:
            return None

    confidence = calculate_confidence(fp, row)
    evidence = "; ".join(evidence_parts) if evidence_parts else ""

    return {
        "domain": row.get("domain", ""),
        "fp_id": fp["id"],
        "fp_name": fp["name"],
        "confidence": confidence,
        "flame_tp_ids": ";".join(fp.get("flame_tp_ids", [])),
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Domain matching
# ---------------------------------------------------------------------------

def match_domain(row: dict, fingerprints: list) -> list:
    """Match a single domain row against all fingerprints.

    Returns a list of match dicts (one per matching fingerprint).
    """
    matches = []
    for fp in fingerprints:
        result = evaluate_fingerprint(fp, row)
        if result is not None:
            matches.append(result)
    return matches


# ---------------------------------------------------------------------------
# Loading fingerprints
# ---------------------------------------------------------------------------

def load_fingerprints_from_list(fp_dicts: list) -> list:
    """Validate and load fingerprints from a list of dicts (for tests).

    Returns a sorted list (by id) of validated fingerprint dicts.
    """
    fps = []
    for fp in fp_dicts:
        validated = validate_fingerprint(fp, source="list")
        fps.append(validated)
    fps.sort(key=lambda f: f["id"])
    return fps


def load_fingerprints(directory: str = FINGERPRINT_DIR) -> list:
    """Load all YAML fingerprint files from *directory*.

    Globs for ``*.yaml`` files, validates each, and returns a sorted list.
    Bad files are logged and skipped.
    """
    pattern = os.path.join(directory, "*.yaml")
    files = sorted(glob.glob(pattern))

    if not files:
        logger.warning("No fingerprint YAML files found in %s", directory)
        return []

    fps = []
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data is None:
                logger.error("Empty YAML file: %s", fpath)
                continue
            validated = validate_fingerprint(data, source=fpath)
            fps.append(validated)
            logger.info("Loaded fingerprint %s from %s", validated["id"], fpath)
        except yaml.YAMLError as exc:
            logger.error("YAML parse error in %s: %s", fpath, exc)
        except ValueError as exc:
            logger.error("Validation error in %s: %s", fpath, exc)
        except OSError as exc:
            logger.error("Cannot read %s: %s", fpath, exc)

    fps.sort(key=lambda f: f["id"])
    logger.info("Loaded %d fingerprint(s) from %s", len(fps), directory)
    return fps


# ---------------------------------------------------------------------------
# Pipeline run
# ---------------------------------------------------------------------------

def run(input_file: str = DEFAULT_INPUT,
        output_file: str = DEFAULT_OUTPUT,
        fp_dir: str = FINGERPRINT_DIR) -> int:
    """Run the fingerprint matching pipeline.

    Loads fingerprints, reads the input CSV, matches every row, writes
    the output CSV, and returns the total match count.
    """
    fingerprints = load_fingerprints(fp_dir)
    if not fingerprints:
        logger.error("No fingerprints loaded — aborting run")
        return 0

    if not os.path.isfile(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    total_matches = 0
    rows_processed = 0

    try:
        with open(input_file, "r", encoding="utf-8") as fin, \
             open(output_file, "w", encoding="utf-8", newline="") as fout:
            reader = csv.DictReader(fin)
            writer = csv.DictWriter(fout, fieldnames=OUTPUT_FIELDS)
            writer.writeheader()

            for row in reader:
                rows_processed += 1
                matches = match_domain(row, fingerprints)
                for m in matches:
                    writer.writerow(m)
                    total_matches += 1

    except OSError as exc:
        logger.error("I/O error during run: %s", exc)
        return 0

    logger.info(
        "Processed %d rows, wrote %d matches to %s",
        rows_processed, total_matches, output_file,
    )
    return total_matches


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="Match enriched domains against infrastructure fingerprints."
    )
    parser.add_argument(
        "--input", default=DEFAULT_INPUT,
        help=f"Path to the input CSV (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Path to write match results (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--fingerprints", default=FINGERPRINT_DIR,
        help=f"Directory containing fingerprint YAML files (default: {FINGERPRINT_DIR})",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    count = run(
        input_file=args.input,
        output_file=args.output,
        fp_dir=args.fingerprints,
    )
    logger.info("Total matches: %d", count)


if __name__ == "__main__":
    main()
