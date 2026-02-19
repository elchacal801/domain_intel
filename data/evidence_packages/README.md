# Evidence Packages

This directory contains auto-generated FLAME evidence packages from domain_intel investigations. Each package is a structured markdown snippet ready for insertion into a FLAME threat path file.

## Evidence Package Format

Each `.md` file contains one evidence entry following this structure:

```markdown
### EV-TPXXXX-YYYY-NNN: [Title]
- **Source**: domain_intel investigation [date]
- **Cluster**: [IP] ([Provider], [Country])
- **Domain Count**: [N] domains
- **Key Indicators**: [comma-separated IOCs]
- **CFPF Phase Coverage**: [P1, P2, etc.]
- **Confidence**: [High/Medium/Low]
- **Summary**: [2-3 sentence narrative]
```

## Evidence ID Format

`EV-[TP-ID]-[YYYY]-[NNN]`

| Component | Description |
|-----------|-------------|
| `EV` | Evidence prefix |
| `TP-ID` | FLAME threat path ID (e.g., `TP0003`) |
| `YYYY` | Year of evidence creation |
| `NNN` | Sequential number (001, 002, ...) |

Example: `EV-TP0003-2026-001`

## How to Generate

```bash
# Preview what would be generated
python scripts/generate_evidence.py --dry-run

# Generate with default thresholds (>10 domains per cluster)
python scripts/generate_evidence.py

# Generate with duplicate checking against live FLAME index
python scripts/generate_evidence.py --check-duplicates

# Custom minimum domain threshold
python scripts/generate_evidence.py --min-domains 50
```

## How to Review

Before submitting evidence to FLAME, check each package for:

1. **Accuracy**: Does the cluster data match your investigation notes?
2. **Completeness**: Are key indicators sufficient to be useful without domain_intel context?
3. **OPSEC**: No internal detection context, proprietary tooling names, or customer data.
4. **CFPF Mapping**: Is the phase coverage correct for this evidence?
5. **Confidence**: Is the rating appropriate given the volume and pattern strength?

## How to Submit to FLAME

Evidence submission is **manual** after analyst review:

1. Review generated packages in this directory
2. Open the target threat path file in `flame-fraud/ThreatPaths/TP-XXXX-*.md`
3. Find or create the `## Operational Evidence` section (after Detection Approaches, before References)
4. Copy the evidence entry (the `### EV-*` block) into the section
5. Run the FLAME build: `python scripts/build_database.py`
6. Commit and push to the FLAME repo

## OPSEC Guidance

Evidence packages should **include**:

- Infrastructure patterns (IP clusters, NS patterns, hosting co-location)
- Observable IOCs (domain names, IP addresses, nameservers)
- Domain volume and cluster characteristics
- CFPF phase mapping

Evidence packages should **exclude**:

- Internal company detection rule names or IDs
- Customer-specific incident details
- Proprietary tool names or configurations
- Alert thresholds or tuning parameters
- Internal investigation case numbers
