# Unified Regulatory Intelligence Feed Pipeline — Design Document

**Date:** 2026-02-26
**Status:** Approved
**Repos:** flame-fraud (primary), domain_intel (bridge)

## Goal

Build a unified regulatory intelligence feed that ingests data from 6 US regulatory/law enforcement sources, maps alerts to FLAME threat paths via config-driven mapping, and surfaces regulatory velocity in both the FLAME dashboard and domain_intel briefings.

## Architecture

Single monolithic ingestion script (`scripts/fetch_regulatory_data.py`) in the FLAME repo with a pluggable `RegulatorySource` base class and 6 concrete implementations. Output is a normalized CSV consumed by `build_database.py`, which creates a new `regulatory_alerts` table and exports `regulatory-alerts.json`. The domain_intel bridge extends `flame_client.py` and `ai_briefing.py` to consume this data.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Data access for FinCEN/IC3 | PDF parsing (pdfplumber) | Comprehensive coverage, these sources only publish PDFs |
| TP mapping | Config-driven YAML table | Auditable, explicit, easy to update |
| Storage model | New separate table + JSON export | Clean separation from TP schema |
| Bridge model | Extend existing briefing | Enriches current workflow, no new scripts |

---

## Section 1: Ingestion Script

**File:** `flame-fraud/scripts/fetch_regulatory_data.py`

### Source Implementations

| Source | Class | Access Method | Parser | Frequency |
|--------|-------|---------------|--------|-----------|
| FinCEN SAR | `FinCENSource` | PDF download | pdfplumber table extraction | Quarterly |
| CFPB Complaints | `CFPBSource` | REST API (`api.consumerfinance.gov`) | JSON response | Weekly |
| FBI IC3 | `FBIC3Source` | PDF download | pdfplumber + regex | Annual |
| OCC Alerts | `OCCSource` | RSS feed | feedparser | Daily |
| SEC Enforcement | `SECSource` | RSS/EDGAR API | feedparser | Daily |
| OFAC SDN | `OFACSource` | XML download (sdn.xml) | xml.etree | Daily |

### Base Class

```python
class RegulatorySource(ABC):
    name: str

    @abstractmethod
    def fetch(self) -> Any:
        """Download raw data from source."""

    @abstractmethod
    def parse(self, raw_data: Any) -> List[RegulatoryAlert]:
        """Parse raw data into normalized alerts."""
```

### Data Model

```python
@dataclass
class RegulatoryAlert:
    source: str          # e.g., "fincen", "cfpb"
    alert_id: str        # unique per source
    title: str
    date: str            # ISO 8601
    category: str        # source-native category
    mapped_tp_ids: list  # from config mapping
    url: str             # source URL
    severity: str        # "high" / "medium" / "low"
    summary: str         # truncated description
```

### TP Mapping Config

**File:** `flame-fraud/config/regulatory_sources.yaml`

```yaml
sources:
  fincen:
    enabled: true
    url: "https://www.fincen.gov/reports/sar-stats"
    category_mapping:
      "Business Email Compromise": ["TP-0002"]
      "Identity Theft": ["TP-0005", "TP-0015"]
      "Unauthorized Electronic Intrusion": ["TP-0001"]
      "Check Fraud": ["TP-0010"]
      "Wire Transfer Fraud": ["TP-0002", "TP-0001"]
  cfpb:
    enabled: true
    base_url: "https://api.consumerfinance.gov/data/research/complaints"
    category_mapping:
      "Credit card": ["TP-0005"]
      "Money transfer": ["TP-0002"]
      "Checking or savings account": ["TP-0001"]
  fbi_ic3:
    enabled: true
    url: "https://www.ic3.gov/AnnualReport"
    category_mapping:
      "BEC/EAC": ["TP-0002"]
      "Identity Theft": ["TP-0005", "TP-0015"]
      "Phishing/Vishing/Smishing/Pharming": ["TP-0001", "TP-0007"]
  occ:
    enabled: true
    feed_url: "https://www.occ.gov/news-issuances/bulletins/rss.xml"
    category_mapping:
      "Enforcement Action": ["TP-0001"]
  sec:
    enabled: true
    feed_url: "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type=LIT&dateb=&owner=include&count=40&search_text=&action=getcompany&output=atom"
    category_mapping:
      "Securities Fraud": ["TP-0012"]
  ofac:
    enabled: true
    sdn_url: "https://www.treasury.gov/ofac/downloads/sdn.xml"
    category_mapping:
      "SDN List Addition": ["TP-0008"]
```

### Output

CSV at `flame-fraud/data/regulatory_alerts.csv`:
```
alert_id,source,title,date,category,mapped_tp_ids,url,severity,summary
```

### Dependencies

Add to `flame-fraud/requirements.txt`:
- `pdfplumber`
- `feedparser`

---

## Section 2: FLAME Build Process Updates

**File:** `flame-fraud/scripts/build_database.py` (modify)

### New SQLite Tables

```sql
CREATE TABLE IF NOT EXISTS regulatory_alerts (
    alert_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    date TEXT,
    category TEXT,
    severity TEXT,
    url TEXT,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS regulatory_alert_tp_mapping (
    alert_id TEXT NOT NULL,
    tp_id TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES regulatory_alerts(alert_id),
    FOREIGN KEY (tp_id) REFERENCES submissions(id)
);

CREATE INDEX IF NOT EXISTS idx_reg_source ON regulatory_alerts(source);
CREATE INDEX IF NOT EXISTS idx_reg_date ON regulatory_alerts(date);
CREATE INDEX IF NOT EXISTS idx_reg_tp ON regulatory_alert_tp_mapping(tp_id);
```

### New JSON Export

**File:** `flame-fraud/database/regulatory-alerts.json`

```json
[
  {
    "alert_id": "fincen-2025-sar-bec-001",
    "source": "fincen",
    "title": "BEC-Related Suspicious Activity Reports Increase 47%",
    "date": "2025-12-15",
    "category": "Business Email Compromise",
    "severity": "high",
    "url": "https://www.fincen.gov/...",
    "summary": "FinCEN reports 47% increase in BEC-related SARs...",
    "mapped_tp_ids": ["TP-0002"]
  }
]
```

### Stats Update

`flame-stats.json` gets a new `regulatoryAlerts` section:

```json
{
  "regulatoryAlerts": {
    "total": 142,
    "bySeverity": {"high": 23, "medium": 89, "low": 30},
    "bySource": {"fincen": 12, "cfpb": 45, "occ": 30, "sec": 25, "ofac": 18, "fbi_ic3": 12},
    "lastUpdated": "2026-02-26"
  }
}
```

### Build Flow

New `_build_regulatory_alerts(conn, root_dir)` function called from `main()` after existing TP processing. Reads `data/regulatory_alerts.csv`, inserts into tables, exports JSON.

---

## Section 3: UI & CI Integration (FLAME)

### Frontend (`app.js`)

- New "Regulatory Pulse" panel on the dashboard
- Fetches `regulatory-alerts.json` alongside existing data
- Per-source alert counts with severity color coding
- TP detail pages show linked regulatory alerts (filtered by `mapped_tp_ids`)
- Simple table view: date, source badge, title, severity pill, link to original

### CI Workflow Updates

**Modify:** `flame-fraud/.github/workflows/update-database.yml`
- Add trigger path: `data/regulatory_alerts.csv`
- Add step before `Build database`:
  ```yaml
  - name: Fetch regulatory data
    run: python scripts/fetch_regulatory_data.py --output data/regulatory_alerts.csv
    timeout-minutes: 15
    continue-on-error: true
  ```

**New:** `flame-fraud/.github/workflows/fetch-regulatory.yml`
- Scheduled trigger: `cron: '0 6 * * 1-5'` (weekdays 6 AM UTC)
- Fetches all 6 sources → commits `data/regulatory_alerts.csv` to main
- Triggers `update-database.yml` via path change

---

## Section 4: domain_intel Bridge

### flame_client.py

**File:** `domain_intel/scripts/shared/flame_client.py` (modify)

New function:
```python
def get_regulatory_alerts() -> List[Dict[str, Any]]:
    """Fetch regulatory-alerts.json from FLAME GitHub Pages.
    Same 3-tier fallback: fresh cache → network → stale cache → empty.
    Separate cache file: data/.flame_cache/regulatory-alerts.json
    """
```

### Config

**File:** `domain_intel/config/defaults.yaml` (modify)

```yaml
flame:
  regulatory_alerts_url: "https://elchacal801.github.io/flame-fraud/database/regulatory-alerts.json"
```

### ai_briefing.py

**File:** `domain_intel/scripts/ai_briefing.py` (modify)

New section in data summary after `[FLAME Evidence Candidates]`:

```
[Regulatory Pulse]
Active Regulatory Alerts: {total} total ({high} high, {medium} medium, {low} low)
By Source: FinCEN ({n}), CFPB ({n}), OCC ({n}), SEC ({n}), OFAC ({n}), FBI IC3 ({n})
TP-Linked Alerts:
    - TP-0002 (BEC): 15 alerts (8 high severity)
    - TP-0001 (ATO): 12 alerts (5 high severity)
    ...
```

Cross-references `flame_tp_distribution` from AI classifications with regulatory alert counts per TP to identify convergence between observed threats and regulatory activity.

LLM prompt addition:
> "If Regulatory Pulse data is present, include a 'Regulatory Landscape' section assessing how regulatory enforcement trends align with observed threat activity."

---

## Testing Strategy

- Unit tests for each `RegulatorySource` parser (mock HTTP responses)
- Integration test for `build_database.py` regulatory table creation
- Unit test for `flame_client.get_regulatory_alerts()` with cache/network/fallback
- Unit test for `ai_briefing.py` regulatory pulse section formatting
- E2E: run `fetch_regulatory_data.py` with `--dry-run` flag to validate parsing without network calls

## Error Handling

- Each source has `continue-on-error` behavior — one source failing doesn't block others
- PDF parsing failures logged with source name and URL, returns empty list
- Network timeouts: 30s per source, 15min total CI timeout
- Empty/malformed responses: skip source, log warning, continue
