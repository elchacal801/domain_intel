# Unified Regulatory Intelligence Feed — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a unified regulatory intelligence feed that ingests data from 6 US regulatory sources, maps to FLAME threat paths, and surfaces regulatory velocity in the FLAME dashboard and domain_intel briefings.

**Architecture:** Single monolithic `fetch_regulatory_data.py` in FLAME repo with `RegulatorySource` base class and 6 concrete implementations. Output normalized CSV consumed by `build_database.py` via new `regulatory_alerts` table + JSON export. domain_intel bridge extends `flame_client.py` and `ai_briefing.py`.

**Tech Stack:** Python 3.12, pdfplumber, feedparser, xml.etree, requests, sqlite3, pytest

**Repos:**
- **FLAME:** `/c/Users/anon/Documents/anon/repos/flame-fraud` (Tasks 1–7)
- **domain_intel:** `/c/Users/anon/Documents/anon/repos/domain_intel` (Task 8)

---

### Task 1: RegulatoryAlert Model + Base Class + Config

**Files:**
- Create: `flame-fraud/scripts/regulatory/__init__.py`
- Create: `flame-fraud/scripts/regulatory/models.py`
- Create: `flame-fraud/scripts/regulatory/base.py`
- Create: `flame-fraud/config/regulatory_sources.yaml`
- Create: `flame-fraud/tests/test_regulatory_models.py`

**Context:** The FLAME repo has no `config/` directory yet — we create it. Scripts live under `scripts/`. Tests use `sys.path.insert(0, ...)` to import from scripts (see existing `tests/test_build_database.py:16`).

**Step 1: Write the failing test for RegulatoryAlert dataclass**

```python
# tests/test_regulatory_models.py
"""Tests for regulatory feed models and config loading."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from regulatory.models import RegulatoryAlert, load_source_config


class TestRegulatoryAlert:
    def test_create_alert(self):
        alert = RegulatoryAlert(
            source="fincen",
            alert_id="fincen-2025-001",
            title="BEC SARs Increase",
            date="2025-12-15",
            category="Business Email Compromise",
            mapped_tp_ids=["TP-0002"],
            url="https://www.fincen.gov/example",
            severity="high",
            summary="FinCEN reports increase in BEC SARs.",
        )
        assert alert.source == "fincen"
        assert alert.mapped_tp_ids == ["TP-0002"]

    def test_alert_to_csv_row(self):
        alert = RegulatoryAlert(
            source="cfpb",
            alert_id="cfpb-2025-001",
            title="Credit Card Complaints Rise",
            date="2025-11-01",
            category="Credit card",
            mapped_tp_ids=["TP-0005"],
            url="https://api.consumerfinance.gov/...",
            severity="medium",
            summary="Complaints increased.",
        )
        row = alert.to_csv_row()
        assert row["alert_id"] == "cfpb-2025-001"
        assert row["mapped_tp_ids"] == "TP-0005"

    def test_alert_multiple_tp_ids_serialized(self):
        alert = RegulatoryAlert(
            source="fincen",
            alert_id="fincen-2025-002",
            title="Identity Theft SARs",
            date="2025-12-20",
            category="Identity Theft",
            mapped_tp_ids=["TP-0005", "TP-0015"],
            url="https://www.fincen.gov/example2",
            severity="high",
            summary="Identity theft reports.",
        )
        row = alert.to_csv_row()
        assert row["mapped_tp_ids"] == "TP-0005|TP-0015"


class TestLoadSourceConfig:
    def test_load_valid_config(self, tmp_path):
        cfg_file = tmp_path / "regulatory_sources.yaml"
        cfg_file.write_text(
            "sources:\n"
            "  fincen:\n"
            "    enabled: true\n"
            "    url: 'https://example.com'\n"
            "    category_mapping:\n"
            "      'BEC': ['TP-0002']\n"
        )
        config = load_source_config(cfg_file)
        assert "fincen" in config["sources"]
        assert config["sources"]["fincen"]["enabled"] is True

    def test_load_missing_config_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_source_config(tmp_path / "nonexistent.yaml")
```

**Step 2: Run test to verify it fails**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_regulatory_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'regulatory'`

**Step 3: Write minimal implementation**

```python
# scripts/regulatory/__init__.py
"""Regulatory intelligence feed sources."""

# scripts/regulatory/models.py
"""Data models for regulatory alerts."""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml


CSV_COLUMNS = [
    "alert_id", "source", "title", "date", "category",
    "mapped_tp_ids", "url", "severity", "summary",
]


@dataclass
class RegulatoryAlert:
    """Normalized alert from any regulatory source."""
    source: str
    alert_id: str
    title: str
    date: str
    category: str
    mapped_tp_ids: List[str] = field(default_factory=list)
    url: str = ""
    severity: str = "medium"
    summary: str = ""

    def to_csv_row(self) -> Dict[str, str]:
        return {
            "alert_id": self.alert_id,
            "source": self.source,
            "title": self.title,
            "date": self.date,
            "category": self.category,
            "mapped_tp_ids": "|".join(self.mapped_tp_ids),
            "url": self.url,
            "severity": self.severity,
            "summary": self.summary,
        }


def load_source_config(config_path: Path) -> Dict[str, Any]:
    """Load and validate the regulatory sources YAML config."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
```

```python
# scripts/regulatory/base.py
"""Base class for regulatory data sources."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class RegulatorySource(ABC):
    """Abstract base for a regulatory data source."""

    name: str = "unknown"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.category_mapping = config.get("category_mapping", {})

    def map_category_to_tps(self, category: str) -> List[str]:
        """Look up TP IDs for a source-native category string."""
        return self.category_mapping.get(category, [])

    @abstractmethod
    def fetch(self) -> Any:
        """Download raw data from the source. Returns source-specific format."""

    @abstractmethod
    def parse(self, raw_data: Any) -> List[RegulatoryAlert]:
        """Parse raw data into normalized RegulatoryAlert objects."""

    def run(self) -> List[RegulatoryAlert]:
        """Fetch and parse, with error handling."""
        if not self.enabled:
            logger.info("Source %s is disabled, skipping", self.name)
            return []
        try:
            raw = self.fetch()
            alerts = self.parse(raw)
            logger.info("Source %s: fetched %d alerts", self.name, len(alerts))
            return alerts
        except Exception as exc:
            logger.error("Source %s failed: %s", self.name, exc)
            return []
```

```yaml
# config/regulatory_sources.yaml
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
      "Structuring": ["TP-0008"]
      "Money Laundering": ["TP-0008"]
  cfpb:
    enabled: true
    base_url: "https://api.consumerfinance.gov/data/research/complaints"
    category_mapping:
      "Credit card or prepaid card": ["TP-0005"]
      "Money transfer, virtual currency, or money service": ["TP-0002"]
      "Checking or savings account": ["TP-0001"]
      "Debt collection": []
      "Mortgage": []
  fbi_ic3:
    enabled: true
    url: "https://www.ic3.gov/AnnualReport"
    category_mapping:
      "BEC/EAC": ["TP-0002"]
      "Identity Theft": ["TP-0005", "TP-0015"]
      "Phishing/Vishing/Smishing/Pharming": ["TP-0001", "TP-0007"]
      "Investment": ["TP-0012"]
      "Tech Support": ["TP-0017"]
      "Ransomware": ["TP-0001"]
  occ:
    enabled: true
    feed_url: "https://www.occ.gov/news-issuances/bulletins/rss.xml"
    category_mapping:
      "Enforcement Action": ["TP-0001"]
      "Bulletin": []
  sec:
    enabled: true
    feed_url: "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type=LIT&dateb=&owner=include&count=40&search_text=&action=getcompany&output=atom"
    category_mapping:
      "Litigation Release": ["TP-0012"]
      "Administrative Proceeding": ["TP-0012"]
  ofac:
    enabled: true
    sdn_url: "https://www.treasury.gov/ofac/downloads/sdn.xml"
    category_mapping:
      "SDN List Addition": ["TP-0008"]
      "Specially Designated National": ["TP-0008"]
```

**Step 4: Run test to verify it passes**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_regulatory_models.py -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/flame-fraud
git add scripts/regulatory/__init__.py scripts/regulatory/models.py scripts/regulatory/base.py config/regulatory_sources.yaml tests/test_regulatory_models.py
git commit -m "feat: add regulatory alert model, base source class, and config"
```

---

### Task 2: Structured Source Implementations (CFPB, OCC, SEC, OFAC)

**Files:**
- Create: `flame-fraud/scripts/regulatory/sources/__init__.py`
- Create: `flame-fraud/scripts/regulatory/sources/cfpb.py`
- Create: `flame-fraud/scripts/regulatory/sources/occ.py`
- Create: `flame-fraud/scripts/regulatory/sources/sec.py`
- Create: `flame-fraud/scripts/regulatory/sources/ofac.py`
- Create: `flame-fraud/tests/test_regulatory_sources_structured.py`

**Context:** These 4 sources use machine-readable formats (REST API, RSS, XML). No PDF parsing needed. `feedparser` parses RSS/Atom; `xml.etree.ElementTree` parses OFAC SDN XML.

**Step 1: Write the failing tests**

```python
# tests/test_regulatory_sources_structured.py
"""Tests for structured regulatory sources (CFPB, OCC, SEC, OFAC)."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from xml.etree.ElementTree import Element, SubElement, tostring

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from regulatory.sources.cfpb import CFPBSource
from regulatory.sources.occ import OCCSource
from regulatory.sources.sec import SECSource
from regulatory.sources.ofac import OFACSource


# --- CFPB ---

class TestCFPBSource:
    def setup_method(self):
        self.config = {
            "enabled": True,
            "base_url": "https://api.consumerfinance.gov/data/research/complaints",
            "category_mapping": {
                "Credit card or prepaid card": ["TP-0005"],
                "Checking or savings account": ["TP-0001"],
            },
        }
        self.source = CFPBSource(self.config)

    def test_name(self):
        assert self.source.name == "cfpb"

    @patch("regulatory.sources.cfpb.requests.get")
    def test_parse_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "hits": {"hits": [
                {
                    "_source": {
                        "complaint_id": "12345",
                        "product": "Credit card or prepaid card",
                        "date_received": "2025-11-01",
                        "issue": "Fraud or scam",
                        "company": "Acme Bank",
                        "complaint_what_happened": "Unauthorized charges on my card.",
                    }
                }
            ]}
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        raw = self.source.fetch()
        alerts = self.source.parse(raw)
        assert len(alerts) == 1
        assert alerts[0].source == "cfpb"
        assert alerts[0].alert_id == "cfpb-12345"
        assert alerts[0].mapped_tp_ids == ["TP-0005"]


# --- OCC ---

class TestOCCSource:
    def setup_method(self):
        self.config = {
            "enabled": True,
            "feed_url": "https://www.occ.gov/news-issuances/bulletins/rss.xml",
            "category_mapping": {
                "Enforcement Action": ["TP-0001"],
            },
        }
        self.source = OCCSource(self.config)

    def test_name(self):
        assert self.source.name == "occ"

    @patch("regulatory.sources.occ.feedparser.parse")
    def test_parse_rss_entries(self, mock_parse):
        mock_parse.return_value = MagicMock(
            entries=[
                MagicMock(
                    id="https://occ.gov/bulletin/123",
                    title="Enforcement Action Against Bank X",
                    published="2025-12-01T00:00:00Z",
                    link="https://occ.gov/bulletin/123",
                    summary="OCC issues enforcement action.",
                    **{"get": lambda k, d="": {
                        "tags": [MagicMock(term="Enforcement Action")]
                    }.get(k, d)}
                )
            ]
        )
        raw = self.source.fetch()
        alerts = self.source.parse(raw)
        assert len(alerts) >= 1
        assert alerts[0].source == "occ"


# --- SEC ---

class TestSECSource:
    def setup_method(self):
        self.config = {
            "enabled": True,
            "feed_url": "https://www.sec.gov/cgi-bin/browse-edgar",
            "category_mapping": {
                "Litigation Release": ["TP-0012"],
            },
        }
        self.source = SECSource(self.config)

    def test_name(self):
        assert self.source.name == "sec"

    @patch("regulatory.sources.sec.feedparser.parse")
    def test_parse_atom_entries(self, mock_parse):
        mock_parse.return_value = MagicMock(
            entries=[
                MagicMock(
                    id="sec-lr-12345",
                    title="SEC Charges Company With Securities Fraud",
                    published="2025-12-15T00:00:00Z",
                    link="https://sec.gov/litigation/12345",
                    summary="SEC files charges...",
                )
            ]
        )
        raw = self.source.fetch()
        alerts = self.source.parse(raw)
        assert len(alerts) >= 1
        assert alerts[0].source == "sec"
        assert alerts[0].mapped_tp_ids == ["TP-0012"]


# --- OFAC ---

class TestOFACSource:
    def setup_method(self):
        self.config = {
            "enabled": True,
            "sdn_url": "https://www.treasury.gov/ofac/downloads/sdn.xml",
            "category_mapping": {
                "SDN List Addition": ["TP-0008"],
            },
        }
        self.source = OFACSource(self.config)

    def test_name(self):
        assert self.source.name == "ofac"

    @patch("regulatory.sources.ofac.requests.get")
    def test_parse_sdn_xml(self, mock_get):
        # Build minimal SDN XML
        root = Element("sdnList", xmlns="http://tempuri.org/sdnList.xsd")
        pub = SubElement(root, "publshInformation")
        pub_date = SubElement(pub, "Publish_Date")
        pub_date.text = "12/15/2025"
        entry = SubElement(root, "sdnEntry")
        uid = SubElement(entry, "uid")
        uid.text = "12345"
        sdn_type = SubElement(entry, "sdnType")
        sdn_type.text = "Individual"
        first = SubElement(entry, "firstName")
        first.text = "John"
        last = SubElement(entry, "lastName")
        last.text = "DOE"
        programs = SubElement(entry, "programList")
        prog = SubElement(programs, "program")
        prog.text = "SDGT"

        mock_resp = MagicMock()
        mock_resp.content = tostring(root)
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        raw = self.source.fetch()
        alerts = self.source.parse(raw)
        assert len(alerts) >= 1
        assert alerts[0].source == "ofac"
        assert "DOE" in alerts[0].title
```

**Step 2: Run test to verify it fails**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_regulatory_sources_structured.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'regulatory.sources'`

**Step 3: Add `feedparser` to requirements.txt**

Modify `flame-fraud/requirements.txt` — append:
```
feedparser
```

Install: `pip install feedparser`

**Step 4: Write implementations**

```python
# scripts/regulatory/sources/__init__.py
"""Regulatory source implementations."""

# scripts/regulatory/sources/cfpb.py
"""CFPB Consumer Complaints API source."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class CFPBSource(RegulatorySource):
    name = "cfpb"

    def fetch(self) -> Dict[str, Any]:
        """Query CFPB Complaints API for recent fraud-related complaints."""
        url = self.config.get("base_url", "")
        params = {
            "size": 100,
            "sort": "created_date_desc",
            "date_received_min": "",  # filled at runtime
            "no_aggs": True,
        }
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def parse(self, raw_data: Dict[str, Any]) -> List[RegulatoryAlert]:
        hits = raw_data.get("hits", {}).get("hits", [])
        alerts = []
        for hit in hits:
            src = hit.get("_source", {})
            complaint_id = str(src.get("complaint_id", ""))
            product = src.get("product", "")
            tp_ids = self.map_category_to_tps(product)
            alerts.append(RegulatoryAlert(
                source=self.name,
                alert_id=f"cfpb-{complaint_id}",
                title=src.get("issue", product),
                date=src.get("date_received", ""),
                category=product,
                mapped_tp_ids=tp_ids,
                url=f"https://www.consumerfinance.gov/data-research/consumer-complaints/search/detail/{complaint_id}",
                severity="medium",
                summary=(src.get("complaint_what_happened", "") or "")[:500],
            ))
        return alerts
```

```python
# scripts/regulatory/sources/occ.py
"""OCC Bulletins RSS feed source."""
from __future__ import annotations

import logging
from typing import Any, List

import feedparser

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class OCCSource(RegulatorySource):
    name = "occ"

    def fetch(self) -> Any:
        url = self.config.get("feed_url", "")
        return feedparser.parse(url)

    def parse(self, raw_data: Any) -> List[RegulatoryAlert]:
        alerts = []
        for entry in raw_data.entries:
            entry_id = getattr(entry, "id", "") or getattr(entry, "link", "")
            title = getattr(entry, "title", "")
            # Determine category from tags or title keywords
            category = "Bulletin"
            tags = getattr(entry, "tags", [])
            if tags:
                category = tags[0].get("term", "Bulletin") if isinstance(tags, list) and tags else "Bulletin"
            elif "enforcement" in title.lower():
                category = "Enforcement Action"

            tp_ids = self.map_category_to_tps(category)
            alerts.append(RegulatoryAlert(
                source=self.name,
                alert_id=f"occ-{hash(entry_id) & 0xFFFFFFFF:08x}",
                title=title,
                date=getattr(entry, "published", ""),
                category=category,
                mapped_tp_ids=tp_ids,
                url=getattr(entry, "link", ""),
                severity="medium" if tp_ids else "low",
                summary=(getattr(entry, "summary", "") or "")[:500],
            ))
        return alerts
```

```python
# scripts/regulatory/sources/sec.py
"""SEC EDGAR RSS/Atom feed source."""
from __future__ import annotations

import logging
from typing import Any, List

import feedparser

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class SECSource(RegulatorySource):
    name = "sec"

    def fetch(self) -> Any:
        url = self.config.get("feed_url", "")
        return feedparser.parse(url)

    def parse(self, raw_data: Any) -> List[RegulatoryAlert]:
        alerts = []
        for entry in raw_data.entries:
            entry_id = getattr(entry, "id", "")
            title = getattr(entry, "title", "")
            category = "Litigation Release"
            if "administrative" in title.lower():
                category = "Administrative Proceeding"
            tp_ids = self.map_category_to_tps(category)
            alerts.append(RegulatoryAlert(
                source=self.name,
                alert_id=f"sec-{hash(entry_id) & 0xFFFFFFFF:08x}",
                title=title,
                date=getattr(entry, "published", ""),
                category=category,
                mapped_tp_ids=tp_ids,
                url=getattr(entry, "link", ""),
                severity="high" if tp_ids else "medium",
                summary=(getattr(entry, "summary", "") or "")[:500],
            ))
        return alerts
```

```python
# scripts/regulatory/sources/ofac.py
"""OFAC SDN List XML source."""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any, List

import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)

# OFAC SDN XML namespace
_NS = {"sdn": "http://tempuri.org/sdnList.xsd"}


class OFACSource(RegulatorySource):
    name = "ofac"

    def fetch(self) -> bytes:
        url = self.config.get("sdn_url", "")
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        return resp.content

    def parse(self, raw_data: bytes) -> List[RegulatoryAlert]:
        root = ET.fromstring(raw_data)
        # Handle both namespaced and non-namespaced XML
        entries = root.findall("sdnEntry") or root.findall("sdn:sdnEntry", _NS)

        pub_date = ""
        pub_info = root.find("publshInformation") or root.find("sdn:publshInformation", _NS)
        if pub_info is not None:
            pd = pub_info.find("Publish_Date") or pub_info.find("sdn:Publish_Date", _NS)
            if pd is not None and pd.text:
                pub_date = pd.text

        alerts = []
        for entry in entries:
            uid_el = entry.find("uid") or entry.find("sdn:uid", _NS)
            uid = uid_el.text if uid_el is not None else ""
            first_el = entry.find("firstName") or entry.find("sdn:firstName", _NS)
            last_el = entry.find("lastName") or entry.find("sdn:lastName", _NS)
            first = first_el.text if first_el is not None else ""
            last = last_el.text if last_el is not None else ""
            sdn_type_el = entry.find("sdnType") or entry.find("sdn:sdnType", _NS)
            sdn_type = sdn_type_el.text if sdn_type_el is not None else ""

            title = f"{first} {last}".strip() if first else last or f"SDN-{uid}"
            programs_el = entry.find("programList") or entry.find("sdn:programList", _NS)
            programs = []
            if programs_el is not None:
                for prog in programs_el:
                    if prog.text:
                        programs.append(prog.text)

            tp_ids = self.map_category_to_tps("SDN List Addition")
            alerts.append(RegulatoryAlert(
                source=self.name,
                alert_id=f"ofac-{uid}",
                title=f"OFAC SDN: {title} ({sdn_type})",
                date=pub_date,
                category="SDN List Addition",
                mapped_tp_ids=tp_ids,
                url="https://www.treasury.gov/ofac/downloads/sdn.xml",
                severity="high",
                summary=f"Programs: {', '.join(programs)}" if programs else "",
            ))
        return alerts
```

**Step 5: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_regulatory_sources_structured.py -v`
Expected: PASS (all tests)

**Step 6: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/flame-fraud
git add scripts/regulatory/sources/ tests/test_regulatory_sources_structured.py requirements.txt
git commit -m "feat: add CFPB, OCC, SEC, OFAC regulatory source implementations"
```

---

### Task 3: PDF Source Implementations (FinCEN, FBI IC3)

**Files:**
- Create: `flame-fraud/scripts/regulatory/sources/fincen.py`
- Create: `flame-fraud/scripts/regulatory/sources/fbi_ic3.py`
- Create: `flame-fraud/tests/test_regulatory_sources_pdf.py`

**Context:** FinCEN publishes SAR statistics as PDF tables. FBI IC3 publishes annual Internet Crime Reports as PDFs. Both require `pdfplumber` for table/text extraction. Tests mock pdfplumber to avoid actual PDF files.

**Step 1: Write the failing tests**

```python
# tests/test_regulatory_sources_pdf.py
"""Tests for PDF-based regulatory sources (FinCEN, FBI IC3)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from regulatory.sources.fincen import FinCENSource
from regulatory.sources.fbi_ic3 import FBIC3Source


class TestFinCENSource:
    def setup_method(self):
        self.config = {
            "enabled": True,
            "url": "https://www.fincen.gov/reports/sar-stats",
            "category_mapping": {
                "Business Email Compromise": ["TP-0002"],
                "Identity Theft": ["TP-0005", "TP-0015"],
            },
        }
        self.source = FinCENSource(self.config)

    def test_name(self):
        assert self.source.name == "fincen"

    def test_parse_extracted_tables(self):
        """Test parsing of pre-extracted table data (mocking pdfplumber)."""
        # Simulate pdfplumber table extraction result
        mock_tables = [
            [
                ["Suspicious Activity Type", "2024 Count", "2023 Count"],
                ["Business Email Compromise", "45,678", "31,234"],
                ["Identity Theft", "89,012", "72,345"],
                ["Wire Transfer Fraud", "12,345", "10,123"],
            ]
        ]
        alerts = self.source.parse(mock_tables)
        assert len(alerts) >= 2
        bec_alerts = [a for a in alerts if "Business Email Compromise" in a.category]
        assert len(bec_alerts) == 1
        assert bec_alerts[0].mapped_tp_ids == ["TP-0002"]

    def test_parse_empty_tables(self):
        alerts = self.source.parse([])
        assert alerts == []


class TestFBIC3Source:
    def setup_method(self):
        self.config = {
            "enabled": True,
            "url": "https://www.ic3.gov/AnnualReport",
            "category_mapping": {
                "BEC/EAC": ["TP-0002"],
                "Phishing/Vishing/Smishing/Pharming": ["TP-0001", "TP-0007"],
            },
        }
        self.source = FBIC3Source(self.config)

    def test_name(self):
        assert self.source.name == "fbi_ic3"

    def test_parse_extracted_text(self):
        """Test parsing of pre-extracted PDF text (mocking pdfplumber)."""
        mock_text = (
            "Crime Type                   Victims    Loss\n"
            "BEC/EAC                      21,832     $2,946,830,270\n"
            "Phishing/Vishing/Smishing/Pharming  300,497  $18,728,550\n"
            "Investment                   39,570     $4,568,089,661\n"
        )
        alerts = self.source.parse(mock_text)
        assert len(alerts) >= 2
        bec = [a for a in alerts if "BEC" in a.category]
        assert len(bec) == 1
        assert bec[0].mapped_tp_ids == ["TP-0002"]

    def test_parse_empty_text(self):
        alerts = self.source.parse("")
        assert alerts == []
```

**Step 2: Run test to verify it fails**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_regulatory_sources_pdf.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'regulatory.sources.fincen'`

**Step 3: Add `pdfplumber` to requirements.txt**

Modify `flame-fraud/requirements.txt` — append:
```
pdfplumber
```

Install: `pip install pdfplumber`

**Step 4: Write implementations**

```python
# scripts/regulatory/sources/fincen.py
"""FinCEN SAR Statistics PDF source."""
from __future__ import annotations

import io
import logging
import re
from typing import Any, List

import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class FinCENSource(RegulatorySource):
    name = "fincen"

    def fetch(self) -> List[List[List[str]]]:
        """Download FinCEN SAR statistics PDF and extract tables."""
        try:
            import pdfplumber
        except ImportError:
            logger.error("pdfplumber not installed — cannot parse FinCEN PDFs")
            return []

        url = self.config.get("url", "")
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()

        tables = []
        with pdfplumber.open(io.BytesIO(resp.content)) as pdf:
            for page in pdf.pages:
                page_tables = page.extract_tables()
                if page_tables:
                    tables.extend(page_tables)
        return tables

    def parse(self, raw_data: List[List[List[str]]]) -> List[RegulatoryAlert]:
        if not raw_data:
            return []

        alerts = []
        alert_idx = 0
        for table in raw_data:
            if len(table) < 2:
                continue
            header = table[0]
            for row in table[1:]:
                if not row or not row[0]:
                    continue
                category = row[0].strip()
                tp_ids = self.map_category_to_tps(category)
                # Extract count from second column if available
                count_str = row[1].strip() if len(row) > 1 else ""
                count_val = re.sub(r"[^\d]", "", count_str)

                alert_idx += 1
                severity = "high" if tp_ids else "medium"
                alerts.append(RegulatoryAlert(
                    source=self.name,
                    alert_id=f"fincen-sar-{alert_idx:04d}",
                    title=f"FinCEN SAR: {category}",
                    date="",  # filled from PDF metadata if available
                    category=category,
                    mapped_tp_ids=tp_ids,
                    url=self.config.get("url", ""),
                    severity=severity,
                    summary=f"SAR filings: {count_val}" if count_val else "",
                ))
        return alerts
```

```python
# scripts/regulatory/sources/fbi_ic3.py
"""FBI IC3 Annual Internet Crime Report PDF source."""
from __future__ import annotations

import io
import logging
import re
from typing import Any, List

import requests

from regulatory.base import RegulatorySource
from regulatory.models import RegulatoryAlert

logger = logging.getLogger(__name__)


class FBIC3Source(RegulatorySource):
    name = "fbi_ic3"

    def fetch(self) -> str:
        """Download FBI IC3 annual report PDF and extract text."""
        try:
            import pdfplumber
        except ImportError:
            logger.error("pdfplumber not installed — cannot parse IC3 PDFs")
            return ""

        url = self.config.get("url", "")
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()

        text_parts = []
        with pdfplumber.open(io.BytesIO(resp.content)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
        return "\n".join(text_parts)

    def parse(self, raw_data: str) -> List[RegulatoryAlert]:
        if not raw_data:
            return []

        # Pattern: "Crime Type   Victims   Loss"
        # Match lines like: "BEC/EAC                      21,832     $2,946,830,270"
        pattern = re.compile(
            r"^([\w/\s]+?)\s{2,}([\d,]+)\s+\$?([\d,]+)",
            re.MULTILINE
        )

        alerts = []
        alert_idx = 0
        for match in pattern.finditer(raw_data):
            category = match.group(1).strip()
            victims = match.group(2).strip()
            loss = match.group(3).strip()
            tp_ids = self.map_category_to_tps(category)

            alert_idx += 1
            alerts.append(RegulatoryAlert(
                source=self.name,
                alert_id=f"ic3-{alert_idx:04d}",
                title=f"IC3: {category}",
                date="",  # from report year
                category=category,
                mapped_tp_ids=tp_ids,
                url=self.config.get("url", ""),
                severity="high" if tp_ids else "medium",
                summary=f"Victims: {victims}, Loss: ${loss}",
            ))
        return alerts
```

**Step 5: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_regulatory_sources_pdf.py -v`
Expected: PASS (all tests)

**Step 6: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/flame-fraud
git add scripts/regulatory/sources/fincen.py scripts/regulatory/sources/fbi_ic3.py tests/test_regulatory_sources_pdf.py requirements.txt
git commit -m "feat: add FinCEN and FBI IC3 PDF-based regulatory sources"
```

---

### Task 4: CLI Orchestration Script

**Files:**
- Create: `flame-fraud/scripts/fetch_regulatory_data.py`
- Create: `flame-fraud/tests/test_fetch_regulatory_data.py`

**Context:** This is the main entry point. It loads config, instantiates all 6 sources, runs them, merges results, and writes the output CSV. CLI flags: `--output` (CSV path), `--config` (YAML path), `--dry-run` (parse only, no file write), `--sources` (comma-separated list to run).

**Step 1: Write the failing tests**

```python
# tests/test_fetch_regulatory_data.py
"""Tests for the regulatory data fetch orchestrator."""
import csv
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from fetch_regulatory_data import collect_alerts, write_csv, SOURCE_REGISTRY
from regulatory.models import RegulatoryAlert, CSV_COLUMNS


class TestSourceRegistry:
    def test_all_sources_registered(self):
        assert "cfpb" in SOURCE_REGISTRY
        assert "occ" in SOURCE_REGISTRY
        assert "sec" in SOURCE_REGISTRY
        assert "ofac" in SOURCE_REGISTRY
        assert "fincen" in SOURCE_REGISTRY
        assert "fbi_ic3" in SOURCE_REGISTRY


class TestCollectAlerts:
    def test_collect_from_single_source(self):
        mock_source = MagicMock()
        mock_source.run.return_value = [
            RegulatoryAlert(
                source="test", alert_id="t-001", title="Test",
                date="2025-01-01", category="Test Cat",
                mapped_tp_ids=["TP-0001"], url="", severity="low",
                summary="A test alert.",
            )
        ]
        alerts = collect_alerts({"test": mock_source})
        assert len(alerts) == 1

    def test_collect_handles_source_failure(self):
        mock_source = MagicMock()
        mock_source.run.return_value = []  # source failed gracefully
        alerts = collect_alerts({"failing": mock_source})
        assert alerts == []


class TestWriteCSV:
    def test_write_produces_valid_csv(self, tmp_path):
        alerts = [
            RegulatoryAlert(
                source="cfpb", alert_id="cfpb-001", title="Test",
                date="2025-01-01", category="Credit card",
                mapped_tp_ids=["TP-0005"], url="https://example.com",
                severity="medium", summary="Test summary.",
            ),
        ]
        out_file = tmp_path / "alerts.csv"
        write_csv(alerts, out_file)

        with open(out_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["alert_id"] == "cfpb-001"
        assert rows[0]["mapped_tp_ids"] == "TP-0005"
        assert set(reader.fieldnames) == set(CSV_COLUMNS)

    def test_write_empty_alerts(self, tmp_path):
        out_file = tmp_path / "empty.csv"
        write_csv([], out_file)
        with open(out_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0
        assert set(reader.fieldnames) == set(CSV_COLUMNS)
```

**Step 2: Run test to verify it fails**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_fetch_regulatory_data.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'fetch_regulatory_data'`

**Step 3: Write implementation**

```python
#!/usr/bin/env python3
# scripts/fetch_regulatory_data.py
"""
Unified Regulatory Intelligence Feed — Ingestion Orchestrator

Fetches data from 6 US regulatory/law enforcement sources, normalizes
to RegulatoryAlert format, maps categories to FLAME threat path IDs
via config, and writes a consolidated CSV for build_database.py.

Usage:
    python scripts/fetch_regulatory_data.py
    python scripts/fetch_regulatory_data.py --output data/regulatory_alerts.csv
    python scripts/fetch_regulatory_data.py --dry-run --sources cfpb,occ
"""
from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path
from typing import Dict, List

from regulatory.models import RegulatoryAlert, CSV_COLUMNS, load_source_config
from regulatory.sources.cfpb import CFPBSource
from regulatory.sources.occ import OCCSource
from regulatory.sources.sec import SECSource
from regulatory.sources.ofac import OFACSource
from regulatory.sources.fincen import FinCENSource
from regulatory.sources.fbi_ic3 import FBIC3Source

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

SOURCE_REGISTRY = {
    "cfpb": CFPBSource,
    "occ": OCCSource,
    "sec": SECSource,
    "ofac": OFACSource,
    "fincen": FinCENSource,
    "fbi_ic3": FBIC3Source,
}

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "regulatory_sources.yaml"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "data" / "regulatory_alerts.csv"


def collect_alerts(sources: Dict[str, object]) -> List[RegulatoryAlert]:
    """Run all source instances and merge results."""
    all_alerts: List[RegulatoryAlert] = []
    for name, source in sources.items():
        alerts = source.run()
        all_alerts.extend(alerts)
    return all_alerts


def write_csv(alerts: List[RegulatoryAlert], output_path: Path) -> None:
    """Write alerts to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert.to_csv_row())
    logger.info("Wrote %d alerts to %s", len(alerts), output_path)


def main():
    parser = argparse.ArgumentParser(description="Fetch regulatory intelligence data")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output CSV path")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Source config YAML")
    parser.add_argument("--dry-run", action="store_true", help="Parse only, don't write CSV")
    parser.add_argument("--sources", type=str, default="", help="Comma-separated source names to run (default: all)")
    args = parser.parse_args()

    config = load_source_config(args.config)
    source_configs = config.get("sources", {})

    # Filter to requested sources
    requested = set(args.sources.split(",")) if args.sources else set(source_configs.keys())

    # Instantiate sources
    instances = {}
    for name in requested:
        if name not in SOURCE_REGISTRY:
            logger.warning("Unknown source: %s", name)
            continue
        src_config = source_configs.get(name, {})
        instances[name] = SOURCE_REGISTRY[name](src_config)

    logger.info("Running %d sources: %s", len(instances), ", ".join(instances.keys()))
    alerts = collect_alerts(instances)
    logger.info("Total alerts collected: %d", len(alerts))

    if args.dry_run:
        for alert in alerts[:10]:
            print(f"  [{alert.source}] {alert.alert_id}: {alert.title}")
        if len(alerts) > 10:
            print(f"  ... and {len(alerts) - 10} more")
        return

    write_csv(alerts, args.output)


if __name__ == "__main__":
    main()
```

**Step 4: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_fetch_regulatory_data.py -v`
Expected: PASS (all tests)

**Step 5: Run all regulatory tests together**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_regulatory_models.py tests/test_regulatory_sources_structured.py tests/test_regulatory_sources_pdf.py tests/test_fetch_regulatory_data.py -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/flame-fraud
git add scripts/fetch_regulatory_data.py tests/test_fetch_regulatory_data.py
git commit -m "feat: add regulatory data fetch orchestrator with CLI"
```

---

### Task 5: build_database.py Updates

**Files:**
- Modify: `flame-fraud/scripts/build_database.py` (SCHEMA constant + new function + main)
- Modify: `flame-fraud/tests/test_build_database.py`

**Context:** The existing SCHEMA string (lines 170–246) defines all current tables. We add new tables at the end. The `export_stats_json` function (around line 490) builds the stats dict. The `main()` function (around line 690) orchestrates all exports. We add a `_build_regulatory_alerts()` function and call it from main before the final exports.

**Step 1: Write the failing test**

Add to `tests/test_build_database.py`:

```python
class TestRegulatoryAlerts:
    """Tests for regulatory alert table creation and CSV ingestion."""

    def test_regulatory_schema_creates_tables(self, tmp_path):
        """Verify regulatory_alerts and mapping tables are created."""
        db_path = tmp_path / "test.db"
        conn = init_database(db_path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        assert "regulatory_alerts" in tables
        assert "regulatory_alert_tp_mapping" in tables
        conn.close()

    def test_build_regulatory_alerts_from_csv(self, tmp_path):
        """Test CSV ingestion into regulatory_alerts table."""
        from build_database import build_regulatory_alerts

        db_path = tmp_path / "test.db"
        conn = init_database(db_path)

        csv_path = tmp_path / "regulatory_alerts.csv"
        csv_path.write_text(
            "alert_id,source,title,date,category,mapped_tp_ids,url,severity,summary\n"
            "cfpb-001,cfpb,Test Alert,2025-01-01,Credit card,TP-0005,https://example.com,medium,Test\n"
            "fincen-001,fincen,BEC Alert,2025-02-01,BEC,TP-0002|TP-0001,https://fincen.gov,high,BEC rise\n"
        )

        count = build_regulatory_alerts(conn, csv_path)
        assert count == 2

        rows = conn.execute("SELECT * FROM regulatory_alerts").fetchall()
        assert len(rows) == 2

        mappings = conn.execute("SELECT * FROM regulatory_alert_tp_mapping").fetchall()
        assert len(mappings) == 3  # 1 + 2

        conn.close()

    def test_build_regulatory_alerts_missing_csv(self, tmp_path):
        """If CSV doesn't exist, function returns 0 gracefully."""
        from build_database import build_regulatory_alerts

        db_path = tmp_path / "test.db"
        conn = init_database(db_path)
        count = build_regulatory_alerts(conn, tmp_path / "nonexistent.csv")
        assert count == 0
        conn.close()
```

**Step 2: Run test to verify it fails**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_build_database.py::TestRegulatoryAlerts -v`
Expected: FAIL — `regulatory_alerts` table not found, `build_regulatory_alerts` not importable

**Step 3: Modify build_database.py**

**3a.** Append to the SCHEMA string (after line 245, before the closing `"""`):

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
    FOREIGN KEY (alert_id) REFERENCES regulatory_alerts(alert_id)
);

CREATE INDEX IF NOT EXISTS idx_reg_source ON regulatory_alerts(source);
CREATE INDEX IF NOT EXISTS idx_reg_date ON regulatory_alerts(date);
CREATE INDEX IF NOT EXISTS idx_reg_tp ON regulatory_alert_tp_mapping(tp_id);
```

**3b.** Add `build_regulatory_alerts` function (before `main()`):

```python
def build_regulatory_alerts(conn: sqlite3.Connection, csv_path: Path) -> int:
    """Ingest regulatory_alerts.csv into the database.

    Returns the number of alerts inserted.
    """
    if not csv_path.exists():
        log.info("No regulatory alerts CSV at %s — skipping", csv_path)
        return 0

    import csv as csv_mod

    count = 0
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv_mod.DictReader(f)
        for row in reader:
            conn.execute(
                "INSERT OR REPLACE INTO regulatory_alerts "
                "(alert_id, source, title, date, category, severity, url, summary) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    row["alert_id"], row["source"], row["title"],
                    row.get("date", ""), row.get("category", ""),
                    row.get("severity", "medium"), row.get("url", ""),
                    row.get("summary", ""),
                ),
            )
            # Insert TP mappings
            tp_ids_str = row.get("mapped_tp_ids", "")
            if tp_ids_str:
                for tp_id in tp_ids_str.split("|"):
                    tp_id = tp_id.strip()
                    if tp_id:
                        conn.execute(
                            "INSERT INTO regulatory_alert_tp_mapping (alert_id, tp_id) VALUES (?, ?)",
                            (row["alert_id"], tp_id),
                        )
            count += 1
    conn.commit()
    log.info("Inserted %d regulatory alerts", count)
    return count


def export_regulatory_json(conn: sqlite3.Connection, output_path: Path) -> int:
    """Export regulatory_alerts table as JSON."""
    rows = conn.execute(
        "SELECT alert_id, source, title, date, category, severity, url, summary "
        "FROM regulatory_alerts ORDER BY date DESC"
    ).fetchall()

    alerts = []
    for r in rows:
        alert_id = r[0]
        tp_ids = [
            row[0] for row in conn.execute(
                "SELECT tp_id FROM regulatory_alert_tp_mapping WHERE alert_id = ?",
                (alert_id,),
            ).fetchall()
        ]
        alerts.append({
            "alert_id": alert_id,
            "source": r[1],
            "title": r[2],
            "date": r[3],
            "category": r[4],
            "severity": r[5],
            "url": r[6],
            "summary": r[7],
            "mapped_tp_ids": tp_ids,
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(alerts, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return len(alerts)
```

**3c.** Update `export_stats_json` — add `regulatoryAlerts` to the stats dict (before the `return stats` line):

```python
    # Regulatory alerts stats
    reg_total = conn.execute("SELECT COUNT(*) FROM regulatory_alerts").fetchone()[0]
    reg_by_severity = {}
    for row in conn.execute("SELECT severity, COUNT(*) FROM regulatory_alerts GROUP BY severity").fetchall():
        reg_by_severity[row[0]] = row[1]
    reg_by_source = {}
    for row in conn.execute("SELECT source, COUNT(*) FROM regulatory_alerts GROUP BY source").fetchall():
        reg_by_source[row[0]] = row[1]
    stats["regulatoryAlerts"] = {
        "total": reg_total,
        "bySeverity": reg_by_severity,
        "bySource": reg_by_source,
        "lastUpdated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
```

**3d.** Update `main()` — add regulatory processing after TP loading, before JSON exports (insert after `conn.commit()` around line 749, before the JSON export block):

```python
    # Regulatory alerts
    reg_csv = root / "data" / "regulatory_alerts.csv"
    reg_count = build_regulatory_alerts(conn, reg_csv)
    log.info("Regulatory alerts: %d", reg_count)
```

And add regulatory JSON export after the evidence index export:

```python
    # Export regulatory alerts JSON
    reg_json_path = root / "database" / "regulatory-alerts.json"
    reg_json_count = export_regulatory_json(conn, reg_json_path)
    log.info("Exported %d regulatory alerts to %s", reg_json_count, reg_json_path)
```

**Step 4: Update test imports**

In `tests/test_build_database.py`, add `build_regulatory_alerts` to the import line:

```python
from build_database import (
    extract_frontmatter,
    extract_body,
    extract_summary,
    extract_evidence,
    _insert_multi,
    _fetch_list,
    _VALID_MULTI_TABLES,
    init_database,
    build_regulatory_alerts,
)
```

**Step 5: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest tests/test_build_database.py -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/flame-fraud
git add scripts/build_database.py tests/test_build_database.py
git commit -m "feat: add regulatory_alerts table, CSV ingestion, and JSON export to build_database"
```

---

### Task 6: CI Workflows

**Files:**
- Create: `flame-fraud/.github/workflows/fetch-regulatory.yml`
- Modify: `flame-fraud/.github/workflows/update-database.yml`

**Context:** The existing `update-database.yml` triggers on push to main when ThreatPaths/Baselines/DetectionLogic/cfpf_techniques.json change. We add `data/regulatory_alerts.csv` as a trigger path and add a regulatory fetch step. We also create a new standalone scheduled workflow.

**Step 1: Create the scheduled fetch workflow**

```yaml
# .github/workflows/fetch-regulatory.yml
name: Fetch Regulatory Data

on:
  schedule:
    - cron: '0 6 * * 1-5'  # Weekdays at 6 AM UTC
  workflow_dispatch:  # Manual trigger

permissions:
  contents: write

jobs:
  fetch:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Fetch regulatory data
        run: python scripts/fetch_regulatory_data.py --output data/regulatory_alerts.csv
        timeout-minutes: 15
        continue-on-error: true

      - name: Commit updated data
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add data/regulatory_alerts.csv
          git diff --cached --quiet || git commit -m "chore: update regulatory alerts [automated]"
          git push
```

**Step 2: Update existing workflow**

Modify `flame-fraud/.github/workflows/update-database.yml`:

Add to the `paths` list:
```yaml
      - 'data/regulatory_alerts.csv'
```

Add a step before `Build database`:
```yaml
      - name: Fetch regulatory data
        run: python scripts/fetch_regulatory_data.py --output data/regulatory_alerts.csv
        timeout-minutes: 15
        continue-on-error: true
```

**Step 3: Verify YAML syntax**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -c "import yaml; yaml.safe_load(open('.github/workflows/fetch-regulatory.yml')); print('OK')" && python -c "import yaml; yaml.safe_load(open('.github/workflows/update-database.yml')); print('OK')"`
Expected: OK OK

**Step 4: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/flame-fraud
git add .github/workflows/fetch-regulatory.yml .github/workflows/update-database.yml
git commit -m "ci: add scheduled regulatory data fetch and update-database trigger"
```

---

### Task 7: Frontend Regulatory Pulse Panel

**Files:**
- Modify: `flame-fraud/app.js`
- Modify: `flame-fraud/index.html` (add container div)
- Modify: `flame-fraud/style.css` (add panel styles)

**Context:** `app.js` is a single IIFE (753 lines). The FlameData module manages data loading. The UI renders cards, detail views, and a heat map. We add a "Regulatory Pulse" panel to the dashboard.

**Step 1: Add HTML container**

In `index.html`, find the heat-map container and add after it:

```html
<section id="regulatory-pulse" class="panel" style="display:none;">
    <h2>Regulatory Pulse</h2>
    <div id="regulatory-pulse-body"></div>
</section>
```

**Step 2: Add CSS styles**

In `style.css`, add:

```css
/* Regulatory Pulse */
#regulatory-pulse { margin-top: 1.5rem; }
.reg-source-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin-right: 4px; }
.reg-source-badge.fincen { background: #fee2e2; color: #991b1b; }
.reg-source-badge.cfpb { background: #dbeafe; color: #1e40af; }
.reg-source-badge.fbi_ic3 { background: #fef3c7; color: #92400e; }
.reg-source-badge.occ { background: #d1fae5; color: #065f46; }
.reg-source-badge.sec { background: #ede9fe; color: #5b21b6; }
.reg-source-badge.ofac { background: #fce7f3; color: #9d174d; }
.reg-severity-pill { display: inline-block; padding: 1px 6px; border-radius: 9999px; font-size: 0.7rem; }
.reg-severity-pill.high { background: #ef4444; color: white; }
.reg-severity-pill.medium { background: #f59e0b; color: white; }
.reg-severity-pill.low { background: #6b7280; color: white; }
.reg-table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; }
.reg-table th, .reg-table td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #e5e7eb; font-size: 0.85rem; }
.reg-table th { font-weight: 600; color: #6b7280; }
.reg-summary-row { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.75rem; }
.reg-stat { padding: 0.5rem 1rem; background: #1e293b; border-radius: 8px; }
.reg-stat .label { font-size: 0.75rem; color: #94a3b8; }
.reg-stat .value { font-size: 1.25rem; font-weight: 700; }
```

**Step 3: Add JavaScript data loading and rendering**

In `app.js`, within the FlameData module (near the existing data loading logic), add regulatory alerts loading:

```javascript
// Inside FlameData module, add:
let _regulatoryAlerts = [];

function loadRegulatoryAlerts() {
    var baseUrl = /* same base URL derivation as flame-index.json */;
    var url = baseUrl + 'regulatory-alerts.json';
    return fetch(url)
        .then(function(resp) {
            if (!resp.ok) return [];
            return resp.json();
        })
        .then(function(data) {
            _regulatoryAlerts = Array.isArray(data) ? data : [];
            return _regulatoryAlerts;
        })
        .catch(function() {
            _regulatoryAlerts = [];
            return [];
        });
}

function getRegulatoryAlerts() { return _regulatoryAlerts; }
```

Add a `renderRegulatoryPulse()` function before the closing IIFE:

```javascript
function renderRegulatoryPulse() {
    var alerts = FlameData.getRegulatoryAlerts();
    var panel = document.getElementById('regulatory-pulse');
    var body = document.getElementById('regulatory-pulse-body');
    if (!alerts || alerts.length === 0) {
        panel.style.display = 'none';
        return;
    }
    panel.style.display = '';

    // Summary stats
    var bySeverity = {high: 0, medium: 0, low: 0};
    var bySource = {};
    alerts.forEach(function(a) {
        bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
        bySource[a.source] = (bySource[a.source] || 0) + 1;
    });

    var html = '<div class="reg-summary-row">';
    html += '<div class="reg-stat"><div class="label">Total Alerts</div><div class="value">' + alerts.length + '</div></div>';
    html += '<div class="reg-stat"><div class="label">High Severity</div><div class="value" style="color:#ef4444">' + bySeverity.high + '</div></div>';
    html += '<div class="reg-stat"><div class="label">Sources Active</div><div class="value">' + Object.keys(bySource).length + '</div></div>';
    html += '</div>';

    // Table of recent alerts (top 20)
    var recent = alerts.slice(0, 20);
    html += '<table class="reg-table"><thead><tr><th>Date</th><th>Source</th><th>Title</th><th>Severity</th><th>TPs</th></tr></thead><tbody>';
    recent.forEach(function(a) {
        var tps = (a.mapped_tp_ids || []).join(', ');
        html += '<tr>';
        html += '<td>' + escapeHtml(a.date || '—') + '</td>';
        html += '<td><span class="reg-source-badge ' + escapeHtml(a.source) + '">' + escapeHtml(a.source.toUpperCase()) + '</span></td>';
        html += '<td>' + escapeHtml(a.title) + '</td>';
        html += '<td><span class="reg-severity-pill ' + escapeHtml(a.severity) + '">' + escapeHtml(a.severity) + '</span></td>';
        html += '<td>' + escapeHtml(tps || '—') + '</td>';
        html += '</tr>';
    });
    html += '</tbody></table>';

    body.innerHTML = html;
}
```

Call `loadRegulatoryAlerts()` alongside existing data loading, and call `renderRegulatoryPulse()` after render.

**Step 4: Test manually**

Open `index.html` in browser, verify panel renders (or hides if no data).

**Step 5: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/flame-fraud
git add app.js index.html style.css
git commit -m "feat: add Regulatory Pulse dashboard panel"
```

---

### Task 8: domain_intel Bridge

**Files:**
- Modify: `domain_intel/scripts/shared/flame_client.py`
- Modify: `domain_intel/config/defaults.yaml`
- Modify: `domain_intel/scripts/ai_briefing.py`
- Create: `domain_intel/tests/test_flame_regulatory.py`

**Context:** This task is in the domain_intel repo (`/c/Users/anon/Documents/anon/repos/domain_intel`). The existing `flame_client.py` (173 lines) has `get_threat_paths()` and `get_tp_summaries_for_prompt()` with 3-tier cache fallback. The `ai_briefing.py` builds a data_summary string with sections like `[FLAME Threat Path Distribution]`.

**Step 1: Write the failing tests**

```python
# tests/test_flame_regulatory.py
"""Tests for FLAME regulatory alerts bridge."""
import json
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from shared.flame_client import get_regulatory_alerts, _REG_CACHE_FILE


class TestGetRegulatoryAlerts:
    def test_returns_list_from_network(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shared.flame_client._REG_CACHE_FILE", tmp_path / "reg.json")
        monkeypatch.setattr("shared.flame_client._REG_CACHE_META", tmp_path / "reg_meta.json")

        mock_data = [
            {"alert_id": "cfpb-001", "source": "cfpb", "title": "Test", "severity": "medium", "mapped_tp_ids": ["TP-0005"]}
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status = MagicMock()

        with patch("shared.flame_client.requests.get", return_value=mock_resp):
            result = get_regulatory_alerts()
        assert len(result) == 1
        assert result[0]["alert_id"] == "cfpb-001"

    def test_returns_empty_on_failure(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shared.flame_client._REG_CACHE_FILE", tmp_path / "reg.json")
        monkeypatch.setattr("shared.flame_client._REG_CACHE_META", tmp_path / "reg_meta.json")

        with patch("shared.flame_client.requests.get", side_effect=Exception("Network error")):
            result = get_regulatory_alerts()
        assert result == []

    def test_uses_cache_when_fresh(self, tmp_path, monkeypatch):
        cache_file = tmp_path / "reg.json"
        meta_file = tmp_path / "reg_meta.json"
        monkeypatch.setattr("shared.flame_client._REG_CACHE_FILE", cache_file)
        monkeypatch.setattr("shared.flame_client._REG_CACHE_META", meta_file)

        cached_data = [{"alert_id": "cached-001", "source": "occ"}]
        cache_file.write_text(json.dumps(cached_data))
        meta_file.write_text(json.dumps({"fetched_at": time.time()}))

        result = get_regulatory_alerts()
        assert len(result) == 1
        assert result[0]["alert_id"] == "cached-001"
```

**Step 2: Run test to verify it fails**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_flame_regulatory.py -v`
Expected: FAIL — `get_regulatory_alerts` not importable

**Step 3: Add to config/defaults.yaml**

Add under the `flame:` section:

```yaml
  regulatory_alerts_url: "https://elchacal801.github.io/flame-fraud/database/regulatory-alerts.json"
```

**Step 4: Add get_regulatory_alerts() to flame_client.py**

After the existing `_CACHE_META` constant (line 34), add:

```python
_REG_CACHE_FILE = _CACHE_DIR / "regulatory-alerts.json"
_REG_CACHE_META = _CACHE_DIR / ".reg_meta.json"
```

Add a new `_regulatory_url()` helper:

```python
def _regulatory_url() -> str:
    """Resolve the FLAME regulatory alerts URL from config."""
    return cfg.get("flame.regulatory_alerts_url",
                    "https://elchacal801.github.io/flame-fraud/database/regulatory-alerts.json")
```

Add the public function after `get_tp_summaries_for_prompt()`:

```python
def get_regulatory_alerts() -> List[Dict[str, Any]]:
    """Return FLAME regulatory alerts, using cache when fresh.

    Resolution order (same as get_threat_paths):
    1. Fresh local cache  → return immediately
    2. Network fetch      → cache & return
    3. Stale local cache  → return with warning
    4. Nothing available  → return ``[]``
    """
    # 1. Check cache
    if _REG_CACHE_FILE.exists() and _REG_CACHE_META.exists():
        try:
            with open(_REG_CACHE_META, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
            if (time.time() - meta.get("fetched_at", 0)) <= _cache_ttl_seconds():
                with open(_REG_CACHE_FILE, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                logger.debug("Regulatory cache hit (%d alerts)", len(data))
                return data
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    # 2. Fetch from network
    url = _regulatory_url()
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            # Save cache
            try:
                _CACHE_DIR.mkdir(parents=True, exist_ok=True)
                with open(_REG_CACHE_FILE, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
                with open(_REG_CACHE_META, "w", encoding="utf-8") as fh:
                    json.dump({"fetched_at": time.time()}, fh)
            except OSError:
                pass
            return data
    except Exception as exc:
        logger.warning("Failed to fetch regulatory alerts: %s", exc)

    # 3. Stale cache fallback
    if _REG_CACHE_FILE.exists():
        try:
            with open(_REG_CACHE_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            logger.info("Using stale regulatory cache (%d alerts)", len(data))
            return data
        except (json.JSONDecodeError, OSError):
            pass

    return []
```

**Step 5: Update ai_briefing.py**

Add import at top:

```python
from shared.flame_client import get_regulatory_alerts
```

In the `build_data_summary()` function (or wherever the data_summary string is built), after the `[FLAME Evidence Candidates]` section (around line 423), add:

```python
    # Regulatory Pulse
    reg_alerts = get_regulatory_alerts()
    reg_str = "No regulatory data available"
    if reg_alerts:
        by_severity = {"high": 0, "medium": 0, "low": 0}
        by_source = {}
        tp_alert_counts = {}
        for ra in reg_alerts:
            sev = ra.get("severity", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            src = ra.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1
            for tp_id in ra.get("mapped_tp_ids", []):
                if tp_id not in tp_alert_counts:
                    tp_alert_counts[tp_id] = {"total": 0, "high": 0}
                tp_alert_counts[tp_id]["total"] += 1
                if sev == "high":
                    tp_alert_counts[tp_id]["high"] += 1

        source_parts = ", ".join([f"{s.upper()} ({c})" for s, c in sorted(by_source.items(), key=lambda x: x[1], reverse=True)])
        tp_parts = "\n".join([
            f"    - {tp}: {counts['total']} alerts ({counts['high']} high severity)"
            for tp, counts in sorted(tp_alert_counts.items(), key=lambda x: x[1]['total'], reverse=True)[:10]
        ])

        reg_str = (
            f"Active Regulatory Alerts: {len(reg_alerts)} total "
            f"({by_severity.get('high', 0)} high, {by_severity.get('medium', 0)} medium, {by_severity.get('low', 0)} low)\n"
            f"    By Source: {source_parts}\n"
            f"    TP-Linked Alerts:\n{tp_parts}"
        )
```

Add to the data_summary f-string:

```
    [Regulatory Pulse]
{reg_str}
```

Add to the LLM prompt instructions (in the SYSTEM_PROMPT or the data_summary instructions):

```
    If Regulatory Pulse data is present, include a "Regulatory Landscape" section assessing
    how regulatory enforcement trends align with observed threat activity in the domain telemetry.
```

**Step 6: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_flame_regulatory.py -v`
Expected: PASS

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest -v`
Expected: ALL PASS

**Step 7: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
git add scripts/shared/flame_client.py config/defaults.yaml scripts/ai_briefing.py tests/test_flame_regulatory.py
git commit -m "feat: add regulatory pulse to FLAME bridge and AI briefing"
```

---

### Task 9: Final Validation

**Step 1: Run all FLAME tests**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python -m pytest -v`
Expected: ALL PASS

**Step 2: Run all domain_intel tests**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest -v`
Expected: ALL PASS

**Step 3: Dry-run the regulatory fetch**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python scripts/fetch_regulatory_data.py --dry-run --sources occ,sec`
Expected: Prints fetched alerts without writing CSV

**Step 4: Verify build_database.py works with regulatory data**

Run: `cd /c/Users/anon/Documents/anon/repos/flame-fraud && python scripts/build_database.py`
Expected: Completes without errors, outputs regulatory alerts count (0 if no CSV yet)
