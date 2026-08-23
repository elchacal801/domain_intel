#!/usr/bin/env python3
"""
tests/test_rdap_parsing.py

Tests for the RDAP parsing helpers in enrich_reputation.py:
  - _extract_org_from_vcard
  - _extract_registrant_org
  - _extract_creation_date
  - get_rdap_data  (integration-level, with mocked HTTP)
  - process_one    (end-to-end row enrichment, fully mocked)
"""

import datetime
import sys
import os
from unittest.mock import patch, MagicMock

import pytest

# Ensure scripts/ is on sys.path so we can import enrich_reputation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from enrich_reputation import (
    _extract_org_from_vcard,
    _extract_registrant_org,
    _extract_creation_date,
    get_rdap_data,
    process_one,
)


# ---------------------------------------------------------------------------
# Fixtures: representative RDAP response fragments
# ---------------------------------------------------------------------------

def _make_vcard(properties):
    """Convenience: wrap a list of jCard properties in a vcardArray."""
    return ["vcard", [["version", {}, "text", "4.0"]] + properties]


# ---------------------------------------------------------------------------
# _extract_org_from_vcard
# ---------------------------------------------------------------------------

class TestExtractOrgFromVcard:
    def test_standard_org(self):
        vcard = _make_vcard([
            ["fn", {}, "text", "John Doe"],
            ["org", {}, "text", "ACME Inc."],
        ])
        assert _extract_org_from_vcard(vcard) == "ACME Inc."

    def test_fn_only_no_org(self):
        """When there is no org property, fall back to fn."""
        vcard = _make_vcard([
            ["fn", {}, "text", "Jane Registrant"],
        ])
        assert _extract_org_from_vcard(vcard) == "Jane Registrant"

    def test_org_preferred_over_fn(self):
        """org should be returned even when fn comes first."""
        vcard = _make_vcard([
            ["fn", {}, "text", "Person Name"],
            ["org", {}, "text", "Real Org LLC"],
        ])
        assert _extract_org_from_vcard(vcard) == "Real Org LLC"

    def test_org_as_list_value(self):
        """Some RDAP servers return org value as a list (e.g. ['Org Name'])."""
        vcard = _make_vcard([
            ["org", {}, "text", ["Cloudflare, Inc."]],
        ])
        assert _extract_org_from_vcard(vcard) == "Cloudflare, Inc."

    def test_empty_org_falls_back_to_fn(self):
        vcard = _make_vcard([
            ["org", {}, "text", "   "],
            ["fn", {}, "text", "Fallback Name"],
        ])
        assert _extract_org_from_vcard(vcard) == "Fallback Name"

    def test_no_useful_properties(self):
        vcard = _make_vcard([
            ["email", {}, "text", "admin@example.com"],
        ])
        assert _extract_org_from_vcard(vcard) == ""

    def test_none_vcard(self):
        assert _extract_org_from_vcard(None) == ""

    def test_empty_list_vcard(self):
        assert _extract_org_from_vcard([]) == ""

    def test_malformed_property(self):
        """Properties with fewer than 4 elements should be skipped."""
        vcard = _make_vcard([
            ["org", {}],           # too short
            ["fn", {}, "text", "Good"],
        ])
        assert _extract_org_from_vcard(vcard) == "Good"

    def test_org_empty_list_value(self):
        """org value is an empty list -- should be skipped."""
        vcard = _make_vcard([
            ["org", {}, "text", []],
            ["fn", {}, "text", "Fallback"],
        ])
        assert _extract_org_from_vcard(vcard) == "Fallback"


# ---------------------------------------------------------------------------
# _extract_registrant_org
# ---------------------------------------------------------------------------

class TestExtractRegistrantOrg:
    def test_top_level_registrant_with_vcard(self):
        data = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": _make_vcard([
                        ["fn", {}, "text", "Ignored Person"],
                        ["org", {}, "text", "Top Level Org"],
                    ]),
                }
            ]
        }
        assert _extract_registrant_org(data) == "Top Level Org"

    def test_nested_registrant(self):
        """Registrant is nested inside a registrar entity."""
        data = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "handle": "REGISTRAR-123",
                    "entities": [
                        {
                            "roles": ["registrant"],
                            "vcardArray": _make_vcard([
                                ["org", {}, "text", "Nested Org Corp"],
                            ]),
                        }
                    ],
                }
            ]
        }
        assert _extract_registrant_org(data) == "Nested Org Corp"

    def test_handle_fallback(self):
        """When vCard has no useful fields, fall back to handle."""
        data = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "handle": "REG-HANDLE-42",
                    # no vcardArray
                }
            ]
        }
        assert _extract_registrant_org(data) == "REG-HANDLE-42"

    def test_name_fallback(self):
        """When vCard is absent, use the entity 'name' field."""
        data = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "name": "Entity Name LLC",
                }
            ]
        }
        assert _extract_registrant_org(data) == "Entity Name LLC"

    def test_public_ids_fallback(self):
        """publicIds should be used as a last resort."""
        data = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "publicIds": [{"type": "IANA Registrar ID", "identifier": "PUB-ID-99"}],
                }
            ]
        }
        assert _extract_registrant_org(data) == "PUB-ID-99"

    def test_no_registrant_entity(self):
        data = {
            "entities": [
                {"roles": ["registrar"], "handle": "NOT-REGISTRANT"},
            ]
        }
        assert _extract_registrant_org(data) == ""

    def test_no_entities_at_all(self):
        assert _extract_registrant_org({}) == ""
        assert _extract_registrant_org({"entities": []}) == ""

    def test_top_level_preferred_over_nested(self):
        """Top-level registrant should be returned before nested one."""
        data = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": _make_vcard([
                        ["org", {}, "text", "Top Org"],
                    ]),
                },
                {
                    "roles": ["registrar"],
                    "entities": [
                        {
                            "roles": ["registrant"],
                            "vcardArray": _make_vcard([
                                ["org", {}, "text", "Nested Org"],
                            ]),
                        }
                    ],
                },
            ]
        }
        assert _extract_registrant_org(data) == "Top Org"


# ---------------------------------------------------------------------------
# _extract_creation_date
# ---------------------------------------------------------------------------

class TestExtractCreationDate:
    def test_registration_event(self):
        data = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-06-15T10:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
            ]
        }
        creation, age = _extract_creation_date(data)
        assert creation == "2020-06-15"
        assert int(age) > 0

    def test_last_changed_fallback(self):
        data = {
            "events": [
                {"eventAction": "last changed", "eventDate": "2023-03-10T12:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ]
        }
        creation, age = _extract_creation_date(data)
        assert creation == "2023-03-10"
        assert int(age) > 0

    def test_registration_preferred_over_last_changed(self):
        """Even if last changed comes first, registration date wins."""
        data = {
            "events": [
                {"eventAction": "last changed", "eventDate": "2024-12-01T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "2019-05-20T00:00:00Z"},
            ]
        }
        creation, _ = _extract_creation_date(data)
        assert creation == "2019-05-20"

    def test_no_events(self):
        assert _extract_creation_date({}) == ("", "")
        assert _extract_creation_date({"events": []}) == ("", "")

    def test_no_usable_event_actions(self):
        data = {
            "events": [
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ]
        }
        assert _extract_creation_date(data) == ("", "")

    def test_missing_event_date(self):
        data = {
            "events": [
                {"eventAction": "registration"},  # no eventDate
            ]
        }
        assert _extract_creation_date(data) == ("", "")

    def test_age_calculation(self):
        """Verify age_days is roughly correct.

        The input must be built from UTC, not local time: _extract_creation_date
        measures age against datetime.now(timezone.utc), so constructing
        "yesterday" from a local clock behind UTC yields an age of 2 late in the
        local day.
        """
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        yesterday = (utc_now - datetime.timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
        data = {"events": [{"eventAction": "registration", "eventDate": yesterday}]}
        creation, age = _extract_creation_date(data)
        assert int(age) == 1


# ---------------------------------------------------------------------------
# get_rdap_data  (mocked HTTP)
# ---------------------------------------------------------------------------

class TestGetRdapData:
    def _mock_response(self, status_code=200, json_data=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data or {}
        return resp

    @patch("enrich_reputation.requests.get")
    def test_full_successful_response(self, mock_get):
        mock_get.return_value = self._mock_response(200, {
            "events": [
                {"eventAction": "registration", "eventDate": "2021-01-01T00:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": _make_vcard([
                        ["org", {}, "text", "Example Corp"],
                    ]),
                }
            ],
        })

        result = get_rdap_data("example.com")

        assert result["creation_date"] == "2021-01-01"
        assert int(result["age_days"]) > 0
        assert result["registrant_org"] == "Example Corp"
        mock_get.assert_called_once_with(
            "https://rdap.org/domain/example.com", timeout=10
        )

    @patch("enrich_reputation.requests.get")
    def test_http_404(self, mock_get):
        mock_get.return_value = self._mock_response(404)
        result = get_rdap_data("nonexistent.test")
        assert result == {"creation_date": "", "age_days": "", "registrant_org": ""}

    @patch("enrich_reputation.requests.get")
    def test_timeout(self, mock_get):
        import requests as _req
        mock_get.side_effect = _req.Timeout("timed out")
        result = get_rdap_data("slow.test")
        assert result == {"creation_date": "", "age_days": "", "registrant_org": ""}

    @patch("enrich_reputation.requests.get")
    def test_connection_error(self, mock_get):
        import requests as _req
        mock_get.side_effect = _req.ConnectionError("refused")
        result = get_rdap_data("offline.test")
        assert result == {"creation_date": "", "age_days": "", "registrant_org": ""}

    @patch("enrich_reputation.requests.get")
    def test_no_events_no_entities(self, mock_get):
        mock_get.return_value = self._mock_response(200, {})
        result = get_rdap_data("empty.test")
        assert result["creation_date"] == ""
        assert result["age_days"] == ""
        assert result["registrant_org"] == ""

    @patch("enrich_reputation.requests.get")
    def test_nested_registrant(self, mock_get):
        mock_get.return_value = self._mock_response(200, {
            "events": [],
            "entities": [
                {
                    "roles": ["registrar"],
                    "entities": [
                        {
                            "roles": ["registrant"],
                            "vcardArray": _make_vcard([
                                ["fn", {}, "text", "Nested Person"],
                            ]),
                        }
                    ],
                }
            ],
        })
        result = get_rdap_data("nested.test")
        assert result["registrant_org"] == "Nested Person"

    @patch("enrich_reputation.requests.get")
    def test_registrant_org_sanitised(self, mock_get):
        """Values starting with = should be CSV-sanitised."""
        mock_get.return_value = self._mock_response(200, {
            "events": [],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": _make_vcard([
                        ["org", {}, "text", "=DANGEROUS()"],
                    ]),
                }
            ],
        })
        result = get_rdap_data("evil.test")
        assert result["registrant_org"] == "'=DANGEROUS()"

    @patch("enrich_reputation.requests.get")
    def test_json_decode_error(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = resp
        result = get_rdap_data("badjson.test")
        assert result == {"creation_date": "", "age_days": "", "registrant_org": ""}

    @patch("enrich_reputation.requests.get")
    def test_last_changed_fallback_in_integration(self, mock_get):
        mock_get.return_value = self._mock_response(200, {
            "events": [
                {"eventAction": "last changed", "eventDate": "2022-07-04T00:00:00Z"},
            ],
            "entities": [],
        })
        result = get_rdap_data("noregistration.test")
        assert result["creation_date"] == "2022-07-04"
        assert int(result["age_days"]) > 0


# ---------------------------------------------------------------------------
# process_one  (end-to-end with mocked externals)
# ---------------------------------------------------------------------------

class TestProcessOne:
    @patch("enrich_reputation.check_otx", return_value="")
    @patch("enrich_reputation.get_rdap_data")
    @patch("enrich_reputation.check_rbl", return_value=[])
    @patch("enrich_reputation.dns.resolver.Resolver")
    def test_sets_all_fields(self, mock_resolver_cls, mock_rbl, mock_rdap, mock_otx):
        mock_rdap.return_value = {
            "creation_date": "2020-01-15",
            "age_days": "2000",
            "registrant_org": "Test Org",
        }
        row = {"domain": "test.com"}
        result = process_one(row)
        assert result["creation_date"] == "2020-01-15"
        assert result["age_days"] == "2000"
        assert result["registrant_org"] == "Test Org"
        assert result["rbl_hits"] == ""

    @patch("enrich_reputation.check_otx", return_value="")
    @patch("enrich_reputation.get_rdap_data")
    @patch("enrich_reputation.check_rbl", return_value=[])
    @patch("enrich_reputation.dns.resolver.Resolver")
    def test_empty_domain_skips(self, mock_resolver_cls, mock_rbl, mock_rdap, mock_otx):
        row = {"domain": ""}
        result = process_one(row)
        mock_rdap.assert_not_called()

    @patch("enrich_reputation.check_otx", return_value="OTX_Pulses:2;Bad,Worse")
    @patch("enrich_reputation.get_rdap_data", return_value={"creation_date": "", "age_days": "", "registrant_org": ""})
    @patch("enrich_reputation.check_rbl", return_value=["spamhaus_dbl"])
    @patch("enrich_reputation.dns.resolver.Resolver")
    def test_rbl_and_otx(self, mock_resolver_cls, mock_rbl, mock_rdap, mock_otx):
        row = {"domain": "spam.test"}
        result = process_one(row)
        assert result["rbl_hits"] == "spamhaus_dbl"
        assert "OTX_Pulses:2" in result["otx_risk"]

    @patch("enrich_reputation.check_otx", return_value="")
    @patch("enrich_reputation.get_rdap_data", return_value={"creation_date": "", "age_days": "", "registrant_org": ""})
    @patch("enrich_reputation.check_rbl", return_value=[])
    @patch("enrich_reputation.dns.resolver.Resolver")
    def test_missing_registrant_org_key_defaults_empty(self, mock_resolver_cls, mock_rbl, mock_rdap, mock_otx):
        """process_one uses .get() for registrant_org, so missing key should not crash."""
        mock_rdap.return_value = {"creation_date": "", "age_days": ""}  # no registrant_org key
        row = {"domain": "noorg.test"}
        result = process_one(row)
        assert result["registrant_org"] == ""
