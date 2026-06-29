"""Tests for enriched infra_index with entity stats and private flag."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

def test_enriched_mx_index_has_entity_stats():
    """MX index entries should have domains list, private flag, and entity_stats."""
    from build_frontend_data import build_infra_index
    domains = {
        "shell1.com": {
            "primary_mx": "mx.private-host.com",
            "mx_ip": "1.2.3.4",
            "asn": "12345",
            "a_record": "5.6.7.8",
            "registrant_org": "Shell Corp A",
            "os_match_score": "85",
            "icij_entity_match": "",
            "gleif_status": "ACTIVE",
            "gleif_lei": "ABC123",
        },
        "shell2.com": {
            "primary_mx": "mx.private-host.com",
            "mx_ip": "1.2.3.4",
            "asn": "12345",
            "a_record": "5.6.7.8",
            "registrant_org": "Shell Corp B",
            "os_match_score": "70",
            "icij_entity_match": "Panama Papers",
            "gleif_status": "",
            "gleif_lei": "",
        },
        "shell3.com": {
            "primary_mx": "mx.private-host.com",
            "mx_ip": "1.2.3.4",
            "asn": "12345",
            "a_record": "5.6.7.8",
            "registrant_org": "Shell Corp A",
            "os_match_score": "",
            "icij_entity_match": "",
            "gleif_status": "",
            "gleif_lei": "",
        },
    }
    fp_matches = {}
    index = build_infra_index(domains, fp_matches)

    mx_entry = index["mx"]["mx.private-host.com"]
    assert isinstance(mx_entry, dict), "MX entry should be a dict, not a list"
    assert set(mx_entry["domains"]) == {"shell1.com", "shell2.com", "shell3.com"}
    assert mx_entry["private"] is True  # not a known shared provider

    stats = mx_entry["entity_stats"]
    assert stats["os_hits"] == 2      # shell1 (85) + shell2 (70)
    assert stats["icij_hits"] == 1    # shell2 only
    assert stats["gleif_active"] == 1 # shell1 only
    assert stats["unique_registrants"] == 2  # "Shell Corp A" + "Shell Corp B"
    assert stats["total"] == 3


def test_shared_provider_marked_not_private():
    """Known shared providers (Google, Microsoft) should have private=False."""
    from build_frontend_data import build_infra_index
    domains = {
        "user1.com": {
            "primary_mx": "aspmx.l.google.com",
            "mx_ip": "142.251.40.26",
            "asn": "15169",
            "a_record": "",
            "registrant_org": "User 1",
            "os_match_score": "",
            "icij_entity_match": "",
            "gleif_status": "",
            "gleif_lei": "",
        },
        "user2.com": {
            "primary_mx": "aspmx.l.google.com",
            "mx_ip": "142.251.40.26",
            "asn": "15169",
            "a_record": "",
            "registrant_org": "User 2",
            "os_match_score": "",
            "icij_entity_match": "",
            "gleif_status": "",
            "gleif_lei": "",
        },
    }
    fp_matches = {}
    index = build_infra_index(domains, fp_matches)

    mx_entry = index["mx"]["aspmx.l.google.com"]
    assert mx_entry["private"] is False


def test_non_mx_categories_also_enriched():
    """ASN, IP, registrar, a_record, fp categories should also use enriched format."""
    from build_frontend_data import build_infra_index
    domains = {
        "d1.com": {
            "primary_mx": "", "mx_ip": "", "asn": "16509",
            "a_record": "1.2.3.4", "registrant_org": "Org A",
            "os_match_score": "50", "icij_entity_match": "", "gleif_status": "", "gleif_lei": "",
        },
        "d2.com": {
            "primary_mx": "", "mx_ip": "", "asn": "16509",
            "a_record": "1.2.3.4", "registrant_org": "Org B",
            "os_match_score": "", "icij_entity_match": "Offshore", "gleif_status": "", "gleif_lei": "",
        },
    }
    fp_matches = {}
    index = build_infra_index(domains, fp_matches)

    asn_entry = index["asn"]["16509"]
    assert isinstance(asn_entry, dict)
    assert set(asn_entry["domains"]) == {"d1.com", "d2.com"}
    assert asn_entry["entity_stats"]["os_hits"] == 1
