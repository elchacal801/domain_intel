"""Tests for OTX MX cluster expansion script."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

def test_extract_mx_targets_from_infra_index():
    """Should extract private MX hosts with 5+ domains from enriched infra_index."""
    from expand_mx_clusters import extract_mx_targets
    infra_index = {
        "mx": {
            "mx.private.com": {
                "domains": ["d1.com", "d2.com", "d3.com", "d4.com", "d5.com"],
                "private": True,
                "entity_stats": {"os_hits": 1, "icij_hits": 0, "gleif_active": 0, "unique_registrants": 5, "total": 5}
            },
            "aspmx.l.google.com": {
                "domains": ["g1.com", "g2.com", "g3.com", "g4.com", "g5.com", "g6.com"],
                "private": False,
                "entity_stats": {"os_hits": 0, "icij_hits": 0, "gleif_active": 0, "unique_registrants": 6, "total": 6}
            },
            "mx.small.com": {
                "domains": ["s1.com", "s2.com"],
                "private": True,
                "entity_stats": {"os_hits": 0, "icij_hits": 0, "gleif_active": 0, "unique_registrants": 2, "total": 2}
            },
        }
    }
    targets = extract_mx_targets(infra_index, min_size=5)
    assert targets == ["mx.private.com"]  # only private with 5+ domains


def test_extract_mx_targets_empty():
    """Should return empty list when no targets meet criteria."""
    from expand_mx_clusters import extract_mx_targets
    assert extract_mx_targets({"mx": {}}, min_size=5) == []
    assert extract_mx_targets({}, min_size=5) == []
