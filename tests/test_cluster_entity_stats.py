"""Tests for cluster-level entity screening stats."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

def test_cluster_entity_stats_computed():
    """Infrastructure nodes should have entity screening stats."""
    clusters = {
        "nodes": [
            {"id": "mx:mail.bad.com", "type": "mx_host", "shared_infra": False},
            {"id": "dom:shell1.com", "type": "domain"},
            {"id": "dom:shell2.com", "type": "domain"},
        ],
        "edges": [
            {"source": "dom:shell1.com", "target": "mx:mail.bad.com"},
            {"source": "dom:shell2.com", "target": "mx:mail.bad.com"},
        ],
    }
    domains = {
        "shell1.com": {"os_match_score": "85", "icij_entity_match": "", "gleif_status": "ACTIVE", "registrant_org": "Reg A"},
        "shell2.com": {"os_match_score": "", "icij_entity_match": "Panama Papers", "gleif_status": "", "registrant_org": "Reg B"},
    }
    from build_frontend_data import enrich_clusters_with_entity_stats
    enrich_clusters_with_entity_stats(clusters, domains)

    infra_node = clusters["nodes"][0]
    assert infra_node["entity_stats"]["os_hits"] == 1
    assert infra_node["entity_stats"]["icij_hits"] == 1
    assert infra_node["entity_stats"]["gleif_active"] == 1
    assert infra_node["entity_stats"]["unique_registrants"] == 2
    assert infra_node["entity_risk"] is True  # private infra + >=2 entity hits


def test_shared_infra_no_entity_risk():
    """Shared infrastructure should not get entity_risk even with entity hits."""
    clusters = {
        "nodes": [
            {"id": "mx:aspmx.l.google.com", "type": "mx_host", "shared_infra": True},
            {"id": "dom:d1.com", "type": "domain"},
            {"id": "dom:d2.com", "type": "domain"},
        ],
        "edges": [
            {"source": "dom:d1.com", "target": "mx:aspmx.l.google.com"},
            {"source": "dom:d2.com", "target": "mx:aspmx.l.google.com"},
        ],
    }
    domains = {
        "d1.com": {"os_match_score": "90", "icij_entity_match": "Paradise Papers", "gleif_status": "ACTIVE", "registrant_org": "Reg A"},
        "d2.com": {"os_match_score": "80", "icij_entity_match": "", "gleif_status": "", "registrant_org": "Reg B"},
    }
    from build_frontend_data import enrich_clusters_with_entity_stats
    enrich_clusters_with_entity_stats(clusters, domains)

    infra_node = clusters["nodes"][0]
    assert infra_node["entity_stats"]["os_hits"] == 2  # stats are still computed
    assert infra_node["entity_risk"] is False  # but no risk because shared


def test_domain_nodes_not_enriched():
    """Domain-type nodes should NOT have entity_stats added."""
    clusters = {
        "nodes": [
            {"id": "mx:mail.test.com", "type": "mx_host", "shared_infra": False},
            {"id": "dom:test.com", "type": "domain"},
        ],
        "edges": [
            {"source": "dom:test.com", "target": "mx:mail.test.com"},
        ],
    }
    domains = {
        "test.com": {"os_match_score": "50", "icij_entity_match": "", "gleif_status": "", "registrant_org": "Reg"},
    }
    from build_frontend_data import enrich_clusters_with_entity_stats
    enrich_clusters_with_entity_stats(clusters, domains)

    domain_node = clusters["nodes"][1]
    assert "entity_stats" not in domain_node
    assert "entity_risk" not in domain_node
