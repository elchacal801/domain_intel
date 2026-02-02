
import pytest
import collections
import sys
import os

# Ensure scripts directory is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from generate_pivots import normalize

def test_normalize():
    assert normalize("  Example.COM.  ") == "example.com"
    assert normalize("foo.bar") == "foo.bar"
    assert normalize("") == ""

def test_risk_counting_logic():
    """
    Simulate the logic used in generate_pivots loop for risk tags
    """
    risk_counts = collections.Counter()
    
    # Simulating rows
    rows = [
        {"risk_tags": "HighRisk:Nicenic"},
        {"risk_tags": "HighRisk:Nicenic; Bulletproof"},
        {"risk_tags": ""},
        {"risk_tags": "  HighRisk:Nicenic  "} # Testing trim
    ]
    
    for row in rows:
        risks = row.get("risk_tags", "").strip()
        if risks:
            for tag in risks.split(';'):
                t = tag.strip()
                if t:
                    risk_counts[t] += 1
                    
    assert risk_counts["HighRisk:Nicenic"] == 3
    assert risk_counts["Bulletproof"] == 1
    assert len(risk_counts) == 2
