
import importlib
import pytest
import sys
import os

# Ensure scripts directory is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

def test_imports():
    """
    Smoke test: Ensure all major scripts can be imported without syntax errors.
    This doesn't run them, just compiles and loads the modules.
    """
    scripts = [
        'enrich_infrastructure',
        'enrich_reputation',
        'probe_web',
        'merge_results',
        'generate_pivots',
        'clean_data',
        'asn_intel',
        'split_data'
    ]
    
    for script_name in scripts:
        try:
            importlib.import_module(script_name)
        except ImportError as e:
            pytest.fail(f"Failed to import {script_name}: {e}")
        except SyntaxError as e:
            pytest.fail(f"Syntax error in {script_name}: {e}")
