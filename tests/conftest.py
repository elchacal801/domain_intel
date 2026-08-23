"""Shared pytest configuration for the domain_intel test suite.

Puts ``scripts/`` on ``sys.path`` once, for every test module.

36 of 40 test modules previously did this themselves. The four that did not
could only be collected when some *other* module had already run and set the
path as a side effect -- ``pytest tests/test_shared.py`` on its own failed with
``ModuleNotFoundError: No module named 'shared'``. Doing it here removes that
whole class of ordering dependency; the per-module inserts that remain are now
redundant but harmless.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
