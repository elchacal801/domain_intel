"""Guards against test-suite defects that hide real failures.

These are meta-tests: they assert properties of the suite itself rather than of
production code. Both encode faults that actually occurred and cost real time.
"""

import glob
import os
import re

TESTS_DIR = os.path.dirname(__file__)


def _test_modules():
    return sorted(glob.glob(os.path.join(TESTS_DIR, "test_*.py")))


class TestNoSysModulesLeakage:
    """A test module must not permanently stub entries in sys.modules.

    Three modules used to install MagicMocks at import time with no teardown:

        sys.modules.setdefault("shared.llm_client", MagicMock())

    Because pytest collects alphabetically, every module importing those names
    later received a MagicMock instead of the real thing. That produced 66
    spurious failures in a full run while each file passed on its own -- the
    kind of noise that trains people to ignore a red suite.

    Stubbing is still allowed; it must simply be undone. Either restore the
    previous sys.modules state after the guarded import, or use
    unittest.mock.patch.dict, which restores on exit.
    """

    STUB_PATTERN = re.compile(r"sys\.modules\s*(?:\.setdefault\s*\(|\[)")

    def test_stubs_are_restored(self):
        offenders = []
        for path in _test_modules():
            src = open(path, encoding="utf-8", errors="ignore").read()
            if not self.STUB_PATTERN.search(src):
                continue
            restores = "patch.dict" in src or ("_saved" in src and "finally" in src)
            if not restores:
                offenders.append(os.path.basename(path))

        assert not offenders, (
            "these test modules stub sys.modules without restoring it, which "
            f"leaks into every later module: {offenders}"
        )


class TestModulesAreSelfContained:
    """Every test module must be importable on its own.

    tests/conftest.py puts scripts/ on sys.path for the whole suite. This test
    fails if a module reaches for something conftest does not provide, which
    would once again make collection depend on run order.
    """

    def test_every_module_declares_its_imports(self):
        missing = []
        for path in _test_modules():
            src = open(path, encoding="utf-8", errors="ignore").read()
            # A module importing from scripts/ needs either conftest's path
            # setup (always present now) or its own -- what it must never do is
            # rely on another *test* module having imported something first.
            if re.search(r"^from tests\.", src, re.M):
                missing.append(os.path.basename(path))

        assert not missing, (
            f"test modules importing from sibling test modules: {missing}"
        )
