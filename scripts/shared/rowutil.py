#!/usr/bin/env python3
"""
shared/rowutil.py

Helpers for annotating pipeline CSV rows in place.
"""


def append_error(row: dict, marker: str) -> None:
    """Append a stage-tagged marker to row['error'] without duplicating it.

    Later pipeline stages share one ``error`` column with earlier stages, so
    markers are appended with ';' rather than overwriting, and re-annotation
    with the same marker is a no-op (stages can touch a row more than once
    around a deadline).
    """
    existing = (row.get("error") or "").strip()
    if marker in existing:
        return
    row["error"] = f"{existing};{marker}" if existing else marker
