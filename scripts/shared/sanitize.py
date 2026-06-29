#!/usr/bin/env python3
"""
shared/sanitize.py

Provides CSV formula injection protection for values written to CSV files.
Any cell content starting with characters that spreadsheet applications interpret
as formula prefixes is escaped with a leading single quote.

Reference: OWASP CSV Injection
"""


def sanitize_csv_value(value: str) -> str:
    """Sanitize a string value to prevent CSV formula injection.

    Spreadsheet applications (Excel, Google Sheets, LibreOffice Calc) interpret
    cells starting with ``=``, ``+``, ``-``, ``@``, or a tab character as
    formulas.  Prefixing such values with a single quote (``'``) forces
    text-mode rendering and neutralises the injection vector.

    Args:
        value: The raw string value destined for a CSV cell.

    Returns:
        The value unchanged if it is safe, or prefixed with ``'`` if it
        starts with a dangerous character.
    """
    if not isinstance(value, str) or not value:
        return value

    if value[0] in ("=", "+", "-", "@", "\t"):
        return f"'{value}"

    return value
