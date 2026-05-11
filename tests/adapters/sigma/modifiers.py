"""Sigma value modifiers and field-matching primitives.

Modifiers in scope for v1:
    startswith, endswith, contains, all, cased, re (with i/m/s sub-modifiers)

Modifiers explicitly out of scope (raise ValueError):
    base64, base64offset, utf16le, utf16be, utf16, wide, windash,
    cidr, lt, lte, gt, gte, neq, exists, expand, fieldref,
    minute, hour, day, week, month, year
"""

from __future__ import annotations

import re


def match_field(modifiers: list[str], field_value: object, expected_value: object) -> bool:
    """Apply a chain of Sigma modifiers to compare field_value against expected_value.

    Returns True if the comparison succeeds.
    Raises ValueError on unknown or unsupported modifiers.
    """
    options = {}
    handler = _match_exact
    for mod in modifiers:
        if mod == "startswith":
            handler = _match_startswith
        elif mod == "endswith":
            handler = _match_endswith
        elif mod == "contains":
            handler = _match_contains
        elif mod == "re":
            handler = _match_regex
        elif mod == "cased":
            options["cased"] = True
        elif mod == "i":
            options["re_i"] = True
        elif mod == "m":
            options["re_m"] = True
        elif mod == "s":
            options["re_s"] = True
        elif mod == "all":
            pass  # handled by caller
        elif mod in OUT_OF_SCOPE_MODIFIERS:
            raise ValueError(f"Sigma modifier '{mod}' is out of scope for this adapter")
        else:
            raise ValueError(f"Unknown Sigma modifier: '{mod}'")
    return handler(field_value, expected_value, options)


def _match_exact(field_value: object, expected_value: object, options: dict) -> bool:
    flag = 0 if options.get("cased", False) else re.IGNORECASE
    field_str = str(field_value)
    expected_pattern = wildcard_to_regex(str(expected_value))
    return re.fullmatch(expected_pattern, field_str, flags=flag) is not None


def _match_startswith(field_value: object, expected_value: object, options: dict) -> bool:
    cased = options.get("cased", False)
    field_str = str(field_value)
    expected_str = str(expected_value)
    if not cased:
        field_str = field_str.lower()
        expected_str = expected_str.lower()
    return field_str.startswith(expected_str)


def _match_endswith(field_value: object, expected_value: object, options: dict) -> bool:
    cased = options.get("cased", False)
    field_str = str(field_value)
    expected_str = str(expected_value)
    if not cased:
        field_str = field_str.lower()
        expected_str = expected_str.lower()
    return field_str.endswith(expected_str)


def _match_contains(field_value: object, expected_value: object, options: dict) -> bool:
    cased = options.get("cased", False)
    field_str = str(field_value)
    expected_str = str(expected_value)
    if not cased:
        field_str = field_str.lower()
        expected_str = expected_str.lower()
    return expected_str in field_str


def _match_regex(field_value: object, expected_value: object, options: dict) -> bool:
    flags = 0
    if options.get("re_i", False):
        flags |= re.IGNORECASE
    if options.get("re_m", False):
        flags |= re.MULTILINE
    if options.get("re_s", False):
        flags |= re.DOTALL
    field_str = str(field_value)
    pattern = str(expected_value)
    return re.fullmatch(pattern, field_str, flags=flags) is not None


def wildcard_to_regex(pattern: str) -> str:
    result = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            result.append(re.escape(pattern[i+1]))
            i += 2
        elif char == "*":
            result.append(".*")
            i += 1
        elif char == "?":
            result.append(".")
            i += 1
        else:
            result.append(re.escape(char))
            i += 1
    return "".join(result)


OUT_OF_SCOPE_MODIFIERS: set[str] = {
    "base64", "base64offset",
    "utf16le", "utf16be", "utf16", "wide",
    "windash",
    "cidr",
    "lt", "lte", "gt", "gte",
    "neq",
    "exists",
    "expand",
    "fieldref",
    "minute", "hour", "day", "week", "month", "year",
    }
