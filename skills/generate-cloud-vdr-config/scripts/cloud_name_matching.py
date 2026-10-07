"""Cloud name-rule matching shared verbatim by the VDR skill and TSW."""

import fnmatch
from functools import lru_cache

MAX_REGEX_LENGTH = 2048
REGEX_TIMEOUT_SECONDS = 0.025


@lru_cache(maxsize=256)
def _compile(pattern):
    try:
        import regex
    except ImportError as exc:
        raise ValueError("matchRegex requires the regex package (regex>=2024.11.4)") from exc
    try:
        return regex.compile(pattern, flags=regex.VERSION0)
    except regex.error as exc:
        raise ValueError(f"invalid matchRegex: {exc}") from exc


def selector_errors(rule, family):
    """Validate selectors even when no inventory resource could match."""
    if family != "nameRules":
        return ["matchRegex is only allowed in nameRules"] if rule.get("matchRegex") is not None else []
    selectors = [key for key in ("match", "matchRegex") if rule.get(key) is not None]
    if len(selectors) != 1:
        return ["nameRules requires exactly one of match or matchRegex"]
    key = selectors[0]
    value = rule[key]
    if not isinstance(value, str) or not value.strip():
        return [f"{key} must be a non-empty string"]
    if key == "match":
        return []
    errors = []
    if not isinstance(rule.get("type"), str) or not rule["type"].strip():
        errors.append("matchRegex requires an explicit non-empty type")
    if len(value) > MAX_REGEX_LENGTH:
        errors.append(f"matchRegex exceeds {MAX_REGEX_LENGTH} characters")
    else:
        try:
            _compile(value)
        except ValueError as exc:
            errors.append(str(exc))
    return errors


def name_matches(rule, identifier):
    """Case-sensitive, whole-identifier matching; timeouts never mean no match.

    Direct resolver calls receive the same selector checks as policy validation.
    """
    errors = selector_errors(rule, "nameRules")
    if errors:
        raise ValueError("; ".join(errors))
    pattern = rule.get("matchRegex")
    if pattern is None:
        return fnmatch.fnmatchcase(identifier, rule.get("match") or "")
    if not isinstance(pattern, str) or len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"matchRegex must be a string of at most {MAX_REGEX_LENGTH} characters")
    try:
        return _compile(pattern).fullmatch(identifier, timeout=REGEX_TIMEOUT_SECONDS) is not None
    except TimeoutError as exc:
        raise ValueError(f"matchRegex evaluation exceeded {REGEX_TIMEOUT_SECONDS * 1000:g} ms; simplify the pattern") from exc
