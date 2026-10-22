"""Numeric Guardrail for Aegis Guard.

Extracts numbers with units (currency, duration, temperature, counts) from LLM replies
and verifies that every number matches a ground-truth fact, normalizing format discrepancies
(e.g., $1,200.00 vs 1200, 71.0 vs 71).
"""

from dataclasses import dataclass, field
import re
from typing import Any, Mapping


@dataclass
class ExtractedNumber:
    """A numeric mention parsed from LLM reply text."""

    raw_text: str
    value: float
    unit: str  # 'usd', 'seconds', 'minutes', 'degrees', 'count', 'number'
    normalized_values: list[float] = field(default_factory=list)
    start_pos: int = 0
    end_pos: int = 0


def _parse_float(s: str) -> float:
    """Parse string to float, stripping commas and whitespace."""
    clean = s.replace(",", "").strip()
    return float(clean)


def _almost_equal(a: float, b: float, tol: float = 1e-3) -> bool:
    """Return True if two floats are equal within a small tolerance."""
    return abs(a - b) <= tol


class FactsIndex:
    """Structured index of numeric values extracted from ground truth facts."""

    def __init__(self, facts: Mapping[str, Any]) -> None:
        self.all_values: set[float] = set()
        self.usd_values: set[float] = set()
        self.temperature_values: set[float] = set()
        self.duration_seconds: set[float] = set()
        self.count_values: set[float] = set()

        self._index_recursive(facts, parent_key="")

    def _index_recursive(self, data: Any, parent_key: str = "") -> None:
        if isinstance(data, Mapping):
            for k, v in data.items():
                new_key = f"{parent_key}.{k}" if parent_key else str(k)
                self._index_recursive(v, new_key)
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                self._index_recursive(item, parent_key)
        elif isinstance(data, (int, float)) and not isinstance(data, bool):
            val = float(data)
            self.all_values.add(val)
            low_k = parent_key.lower()

            # Categorize by key naming patterns
            if any(term in low_k for term in ("usd", "dollar", "price", "value", "cost")):
                self.usd_values.add(val)
            if any(term in low_k for term in ("temp", "temperature", "degree", "_f", "_c", "climate")):
                self.temperature_values.add(val)
            if any(term in low_k for term in ("second", "sec", "dwell", "duration")):
                self.duration_seconds.add(val)
                if val > 0:
                    self.duration_seconds.add(val / 60.0)
            if any(term in low_k for term in ("count", "bpm", "heart_rate")):
                self.count_values.add(val)

        elif isinstance(data, str):
            # Parse only clean numeric strings (e.g. "$1,200.00" or "71.0"), avoiding ISO dates/timestamps
            cleaned = data.strip().replace("$", "").replace(",", "")
            try:
                self.all_values.add(float(cleaned))
            except ValueError:
                pass

    def matches(self, extracted: ExtractedNumber) -> bool:
        """Check if an extracted number matches any allowable ground truth fact value."""
        candidates_to_check = extracted.normalized_values or [extracted.value]

        # 1. Check unit-specific facts first
        category_set: set[float] | None = None
        if extracted.unit == "usd":
            category_set = self.usd_values
        elif extracted.unit == "degrees":
            category_set = self.temperature_values
        elif extracted.unit in ("seconds", "minutes"):
            category_set = self.duration_seconds
        elif extracted.unit == "count":
            category_set = self.count_values

        if category_set is not None:
            if len(category_set) > 0:
                for cand in candidates_to_check:
                    for fact_val in category_set:
                        if _almost_equal(cand, fact_val):
                            return True
                return False

        # 2. Check general numeric facts set as fallback for plain numbers
        for cand in candidates_to_check:
            for fact_val in self.all_values:
                if _almost_equal(cand, fact_val):
                    return True

        return False


def extract_numbers(text: str) -> list[ExtractedNumber]:
    """Extract all numbers with units and standalone quantities from text.

    Supported patterns:
    - Currency: $120, $1,200.00, 120 USD, 120 dollars
    - Temperature: 71°F, 71.0 degrees, 71°, 71 degrees F
    - Duration: 42.5 seconds, 42.5s, 42 sec, 2 minutes, 2 min
    - Counts/Units: 72 bpm, 1 package
    - Plain numbers: 1,200, 71.0, 42
    """
    results: list[ExtractedNumber] = []
    matched_spans: list[tuple[int, int]] = []

    def span_overlaps(start: int, end: int) -> bool:
        return any(s < end and end <= e or start >= s and start < e for s, e in matched_spans)

    # 1. Currency: e.g. $1,200.00 or 1200 USD / dollars
    for m in re.finditer(r"\$\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)\b", text, re.IGNORECASE):
        start, end = m.span()
        val = _parse_float(m.group(1))
        results.append(ExtractedNumber(
            raw_text=m.group(0),
            value=val,
            unit="usd",
            normalized_values=[val],
            start_pos=start,
            end_pos=end,
        ))
        matched_spans.append((start, end))

    for m in re.finditer(r"\b([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)\s*(?:dollars?|usd)\b", text, re.IGNORECASE):
        start, end = m.span()
        if not span_overlaps(start, end):
            val = _parse_float(m.group(1))
            results.append(ExtractedNumber(
                raw_text=m.group(0),
                value=val,
                unit="usd",
                normalized_values=[val],
                start_pos=start,
                end_pos=end,
            ))
            matched_spans.append((start, end))

    # 2. Temperature: 71°F, 71 degrees, 71.5°
    for m in re.finditer(r"\b([0-9]+(?:\.[0-9]+)?)\s*(?:°\s*[FfCc]?|degrees?(?:\s*(?:[FfCc]|fahrenheit|celsius))?)\b", text):
        start, end = m.span()
        if not span_overlaps(start, end):
            val = _parse_float(m.group(1))
            results.append(ExtractedNumber(
                raw_text=m.group(0),
                value=val,
                unit="degrees",
                normalized_values=[val],
                start_pos=start,
                end_pos=end,
            ))
            matched_spans.append((start, end))

    # 3. Duration: seconds, minutes
    for m in re.finditer(r"\b([0-9]+(?:\.[0-9]+)?)\s*(seconds?|secs?|minutes?|mins?|s|m)\b", text, re.IGNORECASE):
        start, end = m.span()
        if not span_overlaps(start, end):
            val = _parse_float(m.group(1))
            unit_str = m.group(2).lower()
            if unit_str in ("minute", "minutes", "min", "mins", "m"):
                # Minutes: normalized as both minutes and converted seconds (val * 60)
                norm_vals = [val, val * 60.0]
                unit_name = "minutes"
            else:
                # Seconds: normalized as seconds and converted minutes (val / 60)
                norm_vals = [val, val / 60.0]
                unit_name = "seconds"

            results.append(ExtractedNumber(
                raw_text=m.group(0),
                value=val,
                unit=unit_name,
                normalized_values=norm_vals,
                start_pos=start,
                end_pos=end,
            ))
            matched_spans.append((start, end))

    # 4. Heart rate / BPM
    for m in re.finditer(r"\b([0-9]+(?:\.[0-9]+)?)\s*(?:bpm|beats\s*per\s*minute)\b", text, re.IGNORECASE):
        start, end = m.span()
        if not span_overlaps(start, end):
            val = _parse_float(m.group(1))
            results.append(ExtractedNumber(
                raw_text=m.group(0),
                value=val,
                unit="count",
                normalized_values=[val],
                start_pos=start,
                end_pos=end,
            ))
            matched_spans.append((start, end))

    # 5. Generic numbers with commas or decimals (excluding dates / timestamps)
    for m in re.finditer(r"(?<![\$\w:\-])([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)(?![\w°:\-])", text):
        start, end = m.span()
        if not span_overlaps(start, end):
            raw_s = m.group(1)
            # Ignore year numbers 2000-2099 if they look like calendar years in text
            try:
                val = _parse_float(raw_s)
                results.append(ExtractedNumber(
                    raw_text=raw_s,
                    value=val,
                    unit="number",
                    normalized_values=[val],
                    start_pos=start,
                    end_pos=end,
                ))
                matched_spans.append((start, end))
            except ValueError:
                pass

    return results


def verify(reply_text: str, facts: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Verify that every number mentioned in the reply matches a ground-truth fact.

    Normalizes formatting differences ($1,200 vs 1200, 71.0 vs 71, minutes vs seconds).

    Args:
        reply_text: The drafted text summary (e.g. from an LLM).
        facts: Ground-truth facts dictionary.

    Returns:
        tuple[bool, list[str]]: (ok, violations)
        - ok is True if all extracted numbers match a fact in facts.
        - violations is a list of error descriptions for any unverified or hallucinated numbers.
    """
    if not reply_text:
        return True, []

    index = FactsIndex(facts)
    extracted_numbers = extract_numbers(reply_text)
    violations: list[str] = []

    for item in extracted_numbers:
        if not index.matches(item):
            violations.append(
                f"Numeric hallucination detected: '{item.raw_text}' (normalized: {item.value}, unit: '{item.unit}') "
                f"does not match any ground truth facts."
            )

    return len(violations) == 0, violations
