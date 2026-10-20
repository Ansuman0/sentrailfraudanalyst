"""Check that every number and date the LLM wrote exists in the case facts.

Unverified figures are returned so the UI can highlight them in red.
Dates are checked as whole dates (not as loose small numbers), so an invented
count like "12 senders" is caught even though 12 could also be a day of the month.
"""
import re
from datetime import datetime

NUM = re.compile(r"(?<![\w<])\d[\d,]*(?:\.\d+)?(?![\w>])")
ISO_DATE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b")
MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
WORD_DATES = [
    (re.compile(rf"\b(?:{MONTHS})\s+\d{{1,2}},\s*\d{{4}}\b"), "%B %d, %Y"),   # March 5, 2024
    (re.compile(rf"\b\d{{1,2}}\s+(?:{MONTHS})\s+\d{{4}}\b"), "%d %B %Y"),    # 5 March 2024
]


def _norm(s: str) -> float | None:
    try:
        return round(float(s.replace(",", "")), 2)
    except ValueError:
        return None


def _take_dates(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Remove dates from the text and return them as (as written, YYYY-MM-DD)."""
    found = []
    def iso(m):
        found.append((m.group(0), f"{m.group(1)}-{m.group(2)}-{m.group(3)}")); return " "
    text = ISO_DATE.sub(iso, text)
    for rx, fmt in WORD_DATES:
        def word(m):
            raw = re.sub(r"\s+", " ", m.group(0))
            try:
                found.append((m.group(0), datetime.strptime(raw.replace(" ,", ","), fmt).strftime("%Y-%m-%d")))
            except ValueError:
                found.append((m.group(0), "invalid"))
            return " "
        text = rx.sub(word, text)
    return text, found


def collect_facts(obj, nums=None, dates=None) -> tuple[set[float], set[str]]:
    nums = set() if nums is None else nums
    dates = set() if dates is None else dates
    if isinstance(obj, dict):
        for v in obj.values(): collect_facts(v, nums, dates)
    elif isinstance(obj, list):
        for v in obj: collect_facts(v, nums, dates)
    elif isinstance(obj, bool):
        pass
    elif isinstance(obj, (int, float)):
        nums.add(round(float(obj), 2))
    elif isinstance(obj, str):
        rest, ds = _take_dates(obj)
        dates.update(d for _, d in ds)
        for m in NUM.findall(rest):
            n = _norm(m)
            if n is not None: nums.add(n)
    return nums, dates


def collect_numbers(obj) -> set[float]:
    return collect_facts(obj)[0]


def verify(narrative: str, facts: dict) -> dict:
    known_nums, known_dates = collect_facts(facts)
    rest, dates = _take_dates(narrative)
    found = [m for m in NUM.findall(rest) if _norm(m) is not None]
    bad = [m for m in found if _norm(m) not in known_nums]
    bad += [written for written, d in dates if d not in known_dates]
    return {"checked": len(found) + len(dates), "unverified": bad, "ok": not bad}
