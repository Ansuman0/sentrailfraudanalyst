"""Reversible PII masking with Microsoft Presidio.

Names, emails, phone numbers, account numbers and wallet addresses become
tokens like <PERSON_1> before text reaches the LLM, and are restored after.
"""
import re
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

_analyzer = None


def _engine() -> AnalyzerEngine:
    """Built on first use (it loads a large spaCy model)."""
    global _analyzer
    if _analyzer is None:
        a = AnalyzerEngine()
        a.registry.add_recognizer(PatternRecognizer(
            supported_entity="WALLET", patterns=[
                Pattern("tron", r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", 0.9),
                Pattern("evm", r"\b0x[a-fA-F0-9]{40}\b", 0.9)]))
        a.registry.add_recognizer(PatternRecognizer(
            supported_entity="ACCOUNT", patterns=[Pattern("acct", r"\b[A-Z]{2,4}\d{6,14}\b", 0.6)]))
        _analyzer = a
    return _analyzer


def _drop_overlaps(results):
    """Two recognizers can flag the same text (e.g. PHONE and ACCOUNT). Keep the highest-scoring,
    longest span so a token is never written inside another token."""
    kept = []
    for r in sorted(results, key=lambda r: (-r.score, -(r.end - r.start))):
        if all(r.end <= k.start or r.start >= k.end for k in kept):
            kept.append(r)
    return kept

ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD", "WALLET", "ACCOUNT"]


def mask(text: str) -> tuple[str, dict]:
    results = sorted(_drop_overlaps(_engine().analyze(text=text, entities=ENTITIES, language="en")),
                     key=lambda r: r.start, reverse=True)
    mapping, counters, seen = {}, {}, {}
    for r in results:
        original = text[r.start:r.end]
        if original not in seen:
            counters[r.entity_type] = counters.get(r.entity_type, 0) + 1
            seen[original] = f"<{r.entity_type}_{counters[r.entity_type]}>"
            mapping[seen[original]] = original
        text = text[:r.start] + seen[original] + text[r.end:]
    return text, mapping


def unmask(text: str, mapping: dict) -> str:
    for token, original in mapping.items():
        text = text.replace(token, original)
    return text
