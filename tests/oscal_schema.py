"""Validate documents against the vendored NIST OSCAL JSON schemas."""

import json
from pathlib import Path

from jsonschema import Draft7Validator

SCHEMAS = Path(__file__).parent / "fixtures" / "oscal"

# OSCAL patterns use Unicode property classes that Python's `re` cannot compile.
_PY_EQUIVALENTS = {r"\p{L}": r"[^\W\d_]", r"\p{N}": r"\d"}


def validate(document: dict, schema_file: str) -> None:
    """Raise jsonschema.ValidationError if `document` does not conform."""
    text = (SCHEMAS / schema_file).read_text(encoding="utf-8")
    for unicode_class, python_class in _PY_EQUIVALENTS.items():
        text = text.replace(unicode_class.replace("\\", "\\\\"), python_class.replace("\\", "\\\\"))
    Draft7Validator(json.loads(text)).validate(document)
