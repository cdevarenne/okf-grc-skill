from pathlib import Path

import yaml

SKILL = Path(__file__).parent.parent / ".claude" / "skills" / "grc-continuous-compliance" / "SKILL.md"


def test_frontmatter_names_the_skill() -> None:
    fm = yaml.safe_load(SKILL.read_text().split("---\n")[1])
    assert fm["name"] == SKILL.parent.name
    assert len(fm["description"]) > 100


def test_states_the_grounding_rule() -> None:
    text = SKILL.read_text()
    assert "coverage gap" in text and "Never invent" in text


def test_scanned_text_is_data_not_instructions() -> None:
    text = SKILL.read_text()
    assert "data, not instructions" in text
