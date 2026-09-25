"""Load an OKF v0.2 bundle into an in-memory concept graph."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

RESERVED = frozenset({"index.md", "log.md"})
CONTROL_TYPE = "SOC 2 Control"
SCANNER_TYPE = "Scanner"
GUARDRAIL_TYPES = ("Rego Policy", "Semgrep Rule")
COMPONENT_TYPE = "Stack Component"
_CONTROL_TAG = re.compile(r"^cc\d+\.\d+$")
_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n?(.*)\Z", re.S)
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_H1 = re.compile(r"^# (.+?)\s*$", re.M)


class BundleError(ValueError):
    """A bundle file violates OKF v0.2 conformance (§11)."""


@dataclass(frozen=True)
class Concept:
    """One OKF concept document."""

    id: str
    path: str
    type: str
    title: str
    description: str
    tags: tuple[str, ...]
    rule_ids: tuple[str, ...]
    frontmatter: Mapping[str, Any]
    body: str
    links: tuple[str, ...]

    @property
    def code(self) -> str:
        """Last path segment of the id, e.g. 'cc7.1' for 'controls/cc7.1'."""
        return self.id.rsplit("/", 1)[-1]

    @property
    def control_tags(self) -> tuple[str, ...]:
        """Tags naming a SOC 2 criterion, e.g. ('cc7.1',)."""
        return tuple(t for t in self.tags if _CONTROL_TAG.match(t))


@dataclass(frozen=True)
class Bundle:
    """All concepts in a bundle, keyed by concept id."""

    concepts: Mapping[str, Concept]

    def of_type(self, *types: str) -> list[Concept]:
        """Concepts of the given type(s), sorted by id."""
        return sorted((c for c in self.concepts.values() if c.type in types), key=lambda c: c.id)

    def controls(self) -> list[Concept]:
        """SOC 2 control concepts, sorted by id."""
        return self.of_type(CONTROL_TYPE)

    def control(self, code: str) -> Concept | None:
        """The control concept whose code is `code`, if the bundle has one."""
        return next((c for c in self.controls() if c.code == code), None)

    def by_rule(self, tool: str, rule_id: str) -> list[Concept]:
        """Concepts whose `rule_ids` declare coverage of this scanner rule (globs allowed)."""
        return [
            c
            for c in sorted(self.concepts.values(), key=lambda c: c.id)
            if any(_rule_matches(entry, tool, rule_id) for entry in c.rule_ids)
        ]

    def section(self, concept: Concept, heading: str) -> str | None:
        """Body text under `# heading`, up to the next level-1 heading."""
        matches = list(_H1.finditer(concept.body))
        for i, m in enumerate(matches):
            if m.group(1) == heading:
                end = matches[i + 1].start() if i + 1 < len(matches) else len(concept.body)
                return concept.body[m.end() : end].strip()
        return None


def _rule_matches(entry: str, tool: str, rule_id: str) -> bool:
    entry_tool, _, pattern = entry.partition(":")
    return entry_tool == tool and fnmatchcase(rule_id, pattern)


def _resolve_link(target: str, concept_path: str) -> str | None:
    """Bundle-relative concept id for a markdown link, or None if it is not a concept link."""
    target = target.split("#", 1)[0]
    if "://" in target or target.startswith("mailto:") or not target.endswith(".md"):
        return None
    if target.startswith("/"):
        resolved = posixpath.normpath(target.lstrip("/"))
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(concept_path), target))
    if resolved.startswith("..") or posixpath.basename(resolved) in RESERVED:
        return None
    return resolved.removesuffix(".md")


def _parse(rel_path: str, text: str) -> Concept:
    m = _FRONTMATTER.match(text)
    if not m:
        raise BundleError(f"{rel_path}: missing YAML frontmatter")
    try:
        fm = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as e:
        raise BundleError(f"{rel_path}: unparseable frontmatter: {e}") from e
    if not isinstance(fm, dict) or not str(fm.get("type") or "").strip():
        raise BundleError(f"{rel_path}: frontmatter has no non-empty 'type'")
    body = m.group(2)
    stem = rel_path.removesuffix(".md")
    return Concept(
        id=stem,
        path=rel_path,
        type=str(fm["type"]).strip(),
        title=str(fm.get("title") or posixpath.basename(stem)),
        description=str(fm.get("description") or ""),
        tags=tuple(str(t) for t in fm.get("tags") or ()),
        rule_ids=tuple(str(r) for r in fm.get("rule_ids") or ()),
        frontmatter=fm,
        body=body,
        links=tuple(
            dict.fromkeys(
                link for t in _LINK.findall(body) if (link := _resolve_link(t, rel_path)) is not None
            )
        ),
    )


def load_bundle(root: Path) -> Bundle:
    """Parse every non-reserved .md under `root` into a Bundle."""
    concepts: dict[str, Concept] = {}
    for path in sorted(root.rglob("*.md")):
        if path.name in RESERVED:
            continue
        rel = path.relative_to(root).as_posix()
        concept = _parse(rel, path.read_text(encoding="utf-8"))
        concepts[concept.id] = concept
    return Bundle(concepts=concepts)
