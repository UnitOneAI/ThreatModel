"""Skill loader.

Skills are agentskills.io-style markdown with a YAML frontmatter block. The loader
scans the skills/ dir and builds the index by reading each SKILL.md's frontmatter —
so adding a skill file adds a capability with no code change. The planner reads this
index to *select* skills per component.

Frontmatter is parsed with a small stdlib parser (the subset we use: scalars and
simple lists) so there is no PyYAML dependency for the core path.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

# Canonical skills ship INSIDE the package (so they're present in a wheel — arch
# review D1). An env override (SYNTHESIS_SKILLS_DIR) lets operators point at a custom
# skill set.
_IN_PACKAGE_SKILLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")
DEFAULT_SKILLS_DIR = os.environ.get("SYNTHESIS_SKILLS_DIR", _IN_PACKAGE_SKILLS)


@dataclass
class Skill:
    id: str
    domain: str
    title: str
    triggers: list[str] = field(default_factory=list)  # component kinds / keywords
    control_frameworks: list[str] = field(default_factory=list)
    confidence_cap: float = 0.7
    path: str = ""
    body: str = ""  # the markdown body = the cached system prompt for reviewers

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "body"}
        d["body_chars"] = len(self.body)
        return d


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return (frontmatter_dict, body). Supports `key: scalar` and block lists."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    fm_block = text[3:end].strip("\n")
    body = text[end + 4 :].lstrip("\n")
    data: dict[str, Any] = {}
    cur_key: str | None = None
    for raw in fm_block.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- ") and cur_key:
            data.setdefault(cur_key, [])
            if isinstance(data[cur_key], list):
                data[cur_key].append(_scalar(line.lstrip()[2:].strip()))
            continue
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            cur_key = key
            if val == "":
                data[key] = []  # block list or empty follows
            elif val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                data[key] = [_scalar(x.strip()) for x in inner.split(",") if x.strip()]
            else:
                data[key] = _scalar(val)
    return data, body


def _scalar(v: str) -> Any:
    v = v.strip().strip('"').strip("'")
    try:
        if "." in v:
            return float(v)
        return int(v)
    except ValueError:
        return v


def load_skills(skills_dir: str | None = None) -> dict[str, Skill]:
    skills_dir = skills_dir or DEFAULT_SKILLS_DIR
    out: dict[str, Skill] = {}
    if not os.path.isdir(skills_dir):
        return out
    for root, _dirs, files in os.walk(skills_dir):
        for fn in files:
            if not fn.endswith(".md"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            fm, body = _parse_frontmatter(text)
            sid = fm.get("id")
            if not sid:
                continue
            out[sid] = Skill(
                id=sid,
                domain=fm.get("domain", "uncategorized"),
                title=fm.get("title", sid),
                triggers=_as_list(fm.get("triggers")),
                control_frameworks=_as_list(fm.get("control_frameworks")),
                confidence_cap=float(fm.get("confidence_cap", 0.7)),
                path=path,
                body=body,
            )
    return out


def select_skills(
    skills: dict[str, Skill], component_kinds: list[str], text: str = ""
) -> list[str]:
    """Heuristic skill selection (the scripted planner's selector).

    A skill fires when any of its triggers matches a present component kind or a
    keyword in the ingested text. The LLM planner can override/extend this.
    """
    text_l = text.lower()
    selected: list[str] = []
    for sid, sk in skills.items():
        for trig in sk.triggers:
            t = str(trig).lower()
            if t in (k.lower() for k in component_kinds) or (t and t in text_l):
                selected.append(sid)
                break
    # always include the base threat-modeling skill if present
    base = next((s for s in skills if "threat-modeling" in s), None)
    if base and base not in selected:
        selected.insert(0, base)
    return selected or list(skills.keys())[:1]


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]
