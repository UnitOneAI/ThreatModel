"""Skill loader.

Skills follow the **SecuritySkills / agentskills.io `SKILL.md`** format: a directory
`skills/<domain>/<skill-name>/SKILL.md` with YAML frontmatter, plus optional sibling
reference files (progressive disclosure — see github.com/UnitOneAI/SecuritySkills).
The loader also reads the engine's legacy flat `<domain>/<name>.md` skills (frontmatter
with an `id`) so bundled offline skills keep working. Adding a skill file adds a
capability with no code change; the planner reads the index to *select* skills per
component, and a reviewer loads the skill's prompt (read-only).

Because a real `SKILL.md` body can be tens of KB and the engine fans out one reviewer
per (component x skill), we do NOT feed the whole document to every reviewer. For
`SKILL.md` skills the loader compiles a **bounded reviewer prompt** (description +
a capped slice of the guidance + the engine's JSON output contract). That is
progressive disclosure applied at the engine layer.

Frontmatter is parsed with a small stdlib parser (scalars, inline/block lists, and
`>`/`|` block scalars) so there is no PyYAML dependency for the core path.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

# Canonical skills ship INSIDE the package (so they're present in a wheel — arch
# review D1). An env override (SYNTHESIS_SKILLS_DIR) lets operators point at a custom
# skill set, e.g. a clone of github.com/UnitOneAI/SecuritySkills (.../skills).
_IN_PACKAGE_SKILLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")
DEFAULT_SKILLS_DIR = os.environ.get("SYNTHESIS_SKILLS_DIR", _IN_PACKAGE_SKILLS)

# Default confidence cap for a SKILL.md skill that doesn't declare one (new skills
# start LOW and earn the cap via outcomes — see CONTRIBUTING.md / memory.py).
_DEFAULT_CAP = 0.65
# Max chars of a SKILL.md body fed to a reviewer (progressive disclosure / token budget).
_REVIEWER_BODY_CAP = 1600

# The engine's output contract. Legacy skills embed this in their body; for SKILL.md
# skills (written for humans/agents, not the engine) the loader appends it.
_OUTPUT_CONTRACT = (
    "\n\nFor each risk that applies to THIS element, emit a threat whose control id "
    "RESOLVES in the cited frameworks (never invent control ids). Output JSON only:\n"
    '{"threats":[{"name","stride","owasp","cwe","mitre","actor","severity",'
    '"likelihood","impact","evidence","mitigation"}]}'
)


@dataclass
class Skill:
    id: str
    domain: str
    title: str
    triggers: list[str] = field(default_factory=list)  # component kinds / keywords
    control_frameworks: list[str] = field(default_factory=list)
    confidence_cap: float = 0.7
    path: str = ""
    body: str = ""  # the prompt fed to a reviewer (bounded for SKILL.md skills)

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "body"}
        d["body_chars"] = len(self.body)
        return d


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return (frontmatter_dict, body).

    Supports `key: scalar`, inline lists `[a, b]`, block lists (`- item`), and
    `>`/`|` block scalars (folded / literal) — enough for the SKILL.md format.
    """
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    fm_block = text[3:end].strip("\n")
    body = text[end + 4 :].lstrip("\n")
    data: dict[str, Any] = {}
    lines = fm_block.splitlines()
    i = 0
    cur_key: str | None = None
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        if not line.strip():
            i += 1
            continue
        stripped = line.lstrip()
        # block list item
        if stripped.startswith("- ") and cur_key:
            data.setdefault(cur_key, [])
            if isinstance(data[cur_key], list):
                data[cur_key].append(_scalar(stripped[2:].strip()))
            i += 1
            continue
        # top-level key
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            cur_key = key
            if val in (">", "|", ">-", "|-", ">+", "|+"):
                # block scalar: consume following indented lines
                folded = val.startswith(">")
                buf: list[str] = []
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if nxt.strip() and not nxt.startswith((" ", "\t")):
                        break
                    buf.append(nxt.strip())
                    i += 1
                joined = (" " if folded else "\n").join(b for b in buf).strip()
                data[key] = joined
                continue
            if val == "":
                data[key] = []  # block list or empty follows
            elif val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                data[key] = [_scalar(x.strip()) for x in inner.split(",") if x.strip()]
            else:
                data[key] = _scalar(val)
        i += 1
    return data, body


def _scalar(v: str) -> Any:
    v = v.strip().strip('"').strip("'")
    try:
        if "." in v:
            return float(v)
        return int(v)
    except ValueError:
        return v


def _compact_reviewer_prompt(name: str, description: str, frameworks: list[str], body: str) -> str:
    """Bounded reviewer prompt for a SKILL.md skill (progressive disclosure)."""
    guidance = body.strip()
    if len(guidance) > _REVIEWER_BODY_CAP:
        cut = guidance.rfind("\n", 0, _REVIEWER_BODY_CAP)
        guidance = guidance[: cut if cut > 0 else _REVIEWER_BODY_CAP].rstrip() + "\n…"
    fw = ", ".join(frameworks) if frameworks else "the relevant published frameworks"
    head = (
        f'You are a focused, read-only security reviewer applying the "{name}" skill '
        f"to ONE component. Frameworks: {fw}."
    )
    desc = f"\n{description.strip()}" if description else ""
    return f"{head}{desc}\n\n{guidance}{_OUTPUT_CONTRACT}"


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
                fm, body = _parse_frontmatter(fh.read())

            if fn == "SKILL.md":
                # SecuritySkills / agentskills.io format. Skill id = <domain>/<dir>.
                skill_name = fm.get("name") or os.path.basename(root)
                domain = os.path.basename(os.path.dirname(root)) or "uncategorized"
                sid = f"{domain}/{skill_name}"
                triggers = _as_list(fm.get("tags")) + [
                    t for t in str(skill_name).split("-") if t
                ]
                out[sid] = Skill(
                    id=sid,
                    domain=domain,
                    title=str(fm.get("name", skill_name)),
                    triggers=_dedup_lower(triggers),
                    control_frameworks=_as_list(fm.get("frameworks")),
                    confidence_cap=float(fm.get("confidence_cap", _DEFAULT_CAP)),
                    path=path,
                    body=_compact_reviewer_prompt(
                        str(fm.get("name", skill_name)),
                        str(fm.get("description", "")),
                        _as_list(fm.get("frameworks")),
                        body,
                    ),
                )
                continue

            # Legacy engine format: a flat <domain>/<name>.md with an `id`.
            sid = fm.get("id")
            if not sid:
                continue  # not a skill (e.g. a SKILL.md reference sibling)
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


def _dedup_lower(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        k = str(it).lower()
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out
