"""Phase 0 — INGEST. N repos + N docs -> merged context + DFD seed.

Multi-source AND multi-doc: several repos and several docs are merged into ONE system
(the thing no free competitor does). Docs may be local file paths, http(s) URLs, or
pasted inline text. With a key + network the LLM proposes the DFD from fetched
context; offline it falls back to a keyword-driven seed so the engine always runs.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from .llm import LLM
from .logging_setup import get_logger
from .types import DATA_STORE, EXTERNAL_ENTITY, PROCESS, Component, DesignDoc, Dfd, Flow

_log = get_logger("ingest")

_KEYWORD_COMPONENTS = {
    "auth": ("Auth / Session Service", PROCESS, "app"),
    "jwt": ("Auth / Session Service", PROCESS, "app"),
    "login": ("Auth / Session Service", PROCESS, "app"),
    "api": ("API Gateway", PROCESS, "dmz"),
    "rest": ("API Gateway", PROCESS, "dmz"),
    "graphql": ("GraphQL API", PROCESS, "dmz"),
    "upload": ("Upload / File Handler", PROCESS, "app"),
    "llm": ("LLM / Agent Service", PROCESS, "app"),
    "ai": ("LLM / Agent Service", PROCESS, "app"),
    "agent": ("LLM / Agent Service", PROCESS, "app"),
    "sql": ("Primary Database", DATA_STORE, "data"),
    "database": ("Primary Database", DATA_STORE, "data"),
    "postgres": ("Primary Database", DATA_STORE, "data"),
    "s3": ("Object Storage", DATA_STORE, "data"),
    "secret": ("Secret / Key Store", DATA_STORE, "data"),
}

_MAX_DOC_CHARS = 8000


def ingest(
    sources: list[str], docs: list[str], focus: str, llm: LLM, trace=None
) -> tuple[DesignDoc, Dfd, str]:
    context_parts: list[str] = []
    refs: list[str] = []
    for url in sources:
        fetched = _maybe_fetch_repo(url)
        if fetched:
            context_parts.append(fetched["summary"])
            refs.extend(fetched["refs"])

    doc_labels: list[str] = []
    merged_doc_parts: list[str] = []
    for d in docs:
        label, text = _load_doc(d)
        if text:
            doc_labels.append(label)
            merged_doc_parts.append(f"# doc: {label}\n{text[:_MAX_DOC_CHARS]}")
    merged_doc = "\n\n".join(merged_doc_parts)
    if merged_doc:
        context_parts.append(merged_doc)

    context = "\n\n".join(context_parts) or " ".join(sources)
    design = DesignDoc(sources=list(sources), docs=doc_labels,
                       doc_excerpt=merged_doc[:600], focus=focus)

    if not llm.scripted:
        dfd = _llm_dfd(sources, context, focus, llm) or _scripted_dfd(sources, context, refs)
    else:
        dfd = _scripted_dfd(sources, context, refs)

    if trace:
        trace.mark("ingest", sources=len(sources), docs=len(doc_labels),
                   components=len(dfd.components), flows=len(dfd.flows), provider=llm.name)
    return design, dfd, context


def _load_doc(d: str) -> tuple[str, str]:
    """Classify a doc ref -> (label, text). Path | URL | inline text."""
    if d.startswith(("http://", "https://")):
        try:
            req = urllib.request.Request(d, headers={"user-agent": "synthesis-engine"})
            with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
                return d, r.read().decode("utf-8", errors="ignore")
        except (urllib.error.URLError, ValueError, TimeoutError) as e:
            _log.warning("doc fetch failed for %s: %s", d, e)
            return d, ""
    if os.path.exists(d):
        try:
            with open(d, encoding="utf-8", errors="ignore") as fh:
                return os.path.basename(d), fh.read()
        except OSError as e:
            _log.warning("doc read failed for %s: %s", d, e)
            return os.path.basename(d), ""
    return "inline", d  # treat as pasted text


def _maybe_fetch_repo(url: str) -> dict[str, Any] | None:
    """Best-effort GitHub tree fetch for source_refs. The fetch target is hard-coded
    to api.github.com; user input only forms the path. Validates the host properly
    (arch review S7). Silent-but-logged on failure so the engine never blocks."""
    try:
        host = (urlparse(url).netloc or "").lower()
    except ValueError:
        return None
    if host not in ("github.com", "www.github.com"):
        return None
    try:
        slug = urlparse(url).path.strip("/").removesuffix(".git")
        parts = [p for p in slug.split("/") if p]
        if len(parts) < 2:
            return None
        owner_repo = f"{parts[0]}/{parts[1]}"
        api = f"https://api.github.com/repos/{owner_repo}/git/trees/HEAD?recursive=1"
        req = urllib.request.Request(api, headers=_gh_headers())
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
            data = json.loads(r.read().decode())
        paths = [t["path"] for t in data.get("tree", []) if t.get("type") == "blob"]
        scored = _score_security_files(paths)[:25]
        return {"summary": f"repo {owner_repo}: " + ", ".join(scored), "refs": scored}
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as e:
        _log.warning("repo fetch failed for %s: %s", url, e)
        return None


def _gh_headers() -> dict[str, str]:
    from .config import get_config
    h = {"accept": "application/vnd.github+json", "user-agent": "synthesis-engine"}
    tok = get_config().github_token  # from Configure UI / settings.json / env
    if tok:
        h["authorization"] = f"Bearer {tok}"
    return h


_SEC_KEYWORDS = ("auth", "login", "session", "token", "jwt", "crypto", "password",
                 "api", "route", "controller", "upload", "deserialize", "sql",
                 "query", "secret", "key", "llm", "prompt", "agent", "middleware")


def _score_security_files(paths: list[str]) -> list[str]:
    def score(p: str) -> int:
        pl = p.lower()
        return sum(2 if k in pl else 0 for k in _SEC_KEYWORDS)
    return [p for p in sorted(paths, key=score, reverse=True) if score(p) > 0]


def _scripted_dfd(sources: list[str], context: str, refs: list[str]) -> Dfd:
    text = (context + " " + " ".join(sources) + " " + " ".join(refs)).lower()
    comps: dict[str, Component] = {}

    def add(name: str, kind: str, zone: str) -> Component:
        cid = "c-" + name.lower().split("/")[0].strip().replace(" ", "-")[:24]
        if cid not in comps:
            comps[cid] = Component(id=cid, name=name, kind=kind, zone=zone, source_refs=refs[:5])
        return comps[cid]

    attacker = add("Unauthenticated Network Peer", EXTERNAL_ENTITY, "untrusted")
    gateway = add("API Gateway", PROCESS, "dmz")
    for kw, (name, kind, zone) in _KEYWORD_COMPONENTS.items():
        if kw in text:
            add(name, kind, zone)
    store = next((c for c in comps.values() if c.kind == DATA_STORE), None)
    if store is None:
        store = add("Primary Database", DATA_STORE, "data")

    flows = [Flow(id="f-1", src=attacker.id, dst=gateway.id, label="HTTPS request",
                  crosses_boundary=True, control="partial")]
    processes = [c for c in comps.values() if c.kind == PROCESS and c.id != gateway.id]
    fi = 2
    for p in processes:
        flows.append(Flow(id=f"f-{fi}", src=gateway.id, dst=p.id, label="internal call",
                          crosses_boundary=True, control="none"))
        fi += 1
        flows.append(Flow(id=f"f-{fi}", src=p.id, dst=store.id, label="read/write",
                          crosses_boundary=True, control="none"))
        fi += 1
    if not processes:
        flows.append(Flow(id="f-2", src=gateway.id, dst=store.id, label="read/write",
                          crosses_boundary=True, control="none"))
    return Dfd(components=list(comps.values()), flows=flows)


def _llm_dfd(sources, context, focus, llm: LLM) -> Dfd | None:
    system = (
        "You are a security architect. From the provided repo summaries and design "
        "doc, produce a data-flow diagram as JSON. Element kinds: external_entity, "
        "process, data_store. Mark each flow that crosses a trust boundary and the "
        "control on it (strong|partial|none)."
    )
    user = (
        f"Sources: {sources}\nCustomer focus: {focus}\n\nContext:\n{context[:6000]}\n\n"
        'Return JSON: {"components":[{"id","name","kind","zone"}],'
        '"flows":[{"id","src","dst","label","crosses_boundary","control"}]}'
    )
    data = llm.json(system, user)
    if not isinstance(data, dict) or not data.get("components"):
        return None
    comps = [Component(id=c["id"], name=c.get("name", c["id"]),
                       kind=c.get("kind", PROCESS), zone=c.get("zone", "app"))
             for c in data["components"]]
    flows = [Flow(id=f.get("id", f"f-{i}"), src=f["src"], dst=f["dst"],
                  label=f.get("label", ""), crosses_boundary=bool(f.get("crosses_boundary")),
                  control=f.get("control", "none"))
             for i, f in enumerate(data.get("flows", []))]
    return Dfd(components=comps, flows=flows)
