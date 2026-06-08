"""Visual artifacts — deterministic Mermaid DFD from the model.

Threat modeling is visual: this renders the data-flow diagram with trust-zone
subgraphs, node shapes by element kind, control-labeled flows, and highlighting for
the attacker entry, the assets (data stores), and any element an attacker path
actually reaches (exposed). Pure string output — the UI renders it with Mermaid.js.
"""
from __future__ import annotations

from .types import DATA_STORE, EXTERNAL_ENTITY, PROCESS, Dfd, Threat


def _esc(label: str) -> str:
    return (label or "").replace('"', "'").replace("\n", " ").strip()


def _edge_label(label: str) -> str:
    # edge labels are rendered UNQUOTED (the spine's proven-safe form); strip chars
    # that break mermaid edge-label parsing.
    return _esc(label).replace("|", "/").replace("(", "").replace(")", "")


def _node(node_id: str, kind: str, name: str) -> str:
    n = _esc(name)
    if kind == EXTERNAL_ENTITY:
        return f'{node_id}["{n}"]'          # rectangle
    if kind == DATA_STORE:
        return f'{node_id}[("{n}")]'         # cylinder
    return f'{node_id}(("{n}"))'             # process = circle


def dfd_to_mermaid(dfd: Dfd, threats: list[Threat] | None = None) -> str:
    if not dfd.components:
        return "flowchart LR\n  empty[No components detected]"

    threats = threats or []
    exposed = {t.target_element for t in threats if t.reachability == "exposed"}
    nid = {c.id: f"N{i}" for i, c in enumerate(dfd.components)}

    lines = ["flowchart LR"]

    # group by trust zone -> subgraphs
    zones: dict[str, list] = {}
    for c in dfd.components:
        zones.setdefault(c.zone or "unzoned", []).append(c)
    for zi, (zone, comps) in enumerate(zones.items()):
        lines.append(f'  subgraph Z{zi}["trust zone: {_esc(zone)}"]')
        for c in comps:
            lines.append("    " + _node(nid[c.id], c.kind, c.name))
        lines.append("  end")

    # flows (label includes the control strength on the crossing)
    for f in dfd.flows:
        if f.src in nid and f.dst in nid:
            lbl = _edge_label(f.label) or "flow"
            if f.crosses_boundary:
                lbl += f" / {f.control}"
            arrow = "-->" if f.control == "strong" else "-.->"  # weak crossings dashed
            lines.append(f"  {nid[f.src]} {arrow}|{lbl}| {nid[f.dst]}")

    # styling
    lines.append("")
    attackers = [nid[c.id] for c in dfd.components
                 if c.kind == EXTERNAL_ENTITY and c.zone == "untrusted"]
    assets = [nid[c.id] for c in dfd.components if c.kind == DATA_STORE]
    exposed_nodes = [nid[cid] for cid in exposed if cid in nid]
    procs = [nid[c.id] for c in dfd.components if c.kind == PROCESS]

    lines.append("  classDef attacker fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d")
    lines.append("  classDef asset fill:#fef3c7,stroke:#d97706,stroke-width:2px,color:#78350f")
    lines.append("  classDef proc fill:#e0e7ff,stroke:#4f46e5,color:#3730a3")
    lines.append("  classDef exposed stroke:#dc2626,stroke-width:4px,stroke-dasharray:4 2")
    if procs:
        lines.append(f"  class {','.join(procs)} proc")
    if assets:
        lines.append(f"  class {','.join(assets)} asset")
    if attackers:
        lines.append(f"  class {','.join(attackers)} attacker")
    if exposed_nodes:
        lines.append(f"  class {','.join(exposed_nodes)} exposed")
    return "\n".join(lines)
