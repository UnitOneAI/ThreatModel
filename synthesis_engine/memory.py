"""Local, single-tenant Intent Graph + skill confidence calibration.

This is the OSS memory tier: your own past threat models warm-start your next one,
and your own accept/reject outcomes tune each skill's confidence cap. It ships free
because "auto-evolving" must be a true claim for a self-hoster.

Backends (arch review D2):
  - SQLite (default): WAL + busy_timeout for safe concurrent CLI + MCP-server access.
  - PostgreSQL (set SYNTHESIS_DB=postgresql://...): for multi-instance deployments.
    Requires `pip install 'synthesis-engine[postgres]'`. Beta — sqlite is the
    CI-tested default.

The *federated* graph (every customer's outcomes improving every customer's planner)
is the paid tier and is intentionally NOT implemented here; `federated_warm_start()`
is the seam a managed client overrides.

Graph shape:  design -has_component-> component -exposes-> threat
              threat -mitigated_by-> mitigation -resulted_in-> outcome
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

from .config import get_config
from .types import Component, ThreatModel

_PG_SCHEMES = ("postgres://", "postgresql://")


def _is_pg(dsn: str) -> bool:
    return dsn.startswith(_PG_SCHEMES)


class IntentGraph:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or get_config().db
        self.is_pg = _is_pg(self.db_path)
        self.ph = "%s" if self.is_pg else "?"
        self._connect()
        self._init()

    # --- backend plumbing -------------------------------------------------
    def _connect(self) -> None:
        if self.is_pg:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as e:  # pragma: no cover
                raise RuntimeError(
                    "PostgreSQL backend needs psycopg: pip install 'synthesis-engine[postgres]'"
                ) from e
            self.conn = psycopg.connect(self.db_path, row_factory=dict_row)
        else:
            import sqlite3
            if self.db_path != ":memory:":
                os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            # concurrency hardening (arch review D2)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self.conn.execute("PRAGMA synchronous=NORMAL")

    def _exec(self, sql: str, params: tuple = ()):  # noqa: ANN201
        return self.conn.execute(sql, params)

    def _init(self) -> None:
        real = "DOUBLE PRECISION" if self.is_pg else "REAL"
        bigint = "BIGINT" if self.is_pg else "INTEGER"
        stmts = [
            f"CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, type TEXT, attrs TEXT, ts {real})",
            f"CREATE TABLE IF NOT EXISTS edges (from_id TEXT, relation TEXT, to_id TEXT, attrs TEXT, ts {real})",
            (f"CREATE TABLE IF NOT EXISTS skill_stats (skill_id TEXT PRIMARY KEY, "
             f"accepted {bigint} DEFAULT 0, rejected {bigint} DEFAULT 0, "
             f"confidence_cap {real} DEFAULT 0.7)"),
            "CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_id)",
            "CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type)",
        ]
        for s in stmts:
            self._exec(s)
        self.conn.commit()

    # --- write cycle (Phase E close) -------------------------------------
    def write_model(self, model: ThreatModel) -> None:
        now = time.time()
        self._node(model.id, "design", {"sources": model.design.sources,
                                        "docs": model.design.docs}, now)
        for c in model.dfd.components:
            self._node(c.id, "component", {"name": c.name, "kind": c.kind, "zone": c.zone}, now)
            self._edge(model.id, "has_component", c.id, now)
        for t in model.threats:
            self._node(t.id, "threat", {"name": t.name, "stride": t.stride,
                                        "severity": t.severity, "skill_id": t.skill_id}, now)
            self._edge(t.target_element, "exposes", t.id, now)
            if t.mitigation:
                mid = f"m-{t.id}"
                self._node(mid, "mitigation", {"skill_id": t.mitigation.skill_id,
                                               "confidence": t.mitigation.confidence}, now)
                self._edge(t.id, "mitigated_by", mid, now)
                oid = f"o-{t.id}"
                self._node(oid, "outcome", {"label": self._outcome_label(t)}, now)
                self._edge(mid, "resulted_in", oid, now)
        self.conn.commit()

    @staticmethod
    def _outcome_label(t) -> str:
        if t.status in ("accepted", "mitigated"):
            return "accepted"
        if t.status == "rejected":
            return "rejected"
        if t.status == "security_verified":
            return "security_verified"
        return "open"

    def _node(self, nid: str, ntype: str, attrs: dict, ts: float) -> None:
        p = self.ph
        self._exec(
            f"INSERT INTO nodes(id,type,attrs,ts) VALUES ({p},{p},{p},{p}) "
            f"ON CONFLICT(id) DO UPDATE SET type=excluded.type, attrs=excluded.attrs, ts=excluded.ts",
            (nid, ntype, json.dumps(attrs), ts),
        )

    def _edge(self, frm: str, rel: str, to: str, ts: float) -> None:
        p = self.ph
        self._exec(f"INSERT INTO edges(from_id,relation,to_id,attrs,ts) VALUES ({p},{p},{p},{p},{p})",
                   (frm, rel, to, json.dumps({}), ts))

    # --- read cycle (planner warm-start, Phase 0) ------------------------
    def warm_start(self, components: list[Component], limit: int = 20) -> list[dict[str, Any]]:
        priors: list[dict[str, Any]] = []
        prior_components = self._exec("SELECT id, attrs FROM nodes WHERE type='component'").fetchall()
        for c in components:
            for row in prior_components:
                attrs = json.loads(row["attrs"])
                if _similar(c.name + " " + c.kind, attrs.get("name", "") + " " + attrs.get("kind", "")):
                    for t in self._accepted_threats_for(row["id"]):
                        priors.append({"like_component": c.name, **t})
        seen, out = set(), []
        for prr in priors:
            if prr["name"] in seen:
                continue
            seen.add(prr["name"])
            out.append(prr)
            if len(out) >= limit:
                break
        return out

    def _accepted_threats_for(self, component_id: str) -> list[dict[str, Any]]:
        p = self.ph
        rows = self._exec(f"SELECT to_id FROM edges WHERE from_id={p} AND relation='exposes'",
                          (component_id,)).fetchall()
        out = []
        for r in rows:
            tid = r["to_id"]
            outcome = self._exec(
                f"""SELECT n.attrs AS attrs FROM edges e1
                    JOIN edges e2 ON e1.to_id=e2.from_id
                    JOIN nodes n ON e2.to_id=n.id
                    WHERE e1.from_id={p} AND e1.relation='mitigated_by'
                      AND e2.relation='resulted_in'""",
                (tid,),
            ).fetchone()
            label = json.loads(outcome["attrs"]).get("label") if outcome else "open"
            if label in ("accepted", "security_verified"):
                tnode = self._exec(f"SELECT attrs FROM nodes WHERE id={p}", (tid,)).fetchone()
                if tnode:
                    a = json.loads(tnode["attrs"])
                    out.append({"name": a.get("name"), "stride": a.get("stride"),
                                "severity": a.get("severity"), "outcome": label})
        return out

    def federated_warm_start(self, components: list[Component]) -> list[dict[str, Any]]:
        """PAID SEAM. The managed client overrides this to query the cross-customer
        graph. OSS build returns nothing (local-only)."""
        return []

    # --- confidence calibration (automatic, local) -----------------------
    def confidence(self, skill_id: str, default_cap: float = 0.7) -> float:
        p = self.ph
        row = self._exec(f"SELECT confidence_cap FROM skill_stats WHERE skill_id={p}",
                         (skill_id,)).fetchone()
        return row["confidence_cap"] if row else default_cap

    def calibrate(self, skill_id: str, accepted: bool, default_cap: float = 0.7) -> float:
        p = self.ph
        row = self._exec(f"SELECT accepted, rejected FROM skill_stats WHERE skill_id={p}",
                         (skill_id,)).fetchone()
        a = (row["accepted"] if row else 0) + (1 if accepted else 0)
        r = (row["rejected"] if row else 0) + (0 if accepted else 1)
        cap = max(0.3, min(0.95, round((a + 1) / (a + r + 2), 3)))
        self._exec(
            f"""INSERT INTO skill_stats(skill_id,accepted,rejected,confidence_cap)
                VALUES ({p},{p},{p},{p})
                ON CONFLICT(skill_id) DO UPDATE SET accepted=excluded.accepted,
                  rejected=excluded.rejected, confidence_cap=excluded.confidence_cap""",
            (skill_id, a, r, cap),
        )
        self.conn.commit()
        return cap

    def skill_stats(self) -> list[dict[str, Any]]:
        rows = self._exec("SELECT * FROM skill_stats ORDER BY skill_id").fetchall()
        return [dict(r) for r in rows]

    def subgraph(self, design_id: str) -> dict[str, Any]:
        p = self.ph
        edges = self._exec(
            f"SELECT from_id,relation,to_id FROM edges WHERE from_id={p} OR from_id IN "
            f"(SELECT to_id FROM edges WHERE from_id={p})", (design_id, design_id)
        ).fetchall()
        return {"design": design_id, "edges": [dict(e) for e in edges]}

    def close(self) -> None:
        self.conn.close()


def _similar(a: str, b: str, threshold: float = 0.4) -> bool:
    """Cheap token-overlap similarity stand-in for embeddings (honest placeholder)."""
    ta, tb = set(a.lower().split()), set(b.lower().split())
    if not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= threshold
