#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 meistsec
"""
threat_meister.intel - bridge between the threat_meister sample catalog and threathunt's
VirusTotal enrichment / scoring engine.

This is the seam that makes the two tools one product:

  static analysis (threat_meister)                 threat intel (threathunt)
  ────────────────────────                 ─────────────────────────
  a sample's own hash        ──enrich──▶    VT reputation + risk score
  its extracted C2 IOCs      ──enrich──▶    VT reputation + risk score
                             ◀─reflect──    vt_score, tags, note on the sample

  a hunt over Wazuh/Rita     ──lookup──▶    "this hash/host is lab sample #N
                                             (family=X)"  → higher score

Nothing here talks to VT directly; it reuses threathunt's VirusTotalClient,
RateLimiter, Store, IOC, enrich() and score_risk() so there is exactly one
implementation of rate limiting, caching, scoring and the resume queue.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import threathunt as th


# ---------------------------------------------------------------------------
# Catalog -> threathunt: turn a sample record into enrichable IOCs
# ---------------------------------------------------------------------------

def _lab_context(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "family": row["family"],
        "category": row["category"],
        "platform": row["platform"],
        "via": "sample-hash",
    }


def sample_to_iocs(conn: sqlite3.Connection, row: sqlite3.Row) -> list["th.IOC"]:
    """Build the IOC set for one sample: its own hash plus its saved IOCs.

    The sample's own hash carries lab_sample context so score_risk() credits it
    even when VT has never seen the file (common for coursework samples).
    """
    iocs: list[th.IOC] = []
    labctx = _lab_context(row)

    # The sample's own file hash (sha256 is the canonical key).
    if row["sha256"]:
        iocs.append(th.IOC(value=row["sha256"].lower(), kind="hash",
                           sources={"threat_meister"}, context={"lab_sample": labctx}))

    # Its extracted network IOCs (from `threat_meister triage --save-iocs`).
    for r in conn.execute("SELECT itype, value FROM iocs WHERE sample_id=?", (row["id"],)):
        value = (r["value"] or "").strip()
        kind = th.classify_ioc(value)
        if not kind:
            # urls arrive as full URLs; reduce to host for VT domain/ip lookup
            host = th._host_from_url(value)
            if host:
                value, kind = host, th.classify_ioc(host)
        if kind:
            iocs.append(th.IOC(value=value.lower(), kind=kind, sources={"threat_meister"},
                               context={"lab_sample": {**labctx, "via": "extracted-ioc"}}))
    # de-dupe within the sample
    merged: dict[str, th.IOC] = {}
    for ioc in iocs:
        if ioc.value in merged:
            merged[ioc.value].merge(ioc)
        else:
            merged[ioc.value] = ioc
    return list(merged.values())


# ---------------------------------------------------------------------------
# threathunt -> catalog: the lookup hook used during hunts
# ---------------------------------------------------------------------------

def make_catalog_lookup(catalog_db: Path) -> Callable[[str], Optional[dict]]:
    """Return a callable(value)->lab_context|None for th.LOCAL_CATALOG_LOOKUP.

    Matches a VT indicator against the catalog by file hash (sha256/sha1/md5)
    or against previously-extracted IOC values. Holds one connection open for
    the life of the hunt so large runs stay cheap.
    """
    if not catalog_db.exists():
        return lambda value: None
    conn = sqlite3.connect(str(catalog_db))
    conn.row_factory = sqlite3.Row

    def lookup(value: str) -> Optional[dict]:
        v = (value or "").strip().lower()
        if not v:
            return None
        row = conn.execute(
            "SELECT id, family, category, platform FROM samples "
            "WHERE sha256=? OR sha1=? OR md5=? LIMIT 1", (v, v, v)).fetchone()
        if row:
            return {"id": row["id"], "family": row["family"],
                    "category": row["category"], "platform": row["platform"],
                    "via": "sample-hash"}
        row = conn.execute(
            "SELECT s.id, s.family, s.category, s.platform FROM iocs i "
            "JOIN samples s ON s.id=i.sample_id WHERE i.value=? LIMIT 1",
            (v,)).fetchone()
        if row:
            return {"id": row["id"], "family": row["family"],
                    "category": row["category"], "platform": row["platform"],
                    "via": "extracted-ioc"}
        return None

    return lookup


# ---------------------------------------------------------------------------
# Enrichment driver + reflect-back onto the catalog
# ---------------------------------------------------------------------------

def band_tag(score: int) -> str:
    label = th.band(score)[0].lower()   # critical|elevated|watch|low
    return f"vt:{label}"


def reflect_onto_sample(conn: sqlite3.Connection, sample_id: int,
                        verdicts: list["th.Verdict"]) -> int:
    """Write the enrichment result back onto the catalog record.

    Sets vt_score (the max risk across the sample's own hash + its IOCs),
    stamps vt_checked, adds a band tag, and appends a summary note. Returns
    the reflected score.
    """
    if not verdicts:
        return 0
    top = max(verdicts, key=lambda x: x.risk_score)
    score = top.risk_score
    conn.execute("UPDATE samples SET vt_score=?, vt_checked=? WHERE id=?",
                 (score, datetime.now(timezone.utc).isoformat(), sample_id))
    # replace any prior vt:* tag, add the current band
    conn.execute("DELETE FROM tags WHERE sample_id=? AND tag LIKE 'vt:%'", (sample_id,))
    conn.execute("INSERT OR IGNORE INTO tags VALUES (?,?)", (sample_id, band_tag(score)))

    lines = [f"VT enrichment: top risk {score} ({th.band(score)[0]})."]
    for v in sorted(verdicts, key=lambda x: x.risk_score, reverse=True):
        tag = "self" if v.context.get("lab_sample", {}).get("via") == "sample-hash" else "ioc"
        if v.not_found:
            lines.append(f"  [{tag}] {v.ioc} ({v.kind}): no VT record")
        else:
            lines.append(f"  [{tag}] {v.ioc} ({v.kind}): {v.risk_score} — "
                         f"{v.malicious} mal/{v.suspicious} susp"
                         + (f", {v.as_owner} {v.country}".rstrip() if v.as_owner or v.country else ""))
    conn.execute("INSERT INTO notes (sample_id,ts_utc,phase,body) VALUES (?,?,?,?)",
                 (sample_id, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "analysis", "\n".join(lines)))
    conn.commit()
    return score


def enrich_samples(conn: sqlite3.Connection, intel_db: Path,
                   sample_rows: list[sqlite3.Row], vt_client,
                   ttl_hours: int) -> dict:
    """Enrich the given samples' hashes + IOCs through the shared VT engine.

    `vt_client` is any object with threathunt's VirusTotalClient interface
    (real client in production; a fake in tests). Returns a summary dict.
    """
    store = th.Store(intel_db)
    # wire the reverse lookup so cross-references appear even here
    th.LOCAL_CATALOG_LOOKUP = make_catalog_lookup(Path(conn.execute("PRAGMA database_list").fetchone()[2]))

    summary = {"samples": 0, "iocs": 0, "reflected": [], "overflow": 0}
    for row in sample_rows:
        iocs = sample_to_iocs(conn, row)
        if not iocs:
            continue
        summary["iocs"] += len(iocs)
        verdicts, overflow = th.enrich(iocs, vt_client, store, ttl_hours)
        summary["overflow"] += len(overflow)
        score = reflect_onto_sample(conn, row["id"], verdicts)
        summary["samples"] += 1
        summary["reflected"].append((row["id"], row["sha256"][:12], score))
    return summary


def findings_for_sample(intel_db: Path, conn: sqlite3.Connection,
                        row: sqlite3.Row) -> list[dict]:
    """Latest VT finding per value tied to this sample (hash + its IOCs)."""
    if not intel_db.exists():
        return []
    values = [row["sha256"].lower()] if row["sha256"] else []
    for r in conn.execute("SELECT value FROM iocs WHERE sample_id=?", (row["id"],)):
        v = (r["value"] or "").strip().lower()
        host = th._host_from_url(v) or v
        values.append(host)
    if not values:
        return []
    fconn = sqlite3.connect(str(intel_db))
    fconn.row_factory = sqlite3.Row
    out = []
    for val in dict.fromkeys(values):
        r = fconn.execute(
            "SELECT ioc,kind,risk_score,malicious,suspicious,not_found "
            "FROM findings WHERE ioc=? ORDER BY checked_at DESC LIMIT 1",
            (val,)).fetchone()
        if r:
            out.append(dict(r))
    fconn.close()
    return out
