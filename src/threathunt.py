#!/usr/bin/env python3
"""
threathunt.py — Monthly Threat Hunting with VirusTotal Enrichment
==================================================================

A terminal-based threat-hunting tool that takes indicators of compromise
(IOCs) from your existing security stack — Wazuh alerts and Rita (Real
Intelligence Threat Analytics) network-flow exports — enriches them with
VirusTotal reputation data, correlates behaviour with reputation, scores
the risk, and writes everything to a local SQLite database for historical
tracking.

This is a *forensic / threat-hunting* tool, not a real-time blocker. It is
designed to complement UniFi IDS/IPS and Wazuh, not replace them. Run it on
a schedule (e.g. once a month) to surface things that slipped past the
signature-based defences or to deep-dive an incident after the fact.

Design goals
------------
- **Read-only on your sources.** It never modifies Wazuh or Rita data.
- **Respect the VirusTotal free tier.** 4 requests/minute, 500/day by
  default — configurable. Built-in token-bucket rate limiter + backoff.
- **Idempotent-ish.** Results are cached in SQLite; a re-run within the
  cache window won't re-spend your API quota on the same indicator.
- **Pipeline-friendly.** Plain exit codes, optional JSON/CSV report export.

Usage
-----
    # one-time: set your key (or pass --api-key / use a .env)
    export VT_API_KEY="your_key_here"

    # check a single indicator
    ./threathunt.py check 185.220.101.45
    ./threathunt.py check evil-domain.example
    ./threathunt.py check 44d88612fea8a8f36de82e1278abb02f   # a hash

    # monthly hunt: ingest sources, enrich, score, report
    ./threathunt.py hunt --wazuh alerts.json --rita rita_export.csv

    # review past findings without spending API calls
    ./threathunt.py history --min-score 60 --since 2026-05-01

    # export the latest hunt to a report
    ./threathunt.py hunt --wazuh alerts.json --report report.json
    ./threathunt.py hunt --rita beacons.csv --report report.csv

Author: (you) — released under MIT, adapt freely for your blog post.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional
from urllib import request, error, parse

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

VT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_DB_PATH = Path.home() / ".threathunt" / "threathunt.db"

# Free-tier defaults. The personal free key allows 4 lookups/min and 500/day.
# Bump these if you have a paid key.
DEFAULT_RATE_PER_MIN = 4
DEFAULT_DAILY_CAP = 500

# How long (hours) to trust a cached VT result before re-querying.
DEFAULT_CACHE_TTL_HOURS = 24 * 7  # a week — reputation rarely flips overnight

# Optional integration hook. When threat_meister drives threathunt, it sets this to a
# callable(value: str) -> Optional[dict] that returns local sample-catalog
# context for a matching hash / IP / domain (e.g. {"family": "...", "id": 12}).
# Left as None, threathunt runs exactly as before — fully standalone.
LOCAL_CATALOG_LOOKUP = None

# ANSI colours. Disabled automatically when output isn't a TTY (e.g. piped).
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

    @classmethod
    def disable(cls) -> None:
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")


if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C.disable()


# --------------------------------------------------------------------------
# IOC model + classification
# --------------------------------------------------------------------------

# These regexes are deliberately conservative — we'd rather skip an ambiguous
# token than waste a VT lookup on garbage.
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# RFC1918 / loopback / link-local etc. — never worth a VT lookup, and you
# don't want to leak internal addressing to a third party anyway.
def _is_routable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def classify_ioc(value: str) -> Optional[str]:
    """Return 'ip', 'domain', 'hash', or None if it isn't a useful indicator."""
    value = value.strip().strip(".").lower()
    if not value:
        return None
    if _HASH_RE.match(value):
        return "hash"
    # Try IP before domain (an IP would also pass some loose domain checks).
    try:
        ipaddress.ip_address(value)
        return "ip" if _is_routable_ip(value) else None
    except ValueError:
        pass
    if _DOMAIN_RE.match(value):
        return "domain"
    return None


@dataclass
class IOC:
    """An indicator plus the behavioural context we gathered locally."""
    value: str
    kind: str  # ip | domain | hash
    sources: set[str] = field(default_factory=set)  # {"wazuh", "rita", "manual"}
    # Free-form behavioural context pulled from the source files. This is the
    # "what happened on my network" half that VT alone can't tell you.
    context: dict = field(default_factory=dict)

    def merge(self, other: "IOC") -> None:
        self.sources |= other.sources
        for k, v in other.context.items():
            # Keep the larger / more interesting value when we see the same
            # indicator from multiple events (e.g. max bytes transferred).
            if k in self.context and isinstance(v, (int, float)):
                self.context[k] = max(self.context[k], v)
            else:
                self.context[k] = v

    def local_priority(self) -> float:
        """
        Score this indicator using ONLY local signals — before we spend any
        VirusTotal quota on it. When the daily cap forces us to triage, we
        enrich highest-priority first so the indicators we skip are the
        least interesting ones, not a screaming beacon at position 501.

        This deliberately mirrors the behavioural half of score_risk(), but
        runs with zero API cost.
        """
        p = 0.0
        # Multiple independent sources agreeing is the strongest local signal.
        p += 15 * max(0, len(self.sources) - 1)
        if {"wazuh", "rita"}.issubset(self.sources):
            p += 10

        lvl = self.context.get("wazuh_level")
        if isinstance(lvl, (int, float)):
            p += min(20, float(lvl) * 1.5)  # Wazuh severity 0–15ish

        beacon = (self.context.get("rita_score")
                  or self.context.get("rita_beacon_score") or 0)
        if isinstance(beacon, (int, float)):
            p += float(beacon) * 20  # beacon scores are 0–1

        # UniFi CyberSecure severity, if present.
        sev = self.context.get("unifi_severity")
        if isinstance(sev, str):
            p += {"critical": 18, "high": 14, "medium": 8,
                  "low": 3}.get(sev.lower(), 0)

        # Volume signals from Rita — heavy talkers are more interesting.
        for k in ("rita_total_bytes", "rita_bytes", "rita_connection_count",
                  "rita_conn", "rita_connections"):
            val = self.context.get(k)
            if isinstance(val, (int, float)) and val > 0:
                # log-ish bump so one huge number doesn't dominate
                p += min(8, (float(val) ** 0.25) / 4)
                break
        return p


# --------------------------------------------------------------------------
# Source parsers — Wazuh and Rita
# --------------------------------------------------------------------------

def parse_wazuh(path: Path) -> Iterator[IOC]:
    """
    Parse a Wazuh alerts file. Wazuh's archives/alerts are newline-delimited
    JSON (one alert object per line), so we stream rather than load it all.

    We pull indicators out of the fields Wazuh commonly populates:
      - data.srcip / data.dstip          (network alerts)
      - data.url / data.hostname         (web / DNS)
      - syscheck.md5_after / sha256_after (FIM file hashes)
    and attach the rule that fired as behavioural context.
    """
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                # Some exports are a single JSON array — fall back to that.
                if line_no == 1 and line.startswith("["):
                    fh.seek(0)
                    try:
                        for alert in json.load(fh):
                            yield from _iocs_from_wazuh_alert(alert)
                    except json.JSONDecodeError:
                        eprint(f"{C.YELLOW}warn{C.RESET}: couldn't parse Wazuh file as JSON")
                    return
                continue
            yield from _iocs_from_wazuh_alert(alert)


def _iocs_from_wazuh_alert(alert: dict) -> Iterator[IOC]:
    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}
    syscheck = alert.get("syscheck", {}) or {}
    agent = (alert.get("agent", {}) or {}).get("name", "unknown")

    ctx_base = {
        "wazuh_rule": rule.get("description", ""),
        "wazuh_level": rule.get("level"),
        "wazuh_agent": agent,
        "wazuh_time": alert.get("timestamp", ""),
    }

    candidates: list[tuple[str, dict]] = []
    for fld in ("srcip", "dstip", "src_ip", "dst_ip"):
        if data.get(fld):
            candidates.append((data[fld], {"role": fld}))
    if data.get("url"):
        host = _host_from_url(data["url"])
        if host:
            candidates.append((host, {"url": data["url"]}))
    if data.get("hostname"):
        candidates.append((data["hostname"], {}))
    for fld in ("md5_after", "sha1_after", "sha256_after"):
        if syscheck.get(fld):
            candidates.append((syscheck[fld], {"file": syscheck.get("path", "")}))

    for value, extra in candidates:
        kind = classify_ioc(value)
        if not kind:
            continue
        ctx = {**ctx_base, **{k: v for k, v in extra.items() if v}}
        yield IOC(value=value.strip().lower(), kind=kind,
                  sources={"wazuh"}, context=ctx)


def parse_rita(path: Path) -> Iterator[IOC]:
    """
    Parse a Rita export. Rita's `show-beacons`, `show-long-connections`, and
    similar subcommands export CSV with a header row. The exact columns vary
    by Rita version and subcommand, so we detect them heuristically: anything
    that looks like a 'src'/'dst'/'host'/'domain' column is mined for IOCs,
    and numeric columns like 'score', 'connections', 'bytes' become context.

    The behavioural context Rita gives us — beacon score, connection count,
    total bytes, duration — is exactly the "why is this connection weird"
    signal that pairs so well with VT's "is this host known-bad" signal.
    """
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            return
        cols = {c.lower().strip(): c for c in reader.fieldnames}

        ioc_cols = [orig for low, orig in cols.items()
                    if any(t in low for t in ("dst", "src", "host", "domain", "ip"))]
        # Columns worth keeping as behavioural context.
        ctx_cols = {orig: low for low, orig in cols.items()
                    if any(t in low for t in
                           ("score", "conn", "bytes", "duration",
                            "size", "count", "ts_", "interval"))}

        for row in reader:
            ctx = {}
            for orig, low in ctx_cols.items():
                raw = (row.get(orig) or "").strip()
                if raw:
                    ctx[f"rita_{low}"] = _maybe_number(raw)
            for col in ioc_cols:
                value = (row.get(col) or "").strip()
                kind = classify_ioc(value)
                if not kind:
                    continue
                yield IOC(value=value.lower(), kind=kind,
                          sources={"rita"},
                          context={**ctx, "rita_field": col})


def parse_unifi(path: Path) -> Iterator[IOC]:
    """
    Parse a UniFi CyberSecure threat-alert CSV exported from the UniFi UI.

    UniFi's export columns have shifted across firmware versions and the
    headers aren't perfectly stable, so — as with Rita — we detect columns
    heuristically rather than hard-coding names. We look for:
      - source / destination IP columns (any header containing src/dst/ip)
      - a hostname/domain/host column
      - a signature / threat / category / message column (the rule that fired)
      - a severity column (critical/high/medium/low)
      - a timestamp column

    The signature + severity become behavioural context, mirroring how a
    Wazuh rule description is attached. Each indicator is tagged source
    'unifi' so the dedup in collect_iocs() unions it with any Wazuh/Rita hit
    on the same value (an IP seen by both shows sources {unifi, wazuh}).
    """
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            return
        cols = {c.lower().strip(): c for c in reader.fieldnames}

        def find(*needles: str) -> Optional[str]:
            for low, orig in cols.items():
                if any(n in low for n in needles):
                    return orig
            return None

        # IP columns: anything mentioning ip/src/dst/source/dest.
        ip_cols = [orig for low, orig in cols.items()
                   if any(t in low for t in
                          ("src", "dst", "source", "dest", "ip", "addr"))]
        host_col = find("hostname", "domain", "host", "url")
        sig_col = find("signature", "threat", "category", "message",
                       "name", "description", "rule", "alert")
        sev_col = find("severity", "level", "priority", "risk")
        time_col = find("time", "date", "timestamp", "when")

        for row in reader:
            ctx_base: dict = {}
            if sig_col and row.get(sig_col):
                ctx_base["unifi_signature"] = row[sig_col].strip()
            if sev_col and row.get(sev_col):
                ctx_base["unifi_severity"] = row[sev_col].strip()
            if time_col and row.get(time_col):
                ctx_base["unifi_time"] = row[time_col].strip()

            seen_in_row: set[str] = set()
            candidates: list[tuple[str, dict]] = []
            for col in ip_cols:
                val = (row.get(col) or "").strip()
                if val:
                    candidates.append((val, {"unifi_field": col}))
            if host_col and row.get(host_col):
                raw = row[host_col].strip()
                host = _host_from_url(raw) if "://" in raw or "/" in raw else raw
                if host:
                    candidates.append((host, {"unifi_field": host_col}))

            for value, extra in candidates:
                kind = classify_ioc(value)
                if not kind or value.lower() in seen_in_row:
                    continue
                seen_in_row.add(value.lower())
                yield IOC(value=value.lower(), kind=kind,
                          sources={"unifi"},
                          context={**ctx_base, **extra})


def _host_from_url(url: str) -> Optional[str]:
    try:
        netloc = parse.urlsplit(url if "://" in url else f"http://{url}").netloc
        return netloc.split("@")[-1].split(":")[0] or None
    except ValueError:
        return None


def _maybe_number(s: str):
    try:
        return int(s)
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return s


# --------------------------------------------------------------------------
# Rate limiter — token bucket sized to the VT free tier
# --------------------------------------------------------------------------

class RateLimiter:
    """Simple sliding-window limiter. Blocks until a slot is free."""

    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._times: deque[float] = deque()

    def acquire(self) -> None:
        now = time.monotonic()
        # Drop timestamps older than 60s.
        while self._times and now - self._times[0] >= 60:
            self._times.popleft()
        if len(self._times) >= self.per_minute:
            sleep_for = 60 - (now - self._times[0]) + 0.05
            if sleep_for > 0:
                eprint(f"{C.DIM}  …rate limit: waiting {sleep_for:0.1f}s{C.RESET}")
                time.sleep(sleep_for)
            return self.acquire()
        self._times.append(time.monotonic())


# --------------------------------------------------------------------------
# VirusTotal client
# --------------------------------------------------------------------------

class VTError(Exception):
    pass


class VirusTotalClient:
    """Minimal VT API v3 client using only the stdlib (no extra deps)."""

    def __init__(self, api_key: str, limiter: RateLimiter,
                 daily_cap: int = DEFAULT_DAILY_CAP):
        if not api_key:
            raise VTError("No VirusTotal API key. Set VT_API_KEY or pass --api-key.")
        self.api_key = api_key
        self.limiter = limiter
        self.daily_cap = daily_cap
        self.calls_made = 0

    def _endpoint(self, ioc: IOC) -> str:
        if ioc.kind == "ip":
            return f"/ip_addresses/{ioc.value}"
        if ioc.kind == "domain":
            return f"/domains/{ioc.value}"
        if ioc.kind == "hash":
            return f"/files/{ioc.value}"
        raise VTError(f"unsupported IOC kind: {ioc.kind}")

    def lookup(self, ioc: IOC, retries: int = 3) -> dict:
        if self.calls_made >= self.daily_cap:
            raise VTError(f"daily cap of {self.daily_cap} reached — stopping")
        url = VT_API_BASE + self._endpoint(ioc)
        req = request.Request(url, headers={
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "threathunt/1.0 (+blog demo)",
        })
        backoff = 2.0
        for attempt in range(1, retries + 1):
            self.limiter.acquire()
            try:
                with request.urlopen(req, timeout=30) as resp:
                    self.calls_made += 1
                    return json.loads(resp.read().decode("utf-8"))
            except error.HTTPError as e:
                if e.code == 404:
                    # Not found = VT has never seen it. That's a real result.
                    self.calls_made += 1
                    return {"_not_found": True}
                if e.code == 429:
                    eprint(f"{C.YELLOW}  429 from VT, backing off {backoff:0.0f}s "
                           f"(attempt {attempt}/{retries}){C.RESET}")
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                if e.code in (401, 403):
                    raise VTError(f"auth failed ({e.code}) — check your API key")
                raise VTError(f"HTTP {e.code} from VirusTotal: {e.reason}")
            except (error.URLError, TimeoutError) as e:
                eprint(f"{C.YELLOW}  network error: {e}; retrying{C.RESET}")
                time.sleep(backoff)
                backoff *= 2
        raise VTError(f"gave up on {ioc.value} after {retries} attempts")


# --------------------------------------------------------------------------
# Result parsing + risk scoring
# --------------------------------------------------------------------------

@dataclass
class Verdict:
    ioc: str
    kind: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    country: str = ""
    asn: str = ""
    as_owner: str = ""
    categories: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_analysis: str = ""
    not_found: bool = False
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)


def parse_vt_response(ioc: IOC, raw: dict) -> Verdict:
    v = Verdict(ioc=ioc.value, kind=ioc.kind,
                sources=sorted(ioc.sources), context=ioc.context)
    if raw.get("_not_found"):
        v.not_found = True
        return v

    attrs = (raw.get("data", {}) or {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    v.malicious = stats.get("malicious", 0)
    v.suspicious = stats.get("suspicious", 0)
    v.harmless = stats.get("harmless", 0)
    v.undetected = stats.get("undetected", 0)
    v.reputation = attrs.get("reputation", 0)
    v.country = attrs.get("country", "")
    v.asn = str(attrs.get("asn", "") or "")
    v.as_owner = attrs.get("as_owner", "")

    cats = attrs.get("categories", {}) or {}
    v.categories = sorted(set(cats.values())) if isinstance(cats, dict) else []

    for ts_field, dest in (("first_submission_date", "first_seen"),
                           ("last_analysis_date", "last_analysis"),
                           ("last_modification_date", "last_analysis")):
        ts = attrs.get(ts_field)
        if ts and not getattr(v, dest):
            setattr(v, dest, datetime.fromtimestamp(ts, tz=timezone.utc)
                    .strftime("%Y-%m-%d"))
    return v


def score_risk(v: Verdict) -> Verdict:
    """
    Combine VT *reputation* with local *behaviour* into a single 0–100 score.

    This is the heart of the tool and the part most worth tuning for your
    environment / explaining in a blog post. The weighting below is a sane
    starting point, not gospel.
    """
    score = 0
    reasons: list[str] = []

    total_engines = (v.malicious + v.suspicious + v.harmless + v.undetected) or 1

    # --- Reputation half (VirusTotal) ---
    if v.malicious:
        # Each malicious engine adds weight, with diminishing returns.
        mal_pts = min(60, 12 + v.malicious * 6)
        score += mal_pts
        eng = "engine flags" if v.malicious == 1 else "engines flag"
        reasons.append(f"{v.malicious}/{total_engines} {eng} malicious")
    if v.suspicious:
        score += min(15, v.suspicious * 3)
        eng = "engine flags" if v.suspicious == 1 else "engines flag"
        reasons.append(f"{v.suspicious} {eng} suspicious")
    if v.reputation < 0:
        score += min(10, abs(v.reputation) // 5)
        reasons.append(f"negative community reputation ({v.reputation})")
    bad_cats = {"malware", "malicious", "phishing", "command and control",
                "spam", "suspicious"}
    hit_cats = [c for c in v.categories if c.lower() in bad_cats]
    if hit_cats:
        score += 8
        reasons.append(f"categorised as {', '.join(hit_cats)}")

    # --- Behaviour half (Wazuh + Rita) ---
    lvl = v.context.get("wazuh_level")
    if isinstance(lvl, (int, float)) and lvl >= 10:
        score += 10
        reasons.append(f"high-severity Wazuh rule (level {int(lvl)})")
    beacon = v.context.get("rita_score") or v.context.get("rita_beacon_score")
    if isinstance(beacon, (int, float)) and beacon >= 0.7:
        score += 12
        reasons.append(f"strong Rita beacon score ({beacon})")
    if {"wazuh", "rita"}.issubset(set(v.sources)):
        score += 8
        reasons.append("seen by BOTH Wazuh and Rita")

    sev = v.context.get("unifi_severity")
    if isinstance(sev, str) and sev.lower() in ("critical", "high"):
        score += 10
        reasons.append(f"UniFi CyberSecure severity: {sev.lower()}")
    # Three independent sources flagging the same indicator is a strong signal.
    if len(set(v.sources)) >= 3:
        score += 8
        reasons.append(f"flagged by {len(set(v.sources))} independent sources")

    if v.not_found and v.kind in ("ip", "domain"):
        # Unknown infrastructure that your network still talked to is mildly
        # interesting for hunting — not damning, but worth a note.
        score += 3
        reasons.append("no VT history (unknown infrastructure)")

    # --- Local catalog half (threat_meister) ---
    # This indicator is (or is tied to) a sample you've already analysed in the
    # lab. That's high-confidence local ground truth, so it lifts the score.
    lab = v.context.get("lab_sample")
    if isinstance(lab, dict):
        score += 10
        fam = lab.get("family") or lab.get("category") or "catalogued"
        reasons.append(f"matches known lab sample (family={fam})")

    v.risk_score = max(0, min(100, score))
    v.risk_reasons = reasons
    return v


# --------------------------------------------------------------------------
# SQLite storage
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc           TEXT NOT NULL,
    kind          TEXT NOT NULL,
    risk_score    INTEGER NOT NULL,
    malicious     INTEGER NOT NULL DEFAULT 0,
    suspicious    INTEGER NOT NULL DEFAULT 0,
    reputation    INTEGER NOT NULL DEFAULT 0,
    country       TEXT,
    as_owner      TEXT,
    categories    TEXT,
    sources       TEXT,
    risk_reasons  TEXT,
    context       TEXT,
    not_found     INTEGER NOT NULL DEFAULT 0,
    checked_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_ioc   ON findings(ioc);
CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(risk_score);
CREATE INDEX IF NOT EXISTS idx_findings_time  ON findings(checked_at);

CREATE TABLE IF NOT EXISTS queue (
    ioc        TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    sources    TEXT,
    context    TEXT,
    priority   REAL NOT NULL DEFAULT 0,
    queued_at  TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def cached(self, ioc: str, ttl_hours: int) -> Optional[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM findings WHERE ioc = ? ORDER BY checked_at DESC LIMIT 1",
            (ioc,),
        )
        row = cur.fetchone()
        if not row:
            return None
        try:
            seen = datetime.fromisoformat(row["checked_at"])
        except ValueError:
            return None
        age_h = (datetime.now(timezone.utc) - seen).total_seconds() / 3600
        return row if age_h <= ttl_hours else None

    def save(self, v: Verdict) -> None:
        self.conn.execute(
            """INSERT INTO findings
               (ioc, kind, risk_score, malicious, suspicious, reputation,
                country, as_owner, categories, sources, risk_reasons,
                context, not_found, checked_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (v.ioc, v.kind, v.risk_score, v.malicious, v.suspicious,
             v.reputation, v.country, v.as_owner, json.dumps(v.categories),
             json.dumps(v.sources), json.dumps(v.risk_reasons),
             json.dumps(v.context), int(v.not_found),
             datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def history(self, min_score: int = 0, since: Optional[str] = None,
                limit: int = 200) -> list[sqlite3.Row]:
        q = "SELECT * FROM findings WHERE risk_score >= ?"
        params: list = [min_score]
        if since:
            q += " AND checked_at >= ?"
            params.append(since)
        q += " ORDER BY checked_at DESC, risk_score DESC LIMIT ?"
        params.append(limit)
        return list(self.conn.execute(q, params))

    # --- Resume queue: overflow IOCs that hit the daily cap ---

    def queue_iocs(self, iocs: list["IOC"]) -> None:
        """Persist un-enriched IOCs so a later run can resume them. Re-queuing
        an IOC merges its sources/context with whatever's already queued."""
        now = datetime.now(timezone.utc).isoformat()
        for ioc in iocs:
            existing = self.conn.execute(
                "SELECT sources, context FROM queue WHERE ioc = ?",
                (ioc.value,)).fetchone()
            sources = set(ioc.sources)
            context = dict(ioc.context)
            if existing:
                sources |= set(json.loads(existing["sources"] or "[]"))
                context = {**json.loads(existing["context"] or "{}"), **context}
            self.conn.execute(
                """INSERT INTO queue (ioc, kind, sources, context, priority, queued_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(ioc) DO UPDATE SET
                     sources=excluded.sources, context=excluded.context,
                     priority=excluded.priority""",
                (ioc.value, ioc.kind, json.dumps(sorted(sources)),
                 json.dumps(context), ioc.local_priority(), now))
        self.conn.commit()

    def dequeue_all(self) -> list["IOC"]:
        """Return queued IOCs (highest priority first) and clear the queue."""
        rows = list(self.conn.execute(
            "SELECT * FROM queue ORDER BY priority DESC"))
        iocs = [IOC(value=r["ioc"], kind=r["kind"],
                    sources=set(json.loads(r["sources"] or "[]")),
                    context=json.loads(r["context"] or "{}")) for r in rows]
        self.conn.execute("DELETE FROM queue")
        self.conn.commit()
        return iocs

    def queue_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]


def row_to_verdict(row: sqlite3.Row) -> Verdict:
    return Verdict(
        ioc=row["ioc"], kind=row["kind"], risk_score=row["risk_score"],
        malicious=row["malicious"], suspicious=row["suspicious"],
        reputation=row["reputation"], country=row["country"] or "",
        as_owner=row["as_owner"] or "",
        categories=json.loads(row["categories"] or "[]"),
        sources=json.loads(row["sources"] or "[]"),
        risk_reasons=json.loads(row["risk_reasons"] or "[]"),
        context=json.loads(row["context"] or "{}"),
        not_found=bool(row["not_found"]),
    )


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------

def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def band(score: int) -> tuple[str, str]:
    if score >= 70:
        return "CRITICAL", C.RED
    if score >= 40:
        return "ELEVATED", C.YELLOW
    if score >= 15:
        return "WATCH", C.CYAN
    return "LOW", C.GREEN


def print_verdict(v: Verdict, verbose: bool = False) -> None:
    label, colour = band(v.risk_score)
    kind_icon = {"ip": "🌐", "domain": "🔗", "hash": "📄"}.get(v.kind, "•")
    print(f"{colour}{C.BOLD}[{label:>8}] {v.risk_score:>3}{C.RESET}  "
          f"{kind_icon} {C.BOLD}{v.ioc}{C.RESET}  {C.DIM}({v.kind}){C.RESET}")

    if v.not_found:
        print(f"           {C.DIM}VirusTotal: no record found{C.RESET}")
    else:
        det = f"{C.RED}{v.malicious} malicious{C.RESET}" if v.malicious else \
              f"{C.GREEN}0 malicious{C.RESET}"
        extra = f", {v.suspicious} suspicious" if v.suspicious else ""
        meta = " · ".join(filter(None, [
            v.as_owner, v.country, f"AS{v.asn}" if v.asn else "",
        ]))
        print(f"           VT: {det}{extra}"
              + (f"  {C.DIM}{meta}{C.RESET}" if meta else ""))
        if v.categories:
            print(f"           {C.DIM}categories: {', '.join(v.categories)}{C.RESET}")

    if v.sources:
        print(f"           {C.DIM}sources: {', '.join(v.sources)}{C.RESET}")
    for reason in v.risk_reasons:
        print(f"           {colour}•{C.RESET} {reason}")
    if verbose and v.context:
        for k, val in v.context.items():
            print(f"           {C.DIM}{k}: {val}{C.RESET}")
    print()


def print_summary(verdicts: list[Verdict]) -> None:
    if not verdicts:
        print(f"{C.DIM}No indicators to report.{C.RESET}")
        return
    crit = sum(1 for v in verdicts if v.risk_score >= 70)
    elev = sum(1 for v in verdicts if 40 <= v.risk_score < 70)
    watch = sum(1 for v in verdicts if 15 <= v.risk_score < 40)
    low = len(verdicts) - crit - elev - watch
    print(f"{C.BOLD}── Hunt summary ──{C.RESET}")
    print(f"  {C.RED}CRITICAL{C.RESET}: {crit:>4}   "
          f"{C.YELLOW}ELEVATED{C.RESET}: {elev:>4}   "
          f"{C.CYAN}WATCH{C.RESET}: {watch:>4}   "
          f"{C.GREEN}LOW{C.RESET}: {low:>4}")
    print(f"  total indicators: {len(verdicts)}")


# --------------------------------------------------------------------------
# Report export
# --------------------------------------------------------------------------

def export_report(verdicts: list[Verdict], path: Path) -> None:
    rows = [asdict(v) for v in verdicts]
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps({
            "generated": datetime.now(timezone.utc).isoformat(),
            "count": len(rows),
            "findings": rows,
        }, indent=2), encoding="utf-8")
    elif path.suffix.lower() == ".csv":
        flat_fields = ["ioc", "kind", "risk_score", "malicious", "suspicious",
                       "reputation", "country", "as_owner", "not_found",
                       "categories", "sources", "risk_reasons"]
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=flat_fields, extrasaction="ignore")
            w.writeheader()
            for v in verdicts:
                d = asdict(v)
                for list_field in ("categories", "sources", "risk_reasons"):
                    d[list_field] = "; ".join(map(str, d[list_field]))
                w.writerow(d)
    elif path.suffix.lower() in (".md", ".markdown"):
        path.write_text(build_markdown_report(verdicts), encoding="utf-8")
    else:
        raise SystemExit(
            f"unsupported report format: {path.suffix} (use .json, .csv, or .md)")
    eprint(f"{C.GREEN}✓{C.RESET} report written to {path}")


def _md_escape(text: str) -> str:
    """Escape pipe and backtick so free-form context can't break tables."""
    return str(text).replace("|", "\\|").replace("`", "\u200b`")


def build_markdown_report(verdicts: list[Verdict]) -> str:
    """
    Render a hunt as a self-contained Markdown report — designed to drop
    straight into a blog draft, a ticket, or a wiki. Structure:

      - title + generated timestamp
      - summary line with band counts
      - a findings table (highest risk first)
      - per-indicator detail sections for everything above WATCH, with the
        behavioural context that justifies the score
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    crit = [v for v in verdicts if v.risk_score >= 70]
    elev = [v for v in verdicts if 40 <= v.risk_score < 70]
    watch = [v for v in verdicts if 15 <= v.risk_score < 40]
    low = [v for v in verdicts if v.risk_score < 15]

    out: list[str] = []
    out.append(f"# Threat Hunt Report — {now}")
    out.append("")
    out.append(f"Enriched **{len(verdicts)}** unique indicators against "
               f"VirusTotal, correlated with Wazuh and Rita behavioural signals.")
    out.append("")
    out.append("| Band | Count |")
    out.append("|------|------:|")
    out.append(f"| 🔴 Critical (70+) | {len(crit)} |")
    out.append(f"| 🟡 Elevated (40–69) | {len(elev)} |")
    out.append(f"| 🔵 Watch (15–39) | {len(watch)} |")
    out.append(f"| 🟢 Low (0–14) | {len(low)} |")
    out.append("")

    # --- Findings table ---
    out.append("## Findings")
    out.append("")
    out.append("| Score | Band | Indicator | Type | VT detections | Sources | Owner / Country |")
    out.append("|------:|------|-----------|------|---------------|---------|-----------------|")
    band_emoji = {"CRITICAL": "🔴", "ELEVATED": "🟡", "WATCH": "🔵", "LOW": "🟢"}
    for v in verdicts:
        label = band(v.risk_score)[0]
        if v.not_found:
            det = "_no VT record_"
        else:
            det = f"{v.malicious} mal"
            if v.suspicious:
                det += f" / {v.suspicious} susp"
        owner = " ".join(filter(None, [v.as_owner, f"({v.country})" if v.country else ""]))
        out.append(
            f"| {v.risk_score} | {band_emoji.get(label,'')} {label} "
            f"| `{_md_escape(v.ioc)}` | {v.kind} | {det} "
            f"| {', '.join(v.sources) or '—'} | {_md_escape(owner) or '—'} |")
    out.append("")

    # --- Detail sections, grouped by band (Critical → Elevated → Watch) ---
    groups = [
        ("🔴 Critical", [v for v in verdicts if v.risk_score >= 70]),
        ("🟡 Elevated", [v for v in verdicts if 40 <= v.risk_score < 70]),
        ("🔵 Watch", [v for v in verdicts if 15 <= v.risk_score < 40]),
    ]
    if any(items for _, items in groups):
        out.append("## Indicators needing review")
        out.append("")
        for heading, items in groups:
            if not items:
                continue
            out.append(f"### {heading} ({len(items)})")
            out.append("")
            for v in items:
                _append_detail(out, v, band_emoji)

    out.append("---")
    out.append(f"_Generated by threathunt.py at {now}. "
               f"Scores combine VirusTotal reputation with Wazuh/Rita behaviour; "
               f"tune `score_risk()` for your environment._")
    out.append("")
    return "\n".join(out)


def _fmt_ctx_value(key: str, val) -> str:
    """Render one behavioural-context value for the report.

    The catalog cross-reference (`lab_sample`) arrives as a dict; dumping it
    raw prints Python repr with single quotes, which reads badly in a report.
    Render it as a human sentence instead. Everything else is scalar.
    """
    if key == "lab_sample" and isinstance(val, dict):
        sid = val.get("id")
        fam = val.get("family") or val.get("category") or "catalogued"
        cat = val.get("category")
        via = val.get("via", "")
        bits = [f"sample #{sid}" if sid is not None else "known sample"]
        bits.append(f"{fam}/{cat}" if cat and cat != fam else str(fam))
        text = " ".join(bits)
        if via:
            text += f" (matched via {via.replace('-', ' ')})"
        return text
    return str(val)


def _append_detail(out: list[str], v: Verdict, band_emoji: dict) -> None:
    """Render one indicator's detail block into the report buffer."""
    label = band(v.risk_score)[0]
    out.append(f"#### {band_emoji.get(label,'')} `{_md_escape(v.ioc)}` "
               f"— {label} ({v.risk_score})")
    out.append("")
    if v.not_found:
        out.append("- **VirusTotal:** no record found (unknown infrastructure)")
    else:
        out.append(f"- **VirusTotal:** {v.malicious} malicious, "
                   f"{v.suspicious} suspicious, reputation {v.reputation}")
        if v.as_owner or v.country or v.asn:
            meta = ", ".join(filter(None, [
                v.as_owner, v.country, f"AS{v.asn}" if v.asn else ""]))
            out.append(f"- **Infrastructure:** {_md_escape(meta)}")
        if v.categories:
            out.append(f"- **Categories:** {', '.join(v.categories)}")
        if v.first_seen:
            out.append(f"- **First seen by VT:** {v.first_seen}")
    out.append(f"- **Sources:** {', '.join(v.sources) or '—'}")
    if v.risk_reasons:
        out.append("- **Why it scored:**")
        for r in v.risk_reasons:
            out.append(f"    - {_md_escape(r)}")
    if v.context:
        # Surface the lab-catalog match on its own line — it's the most
        # meaningful piece of context, not just another key=value pair.
        lab = v.context.get("lab_sample")
        if isinstance(lab, dict):
            out.append(f"- **Lab catalog:** {_md_escape(_fmt_ctx_value('lab_sample', lab))}")
        ctx_bits = [f"`{_md_escape(k)}={_md_escape(_fmt_ctx_value(k, val))}`"
                    for k, val in v.context.items() if k != "lab_sample"]
        if ctx_bits:
            out.append(f"- **Context:** {', '.join(ctx_bits)}")
    out.append("")


# --------------------------------------------------------------------------
# Remote fetch over SSH
# --------------------------------------------------------------------------

def _parse_ssh_target(spec: str) -> tuple[str, str]:
    """
    Split a 'user@host:/remote/path' (or 'host:/path') spec into (host, path).

    We keep any user@ prefix attached to the host so it's passed straight to
    ssh, which knows how to handle it (and honours ~/.ssh/config aliases too).
    A bare host without a colon is rejected — we need to know which file.
    """
    if ":" not in spec:
        raise SystemExit(
            f"invalid SSH target '{spec}' — expected user@host:/path/to/file")
    host, remote_path = spec.split(":", 1)
    if not host or not remote_path:
        raise SystemExit(
            f"invalid SSH target '{spec}' — expected user@host:/path/to/file")
    return host, remote_path


def fetch_over_ssh(spec: str, *, use_sudo: bool = False,
                   ssh_opts: Optional[list[str]] = None) -> Path:
    """
    Stream a remote file down to a local temp file by shelling out to the
    system `ssh`. Dependency-free, and it inherits your keys, ~/.ssh/config
    host aliases, agent, and known_hosts exactly as if you typed ssh yourself.

    The Wazuh alerts file is owned by wazuh:wazuh (mode 660), so reading it
    usually needs either membership in the wazuh group or sudo. Pass
    use_sudo=True to prefix the remote read with `sudo` (needs NOPASSWD or a
    tty; for cron, NOPASSWD on that one cat command is the usual approach).

    Returns the local Path of the downloaded copy (caller cleans it up, or
    lets the OS reap the temp dir).
    """
    host, remote_path = _parse_ssh_target(spec)

    # Build the remote command. We cat the file and let ssh stream it to our
    # stdout, which we capture into a temp file. shlex.quote guards against
    # spaces / oddities in the remote path.
    remote_cmd = f"cat {shlex.quote(remote_path)}"
    if use_sudo:
        remote_cmd = f"sudo -n {remote_cmd}"

    cmd = ["ssh"]
    # BatchMode makes ssh fail fast instead of hanging on a password prompt —
    # important for an unattended monthly cron run.
    cmd += ["-o", "BatchMode=yes"]
    if ssh_opts:
        cmd += ssh_opts
    cmd += [host, remote_cmd]

    suffix = Path(remote_path).suffix or ".dat"
    tmp_dir = Path(tempfile.mkdtemp(prefix="threathunt_ssh_"))
    local_path = tmp_dir / (Path(remote_path).name or f"remote{suffix}")

    eprint(f"{C.DIM}fetching {remote_path} from {host} over ssh …{C.RESET}")
    try:
        with local_path.open("wb") as out:
            proc = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE,
                                  timeout=300)
    except FileNotFoundError:
        raise SystemExit("`ssh` not found on PATH — is OpenSSH installed?")
    except subprocess.TimeoutExpired:
        raise SystemExit(f"ssh fetch from {host} timed out after 300s")

    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        hint = ""
        if "sudo" in err.lower() or "a password is required" in err.lower():
            hint = ("\n  hint: the alerts file needs elevated read. Either add "
                    "your user to the 'wazuh' group on the manager, or allow "
                    "NOPASSWD sudo for `cat` on that path and pass --wazuh-sudo.")
        elif "permission denied" in err.lower():
            hint = ("\n  hint: check the file is readable by your SSH user "
                    "(wazuh:wazuh, mode 660), or use --wazuh-sudo.")
        raise SystemExit(f"ssh fetch failed (exit {proc.returncode}): {err}{hint}")

    if local_path.stat().st_size == 0:
        eprint(f"{C.YELLOW}warn{C.RESET}: fetched file is empty — "
               f"is {remote_path} the right path, and non-empty today?")
    return local_path


# --------------------------------------------------------------------------
# Core enrichment pipeline
# --------------------------------------------------------------------------

def collect_iocs(wazuh: Optional[Path], rita: Optional[Path],
                 manual: Iterable[str],
                 unifi: Optional[Path] = None) -> list[IOC]:
    """Ingest all sources and de-duplicate, merging context as we go."""
    merged: dict[str, IOC] = {}

    def add(ioc: IOC) -> None:
        if ioc.value in merged:
            merged[ioc.value].merge(ioc)
        else:
            merged[ioc.value] = ioc

    if wazuh:
        if not wazuh.exists():
            raise SystemExit(f"Wazuh file not found: {wazuh}")
        for ioc in parse_wazuh(wazuh):
            add(ioc)
    if rita:
        if not rita.exists():
            raise SystemExit(f"Rita file not found: {rita}")
        for ioc in parse_rita(rita):
            add(ioc)
    if unifi:
        if not unifi.exists():
            raise SystemExit(f"UniFi CSV not found: {unifi}")
        for ioc in parse_unifi(unifi):
            add(ioc)
    for raw in manual:
        kind = classify_ioc(raw)
        if kind:
            add(IOC(value=raw.strip().lower(), kind=kind, sources={"manual"}))
        else:
            eprint(f"{C.YELLOW}warn{C.RESET}: skipping unrecognised indicator '{raw}'")
    return list(merged.values())


def enrich(iocs: list[IOC], vt: VirusTotalClient, store: Store,
           ttl_hours: int, force: bool = False
           ) -> tuple[list[Verdict], list[IOC]]:
    """
    Enrich indicators against VirusTotal, highest LOCAL priority first.

    Returns (verdicts, overflow) where `overflow` is the list of IOCs we
    could NOT enrich because the VT daily cap / quota was hit. Cache hits are
    free and never count toward the cap, so they're always processed.

    Triaging by local_priority() before spending quota guarantees that if we
    run out of budget at, say, 500 of 1,200 indicators, the 700 we skip are
    the lowest-signal ones — not a high-severity beacon that happened to sort
    late alphabetically.
    """
    # Highest local priority first; this is the triage order.
    ordered = sorted(iocs, key=lambda i: i.local_priority(), reverse=True)

    verdicts: list[Verdict] = []
    overflow: list[IOC] = []
    total = len(ordered)
    capped = False

    for i, ioc in enumerate(ordered, 1):
        # Cross-reference against the local sample catalog (threat_meister), if wired.
        # A match means we've already analysed this exact hash/host in the lab,
        # which both annotates the finding and feeds score_risk().
        if LOCAL_CATALOG_LOOKUP is not None:
            hit = LOCAL_CATALOG_LOOKUP(ioc.value)
            if hit:
                ioc.context.setdefault("lab_sample", hit)

        # Once the cap is hit, everything remaining goes to overflow — but we
        # still drain free cache hits so a re-run tomorrow has less to do.
        if not force:
            cached = store.cached(ioc.value, ttl_hours)
            if cached:
                v = row_to_verdict(cached)
                v.context = {**v.context, **ioc.context}
                v.sources = sorted(set(v.sources) | ioc.sources)
                verdicts.append(score_risk(v))
                eprint(f"{C.DIM}[{i}/{total}]{C.RESET} {ioc.value} "
                       f"{C.DIM}cached{C.RESET}")
                continue

        if capped:
            overflow.append(ioc)
            continue

        eprint(f"{C.DIM}[{i}/{total}]{C.RESET} {ioc.value} …")
        try:
            raw = vt.lookup(ioc)
        except VTError as e:
            # Cap or quota reached: this IOC and all remaining un-cached ones
            # become overflow rather than being silently dropped.
            eprint(f"{C.YELLOW}VT budget reached: {e}{C.RESET}")
            eprint(f"{C.YELLOW}  queuing remaining indicators for resume.{C.RESET}")
            overflow.append(ioc)
            capped = True
            continue
        v = score_risk(parse_vt_response(ioc, raw))
        store.save(v)
        verdicts.append(v)

    verdicts.sort(key=lambda x: x.risk_score, reverse=True)
    return verdicts, overflow


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _read_env_file(path: Path, key: str = "VT_API_KEY") -> str:
    """Pull KEY from a .env-style file. Tolerates `export KEY=val`, surrounding
    quotes, inline whitespace, blank lines and # comments. Returns "" if the
    file is missing or the key isn't present."""
    try:
        if not path.is_file():
            return ""
    except OSError:
        return ""
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        name, val = line.split("=", 1)
        if name.strip() != key:
            continue
        val = val.strip()
        if val[:1] in ("'", '"'):
            # Quoted value: take exactly what's inside the matching quote and
            # ignore anything after it (e.g. a trailing " # comment").
            quote = val[0]
            end = val.find(quote, 1)
            if end != -1:
                return val[1:end]
            # unbalanced quote — fall through and treat literally
            val = val[1:]
        elif " #" in val:
            # Unquoted value: strip a trailing inline comment.
            val = val.split(" #", 1)[0].strip()
        return val.strip()
    return ""


def get_api_key(args) -> str:
    # 1. explicit flag wins
    if getattr(args, "api_key", None):
        return args.api_key
    # 2. environment variable
    if os.environ.get("VT_API_KEY"):
        return os.environ["VT_API_KEY"]
    # 3. env files, in priority order. --env-file and $VT_ENV_FILE let you point
    #    anywhere; otherwise we check a local .env then your secrets file. This
    #    keeps the key out of shell history and the process environment.
    candidates: list[Path] = []
    if getattr(args, "env_file", None):
        candidates.append(Path(args.env_file).expanduser())
    if os.environ.get("VT_ENV_FILE"):
        candidates.append(Path(os.environ["VT_ENV_FILE"]).expanduser())
    candidates.append(Path(".env"))
    candidates.append(Path.home() / ".secrets" / "bug_bounty.env")
    for path in candidates:
        key = _read_env_file(path)
        if key:
            return key
    return ""


def cmd_check(args) -> int:
    store = Store(Path(args.db))
    limiter = RateLimiter(args.rate)
    vt = VirusTotalClient(get_api_key(args), limiter, args.daily_cap)
    iocs = collect_iocs(None, None, args.indicators)
    if not iocs:
        eprint("Nothing valid to check.")
        return 2
    verdicts, _overflow = enrich(iocs, vt, store, args.cache_ttl, force=args.force)
    for v in verdicts:
        print_verdict(v, verbose=args.verbose)
    return 1 if any(v.risk_score >= 70 for v in verdicts) else 0


def cmd_hunt(args) -> int:
    store = Store(Path(args.db))
    limiter = RateLimiter(args.rate)
    vt = VirusTotalClient(get_api_key(args), limiter, args.daily_cap)

    ssh_opts = shlex.split(args.ssh_opt) if args.ssh_opt else None

    # A source can be either a local path or a remote user@host:/path (--*-ssh).
    # Remote sources are streamed down first and then parsed exactly like a
    # local file, so the rest of the pipeline doesn't care where they came from.
    if args.wazuh and args.wazuh_ssh:
        raise SystemExit("use either --wazuh or --wazuh-ssh, not both")
    if args.wazuh_ssh:
        wazuh = fetch_over_ssh(args.wazuh_ssh, use_sudo=args.wazuh_sudo,
                               ssh_opts=ssh_opts)
    else:
        wazuh = Path(args.wazuh) if args.wazuh else None

    if args.rita and args.rita_ssh:
        raise SystemExit("use either --rita or --rita-ssh, not both")
    if args.rita_ssh:
        rita = fetch_over_ssh(args.rita_ssh, ssh_opts=ssh_opts)
    else:
        rita = Path(args.rita) if args.rita else None

    unifi = Path(args.unifi) if args.unifi else None

    # Pull anything left over from a previous capped run first — these have
    # already waited, so they get priority in today's budget.
    resumed = store.dequeue_all()
    if resumed:
        eprint(f"{C.CYAN}Resuming {len(resumed)} indicator(s) queued "
               f"from a previous run.{C.RESET}")

    fresh = collect_iocs(wazuh, rita, args.indicators, unifi=unifi)
    if not fresh and not resumed:
        eprint("Nothing to hunt — pass --wazuh(-ssh), --rita(-ssh), --unifi, "
               "and/or indicators.")
        return 2

    # Merge resumed + fresh (union sources/context on collisions).
    merged: dict[str, IOC] = {}
    for ioc in resumed + fresh:
        if ioc.value in merged:
            merged[ioc.value].merge(ioc)
        else:
            merged[ioc.value] = ioc
    iocs = list(merged.values())

    eprint(f"{C.BOLD}Collected {len(iocs)} unique indicators to enrich.{C.RESET}")
    if len(iocs) > args.daily_cap:
        eprint(f"{C.YELLOW}Note: {len(iocs)} indicators exceeds the daily cap "
               f"of {args.daily_cap}. Highest-priority first; the rest will be "
               f"queued for the next run.{C.RESET}")
    eprint("")

    verdicts, overflow = enrich(iocs, vt, store, args.cache_ttl,
                                force=args.force)

    # Persist whatever we couldn't get to so the next run resumes it.
    if overflow:
        store.queue_iocs(overflow)

    print()
    threshold = args.min_score
    for v in (v for v in verdicts if v.risk_score >= threshold):
        print_verdict(v, verbose=args.verbose)
    print_summary(verdicts)
    eprint(f"\n{C.DIM}VT API calls this run: {vt.calls_made}{C.RESET}")
    if overflow:
        eprint(f"{C.YELLOW}{len(overflow)} indicator(s) queued for next run "
               f"(daily cap reached). Re-run `hunt` tomorrow to continue.{C.RESET}")

    if args.report:
        export_report(verdicts, Path(args.report))
    return 1 if any(v.risk_score >= 70 for v in verdicts) else 0


def cmd_history(args) -> int:
    store = Store(Path(args.db))
    rows = store.history(min_score=args.min_score, since=args.since,
                         limit=args.limit)
    if not rows:
        print(f"{C.DIM}No findings match.{C.RESET}")
        return 0
    verdicts = [score_risk(row_to_verdict(r)) for r in rows]
    for v in verdicts:
        print_verdict(v, verbose=args.verbose)
    print_summary(verdicts)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threathunt",
        description="Monthly threat hunting: enrich Wazuh + Rita IOCs with VirusTotal.")

    # shared options
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=str(DEFAULT_DB_PATH),
                        help=f"SQLite path (default: {DEFAULT_DB_PATH})")
    common.add_argument("--api-key", help="VirusTotal API key (else $VT_API_KEY, "
                        "--env-file, $VT_ENV_FILE, ./.env, or ~/.secrets/bug_bounty.env)")
    common.add_argument("--env-file", help="path to a .env file to read VT_API_KEY from "
                        "(checked before ./.env and ~/.secrets/bug_bounty.env)")
    common.add_argument("--rate", type=int, default=DEFAULT_RATE_PER_MIN,
                        help=f"max VT requests/min (default {DEFAULT_RATE_PER_MIN})")
    common.add_argument("--daily-cap", type=int, default=DEFAULT_DAILY_CAP,
                        help=f"stop after N VT calls (default {DEFAULT_DAILY_CAP})")
    common.add_argument("--cache-ttl", type=int, default=DEFAULT_CACHE_TTL_HOURS,
                        help="hours to trust a cached result (default 168)")
    common.add_argument("--force", action="store_true",
                        help="ignore cache and re-query VT")
    common.add_argument("-v", "--verbose", action="store_true",
                        help="show behavioural context for each indicator")

    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", parents=[common],
                       help="check one or more indicators ad hoc")
    c.add_argument("indicators", nargs="+", help="IPs, domains, and/or hashes")
    c.set_defaults(func=cmd_check)

    h = sub.add_parser("hunt", parents=[common],
                       help="run a full monthly hunt over Wazuh/Rita/UniFi exports")
    h.add_argument("--wazuh", help="path to a LOCAL Wazuh alerts file (JSON / NDJSON)")
    h.add_argument("--wazuh-ssh", metavar="USER@HOST:/PATH",
                   help="fetch Wazuh alerts from a remote manager over ssh, "
                        "e.g. admin@wazuh:/var/ossec/logs/alerts/alerts.json")
    h.add_argument("--wazuh-sudo", action="store_true",
                   help="use `sudo -n cat` on the remote read (alerts file is "
                        "wazuh:wazuh mode 660; needs NOPASSWD sudo for cron)")
    h.add_argument("--rita", help="path to a LOCAL Rita CSV export")
    h.add_argument("--rita-ssh", metavar="USER@HOST:/PATH",
                   help="fetch a Rita CSV from a remote host over ssh")
    h.add_argument("--unifi", help="path to a UniFi CyberSecure threat CSV export")
    h.add_argument("--ssh-opt", metavar="\"-o ... -p ...\"",
                   help="extra options passed verbatim to ssh for all remote "
                        "fetches, e.g. \"-p 2222 -i ~/.ssh/hunt_key\"")
    h.add_argument("indicators", nargs="*", help="extra indicators to include")
    h.add_argument("--min-score", type=int, default=0,
                   help="only print findings at/above this score (default 0)")
    h.add_argument("--report", help="write report to .json, .csv, or .md")
    h.set_defaults(func=cmd_hunt)

    hi = sub.add_parser("history", parents=[common],
                        help="review past findings (no API calls)")
    hi.add_argument("--min-score", type=int, default=0)
    hi.add_argument("--since", help="ISO date, e.g. 2026-05-01")
    hi.add_argument("--limit", type=int, default=200)
    hi.set_defaults(func=cmd_history)

    q = sub.add_parser("queue", parents=[common],
                       help="show how many indicators are queued for resume")
    q.set_defaults(func=cmd_queue)
    return p


def cmd_queue(args) -> int:
    store = Store(Path(args.db))
    n = store.queue_count()
    if n == 0:
        print(f"{C.GREEN}Queue is empty — no pending indicators.{C.RESET}")
    else:
        print(f"{C.YELLOW}{n} indicator(s) queued for the next hunt run.{C.RESET}")
        print(f"{C.DIM}Run `threathunt hunt` to resume them (highest "
              f"priority first).{C.RESET}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except VTError as e:
        eprint(f"{C.RED}error:{C.RESET} {e}")
        return 2
    except KeyboardInterrupt:
        eprint("\ninterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
