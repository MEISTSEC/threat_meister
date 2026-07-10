#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 meistsec
"""
threat_meister - Malware Analysis Lab operational workflow tool.

A single-operator catalog + triage + detection-engineering workflow for a
malware analysis lab. Tracks samples, computes hashes, runs static triage,
captures analyst observations, and scaffolds/tests structured YARA rules that
feed downstream into Wazuh (FIM + Active Response) and ClamAV.

Design goals:
  - Zero mandatory third-party deps (stdlib only). Optional tools/libs
    (yara, ssdeep, tlsh, clamscan, radare2) are auto-detected and used if present.
  - Samples are stored inert: renamed to their SHA-256, made non-executable,
    and (optionally) zip-encrypted so nothing runs by accident.
  - Everything is auditable: a SQLite catalog is the single source of truth.

This tool does NOT execute samples. It performs static cataloguing only.
"""

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

# ----------------------------------------------------------------------------
# Configuration / lab layout
# ----------------------------------------------------------------------------

# Allow importing sibling modules (threathunt.py, intel.py) regardless of where
# the launcher lives, so `threat_meister` works as an installed command.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LAB_ROOT = Path(os.environ.get("THREAT_MEISTER_ROOT", str(Path.home() / "threat_meister"))).resolve()
DB_PATH = LAB_ROOT / "catalog.db"
INTEL_DB = LAB_ROOT / "threathunt.db"   # shared with the threathunt engine
STORE = LAB_ROOT / "store"          # inert sample store, keyed by sha256
QUARANTINE = LAB_ROOT / "quarantine"  # incoming, pre-ingest
YARA_DIR = LAB_ROOT / "yara" / "rules"
EXPORT_DIR = LAB_ROOT / "exports"
NOTES_DIR = LAB_ROOT / "notes"

# Password used when storing samples zip-encrypted. Deliberately weak/standard:
# the point is inertness + convention (VX standard), not secrecy.
STORE_ZIP_PASSWORD = b"infected"

__version__ = "1.0.0"

# ----------------------------------------------------------------------------
# Terminal banner
# ----------------------------------------------------------------------------

_BANNER_ART = r"""
                 ┃
                 ┃
        ╔════════╬════════╗
        ║        ┃        ║
        ║    ╭───╀───╮    ║
   ━━━━━╬━━━━┥   ◉   ┝━━━━╬━━━━━
        ║    ╰───╁───╯    ║
        ║        ┃        ║
        ╚════════╬════════╝
                 ┃
                 ┃
"""

def _color_enabled(stream):
    return stream.isatty() and not os.environ.get("NO_COLOR")

def banner(stream=None):
    """Render the application logo + name. Colour auto-disables when piped/NO_COLOR."""
    stream = stream or sys.stderr
    use = _color_enabled(stream)
    CYAN = "\033[38;5;44m"  if use else ""
    DIM  = "\033[2m"        if use else ""
    BOLD = "\033[1m"        if use else ""
    RED  = "\033[38;5;196m" if use else ""
    RST  = "\033[0m"        if use else ""
    # cyan reticle with a red center dot
    art_lines = []
    for line in _BANNER_ART.strip("\n").splitlines():
        line = line.replace("◉", f"{RED}◉{CYAN}")
        art_lines.append(f"{CYAN}{line}{RST}")
    art = "\n".join(art_lines)
    name = "T H R E A T   M E I S T E R"
    tagline = "malware analysis · YARA authoring · VirusTotal intel · Wazuh detection"
    sub = f"v{__version__} · single-analyst threat-hunting workflow"
    rule = "─" * 66
    out = (f"\n{art}\n\n"
           f"{DIM}{rule}{RST}\n"
           f"          {BOLD}{name}{RST}\n"
           f"  {tagline}\n"
           f"  {DIM}{sub}{RST}\n"
           f"{DIM}{rule}{RST}\n")
    print(out, file=stream)

# Controlled vocabularies help keep the catalog queryable and consistent.
CATEGORIES = [
    "trojan", "ransomware", "rat", "backdoor", "downloader", "dropper",
    "worm", "rootkit", "bootkit", "infostealer", "keylogger", "banker",
    "cryptominer", "wiper", "botnet", "loader", "spyware", "adware",
    "webshell", "exploit", "pua", "unknown",
]
PLATFORMS = ["elf", "pe", "macho", "script", "document", "apk", "jar", "other"]
TLP = ["clear", "green", "amber", "amber+strict", "red"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT UNIQUE NOT NULL,
    sha1         TEXT,
    md5          TEXT,
    ssdeep       TEXT,
    tlsh         TEXT,
    size         INTEGER,
    entropy      REAL,
    filetype     TEXT,
    platform     TEXT,
    orig_name    TEXT,
    family       TEXT,
    category     TEXT DEFAULT 'unknown',
    tlp          TEXT DEFAULT 'amber',
    source       TEXT,
    campaign     TEXT,
    added_utc    TEXT NOT NULL,
    stored_path  TEXT
);
CREATE TABLE IF NOT EXISTS tags (
    sample_id INTEGER, tag TEXT,
    UNIQUE(sample_id, tag),
    FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER, ts_utc TEXT, phase TEXT, body TEXT,
    FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS attack (
    sample_id INTEGER, technique TEXT, note TEXT,
    UNIQUE(sample_id, technique),
    FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER, itype TEXT, value TEXT, note TEXT,
    UNIQUE(sample_id, itype, value),
    FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE, sample_id INTEGER, path TEXT, created_utc TEXT,
    FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE SET NULL
);
"""

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def now_utc():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def today():
    return dt.date.today().isoformat()

def have(tool):
    return shutil.which(tool) is not None

def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)

def db():
    LAB_ROOT.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn

def _migrate(conn):
    """Idempotent schema migrations (SQLite lacks ADD COLUMN IF NOT EXISTS)."""
    have_cols = {r["name"] for r in conn.execute("PRAGMA table_info(samples)")}
    for col, ddl in (("vt_score", "INTEGER"), ("vt_checked", "TEXT")):
        if col not in have_cols:
            conn.execute(f"ALTER TABLE samples ADD COLUMN {col} {ddl}")
    conn.commit()

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)

def hashes(path: Path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def fuzzy_hashes(path: Path):
    ss, tl = None, None
    try:
        import ssdeep  # type: ignore
        ss = ssdeep.hash_from_file(str(path))
    except Exception:
        if have("ssdeep"):
            try:
                out = subprocess.check_output(["ssdeep", "-s", str(path)],
                                               text=True, stderr=subprocess.DEVNULL)
                # last line: "hash,\"filename\""
                line = out.strip().splitlines()[-1]
                ss = line.rsplit(",", 1)[0]
            except Exception:
                pass
    try:
        import tlsh  # type: ignore
        with open(path, "rb") as f:
            h = tlsh.hash(f.read())
        tl = h if h and h != "TNULL" else None
    except Exception:
        pass
    return ss, tl

def detect_filetype(path: Path):
    try:
        import magic  # type: ignore
        return magic.from_file(str(path))
    except Exception:
        if have("file"):
            try:
                return subprocess.check_output(["file", "-b", str(path)],
                                               text=True).strip()
            except Exception:
                pass
    return "unknown"

def guess_platform(filetype: str, head: bytes) -> str:
    ft = filetype.lower()
    if head[:4] == b"\x7fELF" or "elf" in ft:
        return "elf"
    if head[:2] == b"MZ" or "pe32" in ft or "ms-dos" in ft or "windows" in ft:
        return "pe"
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return "macho"
    if head[:2] == b"PK":
        return "jar" if "java" in ft else "other"
    if "script" in ft or "shell" in ft or "python" in ft or "text" in ft:
        return "script"
    if "pdf" in ft or "document" in ft or "word" in ft or "office" in ft:
        return "document"
    return "other"

def store_sample(src: Path, sha256: str, encrypt: bool) -> Path:
    STORE.mkdir(parents=True, exist_ok=True)
    prefix = STORE / sha256[:2]
    prefix.mkdir(exist_ok=True)
    if encrypt:
        dest = prefix / f"{sha256}.zip"
        if not dest.exists():
            # Standard zip with password so the raw binary never sits on disk
            # in directly-runnable form. Uses `zip` if available for real
            # encryption; falls back to stdlib (stored, no crypto) otherwise.
            if have("zip"):
                subprocess.run(["zip", "-j", "-q", "-P",
                                STORE_ZIP_PASSWORD.decode(), str(dest), str(src)],
                               check=True)
            else:
                with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
                    z.write(src, arcname=sha256)
    else:
        dest = prefix / sha256
        if not dest.exists():
            shutil.copy2(src, dest)
            os.chmod(dest, 0o400)  # read-only, non-exec
    return dest

def get_sample(conn, ref):
    """Resolve a sample by id, full sha256, or unambiguous hash prefix."""
    if ref.isdigit():
        row = conn.execute("SELECT * FROM samples WHERE id=?", (int(ref),)).fetchone()
        if row:
            return row
    row = conn.execute("SELECT * FROM samples WHERE sha256=?", (ref.lower(),)).fetchone()
    if row:
        return row
    rows = conn.execute("SELECT * FROM samples WHERE sha256 LIKE ?",
                        (ref.lower() + "%",)).fetchall()
    if len(rows) == 1:
        return rows[0]
    if len(rows) > 1:
        die(f"ambiguous reference '{ref}' matches {len(rows)} samples")
    die(f"no sample matches '{ref}'")

# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------

def cmd_init(args):
    banner()
    for d in (STORE, QUARANTINE, YARA_DIR, EXPORT_DIR, NOTES_DIR):
        d.mkdir(parents=True, exist_ok=True)
    db().close()
    print(f"lab initialized at {LAB_ROOT}")
    print("  catalog:    ", DB_PATH)
    print("  store:      ", STORE, "(inert, sha256-keyed)")
    print("  quarantine: ", QUARANTINE, "(drop new samples here)")
    print("  yara rules: ", YARA_DIR)
    caps = {t: have(t) for t in ("yara", "ssdeep", "clamscan", "radare2", "zip", "file")}
    print("  detected tools:", ", ".join(k for k, v in caps.items() if v) or "none")
    missing = [k for k, v in caps.items() if not v]
    if missing:
        print("  (optional, not found:", ", ".join(missing) + ")")

def cmd_ingest(args):
    src = Path(args.file)
    if not src.is_file():
        die(f"not a file: {src}")
    conn = db()
    md5, sha1, sha256 = hashes(src)
    existing = conn.execute("SELECT id FROM samples WHERE sha256=?", (sha256,)).fetchone()
    if existing and not args.force:
        print(f"already catalogued as sample #{existing['id']} ({sha256[:12]})")
        conn.close(); return
    with open(src, "rb") as f:
        head = f.read(4096)
    data = src.read_bytes() if src.stat().st_size <= (8 << 20) else head
    ent = shannon_entropy(data)
    ss, tl = fuzzy_hashes(src)
    ftype = detect_filetype(src)
    plat = args.platform or guess_platform(ftype, head)
    stored = store_sample(src, sha256, encrypt=not args.no_encrypt)
    conn.execute("""
        INSERT OR REPLACE INTO samples
        (sha256, sha1, md5, ssdeep, tlsh, size, entropy, filetype, platform,
         orig_name, family, category, tlp, source, campaign, added_utc, stored_path)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (sha256, sha1, md5, ss, tl, src.stat().st_size, ent, ftype, plat,
          src.name, args.family, args.category, args.tlp, args.source,
          args.campaign, now_utc(), str(stored)))
    conn.commit()
    row = conn.execute("SELECT id FROM samples WHERE sha256=?", (sha256,)).fetchone()
    sid = row["id"]
    for tag in (args.tag or []):
        conn.execute("INSERT OR IGNORE INTO tags VALUES (?,?)", (sid, tag))
    conn.commit()
    print(f"ingested sample #{sid}")
    print(f"  sha256   {sha256}")
    print(f"  type     {ftype}  [{plat}]  {src.stat().st_size} bytes  entropy {ent}")
    if ss:  print(f"  ssdeep   {ss}")
    if tl:  print(f"  tlsh     {tl}")
    print(f"  stored   {stored}")
    if ent > 7.2:
        print("  note: high entropy -> likely packed/encrypted; consider unpacking before rule authoring")
    conn.close()

def cmd_triage(args):
    """Static triage of a stored sample. Reads the inert copy; never executes."""
    conn = db()
    s = get_sample(conn, args.ref)
    src = Path(s["stored_path"])
    # If zip-encrypted, extract to a temp inert copy for reading only.
    tmp = None
    if src.suffix == ".zip":
        tmp = QUARANTINE / f".triage_{s['sha256'][:12]}"
        with zipfile.ZipFile(src) as z:
            names = z.namelist()
            try:
                z.extractall(QUARANTINE / ".triage_extract", pwd=STORE_ZIP_PASSWORD)
                tmp = QUARANTINE / ".triage_extract" / names[0]
            except Exception:
                die("could not extract encrypted store copy for triage")
        read_path = tmp
    else:
        read_path = src
    data = read_path.read_bytes()
    print(f"=== triage sample #{s['id']}  {s['sha256'][:16]}  [{s['platform']}] ===")
    print(f"family={s['family']}  category={s['category']}  type={s['filetype']}")
    print(f"size={s['size']}  entropy={s['entropy']}")
    # printable strings (ascii + basic utf-16le)
    ascii_strings = re.findall(rb"[\x20-\x7e]{%d,}" % args.min_len, data)
    wide = re.findall((rb"(?:[\x20-\x7e]\x00){%d,}" % args.min_len), data)
    wide = [w.replace(b"\x00", b"") for w in wide]
    allstr = [s_.decode("latin-1") for s_ in (ascii_strings + wide)]
    # surface candidate IOCs
    joined = "\n".join(allstr)
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]{4,}", joined)))
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", joined)))
    domains = sorted(set(re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", joined, re.I)))
    domains = [d for d in domains if d not in ips][:40]
    print(f"\n-- strings: {len(allstr)} (min_len={args.min_len}) --")
    interesting = [x for x in allstr if len(x) >= args.min_len][:args.top]
    for x in interesting:
        print("   ", x[:120])
    if urls:
        print(f"\n-- candidate URLs ({len(urls)}) --")
        for u in urls[:20]: print("   ", u)
    if ips:
        print(f"\n-- candidate IPv4 ({len(ips)}) --")
        for i in ips[:20]: print("   ", i)
    if domains:
        print(f"\n-- candidate domains ({len(domains)}) --")
        for d in domains[:20]: print("   ", d)
    if have("radare2") and args.deep:
        print("\n-- r2 imports (aa; ii) --")
        try:
            out = subprocess.check_output(
                ["r2", "-2", "-q", "-c", "ii", str(read_path)],
                text=True, stderr=subprocess.DEVNULL, timeout=60)
            print(out[:2000])
        except Exception as e:
            print("   r2 failed:", e)
    if args.save_iocs:
        for u in urls: conn.execute("INSERT OR IGNORE INTO iocs (sample_id,itype,value) VALUES (?,?,?)", (s["id"], "url", u))
        for i in ips: conn.execute("INSERT OR IGNORE INTO iocs (sample_id,itype,value) VALUES (?,?,?)", (s["id"], "ipv4", i))
        conn.commit()
        print(f"\nsaved {len(urls)} url + {len(ips)} ipv4 IOCs to catalog")
    # cleanup temp
    if tmp and (QUARANTINE / ".triage_extract").exists():
        shutil.rmtree(QUARANTINE / ".triage_extract", ignore_errors=True)
    conn.close()

def cmd_show(args):
    conn = db()
    s = get_sample(conn, args.ref)
    d = dict(s)
    tags = [r["tag"] for r in conn.execute("SELECT tag FROM tags WHERE sample_id=?", (s["id"],))]
    att = conn.execute("SELECT technique,note FROM attack WHERE sample_id=?", (s["id"],)).fetchall()
    notes = conn.execute("SELECT ts_utc,phase,body FROM notes WHERE sample_id=? ORDER BY id", (s["id"],)).fetchall()
    iocs = conn.execute("SELECT itype,value FROM iocs WHERE sample_id=?", (s["id"],)).fetchall()
    if args.json:
        d["tags"] = tags
        d["attack"] = [dict(a) for a in att]
        d["iocs"] = [dict(i) for i in iocs]
        print(json.dumps(d, indent=2)); conn.close(); return
    print(f"# sample {s['id']}")
    for k in ("sha256","sha1","md5","ssdeep","tlsh","size","entropy","filetype",
              "platform","family","category","tlp","source","campaign","orig_name",
              "added_utc","stored_path"):
        if d.get(k) not in (None, ""):
            print(f"{k:11} {d[k]}")
    if tags: print("tags       ", ", ".join(tags))
    if att:
        print("att&ck     ", ", ".join(f"{a['technique']}" for a in att))
    if iocs:
        print(f"iocs        {len(iocs)}")
    if d.get("vt_score") is not None:
        print(f"vt_score    {d['vt_score']}  (checked {d.get('vt_checked','?')})")
    # Pull any VT findings tied to this sample (hash + its IOCs) from the shared DB.
    try:
        import intel
        finds = intel.findings_for_sample(INTEL_DB, conn, s)
        if finds:
            print("vt findings:")
            for f in finds:
                if f["not_found"]:
                    print(f"  {f['ioc']} ({f['kind']}): no VT record")
                else:
                    print(f"  {f['ioc']} ({f['kind']}): risk {f['risk_score']} "
                          f"({f['malicious']} mal/{f['suspicious']} susp)")
    except Exception:
        pass
    for n in notes:
        print(f"\n[{n['ts_utc']}] ({n['phase']})\n{n['body']}")
    conn.close()

def cmd_list(args):
    conn = db()
    q = "SELECT id,sha256,platform,category,family,entropy,tlp,vt_score,added_utc FROM samples WHERE 1=1"
    p = []
    if args.category: q += " AND category=?"; p.append(args.category)
    if args.family:   q += " AND family LIKE ?"; p.append(f"%{args.family}%")
    if args.platform: q += " AND platform=?"; p.append(args.platform)
    if args.tag:
        q += " AND id IN (SELECT sample_id FROM tags WHERE tag=?)"; p.append(args.tag)
    q += " ORDER BY id DESC"
    rows = conn.execute(q, p).fetchall()
    print(f"{'ID':>4}  {'SHA256':<16} {'PLAT':<7} {'CATEGORY':<12} {'FAMILY':<18} {'ENT':>5}  {'VT':>3}  {'TLP':<6} ADDED")
    for r in rows:
        vt = "" if r["vt_score"] is None else str(r["vt_score"])
        print(f"{r['id']:>4}  {r['sha256'][:16]} {r['platform'] or '-':<7} "
              f"{r['category'] or '-':<12} {(r['family'] or '-')[:18]:<18} "
              f"{r['entropy'] or 0:>5}  {vt:>3}  {r['tlp'] or '-':<6} {r['added_utc']}")
    print(f"\n{len(rows)} sample(s)")
    conn.close()

def cmd_tag(args):
    conn = db(); s = get_sample(conn, args.ref)
    for t in args.tags:
        conn.execute("INSERT OR IGNORE INTO tags VALUES (?,?)", (s["id"], t))
    conn.commit(); print(f"tagged #{s['id']}: {', '.join(args.tags)}"); conn.close()

def cmd_set(args):
    conn = db(); s = get_sample(conn, args.ref)
    field = args.field
    if field not in ("family","category","platform","tlp","source","campaign"):
        die(f"cannot set field '{field}'")
    conn.execute(f"UPDATE samples SET {field}=? WHERE id=?", (args.value, s["id"]))
    conn.commit(); print(f"#{s['id']} {field} = {args.value}"); conn.close()

def cmd_attack(args):
    conn = db(); s = get_sample(conn, args.ref)
    for t in args.techniques:
        if not re.match(r"^T\d{4}(\.\d{3})?$", t):
            print(f"warn: '{t}' is not a MITRE technique id (e.g. T1059.003)")
        conn.execute("INSERT OR IGNORE INTO attack (sample_id,technique) VALUES (?,?)", (s["id"], t))
    conn.commit(); print(f"#{s['id']} att&ck: {', '.join(args.techniques)}"); conn.close()

def cmd_note(args):
    conn = db(); s = get_sample(conn, args.ref)
    body = args.body
    if body == "-":
        body = sys.stdin.read()
    conn.execute("INSERT INTO notes (sample_id,ts_utc,phase,body) VALUES (?,?,?,?)",
                 (s["id"], now_utc(), args.phase, body))
    conn.commit(); print(f"note added to #{s['id']} (phase={args.phase})"); conn.close()

def cmd_yara_new(args):
    """Scaffold a structured YARA rule seeded from a sample's static strings.

    The metadata block is shaped to match what the Wazuh YARA integration and
    its LLM-enrichment path expect (description, author, reference, date), so
    rules drop straight into the pipeline.
    """
    conn = db(); s = get_sample(conn, args.ref)
    src = Path(s["stored_path"])
    # read inert copy
    if src.suffix == ".zip":
        with zipfile.ZipFile(src) as z:
            names = z.namelist()
            data = z.read(names[0], pwd=STORE_ZIP_PASSWORD)
    else:
        data = src.read_bytes()
    MAXLEN = 80  # cap emitted string length; long unique strings are brittle
    ascii_strings = re.findall(rb"[\x20-\x7e]{%d,}" % args.min_len, data)
    # score candidate strings: prefer medium-length, non-generic tokens
    generic = re.compile(rb"^(?:[A-Za-z]:\\|/lib|/usr|GCC|glibc|__|\.text|\.data)", re.I)
    interesting_re = re.compile(
        rb"(https?://|\.onion|cmd\.exe|/bin/sh|powershell|CreateRemoteThread|"
        rb"VirtualAlloc|WSAStartup|HKCU|HKLM|\.dll|\.exe|POST |GET )", re.I)
    scored, seen = [], set()
    for st in ascii_strings:
        st = st[:MAXLEN]                       # truncate rather than discard
        if st in seen:
            continue
        seen.add(st)
        L = len(st)
        if L < args.min_len:
            continue
        score = min(L, 40) - (20 if generic.match(st) else 0)
        if interesting_re.search(st):
            score += 30
        scored.append((score, st))
    scored.sort(key=lambda x: (-x[0], x[1]))
    picks = [st for _, st in scored[:args.count]]
    # Fallback: if filtering left nothing, take the longest raw strings so the
    # rule is always a valid, editable starting point.
    if not picks and ascii_strings:
        uniq = sorted({s_[:MAXLEN] for s_ in ascii_strings}, key=len, reverse=True)
        picks = uniq[:args.count]

    def esc(b: bytes) -> str:
        return b.decode("latin-1").replace("\\", "\\\\").replace('"', '\\"')

    rule_name = args.name or f"{(s['family'] or s['category'] or 'sample')}_{s['sha256'][:8]}"
    rule_name = re.sub(r"[^A-Za-z0-9_]", "_", rule_name)
    if rule_name[0].isdigit():
        rule_name = "r_" + rule_name

    lines = []
    lines.append(f"rule {rule_name}")
    lines.append("{")
    lines.append("    meta:")
    lines.append(f'        description = "Detects {s["family"] or s["category"] or "sample"} ({s["platform"]})"')
    lines.append(f'        author = "{args.author}"')
    lines.append(f'        date = "{today()}"')
    lines.append(f'        reference = "{args.reference or "internal analysis"}"')
    lines.append(f'        hash = "{s["sha256"]}"')
    if s["family"]:   lines.append(f'        malware_family = "{s["family"]}"')
    lines.append(f'        category = "{s["category"]}"')
    lines.append(f'        tlp = "{s["tlp"]}"')
    magic = {
        "pe": "uint16(0) == 0x5A4D",
        "elf": "uint32(0) == 0x464c457f",
        "macho": "uint32(0) == 0xfeedface or uint32(0) == 0xcffaedfe",
    }.get(s["platform"])
    n = len(picks)
    if n:
        lines.append("    strings:")
        for i, st in enumerate(picks, 1):
            # heuristic: emit wide+ascii for likely-PE, ascii otherwise
            mod = " ascii" + (" wide" if s["platform"] == "pe" else "")
            lines.append(f'        $s{i} = "{esc(st)}"{mod}')
        thresh = max(1, min(n, args.threshold))
        cond = f"{thresh} of ($s*)"
    else:
        # No usable printable strings (e.g. fully packed). Emit a compilable
        # skeleton keyed on file magic + a size window for the analyst to refine.
        lo = max(0, int(s["size"]) - int(s["size"]) // 5)
        hi = int(s["size"]) + int(s["size"]) // 5 + 1024
        cond = f"filesize > {lo} and filesize < {hi}  // TODO: no strings extracted; add bytes/imphash"
    lines.append("    condition:")
    lines.append(f"        {magic + ' and ' + cond if magic else cond}")
    lines.append("}")
    rule_text = "\n".join(lines) + "\n"

    out = YARA_DIR / f"{rule_name}.yar"
    YARA_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(rule_text)
    conn.execute("INSERT OR REPLACE INTO rules (name,sample_id,path,created_utc) VALUES (?,?,?,?)",
                 (rule_name, s["id"], str(out), now_utc()))
    conn.commit()
    print(rule_text)
    print(f"# wrote {out}")
    if have("yara"):
        r = subprocess.run(["yara", "-w", str(out), str(out)], capture_output=True, text=True)
        if r.returncode != 0 and r.stderr:
            print("compile check:", r.stderr.strip())
        else:
            print("compile check: OK")
    else:
        print("compile check: (yara not installed here; run `threat_meister yara-test`)")
    conn.close()

def cmd_yara_test(args):
    if not have("yara"):
        die("yara binary not found on PATH")
    rule = Path(args.rule)
    if not rule.exists():
        rule = YARA_DIR / (args.rule if args.rule.endswith(".yar") else args.rule + ".yar")
    if not rule.exists():
        die(f"rule not found: {args.rule}")
    # 1) compile
    c = subprocess.run(["yara", "-w", str(rule), str(rule)], capture_output=True, text=True)
    if c.returncode != 0:
        print("COMPILE FAILED:\n", c.stderr); return
    print(f"compile OK: {rule}")
    # 2) scan target (a sample ref, a path, or the whole store)
    if args.against:
        conn = db()
        try:
            s = get_sample(conn, args.against)
            target = Path(s["stored_path"])
            if target.suffix == ".zip":
                # extract inert copy for scan
                with zipfile.ZipFile(target) as z:
                    nm = z.namelist()[0]
                    tmp = QUARANTINE / f".scan_{s['sha256'][:12]}"
                    tmp.write_bytes(z.read(nm, pwd=STORE_ZIP_PASSWORD))
                    target = tmp
        except SystemExit:
            target = Path(args.against)
        finally:
            conn.close()
    else:
        target = STORE
    r = subprocess.run(["yara", "-w", "-r", str(rule), str(target)],
                       capture_output=True, text=True)
    print("--- matches ---")
    print(r.stdout.strip() or "(no matches)")
    if r.stderr.strip():
        print("stderr:", r.stderr.strip())
    # clean up any temp extraction used for scanning an encrypted store copy
    if args.against and str(target).startswith(str(QUARANTINE / ".scan_")):
        try: target.unlink()
        except OSError: pass

def cmd_yara_bundle(args):
    """Concatenate all lab rules into one deployable .yar for Wazuh."""
    rules = sorted(YARA_DIR.glob("*.yar"))
    if not rules:
        die("no rules in " + str(YARA_DIR))
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = EXPORT_DIR / "lab_rules.yar"
    with open(out, "w") as f:
        f.write(f"/* threat_meister rule bundle - generated {now_utc()} - {len(rules)} rules */\n\n")
        for r in rules:
            f.write(f"/* --- {r.name} --- */\n")
            f.write(r.read_text().rstrip() + "\n\n")
    if have("yara"):
        c = subprocess.run(["yara", "-w", str(out), str(out)], capture_output=True, text=True)
        status = "OK" if c.returncode == 0 else "FAILED:\n" + c.stderr
        print("bundle compile:", status)
    print(f"wrote {out} ({len(rules)} rules)")
    print(f"deploy: copy to the Wazuh agent path referenced in ossec.conf extra_args")

def cmd_clamsig(args):
    """Emit ClamAV custom signatures for cataloged samples.

    - .hdb : hash-based (MD5) exact-match signatures
    - .ndb : optional body-based signature from a hex fragment
    Load with: sudo cp lab.hdb /var/lib/clamav/ ; sudo systemctl reload clamav-daemon
    Verify:    sigtool --info lab.hdb  (or clamscan --database=lab.hdb ...)
    """
    conn = db()
    rows = conn.execute("SELECT md5,size,family,category,sha256 FROM samples").fetchall()
    if not rows:
        die("no samples catalogued")
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    hdb = EXPORT_DIR / "lab.hdb"
    with open(hdb, "w") as f:
        for r in rows:
            name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"Lab.{r['category']}.{r['family'] or r['sha256'][:8]}")
            # hdb format: md5:filesize:signature-name
            f.write(f"{r['md5']}:{r['size']}:{name}\n")
    print(f"wrote {hdb} ({len(rows)} hash signatures)")
    if have("sigtool"):
        v = subprocess.run(["sigtool", "--info", str(hdb)], capture_output=True, text=True)
        print(v.stdout.strip() or v.stderr.strip())
    print("load: sudo cp", hdb, "/var/lib/clamav/ && sudo systemctl reload clamav-daemon")
    conn.close()

def cmd_ioc_export(args):
    conn = db()
    rows = conn.execute("""
        SELECT s.sha256,s.family,s.category,i.itype,i.value
        FROM iocs i JOIN samples s ON s.id=i.sample_id
    """).fetchall()
    samples = conn.execute("SELECT sha256,md5,sha1,family,category FROM samples").fetchall()
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    if args.format == "csv":
        out = EXPORT_DIR / "iocs.csv"
        with open(out, "w") as f:
            f.write("type,value,family,category,sample_sha256\n")
            for s in samples:
                for h in ("sha256","md5","sha1"):
                    if s[h]:
                        f.write(f"{h},{s[h]},{s['family'] or ''},{s['category'] or ''},{s['sha256']}\n")
            for r in rows:
                f.write(f"{r['itype']},{r['value']},{r['family'] or ''},{r['category'] or ''},{r['sha256']}\n")
        print("wrote", out)
    else:  # stix-ish json lines
        out = EXPORT_DIR / "iocs.json"
        objs = []
        for s in samples:
            objs.append({"type":"file","hashes":{k:s[k] for k in ("md5","sha1","sha256") if s[k]},
                         "family":s["family"],"category":s["category"]})
        for r in rows:
            objs.append({"type":r["itype"],"value":r["value"],"family":r["family"],
                         "category":r["category"],"sample":r["sha256"]})
        out.write_text(json.dumps(objs, indent=2))
        print("wrote", out)
    conn.close()

def cmd_stats(args):
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM samples").fetchone()["c"]
    print(f"samples: {total}")
    print("\nby category:")
    for r in conn.execute("SELECT category,COUNT(*) c FROM samples GROUP BY category ORDER BY c DESC"):
        print(f"  {r['category'] or '(none)':<14} {r['c']}")
    print("\nby platform:")
    for r in conn.execute("SELECT platform,COUNT(*) c FROM samples GROUP BY platform ORDER BY c DESC"):
        print(f"  {r['platform'] or '(none)':<14} {r['c']}")
    nrules = conn.execute("SELECT COUNT(*) c FROM rules").fetchone()["c"]
    niocs = conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
    print(f"\nyara rules: {nrules}   iocs: {niocs}")
    conn.close()

# ----------------------------------------------------------------------------
# Threat-intel bridge (threathunt integration)
# ----------------------------------------------------------------------------

def _require_threathunt():
    try:
        import threathunt as th  # noqa: F401
        import intel             # noqa: F401
        return th, intel
    except Exception as e:
        die(f"threat-intel engine unavailable ({e}). "
            f"Ensure threathunt.py and intel.py sit beside threat_meister.py.")

def cmd_enrich(args):
    """Enrich cataloged samples (own hash + extracted IOCs) via VirusTotal,
    then reflect the risk score, a band tag, and a note back onto each sample."""
    th, intel = _require_threathunt()
    conn = db()
    if args.all:
        rows = conn.execute("SELECT * FROM samples ORDER BY id").fetchall()
    else:
        rows = [get_sample(conn, args.ref)]
    if not rows:
        die("no samples to enrich")
    # Resolve the key through threathunt's resolver so `enrich` honours the same
    # sources as `hunt`/`intel`: --api-key, $VT_API_KEY, --env-file, $VT_ENV_FILE,
    # ./.env, then ~/.secrets/bug_bounty.env.
    key = th.get_api_key(argparse.Namespace(
        api_key=args.api_key,
        env_file=getattr(args, "env_file", None)))
    if not key:
        die("no VirusTotal API key — set VT_API_KEY, pass --api-key, or add it "
            "to --env-file / ~/.secrets/bug_bounty.env")
    limiter = th.RateLimiter(args.rate)
    vt = th.VirusTotalClient(key, limiter, args.daily_cap)
    # Pass DB_PATH explicitly: intel.enrich_samples wires the reverse catalog
    # lookup from this path rather than reverse-engineering it from `conn`.
    summary = intel.enrich_samples(conn, INTEL_DB, rows, vt, args.cache_ttl, DB_PATH)
    print(f"enriched {summary['samples']} sample(s), {summary['iocs']} indicator(s); "
          f"{vt.calls_made} VT call(s)"
          + (f", {summary['overflow']} queued (cap reached)" if summary['overflow'] else ""))
    for sid, sha, score in summary["reflected"]:
        band = th.band(score)[0]
        print(f"  #{sid} {sha}  ->  vt_score {score} ({band})")
    conn.close()

def cmd_hunt(args):
    """Delegate to the threathunt hunt, catalog-aware, using the shared lab DB."""
    th, intel = _require_threathunt()
    th.LOCAL_CATALOG_LOOKUP = intel.make_catalog_lookup(DB_PATH)
    rest = list(args.rest)
    if "--db" not in rest:
        rest = ["--db", str(INTEL_DB)] + rest
    LAB_ROOT.mkdir(parents=True, exist_ok=True)
    sys.exit(th.main(["hunt", *rest]))

def cmd_intel(args):
    """Delegate to threathunt's ad-hoc `check`, catalog-aware."""
    th, intel = _require_threathunt()
    th.LOCAL_CATALOG_LOOKUP = intel.make_catalog_lookup(DB_PATH)
    rest = list(args.rest)
    if "--db" not in rest:
        rest = ["--db", str(INTEL_DB)] + rest
    LAB_ROOT.mkdir(parents=True, exist_ok=True)
    sys.exit(th.main(["check", *rest]))

# ----------------------------------------------------------------------------
# Argparse wiring
# ----------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="threat_meister", description="Malware analysis lab workflow tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create lab layout + catalog").set_defaults(func=cmd_init)

    def _cmd_banner(a):
        banner(sys.stdout)
    sub.add_parser("banner", help="print the application banner").set_defaults(func=_cmd_banner)

    g = sub.add_parser("ingest", help="catalog a sample (hashes, triage metadata, inert storage)")
    g.add_argument("file")
    g.add_argument("--family"); g.add_argument("--category", choices=CATEGORIES, default="unknown")
    g.add_argument("--platform", choices=PLATFORMS); g.add_argument("--source")
    g.add_argument("--campaign"); g.add_argument("--tlp", choices=TLP, default="amber")
    g.add_argument("--tag", action="append")
    g.add_argument("--no-encrypt", action="store_true", help="store read-only plaintext instead of zip-encrypted")
    g.add_argument("--force", action="store_true")
    g.set_defaults(func=cmd_ingest)

    g = sub.add_parser("triage", help="static triage: strings, entropy, candidate IOCs")
    g.add_argument("ref"); g.add_argument("--min-len", type=int, default=6)
    g.add_argument("--top", type=int, default=40); g.add_argument("--deep", action="store_true", help="use radare2 if present")
    g.add_argument("--save-iocs", action="store_true"); g.set_defaults(func=cmd_triage)

    g = sub.add_parser("show", help="show a sample record"); g.add_argument("ref")
    g.add_argument("--json", action="store_true"); g.set_defaults(func=cmd_show)

    g = sub.add_parser("list", help="list samples")
    for opt in ("category","family","platform","tag"): g.add_argument("--"+opt)
    g.set_defaults(func=cmd_list)

    g = sub.add_parser("tag"); g.add_argument("ref"); g.add_argument("tags", nargs="+"); g.set_defaults(func=cmd_tag)
    g = sub.add_parser("set", help="set family/category/platform/tlp/source/campaign")
    g.add_argument("ref"); g.add_argument("field"); g.add_argument("value"); g.set_defaults(func=cmd_set)
    g = sub.add_parser("attack", help="attach MITRE ATT&CK technique ids")
    g.add_argument("ref"); g.add_argument("techniques", nargs="+"); g.set_defaults(func=cmd_attack)
    g = sub.add_parser("note", help="attach an analyst note (body '-' reads stdin)")
    g.add_argument("ref"); g.add_argument("body")
    g.add_argument("--phase", default="analysis", choices=["intake","static","dynamic","analysis","reporting"])
    g.set_defaults(func=cmd_note)

    g = sub.add_parser("yara-new", help="scaffold a structured YARA rule from a sample")
    g.add_argument("ref"); g.add_argument("--name"); g.add_argument("--author", default=os.environ.get("USER","analyst"))
    g.add_argument("--reference"); g.add_argument("--count", type=int, default=8)
    g.add_argument("--min-len", type=int, default=8); g.add_argument("--threshold", type=int, default=4)
    g.set_defaults(func=cmd_yara_new)
    g = sub.add_parser("yara-test", help="compile a rule and scan a sample/store")
    g.add_argument("rule"); g.add_argument("--against", help="sample ref or path; default: whole store")
    g.set_defaults(func=cmd_yara_test)
    sub.add_parser("yara-bundle", help="concat all rules into exports/lab_rules.yar").set_defaults(func=cmd_yara_bundle)

    # --- threat-intel bridge (threathunt integration) ---
    g = sub.add_parser("enrich", help="VirusTotal-enrich a sample's hash + IOCs; reflect risk onto the catalog")
    g.add_argument("ref", nargs="?", help="sample id/hash (omit with --all)")
    g.add_argument("--all", action="store_true", help="enrich every catalogued sample")
    g.add_argument("--api-key"); g.add_argument("--env-file",
        help="read VT_API_KEY from this .env file (else ~/.secrets/bug_bounty.env)")
    g.add_argument("--rate", type=int, default=4)
    g.add_argument("--daily-cap", type=int, default=500)
    g.add_argument("--cache-ttl", type=int, default=168)
    g.set_defaults(func=cmd_enrich)
    g = sub.add_parser("hunt", help="run a threathunt hunt over Wazuh/Rita/UniFi exports (catalog-aware)")
    g.add_argument("rest", nargs=argparse.REMAINDER, help="args passed through to threathunt hunt")
    g.set_defaults(func=cmd_hunt)
    g = sub.add_parser("intel", help="ad-hoc VirusTotal check of one or more indicators (catalog-aware)")
    g.add_argument("rest", nargs=argparse.REMAINDER, help="indicators + threathunt check args")
    g.set_defaults(func=cmd_intel)

    g = sub.add_parser("clamsig", help="export ClamAV .hdb hash signatures"); g.set_defaults(func=cmd_clamsig)
    g = sub.add_parser("ioc-export", help="export IOCs (csv|json)")
    g.add_argument("--format", choices=["csv","json"], default="csv"); g.set_defaults(func=cmd_ioc_export)
    sub.add_parser("stats", help="catalog summary").set_defaults(func=cmd_stats)
    return p

def _delegate(kind, rest):
    """Pass-through to threathunt for `hunt`/`intel`, catalog-aware.

    Done before argparse so leading options (e.g. `hunt --min-score 50`) are
    forwarded verbatim instead of being rejected by threat_meister's own parser.
    """
    th, intel = _require_threathunt()
    th.LOCAL_CATALOG_LOOKUP = intel.make_catalog_lookup(DB_PATH)
    rest = list(rest)
    if "--db" not in rest:
        rest = ["--db", str(INTEL_DB)] + rest
    LAB_ROOT.mkdir(parents=True, exist_ok=True)
    subcmd = "hunt" if kind == "hunt" else "check"
    return th.main([subcmd, *rest])

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # No subcommand: show the banner and a usage hint instead of an argparse error.
    if not argv:
        banner()
        build_parser().print_help(sys.stderr)
        return
    # hunt/intel are thin pass-throughs to the threathunt engine.
    if argv and argv[0] in ("hunt", "intel"):
        raise SystemExit(_delegate(argv[0], argv[1:]))
    args = build_parser().parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
