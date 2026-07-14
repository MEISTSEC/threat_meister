# Threat Meister — malware analysis lab workflow

```
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
         T H R E A T   M E I S T E R
```

An operational workflow for a single-analyst malware lab: catalog samples, run
static triage, capture observations, author and test structured YARA rules, push
detections into Wazuh (FIM + Active Response) alongside ClamAV and rkhunter, and
enrich everything with VirusTotal threat intelligence via the integrated
`threathunt` engine. Built for PMAP coursework and as a portfolio piece
demonstrating detection engineering end to end.

The command is `threat_meister`, with a `tm` short alias installed alongside
it; `threat_meister banner` prints the logo above, which also appears on
`init` and when the tool is run with no arguments. The vendored `threathunt`
engine remains runnable on its own as `threathunt`.

The design principle throughout: **the SQLite catalog is the single source of
truth, samples are stored inert, and every detection artifact (YARA rule,
ClamAV signature, IOC export) is generated *from* the catalog** so nothing drifts
out of sync.

In a hurry? See `docs/quickstart.txt` for the end-to-end command sequence.

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/meistsec)

## Installation

**Get the code.** Clone the repo (or use GitHub's "Download ZIP" and extract it):

```bash
git clone https://github.com/MEISTSEC/threat_meister.git
cd threat_meister
```

**Install (Arch Linux).** Review `setup_lab.sh` first — it uses `sudo`, installs
packages, and enables services — then run it from the repo root:

```bash
less setup_lab.sh          # read before running anything with sudo
./setup_lab.sh
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc to persist
```

It installs the toolchain, copies the three modules into
`~/.local/lib/threat_meister/`, symlinks `threat_meister` / `tm` / `threathunt`
into `~/.local/bin`, initializes the lab under `$THREAT_MEISTER_ROOT` (default
`~/threat_meister`), and runs a smoke test that fails loudly if anything is out
of sync.

**Other distros / manual install.** `setup_lab.sh` is Arch-specific (pacman/AUR),
but the tool itself is stdlib-only Python 3. On other systems, install the
optional binaries your package manager provides (`yara`, `clamav`, `rkhunter`,
`radare2`, `ssdeep`, `jq`) and place the three `src/*.py` files **together** in
one directory on your `PATH` — they import each other as siblings:

```bash
install -d ~/.local/lib/threat_meister ~/.local/bin
install -m644 src/threathunt.py src/intel.py ~/.local/lib/threat_meister/
install -m755 src/threat_meister.py ~/.local/lib/threat_meister/
printf '#!/bin/sh\nexec python3 "%s/threat_meister.py" "$@"\n' \
  "$HOME/.local/lib/threat_meister" > ~/.local/bin/threat_meister
chmod 755 ~/.local/bin/threat_meister
threat_meister init
```

**Configure your VirusTotal key.** Put it wherever the resolver looks (see the
threat-intel section); the zero-flag default is `~/.secrets/bug_bounty.env`:

```bash
mkdir -p ~/.secrets && chmod 700 ~/.secrets
echo 'export VT_API_KEY="your_key"' > ~/.secrets/bug_bounty.env
chmod 600 ~/.secrets/bug_bounty.env
```

**Deploy the Wazuh pieces** per "Wazuh wiring" below (manager and agent are
separate hosts).

## Architecture and data flow

```
   analyst / coursework
           │  drops sample
           ▼
   ┌──────────────┐   ingest    ┌───────────────┐   author/test   ┌───────────┐
   │  quarantine  │────────────▶│  catalog.db    │────────────────▶│ yara/rules│
   │  (incoming)  │  hash+triage │ (SQLite: the   │  yara-new/test  │  (.yar)   │
   └──────────────┘             │  source of     │                 └─────┬─────┘
           │                    │  truth)        │                       │ bundle
           │ inert store        └───────┬────────┘                       ▼
           ▼                            │  exports              exports/lab_rules.yar
   store/<sha256> (0400 /              │  clamsig / ioc-export         │ deploy (scp)
   zip-encrypted)                      ▼                               ▼
                             lab.hdb (ClamAV) , iocs.csv/json   Wazuh agent AR path
                                                                        │
   dropzone (FIM realtime) ── file event ──▶ Active Response ── yara.sh ▶ match
                                                                        │
                                                    active-responses.log│
                                                                        ▼
                                              Wazuh manager: decoder → rule 108001
                                                                        ▼
                                                     Wazuh dashboard (Threat Hunting)
```

A third surface — **threat intelligence** — closes the loop around the catalog:

```
   catalog.db (samples + extracted IOCs)
        │  threat_meister enrich
        ▼
   threathunt engine ── VirusTotal v3 ──▶ reputation + risk score (0–100)
        │  reflect-back                         ▲
        ▼                                        │ catalog cross-reference
   sample.vt_score, vt:<band> tag, note   ◀──────┘ (hunt hits a known sample →
                                                    "matches lab sample family=X")
        ▲
        │  threat_meister hunt  (Wazuh / Rita / UniFi exports)
   findings.db (shared threathunt store, under the same lab root)
```

The bridge is bidirectional: a sample's hash and its extracted C2 IOCs flow *out*
to VirusTotal for scoring, and the resulting risk flows *back* onto the sample
record; meanwhile a hunt over network/SIEM exports that turns up a hash or host
already in your catalog is recognized as known lab infrastructure and scored
higher accordingly. Both directions reuse one implementation of rate limiting,
caching, scoring, and the resume queue — `threathunt` — which also still runs
standalone.

Two independent detection surfaces feed the SIEM:

- **On-demand / research surface** — you analyze a sample, build a YARA rule,
  and add its hash to a ClamAV signature set. These are *authored* artifacts.
- **Runtime surface** — the dropzone is watched by Wazuh FIM in realtime; any
  file written there is scanned by your bundled YARA rules via Active Response,
  and ClamAV/rkhunter results are collected as logs. These are *triggered*
  events that land as dashboard alerts.

## The threat_meister CLI

Install puts it at `~/.local/bin/threat_meister`. The lab lives under `$THREAT_MEISTER_ROOT`
(default `~/threat_meister`): `catalog.db`, `store/`, `quarantine/`, `yara/rules/`,
`exports/`.

Core commands:

- `threat_meister init` — create the layout and catalog; reports which optional tools
  (yara, ssdeep, radare2, clamscan) were detected.
- `threat_meister ingest <file> --family <f> --category <c> --platform <p>` — compute
  MD5/SHA1/SHA256 + ssdeep/TLSH fuzzy hashes, Shannon entropy, and file type;
  store the sample inert (renamed to its SHA-256, `0400`, or zip-encrypted with
  the standard `infected` password); record everything. High-entropy samples are
  flagged as likely packed.
- `threat_meister triage <ref> [--save-iocs] [--deep]` — extract ASCII + UTF-16LE
  strings, surface candidate URLs / IPv4 / domains, optionally run radare2
  imports, and persist IOCs. Never executes the sample.
- `threat_meister show <ref> [--json]`, `threat_meister list [--category …]`, `threat_meister stats` —
  query the catalog. `<ref>` is an id, full SHA-256, or unambiguous prefix.
- `threat_meister set <ref> family <name>`, `threat_meister tag`, `threat_meister attack <ref> T1486 …`,
  `threat_meister note <ref> "…" --phase static` — enrich records as analysis proceeds.
- `threat_meister yara-new <ref>` — scaffold a structured rule seeded from the sample's
  strongest strings, with a metadata block (`description`, `author`, `date`,
  `reference`, `hash`, `malware_family`, `category`, `tlp`) shaped to match what
  the Wazuh YARA integration expects. It compiles the result immediately.
- `threat_meister yara-test <rule> [--against <ref>]` — compile a rule and scan a sample
  or the whole store, so you can check true positives and hunt for
  false positives across your corpus *before* deploying.
- `threat_meister yara-bundle` — concatenate every lab rule into one compilable
  `exports/lab_rules.yar` (Wazuh's `yara.sh` takes a single `.yar` file).
- `threat_meister clamsig` — emit `lab.hdb` (MD5:size:name) hash signatures for ClamAV.
- `threat_meister ioc-export --format csv|json` — export hashes + network IOCs.

Threat-intel commands (the `threathunt` bridge):

- `threat_meister enrich <ref> | --all` — send a sample's own hash plus its extracted
  IOCs to VirusTotal, score each, and reflect the top risk back onto the sample
  as `vt_score`, a `vt:<band>` tag, and a breakdown note. `show` and `list` then
  display the score, so one view gives static triage *and* reputation.
- `threat_meister hunt [threathunt args]` — run a full hunt over Wazuh/Rita/UniFi
  exports (`--wazuh`, `--rita`, `--unifi`, `--report hunt.md`, `--min-score N`).
  Catalog-aware: indicators matching a known sample get annotated and up-scored.
  Alert sources on another host are pulled in over SSH (see below).
- `threat_meister intel <ioc…>` — ad-hoc VirusTotal check of IPs/domains/hashes, also
  catalog-aware.

These need a VirusTotal API key. It is resolved in this order, first match wins:
`--api-key`, then `$VT_API_KEY`, then a `.env`-style file — `--env-file <path>`,
`$VT_ENV_FILE`, `./.env`, and finally `~/.secrets/bug_bounty.env`. That last
default lets you keep the key in your existing secrets file, out of shell history
and the process environment; the file may use `export VT_API_KEY=…`, quotes, and
`#` comments. They share one SQLite store (`threathunt.db`) under the lab root,
and respect the VT free-tier limits (4/min, 500/day) with a resume queue for
overflow. `threathunt.py` remains runnable on its own — the threat_meister integration
is a set of default-off hooks that only activate when threat_meister drives it.

The tool is stdlib-only; optional libraries/binaries are auto-detected and it
degrades gracefully when they're absent.

## Threat hunting: sources, scale, and remote Wazuh

`threat_meister hunt` (and the standalone `threathunt hunt`) enriches indicators
of compromise pulled from your existing stack, scores each 0–100 by combining
VirusTotal reputation with local behavioural signals, and writes a report plus a
persistent findings history.

**Sources.** Pass any combination; indicators are de-duplicated across them, so a
host seen by several sources is enriched once and tagged with all of them:

- `--wazuh <alerts.json>` — Wazuh alerts (NDJSON or a JSON array). IOCs are drawn
  from `data.srcip`/`dstip`, `data.url`, and `syscheck` file hashes, with the
  rule level attached as behavioural context.
- `--rita <export.csv>` — a Rita CSV export; beacon score, connection count, and
  bytes become behavioural context (columns auto-detected across Rita versions).
- `--unifi <threats.csv>` — a UniFi CyberSecure threat CSV exported from the UI;
  severity and signature become context (columns auto-detected across firmware).

**Remote Wazuh manager (SSH pull).** When the manager runs on another box — the
usual setup, with agents forwarding to a central manager that writes one
`alerts.json` — point the hunt at the remote file and it is streamed down over
SSH before parsing. It shells out to the system `ssh`, so it uses your existing
keys, agent, `~/.ssh/config` aliases, and `known_hosts`; no new dependency, no
keys stored in the tool.

```bash
threat_meister hunt \
    --wazuh-ssh admin@wazuh:/var/ossec/logs/alerts/alerts.json --wazuh-sudo \
    --rita beacons.csv --unifi threats.csv \
    --report hunt-$(date +%F).md --min-score 40
```

The alerts file is owned `wazuh:wazuh` (mode 660), so a normal SSH user can't
read it: either add your user to the `wazuh` group on the manager, or pass
`--wazuh-sudo` (which runs `sudo -n cat` remotely; for an unattended run, grant
NOPASSWD sudo for that one `cat`). Extra SSH options pass through with
`--ssh-opt "-p 2222 -i ~/.ssh/hunt_key"`, and `--rita-ssh` does the same for a
Rita export on another host. `--wazuh` and `--wazuh-ssh` are mutually exclusive.

> Note: `alerts.json` holds the current day; older days rotate into
> `/var/ossec/logs/alerts/<year>/<month>/`. For a true month-wide hunt,
> concatenate the rotated files on the manager before fetching, or query the
> Wazuh indexer API.

**Large hunts and the free tier.** The VT free key allows ~500 lookups/day. When
a hunt has more new indicators than that, nothing is silently dropped: indicators
are triaged by a local-signal priority *before* any quota is spent (multi-source
agreement, Wazuh severity, Rita beacon strength, UniFi severity, traffic volume),
enrichment runs highest-priority first, and the overflow is saved to a resume
queue. The next run drains that queue first, so a 1,500-indicator hunt spreads
over a few days with the scariest indicators checked on day one. Cache hits never
count against the cap, so month-over-month repeats are free. Check the backlog
with `threathunt queue`.

**Reports.** `--report <file>` writes `.json`, `.csv`, or `.md`. The Markdown
report leads with a band-count summary and a findings table (highest risk first),
then per-band detail sections (Critical → Elevated → Watch) that show each
indicator's VT verdict, the scoring rationale, and the Wazuh/Rita/UniFi context
that justified it — ready to drop into a ticket or writeup.

## Daily workflow (SOP)

1. **Intake.** Move a sample into `quarantine/`. Ingest it with your initial
   triage classification:
   `threat_meister ingest quarantine/sample.bin --family agenttesla --category infostealer --platform pe --source coursework --tag pmap`
2. **Static triage.** `threat_meister triage <id> --save-iocs --deep`. Read strings and
   imports; note the packer if entropy is high (confirm with `detect-it-easy`).
3. **Record findings as you go.** `threat_meister attack <id> T1055 T1071.001`,
   `threat_meister note <id> "PE, UPX-packed, HTTP beacon to <domain>, persistence via Run key" --phase static`.
4. **Author detection.** `threat_meister yara-new <id> --author "$USER" --reference "PMAP module N"`.
   Open the `.yar`, prune weak/generic strings, tighten the condition.
5. **Validate.** `threat_meister yara-test <rule> --against <id>` (must match), then
   `threat_meister yara-test <rule>` (scan the whole store, watch for unwanted matches).
6. **Enrich.** `threat_meister enrich <id>` — VirusTotal-score the sample's hash and its
   C2 IOCs; the sample gets a `vt_score` and a `vt:<band>` tag. Re-run
   `threat_meister show <id>` to see static + reputation together.
7. **Deploy.** `threat_meister yara-bundle`, then scp `exports/lab_rules.yar` to the
   agent (see below). Optionally `threat_meister clamsig` and load the hash set.
8. **Verify the pipeline.** Drop a matching test file into the dropzone; confirm
   an alert appears in the Wazuh dashboard.
9. **Periodic hunt.** `threat_meister hunt --wazuh alerts.json --rita beacons.csv
   --report hunt-$(date +%F).md` — any indicator that ties back to a catalogued
   sample is flagged as known lab infrastructure in the report. If the manager is
   remote, use `--wazuh-ssh` as shown above.

## Install (Arch)

`setup_lab.sh` installs, from the official repos: `yara`, `clamav`, `rkhunter`,
`jq`, `radare2`, `binutils`, `file`, `ssdeep`, `lynis`. From the
AUR (via yay/paru): `capa` (ATT&CK capabilities), `detect-it-easy` (packer ID),
`pev` (PE toolkit), `python-tlsh`, `chkrootkit` (second-opinion rootkit scanner),
and `wazuh-agent`. It removes the `Example`
line from the ClamAV configs, enables `clamav-freshclam` + `clamav-daemon`,
baselines rkhunter (`--propupd`) and adds a weekly scan timer, creates the
`/opt/threat_meister/dropzone`, installs the three modules
(`threathunt.py`, `intel.py`, `threat_meister.py`) side by side into
`~/.local/lib/threat_meister/`, and initializes the catalog.

After install it runs a **post-install smoke test**: it confirms the three
modules import together, that their wiring is consistent (the reconciled
`threathunt` exposes both the SSH pull and the catalog hook; `intel.enrich_samples`
takes the `catalog_db` argument that `threat_meister` passes), and that both the
`threat_meister` and standalone `threathunt` entry points respond. If anything
has drifted out of sync it fails loudly at install time rather than mid-hunt.

Review the script before running it — it uses `sudo` and touches system services.

Note: on Arch the YARA binary is `/usr/bin/yara`, so the manager's
`extra_args` uses `-yara_path /usr/bin` (the Wazuh docs use `/usr/local/bin`
because they compile from source on Ubuntu).

### Layout and staying in sync

The three modules are siblings in `src/`; `threat_meister.py` adds its own
directory to `sys.path` and imports `threathunt` and `intel` as siblings. There
is exactly one `src/threathunt.py` — the canonical engine — and it is the same
file that runs standalone. Keep it that way: don't hand-copy `threathunt.py`
elsewhere in the tree, so the standalone and the vendored engine can never
diverge. The install smoke test is the backstop that catches it if they do.

## Wazuh wiring

The `wazuh/` directory ships everything needed to wire the pipeline:

- `local_decoder.xml` — decodes the `wazuh-yara: … Scan result: <rule> <file>`
  lines into the `yara_rule` / `yara_scanned_file` fields (manager).
- `local_rules.xml` — FIM rules `100200`/`100201` (dropzone modified/added), the
  actionable match rule `108001` (level 12), and the ransomware/wiper elevation
  `108010` (level 14) that pivots on the family encoded in the rule name (manager).
- `ossec_manager_snippet.conf` — the `yara_linux` command + active-response
  binding that runs `yara.sh` on `100200,100201` (manager).
- `ossec_agent_snippet.conf` — realtime FIM on the dropzone, ClamAV + rkhunter
  log collection, and the rkhunter command wodle (agent).
- `yara.sh` — the active-response script itself (agent).

The split is: decoders + rules + AR binding live on the **manager**; FIM + log
collection live on the **agent** (your analysis host).

On the **manager**:
1. Append `wazuh/local_decoder.xml` to `/var/ossec/etc/decoders/local_decoder.xml`.
2. Append `wazuh/local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`.
3. Merge `wazuh/ossec_manager_snippet.conf` into `/var/ossec/etc/ossec.conf`.
4. `sudo systemctl restart wazuh-manager`.

On the **agent**:
1. Install the AR script:
   `sudo cp wazuh/yara.sh /var/ossec/active-response/bin/yara.sh`
   `sudo chown root:wazuh /var/ossec/active-response/bin/yara.sh`
   `sudo chmod 750 /var/ossec/active-response/bin/yara.sh`
2. Deploy your rule bundle:
   `sudo install -Dm750 -o root -g wazuh exports/lab_rules.yar /var/ossec/active-response/bin/yara/rules/lab_rules.yar`
3. Merge `wazuh/ossec_agent_snippet.conf` into `/var/ossec/etc/ossec.conf`.
4. `sudo systemctl restart wazuh-agent`.

How it fires: FIM detects a create/modify in `/opt/threat_meister/dropzone` → rules
`100201`/`100200` → Active Response runs `yara.sh` against the changed file →
matches are written to `active-responses.log` as
`wazuh-yara: INFO - Scan result: <rule> <file>` → the manager decodes them
(`yara_decoder`) → rule `108001` raises a level-12 alert (level 14 for
ransomware/wiper rule names via `108010`).

ClamAV daemon/freshclam logs and rkhunter warnings are collected via the
`<localfile>` blocks and the rkhunter command wodle in the agent snippet, so
they show up alongside YARA alerts.

Note on hosts: the agent snippet and the dropzone belong on your **analysis
host**. The `threat_meister hunt` step reads the manager's `alerts.json`, which
lives on the **manager** — pull it over SSH with `--wazuh-ssh` when that's a
different box.

## Dashboards and alerts

In the Wazuh dashboard, **Threat Hunting → Events**, filter `rule.groups` *is*
`yara` to see matches, or `rule.groups` *is* `threat_meister` for the whole pipeline.
Useful saved visualizations for a portfolio dashboard:

- YARA matches over time, split by `data.yara_rule` (which encodes the family).
- Top matched rules / families (data table on `data.yara_rule`).
- FIM dropzone activity (`rule.id` 100200/100201) as a leading indicator.
- ClamAV detections (built-in clamd rules) and rkhunter warnings on the same
  board, so one screen shows all three engines.

To alert externally, bind an email/webhook Active Response or an `<integration>`
to rule ids `108001`/`108010`.

## Safety notes

- Nothing in `threat_meister` executes samples; it is static-only. Dynamic detonation,
  if you do it, belongs in your existing isolated VM, not on the host running
  the agent.
- The dropzone is a **detection-test** surface, not sample storage. Keep the
  real corpus in the inert `store/`. Don't point network-exposed services at
  either.
- Samples are stored renamed-to-hash and either `0400` or zip-encrypted with the
  conventional `infected` password to prevent accidental execution and to keep
  on-host AV from quarantining your own corpus.
- Treat the ClamAV hash `.hdb` and YARA bundle as artifacts you regenerate from
  the catalog — edit the catalog, re-export, redeploy; don't hand-edit deployed
  files.
- The hunt is read-only on your sources: it never modifies Wazuh, Rita, or UniFi
  data, and private / loopback / link-local IPs are filtered out before any
  lookup, so internal addressing is never sent to VirusTotal.

## Supporting the project

Threat Meister is free and MIT-licensed. If it's useful to you and you'd like to
support it, see [`DONATE.md`](DONATE.md) — via GitHub Sponsors, Buy Me a Coffee,
or Bitcoin (the address there is signed, so you can verify it hasn't been tampered
with before sending anything).

## License

Released under the MIT License — Copyright (c) 2026 meistsec. See `LICENSE`.

Threat Meister orchestrates several GPL-licensed tools (ClamAV, YARA, rkhunter,
Wazuh) as external processes and generates configuration for them; it does not
link or incorporate their source, so their copyleft does not extend to this
project. Each source module carries an `SPDX-License-Identifier: MIT` header.
