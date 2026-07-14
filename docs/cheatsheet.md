# Threat Meister — command cheatsheet

Quick reference for day-to-day use. Commands use the `tm` alias (installed
alongside `threat_meister`); if you run from a clone instead, substitute
`python3 src/threat_meister.py` for `tm`.

## The three you'll reach for most

```bash
tm intel 185.220.101.45          # "is this indicator bad?" — the fastest question
tm queue                         # indicators still waiting from a capped hunt
journalctl --user -u threat-hunt.service --since "1 month ago"   # did the auto-run work?
```

## Ad-hoc threat intel

```bash
tm intel 185.220.101.45                 # one IP / domain / hash (catalog-aware)
tm intel evil.example <sha256>          # several at once
```

Key resolution order for VirusTotal: `--api-key` → `$VT_API_KEY` →
`--env-file` / `$VT_ENV_FILE` → `./.env` → `~/.secrets/bug_bounty.env`.
If a run reports "no API key", that last file is where to look.

## Monthly hunt (manual run)

```bash
# local alerts file
tm hunt --wazuh alerts.json --rita beacons.csv --unifi threats.csv \
        --report ~/threat_meister/reports/hunt-$(date +%F).md --min-score 40

# remote Wazuh manager over SSH (agents forward to one central alerts.json)
tm hunt --wazuh-ssh user@manager:/var/ossec/logs/alerts/alerts.json \
        --report ~/threat_meister/reports/hunt-$(date +%F).md --min-score 40
```

Useful flags:

- `--wazuh-sudo` — read the alerts file via `sudo -n cat` (only if the SSH user
  isn't in the `wazuh` group).
- `--ssh-opt "-p 2222 -i ~/.ssh/key"` — extra options passed straight to ssh.
- `--daily-cap N` — stop after N VT calls (default 500; the rest queue).
- `--min-score N` — only *print* findings at/above N (everything is still stored).
- `--report <file>` — `.md`, `.json`, or `.csv`; parent dirs are created if missing.

Reports go to `~/threat_meister/reports/`, **not** the repo — they contain your
network's indicators and should never be committed.

## Review past results (no API calls)

```bash
tm queue                                # what's waiting from a capped run
tm history --min-score 40 --since 2026-06-01   # past findings from the store
```

## Sample catalog + triage

```bash
tm ingest sample.bin --family <fam> --category <cat> --platform <pe|elf|script>
tm triage <id> --save-iocs --deep       # strings, entropy, IOCs (--deep = radare2)
tm show <id>                            # full record, incl. vt_score if enriched
tm show <id> --json                     # machine-readable
tm list --category ransomware           # filter (also --family, --platform, --tag)
tm stats                                # catalog summary
tm set <id> family <name>               # correct a field
tm tag <id> pmap wip                    # add tags
tm attack <id> T1055 T1071.001          # attach MITRE ATT&CK techniques
tm note <id> "observations" --phase static
```

## Enrichment (catalog ↔ VirusTotal bridge)

```bash
tm enrich <id>                          # VT-score this sample's hash + its IOCs
tm enrich --all                         # every catalogued sample
```

Enrichment reflects the top risk back onto the sample as `vt_score`, a
`vt:<band>` tag, and a note — visible afterward in `tm show` / `tm list`.

## Detection engineering

```bash
tm yara-new <id> --author "$USER" --reference "source"   # scaffold a rule
tm yara-test <rulename> --against <id>  # must match its own sample
tm yara-test <rulename>                 # scan the whole store for false positives
tm yara-bundle                          # combine all rules -> exports/lab_rules.yar
tm clamsig                              # export ClamAV .hdb hash signatures
tm ioc-export --format csv              # dump hashes + network IOCs (csv|json)
```

## Standalone engine

`threathunt` runs on its own (same engine, no catalog awareness). Point it at
the lab's shared store with `--db` if you want it to see the same history:

```bash
threathunt check 1.1.1.1 evil.example <sha256>
threathunt hunt --wazuh alerts.json --report hunt.md
threathunt queue --db ~/threat_meister/threathunt.db
```

## Automation (systemd user timer)

Arch uses systemd timers rather than cron.

```bash
systemctl --user list-timers threat-hunt.timer          # next scheduled run
systemctl --user start threat-hunt.service              # run now
systemctl --user status threat-hunt.timer               # is it active
journalctl --user -u threat-hunt.service -f             # follow a live run
journalctl --user -u threat-hunt.service --since "1 month ago"
loginctl enable-linger $USER                            # run even when logged out
```

## Things worth remembering

- **Cache is 7 days.** Re-running a hunt within a week costs 0 API calls — that's
  why re-rendering a report or re-running after a crash is free.
- **Rate limit, not quota, is the real constraint.** 4 lookups/min on the free
  tier, so ~500 indicators takes about two hours of wall-clock. A slow run is
  normal, not a hang.
- **Private IPs never leave your network.** RFC1918 / loopback / link-local
  addresses are filtered before any VirusTotal lookup.
- **The catalog is the source of truth.** YARA bundles, ClamAV sigs, and IOC
  exports are all regenerated from it — edit the catalog and re-export rather
  than hand-editing deployed artifacts.
