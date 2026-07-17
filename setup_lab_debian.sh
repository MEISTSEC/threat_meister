#!/usr/bin/env bash
# threat_meister - Debian / Ubuntu / Pop!_OS lab bootstrap
# Installs the analysis/detection toolchain, deploys the threat_meister CLI, and
# prepares directories + services. Review before running; do not run blind.
#
# This is the Debian-family counterpart to setup_lab.sh (which targets Arch).
# It uses apt instead of pacman, pulls a few triage tools from pip since they
# aren't in the default repos, and uses Debian's ClamAV service names.
set -euo pipefail

THREAT_MEISTER_ROOT="${THREAT_MEISTER_ROOT:-$HOME/threat_meister}"
DROPZONE="/opt/threat_meister/dropzone"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# --- 0. Sanity: this is the Debian-family script ----------------------------
if ! command -v apt-get >/dev/null 2>&1; then
  warn "apt-get not found — this script targets Debian/Ubuntu/Pop!_OS."
  warn "On Arch, use setup_lab.sh instead."
  exit 1
fi

# --- 1. APT packages --------------------------------------------------------
# Debian/Ubuntu package names differ from Arch. Notable mappings:
#   binutils/file -> same; ssdeep -> ssdeep; radare2 -> radare2 (universe);
#   detect-it-easy / capa / pev are NOT in the default repos (handled below).
APT_PKGS=(
  yara            # rule engine + libyara
  clamav          # AV engine
  clamav-daemon   # clamd (Debian splits this out from the base package)
  clamav-freshclam  # signature updater (also a separate package on Debian)
  rkhunter        # rootkit hunter
  chkrootkit      # second-opinion rootkit scanner (IN Debian repos, unlike Arch)
  jq              # JSON parsing for the Wazuh AR script
  radare2         # static RE / disassembly (may require 'universe' on Ubuntu)
  binutils        # objdump/readelf/nm
  file            # libmagic 'file'
  ssdeep          # fuzzy hashing (CTPH)
  python3         # for the threat_meister CLI
  python3-pip     # to install tlsh (and optionally capa) from PyPI
  unzip zip       # sample store handling
  lynis           # host audit / hardening baseline
)
say "Updating apt and installing packages: ${APT_PKGS[*]}"
sudo apt-get update -y || warn "apt-get update had issues; continuing"
# Don't let one unavailable/renamed package abort the whole bootstrap (set -e).
sudo apt-get install -y --no-install-recommends "${APT_PKGS[@]}" \
  || warn "some apt packages failed to install; review the output above. On Ubuntu/Pop!_OS you may need: sudo add-apt-repository universe"

# --- 2. Python-based triage helpers (pip) -----------------------------------
# TLSH has no reliable Debian package under a consistent name; install the
# binding from PyPI so `import tlsh` works in triage. capa is optional and large;
# offered but not forced. Uses --user so nothing touches system site-packages.
say "Installing Python triage helpers (tlsh; capa optional)"
# PEP 668: modern Debian marks the system Python 'externally managed', so pip
# into --user needs --break-system-packages, or better, a pipx/venv. We try the
# gentle path first and fall back with a clear note.
if pip3 install --user python-tlsh >/dev/null 2>&1 \
   || pip3 install --user --break-system-packages python-tlsh >/dev/null 2>&1; then
  say "  tlsh installed"
else
  warn "  could not install python-tlsh via pip; TLSH fuzzy hashing will be skipped (non-fatal)"
fi
# capa is a heavier optional dependency; install only if you want ATT&CK
# capability detection. Uncomment to enable:
#   pip3 install --user --break-system-packages flare-capa || warn "capa install failed"

# --- 2b. Tools NOT in Debian repos ------------------------------------------
# detect-it-easy (DIE), capa, and pev are AUR packages on Arch with no direct
# Debian equivalent. They're optional triage sharpeners; the tool degrades
# gracefully without them. Point the user at manual installs rather than
# silently omitting them.
MISSING_OPTIONAL=()
command -v die     >/dev/null 2>&1 || command -v diec >/dev/null 2>&1 || MISSING_OPTIONAL+=("detect-it-easy (https://github.com/horsicq/DIE-engine/releases)")
command -v capa    >/dev/null 2>&1 || MISSING_OPTIONAL+=("capa (pip3 install --user flare-capa, or GitHub releases)")
command -v pev     >/dev/null 2>&1 || command -v readpe >/dev/null 2>&1 || MISSING_OPTIONAL+=("pev/readpe (build from https://github.com/mentebinaria/readpe)")
if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
  warn "Optional triage tools not found (install manually if you want them):"
  for t in "${MISSING_OPTIONAL[@]}"; do warn "    - $t"; done
fi

# --- 3. ClamAV: signatures + services (Debian service names) ----------------
say "Configuring ClamAV"
sudo install -d -o clamav -g clamav /var/log/clamav 2>/dev/null || true
# Debian's clamd config lives at /etc/clamav/clamd.conf; freshclam auto-runs.
# Remove any leftover 'Example' guard lines (usually already gone on Debian).
sudo sed -i '/^Example/d' /etc/clamav/freshclam.conf 2>/dev/null || true
sudo sed -i '/^Example/d' /etc/clamav/clamd.conf 2>/dev/null || true
# Ensure clamd logs somewhere Wazuh can read.
if [[ -f /etc/clamav/clamd.conf ]]; then
  grep -q '^LogFile ' /etc/clamav/clamd.conf 2>/dev/null || \
    echo 'LogFile /var/log/clamav/clamav.log' | sudo tee -a /etc/clamav/clamd.conf >/dev/null
fi
# freshclam on Debian runs as a daemon; stop it before a manual update or it
# complains the log is locked. Non-fatal either way.
sudo systemctl stop clamav-freshclam.service 2>/dev/null || true
sudo freshclam || warn "freshclam update failed (network or already-updated); the daemon will retry"
# Debian service names: clamav-daemon + clamav-freshclam (same as Arch here,
# but the daemon package must be installed, which we did above).
sudo systemctl enable --now clamav-freshclam.service 2>/dev/null || warn "clamav-freshclam not started"
sudo systemctl enable --now clamav-daemon.service 2>/dev/null || warn "clamav-daemon not started (it needs signatures first; re-run after freshclam completes)"

# --- 4. rkhunter: baseline + weekly timer -----------------------------------
say "Configuring rkhunter"
sudo rkhunter --update || warn "rkhunter --update failed"
sudo rkhunter --propupd || true   # baseline current file properties
sudo tee /etc/systemd/system/rkhunter-scan.service >/dev/null <<'UNIT'
[Unit]
Description=rkhunter scheduled scan
[Service]
Type=oneshot
ExecStart=/usr/bin/rkhunter --cronjob --report-warnings-only
UNIT
sudo tee /etc/systemd/system/rkhunter-scan.timer >/dev/null <<'UNIT'
[Unit]
Description=Weekly rkhunter scan
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now rkhunter-scan.timer || true

# --- 4b. Wazuh agent (optional, from Wazuh's apt repo) ----------------------
# Unlike Arch's AUR wazuh-agent, Debian installs it from Wazuh's own repo.
# Left commented so the script doesn't add third-party repos without consent.
# To install the agent, follow:
#   https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux/wazuh-agent-package-linux.html
# Typical steps (review before running):
#   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
#   echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
#   sudo apt-get update && sudo WAZUH_MANAGER="<manager-ip>" apt-get install wazuh-agent
say "Wazuh agent: install manually from Wazuh's apt repo if this host is an agent (see comments in this script)."

# --- 5. Dropzone + threat_meister CLI ---------------------------------------
say "Creating dropzone $DROPZONE and initializing threat_meister at $THREAT_MEISTER_ROOT"
sudo install -d -m 0770 "$DROPZONE"
sudo chown "$USER":"$USER" "$DROPZONE"

# Install the three modules together into a lib dir; threat_meister.py adds its own
# directory to sys.path so it imports threathunt.py + intel.py as siblings.
SRC="$(cd "$(dirname "$0")/src" && pwd)"
LIBDIR="$HOME/.local/lib/threat_meister"
install -d "$LIBDIR" "$HOME/.local/bin"
# threathunt.py is symlinked as a bare `threathunt` command and has a
# `#!/usr/bin/env python3` shebang, so install it executable. intel.py is
# import-only, so it stays 644.
install -m755 "$SRC/threathunt.py" "$LIBDIR/threathunt.py"
install -m644 "$SRC/intel.py"      "$LIBDIR/intel.py"
install -m755 "$SRC/threat_meister.py"     "$LIBDIR/threat_meister.py"
cat > "$HOME/.local/bin/threat_meister" <<LAUNCH
#!/bin/sh
exec python3 "$LIBDIR/threat_meister.py" "\$@"
LAUNCH
chmod 755 "$HOME/.local/bin/threat_meister"
# short alias for day-to-day use
ln -sf "$HOME/.local/bin/threat_meister" "$HOME/.local/bin/tm" 2>/dev/null || true
# threathunt stays independently runnable too:
ln -sf "$LIBDIR/threathunt.py" "$HOME/.local/bin/threathunt" 2>/dev/null || true

# On Debian/Ubuntu, ~/.local/bin is on PATH only if it exists at login. It does
# now, but the current shell may not have it yet.
export PATH="$HOME/.local/bin:$PATH"
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
  warn "Add ~/.local/bin to your PATH: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
fi
THREAT_MEISTER_ROOT="$THREAT_MEISTER_ROOT" threat_meister init

# --- 6. Post-install smoke test ---------------------------------------------
# Catches the failure modes that silently bite a month later: a missing sibling
# module, an import error, or a signature/divergence mismatch between the three
# files (e.g. intel.enrich_samples expecting an argument threat_meister.py doesn't pass).
say "Smoke-testing the install"
SMOKE_OK=1

# 6a. All three modules import together from the install dir.
if python3 - "$LIBDIR" <<'PYEOF'
import sys
libdir = sys.argv[1]
sys.path.insert(0, libdir)
try:
    import threathunt, intel, threat_meister      # noqa: F401
except Exception as e:
    print(f"import error: {e}", file=sys.stderr)
    sys.exit(1)

missing = [n for n in ("fetch_over_ssh", "LOCAL_CATALOG_LOOKUP", "enrich", "score_risk")
           if not hasattr(threathunt, n)]
if missing:
    print(f"threathunt missing: {', '.join(missing)} "
          f"(is this the reconciled version?)", file=sys.stderr)
    sys.exit(1)

import inspect
params = inspect.signature(intel.enrich_samples).parameters
if "catalog_db" not in params:
    print("intel.enrich_samples is missing the 'catalog_db' parameter "
          "(threathunt/intel/threat_meister are out of sync)", file=sys.stderr)
    sys.exit(1)

lk = intel.make_catalog_lookup(__import__("pathlib").Path("/nonexistent.db"))
if not hasattr(lk, "close"):
    print("intel.make_catalog_lookup result has no .close() (leak-fix missing)",
          file=sys.stderr)
    sys.exit(1)
print("module wiring OK")
PYEOF
then :; else SMOKE_OK=0; fi

# 6b. The CLI actually responds against the freshly-initialised catalog.
if THREAT_MEISTER_ROOT="$THREAT_MEISTER_ROOT" threat_meister stats >/dev/null 2>&1; then :; else
  warn "threat_meister stats did not run cleanly"
  SMOKE_OK=0
fi

# 6c. threathunt standalone entry point responds.
if THREAT_MEISTER_ROOT="$THREAT_MEISTER_ROOT" python3 "$LIBDIR/threathunt.py" --help >/dev/null 2>&1; then :; else
  warn "threathunt --help did not run cleanly"
  SMOKE_OK=0
fi

if [[ "$SMOKE_OK" -eq 1 ]]; then
  say "Smoke test passed: modules import, wiring is consistent, CLIs respond."
else
  warn "Smoke test FAILED. Check that src/threathunt.py, src/intel.py and"
  warn "src/threat_meister.py are the reconciled, in-sync versions before using the lab."
fi

cat <<EOF

$(say "Base setup complete.")
Next steps:
  1. Add ~/.local/bin to PATH if not already:  export PATH="\$HOME/.local/bin:\$PATH"
  2. Deploy the Wazuh pieces (see README.md 'Wazuh wiring').
  3. Ingest your first sample:
       threat_meister ingest /path/to/sample --family <fam> --category <cat> --platform elf
  4. Author + test a rule, then bundle and deploy:
       threat_meister yara-new <id> --author "\$USER"
       threat_meister yara-test <rulename> --against <id>
       threat_meister yara-bundle
  5. Threat-intel enrichment (needs a VirusTotal key):
       export VT_API_KEY="your_key"
       threat_meister enrich <id>              # or --all; VT-scores hash + IOCs
       threat_meister hunt --wazuh alerts.json --rita beacons.csv --report hunt.md
       threat_meister intel 185.220.101.45     # ad-hoc, catalog-aware
  6. Remote Wazuh manager? Pull its alerts over SSH instead of a local path:
       threat_meister hunt --wazuh-ssh admin@wazuh:/var/ossec/logs/alerts/alerts.json \\
                    --wazuh-sudo --rita beacons.csv --report hunt.md

Debian notes:
  - radare2 lives in Ubuntu's 'universe' component; if it failed to install:
      sudo add-apt-repository universe && sudo apt-get update && sudo apt-get install radare2
  - detect-it-easy, capa, and pev aren't in the default repos — install manually
    if you want them (see the warnings above). The tool works without them.
  - The Wazuh agent installs from Wazuh's own apt repo (see comments in section 4b).

Reminder: keep live samples OFF network-exposed dirs. The dropzone is only for
detonation-detection testing of your own YARA bundle, not long-term storage.
EOF
