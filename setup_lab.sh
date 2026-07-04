#!/usr/bin/env bash
# threat_meister - Arch Linux lab bootstrap
# Installs the analysis/detection toolchain, deploys the threat_meister CLI, and
# prepares directories + services. Review before running; do not run blind.
set -euo pipefail

THREAT_MEISTER_ROOT="${THREAT_MEISTER_ROOT:-$HOME/threat_meister}"
DROPZONE="/opt/threat_meister/dropzone"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# --- 1. Official repo packages (pacman) -------------------------------------
PACMAN_PKGS=(
  yara            # rule engine (provides /usr/bin/yara + libyara)
  clamav          # AV engine + freshclam + clamd
  rkhunter        # rootkit hunter
  jq              # JSON parsing for the Wazuh AR script
  radare2         # static RE / disassembly
  binutils file   # objdump/readelf/nm + libmagic 'file'
  ssdeep          # fuzzy hashing (CTPH)
  python          # for the threat_meister CLI
  unzip zip       # sample store handling
  chkrootkit      # second-opinion rootkit scanner
  lynis           # host audit / hardening baseline
)
say "Installing repo packages: ${PACMAN_PKGS[*]}"
sudo pacman -S --needed --noconfirm "${PACMAN_PKGS[@]}"

# --- 2. AUR packages (optional but recommended) -----------------------------
# Requires an AUR helper (yay/paru). These sharpen static triage.
AUR_PKGS=(
  capa                 # ATT&CK capability detection from binaries
  detect-it-easy       # DIE: packer/compiler/entropy identification
  pev                  # PE analysis toolkit
  python-tlsh          # TLSH fuzzy hashing python binding
  wazuh-agent          # Wazuh endpoint agent
)
if command -v yay >/dev/null 2>&1; then AUR=yay
elif command -v paru >/dev/null 2>&1; then AUR=paru
else AUR=""; fi
if [[ -n "$AUR" ]]; then
  say "Installing AUR packages with $AUR: ${AUR_PKGS[*]}"
  "$AUR" -S --needed --noconfirm "${AUR_PKGS[@]}" || warn "some AUR packages failed; install manually"
else
  warn "No AUR helper (yay/paru) found. Install these from the AUR manually: ${AUR_PKGS[*]}"
fi

# --- 3. ClamAV: signatures + services ---------------------------------------
say "Configuring ClamAV"
sudo install -d -o clamav -g clamav /var/log/clamav || true
# freshclam.conf ships with an Example line that must be removed once.
sudo sed -i '/^Example/d' /etc/clamav/freshclam.conf 2>/dev/null || true
sudo sed -i '/^Example/d' /etc/clamav/clamd.conf 2>/dev/null || true
# enable logging so Wazuh can ingest results
grep -q '^LogFile ' /etc/clamav/clamd.conf 2>/dev/null || \
  echo 'LogFile /var/log/clamav/clamav.log' | sudo tee -a /etc/clamav/clamd.conf >/dev/null
sudo freshclam || warn "freshclam update failed (network?); retry later"
sudo systemctl enable --now clamav-freshclam.service || true
sudo systemctl enable --now clamav-daemon.service || warn "clamav-daemon not started"

# --- 4. rkhunter: baseline + weekly timer -----------------------------------
say "Configuring rkhunter"
sudo rkhunter --update || warn "rkhunter --update failed"
sudo rkhunter --propupd || true   # baseline current file properties
# A simple systemd timer for weekly checks (writes to /var/log/rkhunter.log)
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

# --- 5. Dropzone + threat_meister CLI -----------------------------------------------
say "Creating dropzone $DROPZONE and initializing threat_meister at $THREAT_MEISTER_ROOT"
sudo install -d -m 0770 "$DROPZONE"
sudo chown "$USER":"$USER" "$DROPZONE"

# Install the three modules together into a lib dir; threat_meister.py adds its own
# directory to sys.path so it imports threathunt.py + intel.py as siblings.
SRC="$(cd "$(dirname "$0")/src" && pwd)"
LIBDIR="$HOME/.local/lib/threat_meister"
install -d "$LIBDIR" "$HOME/.local/bin"
install -m644 "$SRC/threathunt.py" "$LIBDIR/threathunt.py"
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

export PATH="$HOME/.local/bin:$PATH"
THREAT_MEISTER_ROOT="$THREAT_MEISTER_ROOT" threat_meister init

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

Reminder: keep live samples OFF network-exposed dirs. The dropzone is only for
detonation-detection testing of your own YARA bundle, not long-term storage.
EOF
