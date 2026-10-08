#!/usr/bin/env python3
"""NEFI OS - correzioni di sicurezza (bandit) dentro config/includes.chroot."""
import os, sys
ROOT = os.path.expanduser("~/nefi-os/config/includes.chroot") if len(sys.argv) < 2 else sys.argv[1]
M = "usr/lib/nefi/modules/"
ERR = 0

def patch(rel, pairs):
    global ERR
    p = os.path.join(ROOT, rel)
    try:
        s = open(p).read()
    except OSError:
        print(f"[MANCA ] {rel}"); ERR = 1; return
    for old, new in pairs:
        if new in s and old not in s:
            print(f"[GIA' OK] {rel}: {new.strip().splitlines()[0][:60]}")
        elif s.count(old) >= 1:
            s = s.replace(old, new)
            print(f"[FATTO ] {rel}: {new.strip().splitlines()[0][:60]}")
        else:
            print(f"[NON TROVATO] {rel}: {old.strip().splitlines()[0][:60]}"); ERR = 1
    open(p, "w").write(s)

# 1. Comandi senza shell (bandit B602)
patch(M + "guardian_worker.py", [(
    'f"systemctl is-active {services} 2>/dev/null",\n            shell=True,',
    '["systemctl", "is-active", *services.split()],\n            ')])
patch(M + "hardening_check.py", [(
    'subprocess.run(f"sysctl -n {key} 2>/dev/null",\n                               shell=True,',
    'subprocess.run(["sysctl", "-n", key],\n                              ')])

# 2. Vulnerability Scanner: niente piu' /tmp (root scriveva in un percorso prevedibile)
patch("opt/nefi/vuln-scanner/scan.sh", [
    ('OUTPUT_DIR="/tmp/nefi-vuln-scan"\nmkdir -p "$OUTPUT_DIR"',
     'OUTPUT_DIR="/var/lib/nefi/vuln-scan"\ninstall -d -m 755 -o root -g root /var/lib/nefi "$OUTPUT_DIR"\nrm -f "$OUTPUT_DIR"/*')])
patch(M + "vuln_scanner.py", [("/tmp/nefi-vuln-scan/", "/var/lib/nefi/vuln-scan/")])

# 3. Threat Intel: feed (scritti da root) in /var/lib/nefi, dati dell'utente in ~/.local/share/nefi (700)
patch(M + "threat_intel.py", [
    ('IOC_FILE = "/tmp/nefi-custom-ioc.json"\nAPIKEY_FILE = "/tmp/nefi-virustotal-key.txt"',
     'import os as _os\n'
     'USER_DIR = _os.path.expanduser("~/.local/share/nefi")\n'
     '_os.makedirs(USER_DIR, mode=0o700, exist_ok=True)\n'
     '_os.chmod(USER_DIR, 0o700)   # chiave VirusTotal e IOC leggibili solo dall\'utente\n'
     'IOC_FILE = _os.path.join(USER_DIR, "custom-ioc.json")\n'
     'APIKEY_FILE = _os.path.join(USER_DIR, "virustotal-key.txt")'),
    ('"/tmp/nefi-ti-status.conf"',
     'next((p for p in ("/var/lib/nefi/threat-intel/status.conf", _os.path.join(USER_DIR, "threat-intel", "status.conf")) if _os.path.exists(p)), "/var/lib/nefi/threat-intel/status.conf")'),
    ("# Usa /tmp per compatibilità live — scrivibile sempre", "# Dati utente privati (non piu' in /tmp)")])
patch("opt/nefi/threat-intel/update-feeds.sh", [
    ('BASE="/tmp/nefi-threat-intel"',
     '# root (pkexec): cartella di sistema; utente normale: cartella privata\n'
     'if [ "$(id -u)" -eq 0 ]; then\n'
     '  BASE="/var/lib/nefi/threat-intel"\n'
     '  install -d -m 755 -o root -g root /var/lib/nefi "$BASE"\n'
     '  trap \'chmod -R a+rX "$BASE" 2>/dev/null\' EXIT\n'
     'else\n'
     '  BASE="$HOME/.local/share/nefi/threat-intel"\n'
     '  mkdir -p -m 700 "$BASE"\n'
     'fi'),
    ('"/tmp/nefi-ti-status.conf"', '"$BASE/status.conf"'),
    ("# Usa /tmp per compatibilità live", "# Dati: /var/lib/nefi se root (pkexec), ~/.local/share/nefi se utente")])
patch("opt/nefi/threat-intel/search-ioc.sh", [
    ('BASE="/tmp/nefi-threat-intel"',
     '# Utente che ha avviato la ricerca (anche via pkexec)\n'
     'NEFI_HOME="$(getent passwd "${PKEXEC_UID:-$(id -u)}" | cut -d: -f6)"; NEFI_HOME="${NEFI_HOME:-$HOME}"\n'
     'BASE="/var/lib/nefi/threat-intel"; [ -d "$BASE" ] || BASE="$NEFI_HOME/.local/share/nefi/threat-intel"'),
    ('IOC_FILE="/tmp/nefi-custom-ioc.json"',
     'IOC_FILE="$NEFI_HOME/.local/share/nefi/custom-ioc.json"\n'
     '[ -L "$IOC_FILE" ] && IOC_FILE=/dev/null   # niente collegamenti: root non deve leggere altri file')])

print("\nRISULTATO:", "tutto applicato" if ERR == 0 else "QUALCOSA NON E' ANDATO (vedi sopra)")
sys.exit(ERR)
