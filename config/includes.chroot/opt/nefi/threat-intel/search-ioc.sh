#!/bin/bash
# NEFI Threat Intelligence — Search IOC with VirusTotal
IOC="$1"
TYPE="$2"
# The VirusTotal key comes from the environment, never from the command line:
# command-line arguments are visible to every local user (ps, /proc/<pid>/cmdline).
VT_KEY="${NEFI_VT_KEY:-}"
# Utente che ha avviato la ricerca (anche via pkexec)
NEFI_HOME="$(getent passwd "${PKEXEC_UID:-$(id -u)}" | cut -d: -f6)"; NEFI_HOME="${NEFI_HOME:-$HOME}"
BASE="/var/lib/nefi/threat-intel"; [ -d "$BASE" ] || BASE="$NEFI_HOME/.local/share/nefi/threat-intel"
IOC_FILE="$NEFI_HOME/.local/share/nefi/custom-ioc.json"
[ -L "$IOC_FILE" ] && IOC_FILE=/dev/null   # niente collegamenti: root non deve leggere altri file

if [ -z "$IOC" ]; then
    echo "Usage: NEFI_VT_KEY=<key> search-ioc.sh <indicator> <type>"
    exit 1
fi

echo "[NEFI-TI] Searching for IOC: $IOC (type: $TYPE)"
FOUND=0

# ── 1. IOC personalizzati dell'utente ───────────────────
if [ -f "$IOC_FILE" ]; then
    # The indicator and the file name are passed as data, never pasted into the Python code
    MATCH=$(NEFI_IOC="$IOC" python3 -c '
import json, os, sys
ioc = os.environ["NEFI_IOC"].lower()
try:
    for i in json.load(open(sys.argv[1])):
        if ioc in str(i.get("value", "")).lower():
            print("[LOCAL IOC] Found in custom watchlist: %s — %s" % (str(i.get("type", "")).upper(), i.get("value")))
except Exception:
    pass
' "$IOC_FILE" 2>/dev/null)
    if [ -n "$MATCH" ]; then
        echo "$MATCH"
        echo "[ALERT] This IOC is in your custom watchlist"
        FOUND=1
    fi
fi

# ── 2. Feed locali scaricati ────────────────────────────
if [ -d "$BASE/ioc" ]; then
    MATCH=$(grep -rF -- "$IOC" "$BASE/ioc/" 2>/dev/null | grep -v '^#' | head -5)
    if [ -n "$MATCH" ]; then
        echo "[MATCH] Found in local threat intelligence feeds:"
        echo "$MATCH"
        FOUND=1
    fi
fi

# ── 3. VirusTotal ───────────────────────────────────────
if [ -n "$VT_KEY" ] && [ "$VT_KEY" != "none" ] && ! [[ "$IOC" =~ ^[A-Za-z0-9.:_-]+$ ]]; then
    echo "[VIRUSTOTAL] Skipped: the indicator contains characters that are not valid in an IP, domain or hash"
elif [ -n "$VT_KEY" ] && [ "$VT_KEY" != "none" ]; then
    echo "[NEFI-TI] Checking VirusTotal..."

    if [ "$TYPE" = "ip" ]; then
        ENDPOINT="https://www.virustotal.com/api/v3/ip_addresses/$IOC"
    elif [ "$TYPE" = "domain" ]; then
        ENDPOINT="https://www.virustotal.com/api/v3/domains/$IOC"
    elif [ "$TYPE" = "hash" ]; then
        ENDPOINT="https://www.virustotal.com/api/v3/files/$IOC"
    else
        ENDPOINT="https://www.virustotal.com/api/v3/ip_addresses/$IOC"
    fi

    # The key goes to curl through stdin (-H @-), so it never appears in the process list
    RESPONSE=$(printf 'x-apikey: %s\n' "$VT_KEY" | curl -fsSL --max-time 15 -H @- "$ENDPOINT" 2>/dev/null)

    if [ -n "$RESPONSE" ]; then
        # The response is passed on stdin: pasting it into the Python code would let
        # attacker-controlled text from VirusTotal (names, whois, tags) run as code
        printf '%s' "$RESPONSE" | python3 -c "$(cat << 'PYEOF'
import json, sys

try:
    d = json.load(sys.stdin)
    stats = d.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    total = malicious + suspicious + harmless + undetected

    print(f"[VIRUSTOTAL] Malicious: {malicious}/{total} | Suspicious: {suspicious} | Harmless: {harmless}")

    if malicious >= 5:
        print(f"[CRITICAL] HIGHLY MALICIOUS — detected by {malicious} engines")
    elif malicious >= 1:
        print(f"[WARNING] SUSPICIOUS — detected by {malicious} engines")
    elif suspicious >= 3:
        print(f"[LOW] Low risk — {suspicious} suspicious detections")
    else:
        print(f"[CLEAN] Clean on VirusTotal ({harmless} engines report harmless)")

    # Mostra engines che lo rilevano
    engines = d.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
    bad_engines = [k for k,v in engines.items() if v.get('category') in ('malicious','suspicious')]
    if bad_engines:
        print(f"[VIRUSTOTAL] Detected by: {', '.join(bad_engines[:5])}")
except Exception as e:
    print(f"[VIRUSTOTAL] Error parsing response: {e}")
PYEOF
)"
    else
        echo "[VIRUSTOTAL] Could not reach VirusTotal — check connection or API key"
    fi
else
    echo "[INFO] VirusTotal check skipped — configure API key in Settings tab"
    echo "[INFO] Get free key at: virustotal.com"
fi

# ── 4. Connessioni attive ───────────────────────────────
NET_MATCH=$(ss -tn 2>/dev/null | grep -F -- "$IOC")
if [ -n "$NET_MATCH" ]; then
    echo "[ALERT] IOC found in ACTIVE NETWORK CONNECTIONS:"
    echo "$NET_MATCH"
    FOUND=1
fi

# ── 5. Log di sistema ───────────────────────────────────
LOG_MATCH=$(journalctl -n 2000 --no-pager 2>/dev/null | grep -F -- "$IOC" | head -5)
if [ -n "$LOG_MATCH" ]; then
    echo "[ALERT] IOC found in SYSTEM LOGS:"
    echo "$LOG_MATCH"
    FOUND=1
fi

if [ "$FOUND" -eq 0 ]; then
    echo "[CLEAN] IOC not found in any local source"
fi
