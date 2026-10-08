#!/bin/bash
# NEFI Threat Intelligence — Update feeds
# Dati: /var/lib/nefi se root (pkexec), ~/.local/share/nefi se utente
# root (pkexec): cartella di sistema; utente normale: cartella privata
if [ "$(id -u)" -eq 0 ]; then
  BASE="/var/lib/nefi/threat-intel"
  install -d -m 755 -o root -g root /var/lib/nefi "$BASE"
  trap 'chmod -R a+rX "$BASE" 2>/dev/null' EXIT
else
  BASE="$HOME/.local/share/nefi/threat-intel"
  mkdir -p -m 700 "$BASE"
fi
mkdir -p "$BASE"/{ioc,yara}
mkdir -p /var/log/nefi 2>/dev/null || true

echo "[NEFI-TI] Starting threat intelligence update: $(date)"

# ── 1. IP blocklist — Feodo Tracker ────────────────────
echo "[NEFI-TI] Downloading IP blocklist (Feodo Tracker)..."
curl -fsSL --max-time 15 \
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
    -o "$BASE/ioc/compromised-ips.txt" 2>/dev/null && \
    echo "[NEFI-TI] IP blocklist: $(grep -v '^#' $BASE/ioc/compromised-ips.txt | grep -v '^$' | wc -l) entries" || \
    echo "[NEFI-TI] WARNING: Could not download IP blocklist"

# ── 2. URLhaus — malicious URLs ────────────────────────
echo "[NEFI-TI] Downloading malicious URL list (URLhaus)..."
curl -fsSL --max-time 15 \
    "https://urlhaus.abuse.ch/downloads/text/" \
    -o "$BASE/ioc/malicious-urls.txt" 2>/dev/null && \
    echo "[NEFI-TI] Malicious URLs: $(grep -v '^#' $BASE/ioc/malicious-urls.txt | grep -v '^$' | wc -l) entries" || \
    echo "[NEFI-TI] WARNING: Could not download URL list"

# ── 3. YARA rules ──────────────────────────────────────
echo "[NEFI-TI] Downloading YARA rules..."
curl -fsSL --max-time 15 \
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar" \
    -o "$BASE/yara/ransomware.yar" 2>/dev/null && \
    echo "[NEFI-TI] YARA ransomware rules downloaded" || \
    echo "[NEFI-TI] WARNING: Could not download YARA rules"

# ── 4. Salva stato in /tmp ─────────────────────────────
IPS=$(grep -v '^#' "$BASE/ioc/compromised-ips.txt" 2>/dev/null | grep -v '^$' | wc -l || echo 0)
URLS=$(grep -v '^#' "$BASE/ioc/malicious-urls.txt" 2>/dev/null | grep -v '^$' | wc -l || echo 0)
YARA=$(ls "$BASE/yara/"*.yar 2>/dev/null | wc -l || echo 0)

cat > "$BASE/status.conf" << STATUS
LAST_UPDATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
IOC_IPS=$IPS
URL_FEED=$URLS
YARA_FILES=$YARA
STATUS

echo "[NEFI-TI] Update completed: $(date)"
echo "[NEFI-TI] Saved to: $BASE"
