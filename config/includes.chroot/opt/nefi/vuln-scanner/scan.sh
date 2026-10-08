#!/bin/bash
# NEFI Vulnerability Scanner — Lynis scan
set -e

OUTPUT_DIR="/var/lib/nefi/vuln-scan"
install -d -m 755 -o root -g root /var/lib/nefi "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*

REPORT="$OUTPUT_DIR/lynis-report.dat"
LOG="$OUTPUT_DIR/lynis.log"

echo "[NEFI-VULN] Starting vulnerability scan..."
echo "[NEFI-VULN] This may take 2-5 minutes."
echo "[NEFI-VULN] Timestamp: $(date)"

# Esegui Lynis
lynis audit system \
    --no-colors \
    --quiet \
    --report-file "$REPORT" \
    --logfile "$LOG" \
    2>&1 | grep -E "^\[|\bWarning\b|\bSuggestion\b|\bHardening\b" || true

# Estrai punteggio
SCORE=$(grep "hardening_index" "$REPORT" 2>/dev/null | cut -d'=' -f2 | tr -d '[:space:]')
if [ -z "$SCORE" ]; then
    SCORE=$(grep -i "hardening index" "$LOG" 2>/dev/null | grep -o '[0-9]*' | tail -1)
fi

echo ""
echo "[NEFI-VULN] ══════════════════════════════════"
echo "[NEFI-VULN] Scan completed"
echo "[NEFI-VULN] Hardening Index: ${SCORE:-N/A}/100"
echo "[NEFI-VULN] Report: $REPORT"
echo "[NEFI-VULN] ══════════════════════════════════"

# Estrai warnings e suggerimenti
echo ""
echo "[NEFI-VULN] WARNINGS:"
grep "^warning\[]=" "$REPORT" 2>/dev/null | \
    sed 's/warning\[]=//g' | head -20 || echo "None found"

echo ""
echo "[NEFI-VULN] SUGGESTIONS:"
grep "^suggestion\[]=" "$REPORT" 2>/dev/null | \
    sed 's/suggestion\[]=//g' | head -20 || echo "None found"

echo ""
# Fix permissions so normal user can read the report
chmod 755 "$OUTPUT_DIR" 2>/dev/null || true
chmod 644 "$OUTPUT_DIR"/* 2>/dev/null || true

echo "SCAN_SCORE=${SCORE:-0}"
