#!/bin/bash
# NEFI Incident Response Mode — Activation
#   activate.sh [--allow IP] [--rollback MINUTES] [--case NEFI-INC-…]
#
#   --allow IP          isolamento selettivo: resta raggiungibile SOLO questo indirizzo
#                       (la postazione da cui si amministra la macchina)
#   --rollback MINUTES  rete di sicurezza: se l'isolamento non viene confermato entro i minuti
#                       indicati, la rete torna da sola (un errore non lascia chiusi fuori)
#   --case ID           l'incidente a cui appartiene l'isolamento (cronologia e prove)
set -e
umask 077     # snapshot e log della sessione: solo root
. /opt/nefi/ir/state.sh

ALLOW="" ; ROLLBACK=0 ; CASE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --allow)    ALLOW="${2:-}" ; shift 2 ;;
        --rollback) ROLLBACK="${2:-}" ; shift 2 ;;
        --case)     CASE="${2:-}" ; shift 2 ;;
        *) echo "usage: activate.sh [--allow IP] [--rollback MINUTES] [--case ID]" >&2 ; exit 2 ;;
    esac
done
[[ "$ROLLBACK" =~ ^(0|5|15|30|60)$ ]] || { echo "[NEFI-IR] ERROR: rollback must be 0, 5, 15, 30 or 60 minutes" >&2; exit 2; }
[[ -z "$CASE" || "$CASE" =~ ^NEFI-INC-[0-9]{8}-[0-9a-f]{4}$ ]] || { echo "[NEFI-IR] ERROR: invalid incident id" >&2; exit 2; }
if [ -n "$ALLOW" ]; then
    # l'indirizzo passa da ipaddress: nella regola del firewall entra solo un IP valido e normalizzato
    ALLOW="$(python3 -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); sys.exit(1) if a.is_unspecified or a.is_multicast else print(a)' "$ALLOW" 2>/dev/null)" \
        || { echo "[NEFI-IR] ERROR: --allow needs one valid IP address" >&2; exit 2; }
fi

echo "[NEFI-IR] Activating Incident Response Mode..."
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[NEFI-IR] Timestamp: $NOW"

ir_state_init
IR_LOG="$STATE_DIR/ir-session.log"
if [ "$(ir_state_get IR_ACTIVE)" = "true" ] && nft list table inet nefi_ir > /dev/null 2>&1; then
    echo "[NEFI-IR] The host is already isolated: nothing to do."
    exit 0
fi
MODE="full" ; [ -n "$ALLOW" ] && MODE="selective"
ir_state_reset IR_START "$NOW" IR_ACTIVE false MODE "$MODE" ALLOW_IP "$ALLOW" CASE "$CASE" CONFIRMED true

# ── 1. Block network ────────────────────────────────────
echo "[NEFI-IR] Blocking network connections..."
if ! ir_isolation_apply "$ALLOW"; then
    echo "[NEFI-IR] ERROR: nftables refused the isolation rules. Nothing was changed: the network works as before." >&2
    exit 1
fi

# Da qui la macchina e' isolata: lo stato lo dice SUBITO, anche se un passo successivo fallisce.
ir_state_set IR_ACTIVE true NETWORK_BLOCKED true
if [ -n "$ALLOW" ]; then
    echo "[NEFI-IR] Network ISOLATED — only $ALLOW can still reach this host"
else
    echo "[NEFI-IR] Network ISOLATED — all external connections blocked"
fi

# ── 1b. Rete di sicurezza ───────────────────────────────
if [ "$ROLLBACK" != "0" ]; then
    systemctl stop nefi-ir-rollback.timer 2>/dev/null || true
    systemctl reset-failed nefi-ir-rollback.service 2>/dev/null || true
    if systemd-run --quiet --unit nefi-ir-rollback --on-active="${ROLLBACK}m" --timer-property=AccuracySec=1s \
            --description "NEFI IR: restore the network if the isolation is not confirmed" \
            /bin/bash /opt/nefi/ir/deactivate.sh --auto; then
        ir_state_set CONFIRMED false ROLLBACK_AT "$(( $(date +%s) + ROLLBACK * 60 ))"
        echo "[NEFI-IR] Safety net: the network comes back by itself in $ROLLBACK minutes unless you confirm the isolation."
    else
        # promessa non mantenibile: meglio nessun isolamento che un isolamento senza via d'uscita
        nft delete table inet nefi_ir 2>/dev/null || true
        ir_state_set IR_ACTIVE false NETWORK_BLOCKED false
        echo "[NEFI-IR] ERROR: the automatic restore could not be scheduled. Isolation removed, network as before." >&2
        exit 1
    fi
fi
ir_log host-isolated mode="$MODE" allow="$ALLOW" rollback_minutes="$ROLLBACK"

# Da qui in poi nessun errore deve interrompere lo script: la macchina e' gia' isolata e lo stato e' scritto.
set +e

# ── 2. Protect logs ─────────────────────────────────────
echo "[NEFI-IR] Protecting log files..."
chattr +i /var/log/syslog 2>/dev/null
chattr +i /var/log/auth.log 2>/dev/null
journalctl --flush 2>/dev/null
sync
ir_state_set LOGS_PROTECTED true

# ── 3. Snapshot processi ────────────────────────────────
echo "[NEFI-IR] Snapshotting current process state..."
ps auxf > "$STATE_DIR/processes-at-ir-activation.txt" 2>/dev/null
ss -tulnp > "$STATE_DIR/network-at-ir-activation.txt" 2>/dev/null
ir_state_set SNAPSHOT_DONE true

# ── 4. Avvia raccolta prove ─────────────────────────────
echo "[NEFI-IR] Starting automatic evidence collection..."
# raccolta con manifest firmato e registro di custodia (dfir.py); se manca, la raccolta semplice
IR_COLLECT=(bash /opt/nefi/forensics/collect.sh)
[ -f /opt/nefi/forensics/dfir.py ] && IR_COLLECT=(python3 /opt/nefi/forensics/dfir.py collect "${CASE:-Incident Response}" "IR mode" "Automatic collection at IR activation")
if "${IR_COLLECT[@]}" 2>&1 | tee -a "$IR_LOG"; [ "${PIPESTATUS[0]}" -eq 0 ]; then
    ir_state_set EVIDENCE_COLLECTED true
else
    ir_state_set EVIDENCE_COLLECTED false
    echo "[NEFI-IR] WARNING: evidence collection failed, see $IR_LOG"
fi
chmod 0600 "$IR_LOG" 2>/dev/null

echo "[NEFI-IR] IR Mode fully activated."
echo "[NEFI-IR] To leave it without the Security Center: sudo nefi-ir-recover"
exit 0
