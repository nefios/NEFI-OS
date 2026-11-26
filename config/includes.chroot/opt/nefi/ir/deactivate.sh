#!/bin/bash
# NEFI Incident Response Mode — Deactivation
#   deactivate.sh            uscita normale (dal Security Center)
#   deactivate.sh --auto     ripristino automatico: l'isolamento non e' stato confermato in tempo
#   deactivate.sh --force    emergenza (nefi-ir-recover): va avanti anche se un passo fallisce
set -e
umask 077
. /opt/nefi/ir/state.sh

HOW="${1:-}"
[ "$HOW" = "--force" ] && set +e
echo "[NEFI-IR] Deactivating Incident Response Mode..."
ir_state_init

# niente ripristino automatico in sospeso (con --auto siamo NOI quel servizio: si ferma solo il timer)
systemctl stop nefi-ir-rollback.timer 2>/dev/null || true

# Ripristina rete: basta togliere la tabella di isolamento, il firewall di base e' intatto
nft delete table inet nefi_ir 2>/dev/null || true
if nft list table inet nefi_ir > /dev/null 2>&1; then
    if [ "$HOW" = "--force" ]; then
        echo "[NEFI-IR] The isolation table resists: reloading the whole firewall from /etc/nftables.conf"
        nft flush ruleset
        nft -f /etc/nftables.conf || systemctl restart nftables
    else
        # l'isolamento e' ancora attivo: lo stato resta "attivo", non dico il falso
        echo "[NEFI-IR] ERROR: the isolation table nefi_ir could not be removed. IR Mode is still active." >&2
        echo "[NEFI-IR] From a terminal: sudo nefi-ir-recover" >&2
        exit 1
    fi
fi
rm -f "$STATE_DIR/nftables-backup.conf"
if ! nft list table inet filter > /dev/null 2>&1; then
    # firewall di base assente (es. caricato a mano da qualcuno): lo ricarico
    nft -f /etc/nftables.conf 2>/dev/null || systemctl restart nftables 2>/dev/null || true
fi
echo "[NEFI-IR] Isolation removed — base firewall active."

# Rimuovi immutabilità log
chattr -i /var/log/syslog 2>/dev/null || true
chattr -i /var/log/auth.log 2>/dev/null || true

case "$HOW" in
    --auto)  ir_log host-released-auto reason="isolation not confirmed in time" ; AUTO=true ;;
    --force) ir_log host-released reason="emergency recovery (nefi-ir-recover)" ; AUTO=false ;;
    *)       ir_log host-released ; AUTO=false ;;
esac

# Aggiorna stato: una sola riga per chiave
ir_state_set IR_ACTIVE false NETWORK_BLOCKED false LOGS_PROTECTED false CONFIRMED true ROLLBACK_AT "" \
    AUTO_RELEASED "$AUTO" IR_END "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "[NEFI-IR] Incident Response Mode deactivated."
echo "[NEFI-IR] Network restored. Logs unlocked."
