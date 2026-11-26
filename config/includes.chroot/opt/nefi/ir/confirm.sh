#!/bin/bash
# NEFI Incident Response Mode — conferma dell'isolamento: ferma il ripristino automatico della rete.
set -e
umask 077
. /opt/nefi/ir/state.sh
ir_state_init
if [ "$(ir_state_get IR_ACTIVE)" != "true" ]; then
    echo "[NEFI-IR] The host is not isolated: nothing to confirm." >&2
    exit 1
fi
systemctl stop nefi-ir-rollback.timer 2>/dev/null || true
if systemctl is-active --quiet nefi-ir-rollback.timer; then
    echo "[NEFI-IR] ERROR: the automatic restore could not be cancelled." >&2
    exit 1
fi
ir_state_set CONFIRMED true ROLLBACK_AT ""
ir_log host-isolation-confirmed
echo "[NEFI-IR] Isolation confirmed: it stays until you exit IR Mode (also after a reboot)."
