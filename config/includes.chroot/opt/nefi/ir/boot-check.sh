#!/bin/bash
# NEFI Incident Response — all'avvio lo stato scritto e la rete devono dire la stessa cosa.
# La tabella di isolamento non sopravvive a un riavvio, il file di stato si':
#   isolamento confermato      -> viene rimesso (un riavvio non deve liberare una macchina compromessa)
#   isolamento non confermato  -> si esce dall'IR Mode (il riavvio vale come "non riesco a confermare")
umask 077
. /opt/nefi/ir/state.sh
[ "$(ir_state_get IR_ACTIVE)" = "true" ] || exit 0
if [ "$(ir_state_get CONFIRMED)" = "false" ]; then
    echo "[NEFI-IR] Isolation was never confirmed before the reboot: leaving IR Mode."
    exec /bin/bash /opt/nefi/ir/deactivate.sh --auto
fi
if ir_isolation_apply "$(ir_state_get ALLOW_IP)"; then
    echo "[NEFI-IR] IR Mode is active: isolation applied again after the reboot."
    ir_log host-isolation-reapplied reason="reboot"
else
    echo "[NEFI-IR] ERROR: could not apply the isolation again; leaving IR Mode so the state stays true." >&2
    exec /bin/bash /opt/nefi/ir/deactivate.sh --force
fi
