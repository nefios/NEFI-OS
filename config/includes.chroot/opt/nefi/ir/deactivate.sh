#!/bin/bash
# NEFI Incident Response Mode — Deactivation
set -e

echo "[NEFI-IR] Deactivating Incident Response Mode..."

# Ripristina rete
if [ -f /var/lib/nefi/ir/nftables-backup.conf ]; then
    nft -f /var/lib/nefi/ir/nftables-backup.conf 2>/dev/null || true
    echo "[NEFI-IR] Network rules restored from backup."
else
    nft flush ruleset
    systemctl restart nftables 2>/dev/null || true
    echo "[NEFI-IR] Network rules reset to default."
fi

# Rimuovi immutabilità log
chattr -i /var/log/syslog 2>/dev/null || true
chattr -i /var/log/auth.log 2>/dev/null || true

# Aggiorna stato
echo "IR_ACTIVE=false" >> /var/lib/nefi/ir/ir-state.conf
echo "IR_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> /var/lib/nefi/ir/ir-state.conf

echo "[NEFI-IR] Incident Response Mode deactivated."
echo "[NEFI-IR] Network restored. Logs unlocked."
