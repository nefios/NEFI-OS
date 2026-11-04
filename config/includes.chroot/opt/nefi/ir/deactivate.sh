#!/bin/bash
# NEFI Incident Response Mode — Deactivation
set -e

echo "[NEFI-IR] Deactivating Incident Response Mode..."

# Ripristina rete: basta togliere la tabella di isolamento, il firewall di base e' intatto
nft delete table inet nefi_ir 2>/dev/null || true
rm -f /var/lib/nefi/ir/nftables-backup.conf
if ! nft list table inet filter > /dev/null 2>&1; then
    # firewall di base assente (es. caricato a mano da qualcuno): lo ricarico
    nft -f /etc/nftables.conf 2>/dev/null || systemctl restart nftables 2>/dev/null || true
fi
echo "[NEFI-IR] Isolation removed — base firewall active."

# Rimuovi immutabilità log
chattr -i /var/log/syslog 2>/dev/null || true
chattr -i /var/log/auth.log 2>/dev/null || true

# Aggiorna stato
echo "IR_ACTIVE=false" >> /var/lib/nefi/ir/ir-state.conf
echo "IR_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> /var/lib/nefi/ir/ir-state.conf

echo "[NEFI-IR] Incident Response Mode deactivated."
echo "[NEFI-IR] Network restored. Logs unlocked."
