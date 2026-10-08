#!/bin/bash
# NEFI Incident Response Mode — Activation
set -e

echo "[NEFI-IR] Activating Incident Response Mode..."
echo "[NEFI-IR] Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p /var/lib/nefi/ir
IR_LOG="/var/lib/nefi/ir/ir-session.log"
echo "IR_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /var/lib/nefi/ir/ir-state.conf

# ── 1. Block network ────────────────────────────────────
echo "[NEFI-IR] Blocking network connections..."

# Salva regole firewall correnti
nft list ruleset > /var/lib/nefi/ir/nftables-backup.conf 2>/dev/null || true

# Applica regole di isolamento totale
nft flush ruleset
nft add table inet nefi_ir
nft add chain inet nefi_ir input  '{ type filter hook input  priority 0; policy drop; }'
nft add chain inet nefi_ir output '{ type filter hook output priority 0; policy drop; }'
nft add chain inet nefi_ir forward '{ type filter hook forward priority 0; policy drop; }'

# Permetti solo loopback
nft add rule inet nefi_ir input  iif lo accept
nft add rule inet nefi_ir output oif lo accept

echo "[NEFI-IR] Network ISOLATED — all external connections blocked"
echo "NETWORK_BLOCKED=true" >> /var/lib/nefi/ir/ir-state.conf

# ── 2. Protect logs ─────────────────────────────────────
echo "[NEFI-IR] Protecting log files..."
chattr +i /var/log/syslog 2>/dev/null || true
chattr +i /var/log/auth.log 2>/dev/null || true

# Freeze journald — flush e sync
journalctl --flush 2>/dev/null || true
sync

echo "LOGS_PROTECTED=true" >> /var/lib/nefi/ir/ir-state.conf

# ── 3. Snapshot processi ────────────────────────────────
echo "[NEFI-IR] Snapshotting current process state..."
ps auxf > /var/lib/nefi/ir/processes-at-ir-activation.txt
ss -tulnp > /var/lib/nefi/ir/network-at-ir-activation.txt

echo "SNAPSHOT_DONE=true" >> /var/lib/nefi/ir/ir-state.conf

# ── 4. Avvia raccolta prove ─────────────────────────────
echo "[NEFI-IR] Starting automatic evidence collection..."
bash /opt/nefi/forensics/collect.sh 2>&1 | tee -a "$IR_LOG" || true

echo "EVIDENCE_COLLECTED=true" >> /var/lib/nefi/ir/ir-state.conf
echo "[NEFI-IR] IR Mode fully activated."
echo "IR_ACTIVE=true" >> /var/lib/nefi/ir/ir-state.conf
