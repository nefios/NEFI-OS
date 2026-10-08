#!/bin/bash
# NEFI Hardening — HOME Profile
set -e
echo "[NEFI] Applying HOME profile..."

systemctl enable --now nftables 2>/dev/null || true
systemctl enable --now apparmor 2>/dev/null || true

apt install -y unattended-upgrades 2>/dev/null || true
systemctl enable --now unattended-upgrades 2>/dev/null || true

echo "[NEFI] HOME profile applied successfully."
