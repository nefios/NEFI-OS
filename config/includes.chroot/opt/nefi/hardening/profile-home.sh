#!/bin/bash
# NEFI Hardening — HOME Profile
set -e
echo "[NEFI] Applying HOME profile..."

# Il profilo HOME annulla il blocco USB dei profili Professional/Paranoid
# (Professional e Paranoid partono da HOME e poi lo rimettono).
rm -f /etc/modprobe.d/nefi-usb-storage.conf \
      /etc/udev/rules.d/99-nefi-usb-restrict.rules \
      /etc/udev/rules.d/99-nefi-usb-paranoid.rules
udevadm control --reload-rules 2>/dev/null || true

systemctl enable --now nftables 2>/dev/null || true
systemctl enable --now apparmor 2>/dev/null || true

apt install -y unattended-upgrades 2>/dev/null || true
systemctl enable --now unattended-upgrades 2>/dev/null || true

echo "[NEFI] HOME profile applied successfully."
