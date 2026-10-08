#!/bin/bash
# NEFI Hardening — PARANOID Profile
set -e
echo "[NEFI] Applying PARANOID profile..."

bash /opt/nefi/hardening/profile-professional.sh

cat > /etc/udev/rules.d/99-nefi-usb-paranoid.rules << 'UDEV'
SUBSYSTEM=="usb", ATTR{bDeviceClass}!="03", RUN+="/bin/sh -c 'echo 0 > /sys$DEVPATH/authorized'"
UDEV
udevadm control --reload-rules 2>/dev/null || true

sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null || true
echo "auth required pam_succeed_if.so user != root" >> /etc/pam.d/login 2>/dev/null || true

aa-enforce /etc/apparmor.d/* 2>/dev/null || true
echo 1 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
sed -i 's/kernel.yama.ptrace_scope.*/kernel.yama.ptrace_scope = 3/' /etc/sysctl.d/99-nefi-hardening.conf 2>/dev/null || true

echo "confidentiality" > /sys/kernel/security/lockdown 2>/dev/null || true

systemctl disable --now bluetooth 2>/dev/null || true
systemctl disable --now cups 2>/dev/null || true
systemctl disable --now avahi-daemon 2>/dev/null || true

sysctl -p /etc/sysctl.d/99-nefi-hardening.conf 2>/dev/null || true

echo "[NEFI] PARANOID profile applied successfully."
echo "[NEFI] NOTE: Secure Boot and TPM must be configured manually in BIOS/UEFI."
