#!/bin/bash
# NEFI Hardening — PROFESSIONAL Profile
set -e
echo "[NEFI] Applying PROFESSIONAL profile..."

bash /opt/nefi/hardening/profile-home.sh

aa-enforce /etc/apparmor.d/* 2>/dev/null || true

cat > /etc/udev/rules.d/99-nefi-usb-restrict.rules << 'UDEV'
SUBSYSTEM=="usb", ATTR{bDeviceClass}=="08", RUN+="/bin/false"
UDEV
udevadm control --reload-rules 2>/dev/null || true

mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/nefi-dns.conf << 'DNS'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net
DNSOverTLS=yes
DNS
systemctl restart systemd-resolved 2>/dev/null || true

cat > /etc/audit/rules.d/nefi-professional.rules << 'AUDIT'
-a always,exit -F arch=b64 -S execve -k all_exec
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /var/log/auth.log -p wa -k auth_log
AUDIT
systemctl restart auditd 2>/dev/null || true

echo "[NEFI] PROFESSIONAL profile applied successfully."
