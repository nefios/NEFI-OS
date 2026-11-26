#!/bin/bash
# NEFI Hardening — PROFESSIONAL Profile
set -e
echo "[NEFI] Applying PROFESSIONAL profile..."

bash /opt/nefi/hardening/profile-home.sh

bash /opt/nefi/hardening/apparmor-mode.sh enforce /var/lib/nefi/hardening-apparmor.list || true

# ── Memorie USB bloccate (chiavette, dischi esterni, lettori di schede) ──
# Prima c'era una regola udev con RUN+="/bin/false": RUN non blocca niente e la classe 08
# (mass storage) sta sull'INTERFACCIA, non sul dispositivo, quindi la regola non scattava mai.
# Ora due livelli:
#  1. il driver usb-storage / uas non si puo' caricare -> nessun disco /dev/sdX
#  2. udev non autorizza le interfacce USB di classe 08 (anche se il driver fosse gia' caricato)
# Tastiere, mouse, stampanti, schede di rete USB continuano a funzionare.
# Per tornare indietro: profilo HOME (rimuove questi due file).
cat > /etc/modprobe.d/nefi-usb-storage.conf << 'MOD'
# NEFI OS - Professional profile: USB mass storage disabled
blacklist usb_storage
blacklist uas
install usb_storage /bin/false
install uas /bin/false
MOD
cat > /etc/udev/rules.d/99-nefi-usb-restrict.rules << 'UDEV'
# NEFI OS - Professional profile: USB mass-storage interfaces (class 08) are not authorized
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTR{bInterfaceClass}=="08", ATTR{authorized}="0"
UDEV
udevadm control --reload-rules 2>/dev/null || true
# driver gia' caricato (una chiavetta era collegata): lo tolgo se nessun disco USB e' in uso
if [ -d /sys/module/usb_storage ] || [ -d /sys/module/uas ]; then
    if modprobe -r uas usb_storage 2>/dev/null; then
        echo "[NEFI] USB storage driver unloaded."
    else
        echo "[NEFI] WARNING: a USB drive is still connected or in use. Unmount and remove it:"
        echo "[NEFI]          the block applies to every drive connected from now on."
    fi
fi
echo "[NEFI] USB mass storage blocked."

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
