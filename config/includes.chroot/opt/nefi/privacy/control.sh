#!/bin/bash
# NEFI Privacy Control
ACTION="$1"
TARGET="$2"

case "$ACTION" in
    disable_bluetooth)
        systemctl stop bluetooth 2>/dev/null || true
        systemctl disable bluetooth 2>/dev/null || true
        rfkill block bluetooth 2>/dev/null || true
        bluetoothctl power off 2>/dev/null || true
        echo "blacklist btusb" > /etc/modprobe.d/nefi-bt-block.conf
        echo "blacklist bluetooth" >> /etc/modprobe.d/nefi-bt-block.conf
        echo "[NEFI-PRIVACY] Bluetooth disabled"
        ;;
    enable_bluetooth)
        rm -f /etc/modprobe.d/nefi-bt-block.conf
        systemctl enable bluetooth 2>/dev/null || true
        systemctl start bluetooth 2>/dev/null || true
        rfkill unblock bluetooth 2>/dev/null || true
        bluetoothctl power on 2>/dev/null || true
        echo "[NEFI-PRIVACY] Bluetooth enabled"
        ;;
    disable_webcam)
        modprobe -r uvcvideo 2>/dev/null || true
        echo "blacklist uvcvideo" > /etc/modprobe.d/nefi-webcam-block.conf
        echo "[NEFI-PRIVACY] Webcam disabled"
        ;;
    enable_webcam)
        rm -f /etc/modprobe.d/nefi-webcam-block.conf
        modprobe uvcvideo 2>/dev/null || true
        echo "[NEFI-PRIVACY] Webcam enabled"
        ;;
    disable_microphone)
        amixer set Capture nocap 2>/dev/null || true
        echo "blacklist snd_hda_intel" > /etc/modprobe.d/nefi-mic-block.conf
        echo "[NEFI-PRIVACY] Microphone disabled"
        ;;
    enable_microphone)
        rm -f /etc/modprobe.d/nefi-mic-block.conf
        amixer set Capture cap 2>/dev/null || true
        echo "[NEFI-PRIVACY] Microphone enabled"
        ;;
    set_dns_cloudflare)
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/nefi-dns.conf << 'DNS'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
DNSOverTLS=yes
DNS
        systemctl restart systemd-resolved 2>/dev/null || true
        echo "[NEFI-PRIVACY] DNS set to Cloudflare (DoT)"
        ;;
    set_dns_quad9)
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/nefi-dns.conf << 'DNS'
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNS
        systemctl restart systemd-resolved 2>/dev/null || true
        echo "[NEFI-PRIVACY] DNS set to Quad9 (DoT)"
        ;;
    set_dns_default)
        rm -f /etc/systemd/resolved.conf.d/nefi-dns.conf
        systemctl restart systemd-resolved 2>/dev/null || true
        echo "[NEFI-PRIVACY] DNS reset to default"
        ;;
    status)
        # Bluetooth
        BT_BLOCK="/etc/modprobe.d/nefi-bt-block.conf"
        BT_RFKILL=$(rfkill list bluetooth 2>/dev/null | grep -c "Soft blocked: yes" || echo 0)
        if [ -f "$BT_BLOCK" ] || [ "$BT_RFKILL" -gt 0 ]; then
            echo "BLUETOOTH=disabled"
        else
            echo "BLUETOOTH=enabled"
        fi

        # Webcam
        WC=$(lsmod 2>/dev/null | grep -c uvcvideo || echo 0)
        echo "WEBCAM=$([ "$WC" -gt 0 ] && echo enabled || echo disabled)"

        # DNS
        DNS_CONF="/etc/systemd/resolved.conf.d/nefi-dns.conf"
        if [ -f "$DNS_CONF" ]; then
            DNS_SERVER=$(grep "^DNS=" "$DNS_CONF" | head -1 | cut -d'=' -f2 | awk '{print $1}')
            echo "DNS=$DNS_SERVER"
        else
            echo "DNS=default"
        fi

        # Microphone
        MIC_BLOCK="/etc/modprobe.d/nefi-mic-block.conf"
        echo "MICROPHONE=$([ -f "$MIC_BLOCK" ] && echo disabled || echo enabled)"
        ;;
esac
