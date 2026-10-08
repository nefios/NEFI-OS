#!/bin/bash
# NEFI Zero Trust Mode
STATE_DIR="/var/lib/nefi/zerotrust"
STATE_FILE="$STATE_DIR/state.conf"
SUDOERS_FILE="/etc/sudoers.d/nefi-zerotrust"
mkdir -p "$STATE_DIR"

case "$1" in

    audit)
        echo "[NEFI-ZT] Running least privilege audit..."
        awk -F: '$3==0{print "UID0|"$1}' /etc/passwd
        getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sed 's/^/SUDO|/'
        grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' | sed 's/^/NOPASSWD|/'
        find / -xdev -perm -4000 -type f 2>/dev/null | sed 's/^/SUID|/'
        find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20 | sed 's/^/WWDIR|/'
        ss -tlnH 2>/dev/null | awk '{print "LISTEN|"$4}'
        echo "[NEFI-ZT] Audit completed."
        ;;

    activate)
        echo "[NEFI-ZT] Activating Zero Trust Mode..."

        # ── 1. Micro-segmentation (default-deny in/out) ──
        echo "[NEFI-ZT] Applying network micro-segmentation..."
        nft list ruleset > "$STATE_DIR/nftables-backup.conf" 2>/dev/null || true
        nft flush ruleset
        nft -f - << 'NFT'
table inet nefi_zt {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        udp sport 67 udp dport 68 accept
        log prefix "NEFI-ZT-IN-DROP " limit rate 5/minute
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oif lo accept
        ct state established,related accept
        udp dport { 53, 67, 123 } accept
        tcp dport { 53, 80, 443 } accept
        log prefix "NEFI-ZT-OUT-DROP " limit rate 5/minute
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
NFT
        echo "[NEFI-ZT] Outbound allowed only: DNS, HTTP/HTTPS, NTP, DHCP"
        echo "NET_SEGMENTATION=true" > "$STATE_FILE"

        # ── 2. Application control: noexec on temp dirs ──
        echo "[NEFI-ZT] Blocking execution from /tmp and /dev/shm..."
        if mountpoint -q /tmp; then
            mount -o remount,noexec,nosuid,nodev /tmp && echo "TMP_NOEXEC=true" >> "$STATE_FILE"
        else
            echo "[NEFI-ZT] /tmp is not a separate mount — skipped"
        fi
        mount -o remount,noexec,nosuid,nodev /dev/shm && echo "SHM_NOEXEC=true" >> "$STATE_FILE"

        # ── 3. AppArmor enforce ──
        echo "[NEFI-ZT] Enforcing AppArmor profiles..."
        aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || echo "[NEFI-ZT] AppArmor not available (normal in live mode)"

        # ── 4. Restrict ptrace to admin only ──
        PREV_PTRACE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo 1)
        echo "PREV_PTRACE=$PREV_PTRACE" >> "$STATE_FILE"
        sysctl -w kernel.yama.ptrace_scope=2 >/dev/null 2>&1 || true
        echo "[NEFI-ZT] ptrace restricted to administrators"

        # ── 5. Least privilege: sudo always asks for password ──
        echo "Defaults timestamp_timeout=0" > "$SUDOERS_FILE"
        chmod 440 "$SUDOERS_FILE"
        if visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1; then
            echo "[NEFI-ZT] sudo now requires password on every use"
        else
            rm -f "$SUDOERS_FILE"
            echo "[NEFI-ZT] WARNING: sudoers rule invalid — skipped"
        fi

        echo "ZT_ACTIVE=true" >> "$STATE_FILE"
        echo "ZT_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$STATE_FILE"
        chmod 755 "$STATE_DIR"; chmod 644 "$STATE_FILE"
        echo "[NEFI-ZT] Zero Trust Mode ACTIVE."
        ;;

    deactivate)
        echo "[NEFI-ZT] Deactivating Zero Trust Mode..."
        nft flush ruleset
        if [ -s "$STATE_DIR/nftables-backup.conf" ]; then
            nft -f "$STATE_DIR/nftables-backup.conf" && echo "[NEFI-ZT] Firewall rules restored"
        else
            systemctl restart nftables 2>/dev/null || true
            echo "[NEFI-ZT] Firewall reset to default"
        fi

        mountpoint -q /tmp && mount -o remount,exec /tmp 2>/dev/null
        mount -o remount,exec /dev/shm 2>/dev/null
        echo "[NEFI-ZT] Execution from temp dirs restored"

        PREV=$(grep '^PREV_PTRACE=' "$STATE_FILE" 2>/dev/null | cut -d= -f2)
        sysctl -w kernel.yama.ptrace_scope="${PREV:-1}" >/dev/null 2>&1 || true

        rm -f "$SUDOERS_FILE"
        echo "ZT_ACTIVE=false" > "$STATE_FILE"
        chmod 644 "$STATE_FILE"
        echo "[NEFI-ZT] Zero Trust Mode deactivated."
        ;;

    status)
        grep -q "ZT_ACTIVE=true" "$STATE_FILE" 2>/dev/null && echo "ZT_ACTIVE=true" || echo "ZT_ACTIVE=false"
        grep -q "NET_SEGMENTATION=true" "$STATE_FILE" 2>/dev/null && grep -q "ZT_ACTIVE=true" "$STATE_FILE" \
            && echo "NET_SEGMENTATION=true" || echo "NET_SEGMENTATION=false"
        findmnt -no OPTIONS /dev/shm 2>/dev/null | grep -q noexec && echo "SHM_NOEXEC=true" || echo "SHM_NOEXEC=false"
        findmnt -no OPTIONS /tmp 2>/dev/null | grep -q noexec && echo "TMP_NOEXEC=true" || echo "TMP_NOEXEC=false"
        echo "PTRACE_SCOPE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo unknown)"
        [ -f "$SUDOERS_FILE" ] && echo "SUDO_STRICT=true" || echo "SUDO_STRICT=false"
        ;;
esac
