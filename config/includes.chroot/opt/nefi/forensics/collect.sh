#!/bin/bash
# NEFI Forensics Collector
set -e

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
OUTPUT_DIR="/var/lib/nefi/forensics/$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

echo "[NEFI] Starting evidence collection: $OUTPUT_DIR"
echo "[NEFI] Timestamp: $TIMESTAMP"

# ── 1. System info ──────────────────────────────────────
echo "[NEFI] Collecting system information..."
mkdir -p "$OUTPUT_DIR/system"
uname -a > "$OUTPUT_DIR/system/uname.txt"
hostname >> "$OUTPUT_DIR/system/uname.txt"
date >> "$OUTPUT_DIR/system/uname.txt"
uptime >> "$OUTPUT_DIR/system/uptime.txt"
who > "$OUTPUT_DIR/system/logged-users.txt"
last -20 > "$OUTPUT_DIR/system/last-logins.txt" 2>/dev/null || echo "last command not available" > "$OUTPUT_DIR/system/last-logins.txt" 2>/dev/null || echo "last command not available" > "$OUTPUT_DIR/system/last-logins.txt"
id > "$OUTPUT_DIR/system/current-user.txt"

# ── 2. Process snapshot ─────────────────────────────────
echo "[NEFI] Capturing process snapshot..."
mkdir -p "$OUTPUT_DIR/processes"
ps auxf > "$OUTPUT_DIR/processes/ps-tree.txt"
ps -eo pid,ppid,user,stat,start,time,comm,args > "$OUTPUT_DIR/processes/ps-full.txt"
ls -la /proc/*/exe 2>/dev/null > "$OUTPUT_DIR/processes/proc-exe.txt" || true

# ── 3. Network snapshot ─────────────────────────────────
echo "[NEFI] Capturing network state..."
mkdir -p "$OUTPUT_DIR/network"
ss -tulnp > "$OUTPUT_DIR/network/listening-ports.txt"
ss -tnp state established > "$OUTPUT_DIR/network/established-connections.txt"
ip addr > "$OUTPUT_DIR/network/ip-addresses.txt"
ip route > "$OUTPUT_DIR/network/routing-table.txt"
arp -n > "$OUTPUT_DIR/network/arp-table.txt" 2>/dev/null || true
cat /etc/hosts > "$OUTPUT_DIR/network/hosts.txt"

# ── 4. Log collection ───────────────────────────────────
echo "[NEFI] Collecting logs..."
mkdir -p "$OUTPUT_DIR/logs"
journalctl -n 5000 --no-pager -o short-iso > "$OUTPUT_DIR/logs/journal.txt" 2>/dev/null || true
journalctl -n 1000 --no-pager -p warning > "$OUTPUT_DIR/logs/journal-warnings.txt" 2>/dev/null || true
cp /var/log/auth.log "$OUTPUT_DIR/logs/" 2>/dev/null || true
cp /var/log/syslog "$OUTPUT_DIR/logs/" 2>/dev/null || true
ls -la /var/log/ > "$OUTPUT_DIR/logs/logfiles-list.txt"

# ── 5. File integrity ───────────────────────────────────
echo "[NEFI] Hashing critical files..."
mkdir -p "$OUTPUT_DIR/integrity"
CRITICAL_FILES="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts /etc/crontab"
for f in $CRITICAL_FILES; do
    if [ -f "$f" ]; then
        sha256sum "$f" >> "$OUTPUT_DIR/integrity/critical-files-hashes.txt"
    fi
done

# Hash di tutti i binari in /usr/bin e /usr/sbin
find /usr/bin /usr/sbin /bin /sbin -type f -exec sha256sum {} \; \
    > "$OUTPUT_DIR/integrity/system-binaries-hashes.txt" 2>/dev/null || true

# ── 6. Persistence check ────────────────────────────────
echo "[NEFI] Checking persistence mechanisms..."
mkdir -p "$OUTPUT_DIR/persistence"
crontab -l 2>/dev/null > "$OUTPUT_DIR/persistence/user-crontab.txt" || echo "No user crontab" > "$OUTPUT_DIR/persistence/user-crontab.txt"
cat /etc/crontab > "$OUTPUT_DIR/persistence/system-crontab.txt" 2>/dev/null || true
ls -la /etc/cron.d/ > "$OUTPUT_DIR/persistence/cron-d.txt" 2>/dev/null || true
ls -la /etc/cron.daily/ >> "$OUTPUT_DIR/persistence/cron-d.txt" 2>/dev/null || true
systemctl list-units --type=service --state=enabled > "$OUTPUT_DIR/persistence/enabled-services.txt" 2>/dev/null || true
ls -la /etc/systemd/system/ > "$OUTPUT_DIR/persistence/systemd-units.txt" 2>/dev/null || true

# ── 7. RAM dump (se possibile) ──────────────────────────
echo "[NEFI] Attempting RAM acquisition..."
mkdir -p "$OUTPUT_DIR/memory"
RAM_SIZE=$(free -m | awk '/^Mem:/{print $2}')
DISK_FREE=$(df -m /var/lib/nefi | awk 'NR==2{print $4}')

if [ "$DISK_FREE" -gt "$RAM_SIZE" ]; then
    echo "[NEFI] Sufficient disk space. Starting RAM dump ($RAM_SIZE MB)..."
    if command -v avml &>/dev/null; then
        avml "$OUTPUT_DIR/memory/ram.lime" 2>/dev/null && \
            echo "[NEFI] RAM dump completed with avml." || \
            echo "[NEFI] avml failed."
    else
        dd if=/dev/mem of="$OUTPUT_DIR/memory/ram-partial.bin" bs=1M count=64 2>/dev/null && \
            echo "[NEFI] Partial RAM dump (64MB) completed." || \
            echo "[NEFI] RAM dump not available (restricted /dev/mem)."
    fi
else
    echo "[NEFI] WARNING: Insufficient disk space for RAM dump. Skipping."
    echo "Disk free: ${DISK_FREE}MB, RAM: ${RAM_SIZE}MB" > "$OUTPUT_DIR/memory/ram-dump-skipped.txt"
fi

# ── 8. Timeline ─────────────────────────────────────────
echo "[NEFI] Building timeline..."
mkdir -p "$OUTPUT_DIR/timeline"
find / -newer /tmp -not -path "/proc/*" -not -path "/sys/*" \
    -not -path "/dev/*" -not -path "/run/*" \
    -printf "%T+ %p\n" 2>/dev/null | sort -r | head -500 \
    > "$OUTPUT_DIR/timeline/recently-modified-files.txt" || true

journalctl --since "24 hours ago" --no-pager -o short-iso \
    > "$OUTPUT_DIR/timeline/last-24h-events.txt" 2>/dev/null || true

# ── 9. Hash finale e manifest ───────────────────────────
echo "[NEFI] Creating evidence manifest..."
find "$OUTPUT_DIR" -type f -not -name "MANIFEST.txt" \
    -exec sha256sum {} \; > "$OUTPUT_DIR/MANIFEST.txt"

echo "[NEFI] Creating compressed archive..."
ARCHIVE="/var/lib/nefi/forensics/evidence-$TIMESTAMP.tar.gz"
tar -czf "$ARCHIVE" -C "/var/lib/nefi/forensics" "$TIMESTAMP" 2>/dev/null

SHA256=$(sha256sum "$ARCHIVE" | awk '{print $1}')
echo "$SHA256  evidence-$TIMESTAMP.tar.gz" > "$ARCHIVE.sha256"

echo ""
echo "[NEFI] ══════════════════════════════════════════"
echo "[NEFI] Evidence collection COMPLETED"
echo "[NEFI] Output directory: $OUTPUT_DIR"
echo "[NEFI] Archive: $ARCHIVE"
echo "[NEFI] Archive SHA256: $SHA256"
echo "[NEFI] ══════════════════════════════════════════"
