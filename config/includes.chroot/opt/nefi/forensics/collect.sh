#!/bin/bash
# NEFI Forensics Collector
# Le prove (log di autenticazione, argomenti dei processi, rete, memoria) sono dati sensibili:
#   /var/lib/nefi/forensics                 root:sudo 0750  gli amministratori vedono SOLO i nomi
#   <raccolta>/ e sottocartelle             root:root 0700
#   file, archivio .tar.gz, MANIFEST        root:root 0600
#   archivio.sha256                         root:sudo 0640  solo l'hash (mostrato dal Security Center)
# Valido qualunque sia l'umask di chi lancia lo script.
set -e
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "[NEFI] ERROR: run as root (pkexec)." >&2
    exit 1
fi

BASE="/var/lib/nefi/forensics"
# dfir.py passa la cartella dell'archivio delle prove (anche un disco esterno) e l'identificativo univoco
if [ -n "${NEFI_EV_BASE:-}" ]; then
    case "$NEFI_EV_BASE" in /*) [ -d "$NEFI_EV_BASE" ] && BASE="$NEFI_EV_BASE" ;; esac
fi
ADMIN_GROUP="sudo"
getent group "$ADMIN_GROUP" > /dev/null || ADMIN_GROUP="root"

install -d -m 0755 -o root -g root /var/lib/nefi
install -d -m 0750 -o root -g "$ADMIN_GROUP" "$BASE"
chown root:"$ADMIN_GROUP" "$BASE"
chmod 0750 "$BASE"

# prove raccolte dalle versioni precedenti (create con permessi aperti): le chiudo.
# Solo quelle: manifest, indice e registro di custodia hanno i loro permessi (vedi custody.py).
for old in "$BASE"/20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]_*; do
    [ -d "$old" ] && [ ! -L "$old" ] || continue
    chown -R root:root "$old"
    chmod -R u=rwX,go= "$old"
done
for old in "$BASE"/evidence-*.tar.gz; do
    [ -f "$old" ] && [ ! -L "$old" ] || continue
    chown root:root "$old"; chmod 0600 "$old"
    [ -f "$old.sha256" ] && { chown root:"$ADMIN_GROUP" "$old.sha256"; chmod 0640 "$old.sha256"; }
done

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
NAME="$TIMESTAMP"
ARCHIVE_NAME="evidence-$TIMESTAMP"
if [[ "${NEFI_EV_NAME:-}" =~ ^NEFI-EV-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$ ]]; then
    NAME="$NEFI_EV_NAME"
    ARCHIVE_NAME="$NEFI_EV_NAME"
fi
OUTPUT_DIR="$BASE/$NAME"
if [ -e "$OUTPUT_DIR" ]; then
    echo "[NEFI] ERROR: $OUTPUT_DIR already exists (two collections in the same second)." >&2
    exit 1
fi
install -d -m 0700 -o root -g root "$OUTPUT_DIR"

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
last -20 > "$OUTPUT_DIR/system/last-logins.txt" 2>/dev/null || echo "last command not available" > "$OUTPUT_DIR/system/last-logins.txt"
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

# ── 7. Memoria ──────────────────────────────────────────
# La RAM non si acquisisce piu' qui: i vecchi 64 MB letti da /dev/mem non erano una prova utilizzabile.
# L'acquisizione completa e verificata (AVML) e' una prova a se': DFIR > Memory Forensics.
mkdir -p "$OUTPUT_DIR/memory"
{
    echo "Memory is acquired separately as its own signed evidence (DFIR > Memory Forensics, AVML)."
    echo "RAM installed: $(free -m | awk '/^Mem:/{print $2}') MB"
    echo "Kernel lockdown: $(cat /sys/kernel/security/lockdown 2>/dev/null || echo unknown)"
} > "$OUTPUT_DIR/memory/README.txt"

# ── 8. Timeline (prima ispezione) ───────────────────────
# Qui solo un'istantanea veloce. La timeline forense strutturata (tempi MACB, journal, accessi,
# pacchetti, browser, avvisi) si costruisce da DFIR > Timeline.
echo "[NEFI] Building quick timeline..."
mkdir -p "$OUTPUT_DIR/timeline"
find /etc /home /root /tmp /var/tmp /usr/local /opt -xdev -mtime -2 -type f \
    -printf "%TY-%Tm-%TdT%TH:%TM:%.2TS%Tz %p\n" 2>/dev/null | sort -r | head -2000 \
    > "$OUTPUT_DIR/timeline/files-modified-last-48h.txt" || true

journalctl --since "24 hours ago" --no-pager -o short-iso \
    > "$OUTPUT_DIR/timeline/last-24h-events.txt" 2>/dev/null || true

# ── 9. Hash finale e manifest ───────────────────────────
echo "[NEFI] Creating evidence manifest..."
find "$OUTPUT_DIR" -type f -not -name "MANIFEST.txt" \
    -exec sha256sum {} \; > "$OUTPUT_DIR/MANIFEST.txt"

echo "[NEFI] Creating compressed archive..."
ARCHIVE="$BASE/$ARCHIVE_NAME.tar.gz"
tar -czf "$ARCHIVE" -C "$BASE" "$NAME" 2>/dev/null

SHA256=$(sha256sum "$ARCHIVE" | awk '{print $1}')
echo "$SHA256  $ARCHIVE_NAME.tar.gz" > "$ARCHIVE.sha256"

# ── 10. Permessi finali (anche per file creati da programmi che ignorano l'umask) ──
chown -R root:root "$OUTPUT_DIR" "$ARCHIVE"
chmod -R u=rwX,go= "$OUTPUT_DIR"
chmod 0600 "$ARCHIVE"
chown root:"$ADMIN_GROUP" "$ARCHIVE.sha256"
chmod 0640 "$ARCHIVE.sha256"
if [ -n "$(find "$OUTPUT_DIR" "$ARCHIVE" -perm /077 -print -quit)" ]; then
    echo "[NEFI] ERROR: some evidence files are still readable by other users." >&2
    exit 1
fi
echo "[NEFI] Permissions: evidence readable by root only."

echo ""
echo "[NEFI] ══════════════════════════════════════════"
echo "[NEFI] Evidence collection COMPLETED"
echo "[NEFI] Output directory: $OUTPUT_DIR"
echo "[NEFI] Archive: $ARCHIVE"
echo "[NEFI] Archive SHA256: $SHA256"
echo "[NEFI] ══════════════════════════════════════════"
