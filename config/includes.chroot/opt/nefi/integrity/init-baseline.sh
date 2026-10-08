#!/bin/bash
# NEFI Integrity Control — Initialize AIDE database
echo "[NEFI] Initializing AIDE integrity database..."
echo "[NEFI] This process may take a few minutes."

mkdir -p /var/lib/aide
mkdir -p /var/log/nefi

# Rimuovi database vecchio se esiste
rm -f /var/lib/aide/aide.db /var/lib/aide/aide.db.new

aide --init --config=/etc/aide/aide.conf 2>&1 | tee /var/log/nefi/aide-init.log

# Controlla entrambi i possibili nomi output
if [ -f /var/lib/aide/aide.db.new ]; then
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    echo "[NEFI] SUCCESS: Baseline database created at /var/lib/aide/aide.db"
    ls -lh /var/lib/aide/aide.db
    exit 0
elif [ -f /var/lib/aide/aide.db.new.gz ]; then
    gunzip -f /var/lib/aide/aide.db.new.gz
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    echo "[NEFI] SUCCESS: Baseline database created at /var/lib/aide/aide.db"
    ls -lh /var/lib/aide/aide.db
    exit 0
else
    echo "[NEFI] ERROR: No database file found after init."
    echo "[NEFI] Files in /var/lib/aide/:"
    ls -la /var/lib/aide/ 2>/dev/null || echo "Directory empty or missing"
    exit 1
fi

# Allow all users to check if database exists (not read content)
sudo chmod 644 /var/lib/aide/aide.db 2>/dev/null || true
sudo chmod 755 /var/lib/aide/ 2>/dev/null || true
