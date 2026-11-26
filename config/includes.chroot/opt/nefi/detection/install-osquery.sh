#!/bin/bash
# NEFI OS - installa osquery (inventario del sistema interrogabile con SQL) dal repository ufficiale
# Uso: pkexec /opt/nefi/detection/install-osquery.sh      (lanciato dal Security Center)
#
# - repository ufficiale pkg.osquery.io, firmato con la loro chiave
# - query pianificate "nefi_*": i cambiamenti finiscono in /var/log/osquery/osqueryd.results.log,
#   che il motore di rilevamento (nefi-detectd) legge come fonte in piu'
# - osqueryi resta disponibile per le ricerche a mano (Detection > Threat Hunting)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "[NEFI] Root required (pkexec)"; exit 1; }

KEYRING=/usr/share/keyrings/osquery-archive-keyring.gpg
LIST=/etc/apt/sources.list.d/osquery.list

echo "[NEFI] 1/4 osquery repository key..."
apt-get install -y -q curl gnupg ca-certificates > /dev/null
TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY"' EXIT
curl -fsSL --proto '=https' https://pkg.osquery.io/deb/pubkey.gpg -o "$TMPKEY"
gpg --dearmor --yes -o "$KEYRING" "$TMPKEY"
chmod 644 "$KEYRING"
echo "[NEFI]     key fingerprint:"
gpg --show-keys --with-fingerprint "$TMPKEY" 2>/dev/null | sed -n '2p' | sed 's/^ */           /'

echo "[NEFI] 2/4 Repository and package..."
echo "deb [arch=amd64 signed-by=$KEYRING] https://pkg.osquery.io/deb deb main" > "$LIST"
apt-get update -q > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -q osquery

echo "[NEFI] 3/4 NEFI configuration (scheduled queries)..."
mkdir -p /etc/osquery /var/log/osquery
cat > /etc/osquery/osquery.conf << 'JSON'
{
  "options": {
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "schedule_splay_percent": "10",
    "events_expiry": "3600",
    "host_identifier": "hostname",
    "utc": "true"
  },
  "schedule": {
    "nefi_process_deleted_binary": {
      "query": "SELECT pid, name, path, cmdline, uid FROM processes WHERE on_disk = 0 AND path != '';",
      "interval": 300, "description": "Processes whose program file was deleted"
    },
    "nefi_process_ld_preload": {
      "query": "SELECT pid, key, value FROM process_envs WHERE key = 'LD_PRELOAD' AND value != '';",
      "interval": 600, "description": "Processes started with a preloaded library"
    },
    "nefi_usb_devices": {
      "query": "SELECT vendor, model, serial, class FROM usb_devices;",
      "interval": 120, "description": "USB devices"
    },
    "nefi_logged_in_users": {
      "query": "SELECT user, host, tty, type FROM logged_in_users WHERE type = 'user';",
      "interval": 120, "description": "Login sessions"
    },
    "nefi_etc_hosts": {
      "query": "SELECT address, hostnames FROM etc_hosts;",
      "interval": 900, "description": "/etc/hosts entries"
    },
    "nefi_apt_sources": {
      "query": "SELECT name, base_uri, release, components FROM apt_sources;",
      "interval": 1800, "description": "APT repositories"
    },
    "nefi_kernel_modules": {
      "query": "SELECT name, size, status FROM kernel_modules;",
      "interval": 600, "description": "Loaded kernel modules"
    },
    "nefi_deb_packages": {
      "query": "SELECT name, version, source FROM deb_packages;",
      "interval": 3600, "description": "Installed packages"
    },
    "nefi_mounts": {
      "query": "SELECT device, path, type FROM mounts WHERE type NOT IN ('proc','sysfs','tmpfs','devtmpfs','cgroup2','devpts','securityfs','debugfs','tracefs','pstore','bpf','autofs','mqueue','hugetlbfs','fusectl','configfs','efivarfs','binfmt_misc','overlay','squashfs','nsfs','ramfs');",
      "interval": 300, "description": "Mounted filesystems"
    }
  }
}
JSON
chmod 640 /etc/osquery/osquery.conf
echo "[NEFI]     checking the configuration..."
osqueryd --config_path=/etc/osquery/osquery.conf --config_check

echo "[NEFI] 4/4 Service..."
systemctl enable osqueryd.service > /dev/null 2>&1 || true
systemctl restart osqueryd.service
sleep 2
if systemctl is-active --quiet osqueryd.service; then
    echo "[NEFI] osquery is running. The detection engine reads its results automatically."
    echo "[NEFI] Try a query in Detection > Threat Hunting."
else
    echo "[NEFI] ERROR: osqueryd did not start. See: journalctl -u osqueryd"
    exit 1
fi
