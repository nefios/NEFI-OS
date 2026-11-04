#!/bin/bash
# NEFI OS - installa e configura Falco (rilevamento a runtime, progetto CNCF)
# Uso: pkexec /opt/nefi/falco/install.sh      (lanciato dal Security Center)
#
# - repository ufficiale di Falco, firmato con la loro chiave
# - driver "modern eBPF": niente moduli del kernel da compilare (compatibile con
#   Secure Boot e con il blocco dei compilatori di NEFI)
# - eventi in formato JSON in /var/log/falco/events.json, leggibile dal gruppo sudo
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "[NEFI] Serve root (pkexec)"; exit 1; }

KEYRING=/usr/share/keyrings/falco-archive-keyring.gpg
LIST=/etc/apt/sources.list.d/falcosecurity.list
LOGDIR=/var/log/falco
EVENTS="$LOGDIR/events.json"
SERVICE=falco-modern-bpf.service

echo "[NEFI] 1/5 Chiave del repository di Falco..."
apt-get install -y -q curl gnupg ca-certificates > /dev/null
TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY"' EXIT
curl -fsSL --proto '=https' https://falco.org/repo/falcosecurity-packages.asc -o "$TMPKEY"
gpg --dearmor --yes -o "$KEYRING" "$TMPKEY"
chmod 644 "$KEYRING"
echo "[NEFI]     impronta della chiave:"
gpg --show-keys --with-fingerprint "$TMPKEY" 2>/dev/null | sed -n '2p' | sed 's/^ */           /'

echo "[NEFI] 2/5 Repository..."
echo "deb [signed-by=$KEYRING] https://download.falco.org/packages/deb stable main" > "$LIST"
apt-get update -q > /dev/null

echo "[NEFI] 3/5 Installazione di Falco (driver modern eBPF, nessuna domanda)..."
export DEBIAN_FRONTEND=noninteractive FALCO_FRONTEND=noninteractive \
       FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no
apt-get install -y -q falco

echo "[NEFI] 4/5 Configurazione NEFI..."
mkdir -p /etc/falco/config.d
cat > /etc/falco/config.d/50-nefi.yaml << 'YAML'
# NEFI OS - eventi in JSON su file, letti dal Security Center (Detection > Runtime Alerts)
json_output: true
json_include_output_property: true
json_include_tags_property: true
priority: notice
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/events.json
YAML
# il file degli eventi esiste prima che Falco parta, con permessi root:sudo 0640,
# cosi' gli amministratori lo leggono dal Security Center senza password
mkdir -p "/etc/systemd/system/$SERVICE.d"
cat > "/etc/systemd/system/$SERVICE.d/50-nefi.conf" << 'UNIT'
[Service]
ExecStartPre=+/usr/bin/install -d -m 0750 -o root -g sudo /var/log/falco
ExecStartPre=+/bin/sh -c 'touch /var/log/falco/events.json && chown root:sudo /var/log/falco/events.json && chmod 0640 /var/log/falco/events.json'
UNIT
# rotazione del file degli eventi
cat > /etc/logrotate.d/nefi-falco << 'ROT'
/var/log/falco/events.json {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0640 root sudo
    copytruncate
}
ROT

echo "[NEFI] 5/5 Avvio del servizio..."
systemctl daemon-reload
systemctl enable "$SERVICE" > /dev/null 2>&1 || true
systemctl restart "$SERVICE"
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
    echo "[NEFI] FATTO: Falco attivo ($SERVICE). Eventi in $EVENTS"
else
    echo "[NEFI] ERRORE: Falco non e' partito. Ultime righe del log:"
    journalctl -u "$SERVICE" -n 20 --no-pager
    exit 1
fi
