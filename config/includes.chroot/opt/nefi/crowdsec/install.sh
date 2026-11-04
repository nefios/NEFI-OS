#!/bin/bash
# NEFI OS - installa e configura CrowdSec (rilevamento + blocco automatico degli indirizzi ostili)
# Uso: pkexec /bin/bash /opt/nefi/crowdsec/install.sh      (lanciato dal Security Center)
#
# - repository ufficiale di CrowdSec (packagecloud), firmato con la loro chiave
# - bouncer nftables: i blocchi vanno in tabelle proprie, il firewall di base di NEFI non si tocca
# - ogni 30 secondi lo stato (blocchi e avvisi) viene esportato in
#   /var/lib/nefi/crowdsec/state.json, leggibile dal gruppo sudo (pagina "Threat Blocking")
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "[NEFI] Root required (pkexec)"; exit 1; }

KEYRING=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg
LIST=/etc/apt/sources.list.d/crowdsec_crowdsec.list
HELPER=/opt/nefi/crowdsec/helper.py

echo "[NEFI] 1/5 CrowdSec repository key..."
apt-get install -y -q curl gnupg ca-certificates > /dev/null
mkdir -p /etc/apt/keyrings
TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY"' EXIT
curl -fsSL --proto '=https' https://packagecloud.io/crowdsec/crowdsec/gpgkey -o "$TMPKEY"
gpg --dearmor --yes -o "$KEYRING" "$TMPKEY"
chmod 644 "$KEYRING"
echo "[NEFI]     key fingerprint:"
gpg --show-keys --with-fingerprint "$TMPKEY" 2>/dev/null | sed -n '2p' | sed 's/^ */           /'

echo "[NEFI] 2/5 Repository..."
echo "deb [signed-by=$KEYRING] https://packagecloud.io/crowdsec/crowdsec/any any main" > "$LIST"
apt-get update -q > /dev/null

echo "[NEFI] 3/5 Installing CrowdSec, then the nftables firewall bouncer..."
export DEBIAN_FRONTEND=noninteractive
# prima il motore e POI il bouncer: se apt li configura insieme, il bouncer puo' essere
# configurato prima del motore e non riceve la chiave di accesso ("access forbidden")
apt-get install -y -q crowdsec
systemctl reload-or-restart crowdsec.service 2> /dev/null || true
apt-get install -y -q crowdsec-firewall-bouncer-nftables

# chiave del bouncer: se manca (o non e' valida) la creo io
BCONF=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
systemctl restart crowdsec-firewall-bouncer.service 2> /dev/null || true
sleep 4
if [ -f "$BCONF" ] && ! systemctl is-active --quiet crowdsec-firewall-bouncer.service; then
    echo "[NEFI]     registering the firewall bouncer with CrowdSec..."
    cscli bouncers delete nefi-firewall-bouncer > /dev/null 2>&1 || true
    KEY="$(cscli bouncers add nefi-firewall-bouncer -o raw)"
    [ -n "$KEY" ] || { echo "[NEFI] ERROR: cannot create the bouncer key"; exit 1; }
    sed -i "s|^api_key:.*|api_key: $KEY|" "$BCONF"
    unset KEY
    chmod 600 "$BCONF"
fi

echo "[NEFI] 4/5 NEFI configuration..."
install -d -m 0750 -o root -g sudo /var/lib/nefi/crowdsec
# export periodico dello stato per il Security Center
cat > /etc/systemd/system/nefi-crowdsec-export.service << 'UNIT'
[Unit]
Description=NEFI — export CrowdSec blocks and alerts for the Security Center
After=crowdsec.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/nefi/crowdsec/helper.py export
NoNewPrivileges=yes
PrivateTmp=yes
PrivateNetwork=no
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=/var/lib/nefi/crowdsec
UNIT
cat > /etc/systemd/system/nefi-crowdsec-export.timer << 'UNIT'
[Unit]
Description=NEFI — export CrowdSec state every 30 seconds

[Timer]
OnBootSec=1min
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
UNIT

echo "[NEFI] 5/5 Starting services..."
systemctl daemon-reload
systemctl enable --now crowdsec.service crowdsec-firewall-bouncer.service > /dev/null 2>&1 || true
systemctl enable --now nefi-crowdsec-export.timer > /dev/null 2>&1 || true
sleep 3
/usr/bin/python3 "$HELPER" export || true
ok=1
for s in crowdsec.service crowdsec-firewall-bouncer.service; do
    if systemctl is-active --quiet "$s"; then echo "[NEFI]     $s: active"
    else echo "[NEFI]     $s: NOT active"; journalctl -u "$s" -n 15 --no-pager; ok=0; fi
done
echo "[NEFI]     protections installed:"
cscli collections list 2>/dev/null | grep -E "crowdsecurity/" | awk '{print "           " $1}' | head -10
[ "$ok" -eq 1 ] && echo "[NEFI] DONE: CrowdSec is active" || { echo "[NEFI] ERROR: see the messages above"; exit 1; }
