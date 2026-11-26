#!/bin/bash
# NEFI OS - collega questa macchina a un server Wazuh ESISTENTE (installa l'agente ufficiale)
# Uso: pkexec /opt/nefi/detection/install-wazuh.sh <indirizzo-del-manager> [versione-agente]
#
# - l'agente da solo non serve: ha bisogno di un Wazuh manager gia' in funzione sulla tua rete
# - l'agente NON puo' essere piu' nuovo del manager: se il manager e' piu' vecchio, indica la versione
#   (es. 4.9.2); il pacchetto viene poi bloccato per non aggiornarsi oltre il manager
# - gli avvisi di NEFI (/var/log/nefi/detection/alerts.jsonl) vengono inviati al manager
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "[NEFI] Root required (pkexec)"; exit 1; }

MANAGER="${1:-}"
VERSION="${2:-}"
if ! [[ "$MANAGER" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
    echo "[NEFI] ERROR: give the address of your Wazuh manager (host name or IP)."; exit 1
fi
if [ -n "$VERSION" ] && ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "[NEFI] ERROR: the version must look like 4.9.2"; exit 1
fi

KEYRING=/usr/share/keyrings/wazuh.gpg
LIST=/etc/apt/sources.list.d/wazuh.list
CONF=/var/ossec/etc/ossec.conf

echo "[NEFI] 1/4 Wazuh repository key..."
apt-get install -y -q curl gnupg ca-certificates > /dev/null
TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY"' EXIT
curl -fsSL --proto '=https' https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "$TMPKEY"
gpg --dearmor --yes -o "$KEYRING" "$TMPKEY"
chmod 644 "$KEYRING"
echo "[NEFI]     key fingerprint:"
gpg --show-keys --with-fingerprint "$TMPKEY" 2>/dev/null | sed -n '2p' | sed 's/^ */           /'

echo "[NEFI] 2/4 Repository and agent (manager: $MANAGER)..."
echo "deb [signed-by=$KEYRING] https://packages.wazuh.com/4.x/apt/ stable main" > "$LIST"
apt-get update -q > /dev/null
PKG="wazuh-agent"
[ -n "$VERSION" ] && PKG="wazuh-agent=${VERSION}-1"
WAZUH_MANAGER="$MANAGER" DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades "$PKG"
apt-mark hold wazuh-agent > /dev/null
echo "[NEFI]     package held: it will not be upgraded beyond your manager automatically."

echo "[NEFI] 3/4 Configuration..."
[ -f "$CONF" ] || { echo "[NEFI] ERROR: $CONF not found"; exit 1; }
cp -a "$CONF" "$CONF.nefi-backup"
# indirizzo del manager (anche se l'agente era gia' installato con un altro indirizzo)
sed -i "0,/<address>[^<]*<\/address>/s//<address>${MANAGER}<\/address>/" "$CONF"
# gli avvisi del motore NEFI vanno al manager
if ! grep -q "/var/log/nefi/detection/alerts.jsonl" "$CONF"; then
    cat >> "$CONF" << 'XML'

<ossec_config>
  <!-- NEFI OS: alerts of the NEFI detection engine -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/nefi/detection/alerts.jsonl</location>
    <label key="source">nefi-detectd</label>
  </localfile>
</ossec_config>
XML
fi

echo "[NEFI] 4/4 Service..."
systemctl daemon-reload
systemctl enable wazuh-agent.service > /dev/null 2>&1 || true
systemctl restart wazuh-agent.service
sleep 5
if systemctl is-active --quiet wazuh-agent.service; then
    echo "[NEFI] The Wazuh agent is running and pointing to $MANAGER."
    echo "[NEFI] On the manager, check that this agent appears as 'active' (ports 1514 and 1515 must be reachable)."
    grep -m1 -i "connected to the server\|unable to connect" /var/ossec/logs/ossec.log 2>/dev/null | sed 's/^/[NEFI]     /' || true
else
    echo "[NEFI] ERROR: the agent did not start. See /var/ossec/logs/ossec.log"
    exit 1
fi
