#!/bin/bash
# NEFI OS - strumenti per la memoria: AVML (acquisizione) e Volatility 3 (analisi)
# Uso: pkexec /opt/nefi/forensics/install-memory-tools.sh            installa AVML e Volatility 3
#      pkexec /opt/nefi/forensics/install-memory-tools.sh symbols    crea la tabella dei simboli di QUESTO kernel
#
# - AVML: binario ufficiale Microsoft (github.com/microsoft/avml), versione fissata e controllata con SHA-256
# - Volatility 3: da PyPI in un ambiente isolato (/opt/nefi/forensics/vol3), versione fissata
# - simboli: Volatility deve conoscere le strutture del kernel acquisito. "symbols" scarica il pacchetto di
#   debug del kernel in uso (circa 1 GB, poi rimosso) e lo converte con dwarf2json (ufficiale, SHA-256 fisso).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "[NEFI] Root required (pkexec)"; exit 1; }

AVML_VER="v0.17.0"
AVML_SHA="ee4684814a0efbf08c5e9b3ed34dc65f94496054cab87835035f48db9dc484ff"
VOL_VER="2.26.2"
D2J_VER="v0.9.0"
D2J_SHA="e2e75ba5bc9c22bc38a48edffbb050456d089d54998d54f46cb580223d9fbc6b"
BASE=/opt/nefi/forensics
SYMBOLS="$BASE/symbols/linux"

fetch() {   # fetch <url> <sha256> <destinazione>: scarica e installa solo se l'hash coincide
    local tmp; tmp="$(mktemp)"
    curl -fsSL --proto '=https' --max-filesize 50000000 "$1" -o "$tmp"
    if [ "$(sha256sum "$tmp" | cut -d' ' -f1)" != "$2" ]; then
        rm -f "$tmp"; echo "[NEFI] ERROR: checksum mismatch for $1 - nothing installed"; exit 1
    fi
    install -m 0755 -o root -g root "$tmp" "$3"; rm -f "$tmp"
}

if [ "${1:-}" = "symbols" ]; then
    KVER="$(uname -r)"
    OUT="$SYMBOLS/debian-$KVER.json.xz"
    [ -f "$OUT" ] && { echo "[NEFI] Symbols for $KVER already present: $OUT"; exit 0; }
    echo "[NEFI] 1/4 dwarf2json $D2J_VER..."
    apt-get install -y -q curl ca-certificates xz-utils > /dev/null
    fetch "https://github.com/volatilityfoundation/dwarf2json/releases/download/$D2J_VER/dwarf2json-linux-amd64" "$D2J_SHA" /usr/local/bin/dwarf2json
    echo "[NEFI] 2/4 Kernel debug package for $KVER (about 1 GB download)..."
    CODENAME="$(. /etc/os-release; echo "${VERSION_CODENAME:-trixie}")"
    LIST=/etc/apt/sources.list.d/nefi-debian-debug.list
    echo "deb http://deb.debian.org/debian-debug ${CODENAME}-debug main" > "$LIST"
    echo "deb http://deb.debian.org/debian-debug ${CODENAME}-proposed-updates-debug main" >> "$LIST"
    apt-get update -q > /dev/null || true
    cleanup() { apt-get purge -y -q "linux-image-$KVER-dbg" > /dev/null 2>&1 || true; rm -f "$LIST"; apt-get update -q > /dev/null 2>&1 || true; }
    trap cleanup EXIT
    apt-get install -y -q "linux-image-$KVER-dbg"
    VMLINUX="/usr/lib/debug/boot/vmlinux-$KVER"
    [ -f "$VMLINUX" ] || { echo "[NEFI] ERROR: $VMLINUX not found"; exit 1; }
    echo "[NEFI] 3/4 Converting (a few minutes, needs about 4 GB of RAM)..."
    mkdir -p "$SYMBOLS"
    /usr/local/bin/dwarf2json linux --elf "$VMLINUX" --system-map "/boot/System.map-$KVER" | xz -T0 -1 > "$OUT.tmp"
    mv "$OUT.tmp" "$OUT"
    echo "[NEFI] 4/4 Removing the debug package..."
    echo "[NEFI] Symbols ready: $OUT ($(du -h "$OUT" | cut -f1))"
    echo "[NEFI] Keep a copy with the memory images: it is needed to analyse them on another machine."
    exit 0
fi

echo "[NEFI] 1/3 AVML $AVML_VER (memory acquisition)..."
apt-get install -y -q curl ca-certificates python3-venv > /dev/null
fetch "https://github.com/microsoft/avml/releases/download/$AVML_VER/avml" "$AVML_SHA" /usr/local/bin/avml
echo "[NEFI]     $(/usr/local/bin/avml --version)"

echo "[NEFI] 2/3 Volatility 3 $VOL_VER (memory analysis, isolated environment)..."
rm -rf "$BASE/vol3"
python3 -m venv "$BASE/vol3"
"$BASE/vol3/bin/pip" install --quiet --no-input --disable-pip-version-check "volatility3==$VOL_VER"
"$BASE/vol3/bin/vol" -h > /dev/null
mkdir -p "$SYMBOLS" /var/cache/nefi-vol3
chmod -R go-w "$BASE/vol3"
echo "[NEFI]     installed in $BASE/vol3"

echo "[NEFI] 3/3 Kernel protections..."
LOCK="$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null || echo none)"
if [ "$LOCK" != "none" ] && [ -n "$LOCK" ]; then
    echo "[NEFI] WARNING: the kernel is in lockdown mode ($LOCK) because of Secure Boot."
    echo "[NEFI]          Lockdown blocks reading physical memory from the running system, so AVML cannot"
    echo "[NEFI]          acquire THIS machine. Options: snapshot from the hypervisor (virtual machines),"
    echo "[NEFI]          or one boot with Secure Boot disabled. Analysis of images from elsewhere works."
else
    echo "[NEFI]     no kernel lockdown: acquisition of this machine is possible."
fi
echo "[NEFI] Done. For process lists and other Linux plugins create the symbols of this kernel:"
echo "[NEFI]   Memory Forensics > Create kernel symbols"
