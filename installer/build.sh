#!/bin/bash
# NEFI OS - build completa dell'installer con un solo comando:
# 0. pacchetti NEFI  1. metadati firmware (dep11)  2. simple-cdd  3. grafica NEFI  4. controlli
# Uso: ./build.sh   oppure   NEFI_VERSION=0.3 ./build.sh
set -uo pipefail
cd "$(dirname "$0")"
VERSION="${NEFI_VERSION:-0.2}"
DIST="trixie"
LOG="$HOME/nefi-installer-build.log"
BASE_ISO="images/debian-13-amd64-DVD-1.iso"
NEFI_ISO="images/nefi-os-$VERSION-amd64.iso"
MIRROR_URL="$(sed -n 's/^debian_mirror="\(.*\)"/\1/p' nefi.conf)"
MIRROR_URL="${MIRROR_URL%/}"
say() { echo "[NEFI] $*"; }

say "0/4 Pacchetti NEFI..."
../packages/build-debs.sh || { say "ERRORE: pacchetti NEFI"; exit 1; }

say "1/4 Metadati firmware (dep11)..."
for comp in main contrib non-free non-free-firmware; do
  dir="tmp/mirror/dists/$DIST/$comp/dep11"
  mkdir -p "$dir"
  if wget -q -N -P "$dir" "$MIRROR_URL/dists/$DIST/$comp/dep11/Components-amd64.yml.gz"; then
    echo "   $comp: ok"
  else
    echo "   $comp: NON scaricato"
  fi
done

say "2/4 simple-cdd (log completo: $LOG)..."
touch /tmp/nefi-build-start
build-simple-cdd --conf nefi.conf --dist "$DIST" > "$LOG" 2>&1
if [ ! "$BASE_ISO" -nt /tmp/nefi-build-start ]; then
  say "ERRORE: la ISO non e' stata creata. Ultime righe del log:"
  tail -25 "$LOG"
  grep -n "ERROR" tmp/log/build-debian-cd.log 2>/dev/null | tail -10
  exit 1
fi
grep "filled with" tmp/log/build-debian-cd.log | tail -1 | sed 's/^/   /'

say "3/4 Grafica NEFI..."
NEFI_VERSION="$VERSION" ./nefi-rebrand-iso.sh "$BASE_ISO" "$NEFI_ISO" | grep -E '^\[NEFI\] (FATTO|Creo)|FAILURE|SORRY' || true
[ -f "$NEFI_ISO" ] || { say "ERRORE: rebranding fallito"; exit 1; }

say "4/4 Controlli..."
ERR=0
if grep -q "ERROR: missing required" tmp/log/build-debian-cd.log; then
  grep "ERROR: missing required" tmp/log/build-debian-cd.log | sed 's/^/   /'; ERR=1
fi
LIST="$(zcat images/debian-13-amd64-DVD-1.list.gz)"
for p in $(grep -hv '^#' profiles/nefi.downloads profiles/nefi.packages 2>/dev/null); do
  grep -q "^${p}_" <<< "$LIST" || { echo "   MANCA SULLA ISO: $p"; ERR=1; }
done
FW="$(xorriso -indev "$NEFI_ISO" -find /firmware -type f 2>/dev/null | wc -l)"
echo "   file in /firmware sulla ISO: $FW"
[ "$FW" -gt 0 ] || { echo "   ATTENZIONE: nessun firmware nella cartella /firmware"; ERR=1; }
echo "   $(file -b "$NEFI_ISO" | cut -c1-80)"
ls -lh "$NEFI_ISO" | awk '{print "   " $5 "  " $9}'

# Copia nella cartella condivisa con Ubuntu
if [ -d /mnt/condivisa ]; then
  rm -f "/mnt/condivisa/$(basename "$NEFI_ISO")" "/mnt/condivisa/$(basename "$NEFI_ISO").sha256"
  cp "$NEFI_ISO" "$NEFI_ISO.sha256" /mnt/condivisa/ && echo "   copiata in /mnt/condivisa/$(basename "$NEFI_ISO")"
fi
if [ "$ERR" -eq 0 ]; then say "FATTO - build completata senza problemi"; else say "FATTO - build completata CON AVVISI (vedi sopra)"; fi
