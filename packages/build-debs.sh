#!/bin/bash
# NEFI OS - costruisce tutti i pacchetti di packages/ in packages/out/
# Prima lancia i generatori (*-gen.sh), in ordine alfabetico.
# Ogni build ha una versione nuova (es. 0.2+202609301530): cosi' il mirror della ISO
# e gli aggiornamenti apt prendono sempre l'ultima.
set -euo pipefail
cd "$(dirname "$0")"
STAMP="$(date +%Y%m%d%H%M)"
mkdir -p out
for gen in *-gen.sh; do [ -f "$gen" ] && ./"$gen"; done
for dir in */; do
  pkg="${dir%/}"
  [ -f "$pkg/DEBIAN/control" ] || continue
  chmod -R go-w "$pkg"   # nessun file NEFI modificabile da utenti normali
  rm -f out/"${pkg}"_*.deb
  sed -i -E "s/^Version: ([^+]*).*/Version: \1+$STAMP/" "$pkg/DEBIAN/control"
  size="$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)"
  sed -i '/^Installed-Size:/d' "$pkg/DEBIAN/control"
  sed -i "/^Architecture:/a Installed-Size: $size" "$pkg/DEBIAN/control"
  # i pacchetti grossi (Ollama) si comprimono con gzip: molto piu' veloce
  Z=""; [ "$size" -gt 300000 ] && Z="-Zgzip"
  dpkg-deb --root-owner-group $Z --build "$pkg" out/ > /dev/null
  echo "[NEFI] pacchetto: $(ls out/"${pkg}"_*.deb)"
done
