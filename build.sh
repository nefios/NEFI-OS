#!/bin/bash
# NEFI OS — build ISO e copia nella cartella condivisa
START=$(date +%s)
cd ~/nefi-os || exit 1

echo "══ [1/3] Controllo sintassi moduli ══"
if ! python3 -m py_compile config/includes.chroot/usr/lib/nefi/modules/*.py \
        config/includes.chroot/usr/bin/nefi-security-center \
        config/includes.chroot/opt/nefi/*/*.py; then
    echo "✗ Errore di sintassi: build annullata. Correggi l'errore qui sopra."
    exit 1
fi
echo "✓ Nessun errore di sintassi"

echo "══ [2/3] Build ISO ══"
sudo lb clean --purge
lb config \
  --distribution trixie \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --archive-areas "main contrib non-free non-free-firmware" \
  --image-name nefi-os \
  --iso-application "NEFI OS" \
  --iso-volume "NEFI OS 0.1" \
  --iso-publisher "NEFI OS Project" \
  --bootappend-live "boot=live components quiet splash hostname=nefiOS username=nefi locales=it_IT.UTF-8 keyboard-layouts=it" \
  --mirror-bootstrap "http://ftp.it.debian.org/debian/" \
  --mirror-binary "http://ftp.it.debian.org/debian/"
sudo lb build 2>&1 | tee ~/nefi-os-build.log

ISO=~/nefi-os/nefi-os-amd64.hybrid.iso
if [ ! -f "$ISO" ]; then
    echo "✗ Build fallita: ISO non creata. Ultime righe del log:"
    tail -20 ~/nefi-os-build.log
    exit 1
fi

echo "══ [3/3] Copia nella cartella condivisa ══"
sudo cp "$ISO" /mnt/condivisa/ || { echo "✗ Copia fallita: la cartella condivisa è montata?"; exit 1; }

MIN=$(( ($(date +%s) - START) / 60 ))
echo "✓ Build completata in $MIN minuti — ISO pronta in ~/condivisa sull'host ($(du -h "$ISO" | cut -f1))"
