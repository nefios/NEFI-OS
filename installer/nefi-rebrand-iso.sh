#!/bin/bash
# NEFI OS - applica la grafica NEFI alla ISO prodotta da simple-cdd.
# Uso: ./nefi-rebrand-iso.sh [ISO-di-ingresso] [ISO-di-uscita]
# L'avvio (BIOS/UEFI/Secure Boot) resta identico: cambiano solo grafica, testi, etichetta.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
VERSION="${NEFI_VERSION:-0.2}"
IN="${1:-$HERE/images/debian-13-amd64-DVD-1.iso}"
OUT="${2:-$HERE/images/nefi-os-$VERSION-amd64.iso}"
ASSETS="$REPO/branding/installer"
GEN="$ASSETS/generated"
SRC_IMG="$ASSETS/sfondo-installer.jpg"
W="$(mktemp -d /tmp/nefi-rebrand.XXXXXX)"
trap 'rm -rf "$W"' EXIT
MAPS=()
CHANGED=()
say() { echo "[NEFI] $*"; }
map_file() { MAPS+=(-map "$1" "$2"); CHANGED+=("$1|$2"); }

[ -f "$IN" ] || { echo "ISO di ingresso non trovata: $IN"; exit 1; }
[ -f "$SRC_IMG" ] || { echo "Manca $SRC_IMG"; exit 1; }

# 0. Immagini
if [ ! -f "$GEN/splash-640x480.png" ]; then
  say "Genero le immagini dell'installer..."
  python3 "$ASSETS/make-installer-assets.py" "$SRC_IMG" "$GEN"
fi

# 1. Estrazione
say "Estraggo i file dalla ISO..."
xorriso -osirrox on -indev "$IN" \
  -extract /isolinux "$W/isolinux" \
  -extract /boot/grub/theme "$W/theme" \
  -extract /boot/grub/grub.cfg "$W/grub.cfg" \
  -extract /install.amd/gtk/initrd.gz "$W/initrd.gz" \
  -extract /md5sum.txt "$W/md5sum.txt" 2>/dev/null
chmod -R u+w "$W"

# 2. Menu BIOS (isolinux)
say "Menu di avvio BIOS..."
cp "$GEN/splash-640x480.png" "$W/isolinux/splash.png"
map_file "$W/isolinux/splash.png" /isolinux/splash.png
cat > "$W/isolinux/stdmenu.cfg" << 'EOF'
menu background splash.png
# Colori NEFI: #AARRGGBB (AA = opacita')
menu color screen * #00000000 #00000000 none
menu color border * #00000000 #00000000 none
menu color title * #ff9be36a #e0051f04 none
menu color unsel * #ffe6f2dc #c8051f04 none
menu color hotkey * #ff9be36a #c8051f04 none
menu color sel * #ffffffff #ff4c9a2a none
menu color hotsel * #ffffffff #ff4c9a2a none
menu color disabled * #ff6f8a66 #c8051f04 none
menu color scrollbar * #ff7dba52 #c8051f04 none
menu color tabmsg * #ffb8d8a8 #00000000 none
menu color cmdmark * #ff7dba52 #00000000 none
menu color cmdline * #ffe6f2dc #00000000 none
menu color timeout_msg * #ffe6f2dc #00000000 none
menu color timeout * #ff9be36a #00000000 none
menu color help * #ffe6f2dc #00000000 none
menu vshift 8
menu rows 12
menu helpmsgrow 23
menu cmdlinerow 25
menu timeoutrow 25
menu tabmsgrow 27
menu tabmsg Press ENTER to boot or TAB to edit a menu entry
EOF
sed -i 's#Debian GNU/Linux#NEFI OS#g' "$W"/isolinux/*.cfg
for f in "$W"/isolinux/*.cfg; do map_file "$f" "/isolinux/$(basename "$f")"; done

# 3. Menu UEFI (GRUB)
say "Menu di avvio UEFI..."
cp "$GEN/bg-1024x768.png" "$W/nefi-bg.png"
map_file "$W/nefi-bg.png" /boot/grub/nefi-bg.png
# Lo sfondo si disegna SOLO nel tema: niente immagine ripetuta all'avvio dell'installer
sed -i -e 's#^if background_image .*; then#if true; then#' \
       -e 's#Debian GNU/Linux#NEFI OS#g' "$W/grub.cfg"
map_file "$W/grub.cfg" /boot/grub/grub.cfg
python3 - "$W/theme" << 'PYEOF'
import sys, os
from PIL import Image
d = sys.argv[1]
LIME, DARK, SEL = (125, 186, 82, 255), (5, 31, 4, 215), (76, 154, 42, 255)
for name, col in [("c", DARK), ("n", LIME), ("s", LIME), ("e", LIME), ("w", LIME),
                  ("nw", LIME), ("ne", LIME), ("sw", LIME), ("se", LIME)]:
    Image.new("RGBA", (2, 2), col).save(os.path.join(d, f"menu_{name}.png"))
Image.new("RGBA", (8, 8), SEL).save(os.path.join(d, "hl_c.png"))
PYEOF
for f in "$W"/theme/*; do
  b="$(basename "$f")"
  case "$b" in
    *.png) map_file "$f" "/boot/grub/theme/$b"; continue ;;
    dark-*) continue ;;
  esac
  sed -i -e 's#^title-text:.*#title-text: ""#' \
    -e 's#^desktop-image:.*#desktop-image: "/boot/grub/nefi-bg.png"#' \
    -e 's#^desktop-color:.*#desktop-color: "\#010f00"#' \
    -e 's#Debian GNU/Linux#NEFI OS#g' \
    -e 's#UEFI Installer menu#installer menu (UEFI mode)#' \
    -e 's#^\(\s*\)top = 80\s*$#\1top = 172#' \
    -e 's#^\(\s*\)left = 45%\s*$#\1left = 20%#' \
    -e 's#^\(\s*\)top = 200\s*$#\1top = 205#' \
    -e 's#^\(\s*\)height = 200\s*$#\1height = 250#' \
    -e 's#^\(\s*\)width = 50%\s*$#\1width = 64%#' \
    -e 's#item_color = \#c0c0c0#item_color = "\#e6f2dc"#' \
    -e 's#selected_item_color = "black"#selected_item_color = "white"#' \
    -e 's#color = "\#c0c0c0"#color = "\#b8d8a8"#g' \
    -e '/installer menu/s#color = "[^"]*"#color = "\#9be36a"#' \
    -e 's#^\(\s*\)+ boot_menu {\s*$#\1+ boot_menu {\n\1 menu_pixmap_style = "menu_*.png"#' \
    "$f"
  map_file "$f" "/boot/grub/theme/$b"
done

# 4. Installer grafico: banner e colori (aggiunti in coda all'initrd GTK)
say "Installer grafico..."
mkdir -p "$W/di"
( cd "$W/di" && zcat "$W/initrd.gz" | cpio -idm --quiet \
    'usr/share/graphics/logo_*' 'usr/share/themes/Clearlooks/gtk-2.0/gtkrc' )
for png in "$W"/di/usr/share/graphics/logo_*.png; do
  size="$(python3 -c "from PIL import Image; i=Image.open('$png'); print(i.width, i.height)")"
  say "  $(basename "$png") (originale ${size/ /x})"
  python3 "$ASSETS/make-banner.py" "$SRC_IMG" $size "$png" > /dev/null
done
cat >> "$W/di/usr/share/themes/Clearlooks/gtk-2.0/gtkrc" << 'EOF'
# ---- NEFI OS: palette verde ----
style "nefi" {
  bg[NORMAL] = "#0b220a"
  bg[PRELIGHT] = "#1d4a17"
  bg[ACTIVE] = "#153a12"
  bg[SELECTED] = "#4c9a2a"
  bg[INSENSITIVE] = "#0b220a"
  fg[NORMAL] = "#e6f2dc"
  fg[PRELIGHT] = "#ffffff"
  fg[ACTIVE] = "#e6f2dc"
  fg[SELECTED] = "#ffffff"
  fg[INSENSITIVE] = "#6f8a66"
  base[NORMAL] = "#061806"
  base[ACTIVE] = "#2f6b22"
  base[SELECTED] = "#4c9a2a"
  base[INSENSITIVE] = "#0b220a"
  text[NORMAL] = "#e6f2dc"
  text[ACTIVE] = "#ffffff"
  text[SELECTED] = "#ffffff"
  text[INSENSITIVE] = "#6f8a66"
}
widget_class "*" style "nefi"
class "*" style "nefi"
EOF
( cd "$W/di" && find usr | cpio -o -H newc -R 0:0 --quiet | gzip -9 ) >> "$W/initrd.gz"
map_file "$W/initrd.gz" /install.amd/gtk/initrd.gz

# 5. md5sum.txt
say "Aggiorno md5sum.txt..."
for entry in "${CHANGED[@]}"; do
  local_file="${entry%%|*}"; iso_path=".${entry#*|}"
  sum="$(md5sum "$local_file" | cut -d' ' -f1)"
  if grep -q " ${iso_path}\$" "$W/md5sum.txt"; then
    sed -i "s#^[0-9a-f]\{32\}\s\+${iso_path}\$#${sum}  ${iso_path}#" "$W/md5sum.txt"
  else
    echo "${sum}  ${iso_path}" >> "$W/md5sum.txt"
  fi
done
MAPS+=(-map "$W/md5sum.txt" /md5sum.txt)

# 6. Nuova ISO (avvio identico all'originale)
say "Creo $OUT ..."
rm -f "$OUT"
xorriso -indev "$IN" -outdev "$OUT" \
  -boot_image any replay \
  -volid "NEFI_OS_${VERSION//./_}_AMD64" \
  "${MAPS[@]}" 2>&1 | grep -E 'FAILURE|SORRY|WARNING|completed successfully' || true
sha256sum "$OUT" > "$OUT.sha256"
say "FATTO - $(ls -lh "$OUT" | awk '{print $5, $9}')"
