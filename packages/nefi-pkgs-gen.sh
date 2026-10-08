#!/bin/bash
# NEFI OS - crea i sorgenti dei pacchetti NEFI dalla configurazione di live-build
# (config/includes.chroot + hook), con gli stessi file e gli stessi percorsi della ISO live:
#   nefi-security-center : app, moduli, script /opt/nefi, servizi, regola udev, impostazioni di sistema
#   nefi-desktop         : personalizzazione KDE (tema, colori, sfondi, pannelli, SDDM, splash, Plymouth)
#   nefi-ollama          : motore AI di Guardian (Ollama + librerie)
set -euo pipefail
cd "$(dirname "$0")"
umask 022
VER="0.2"
MAINT="NEFI OS Project <emanuel2005gabriel@gmail.com>"
LB="$HOME/nefi-os"
SRC="$LB/config/includes.chroot"
HOOKS="$LB/config/hooks/normal"
CHROOT="$LB/chroot"
PKGS="nefi-security-center nefi-desktop nefi-ollama"
[ -d "$SRC" ] || { echo "Manca $SRC"; exit 1; }

TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
for p in $PKGS; do rm -rf "$p"; mkdir -p "$p/DEBIAN"; done

# File che appartengono gia' a un pacchetto Debian (letti dall'ultima build live):
# non si possono sovrascrivere, quindi vengono "deviati" con dpkg-divert.
OWNED="$TMPD/owned"; : > "$OWNED"
if ls "$CHROOT"/var/lib/dpkg/info/*.list > /dev/null 2>&1; then
  cat "$CHROOT"/var/lib/dpkg/info/*.list | sort -u > "$OWNED"
else
  echo "   ATTENZIONE: $CHROOT non c'e' (build live pulita): salto il controllo dei file di Debian"
fi

# 1. Smistamento dei file di includes.chroot nei tre pacchetti
( cd "$SRC" && find . -mindepth 1 \( -type f -o -type l \) -printf '%P\n' | sort ) > "$TMPD/files"
while IFS= read -r f; do
  case "$f" in
    usr/local/bin/ollama|usr/local/lib/ollama/*|usr/local/bin/nefi-ollama*|etc/systemd/system/ollama.service|etc/systemd/system/ollama.service.d/*)
      pkg=nefi-ollama ;;
    etc/nftables.conf|etc/rkhunter.conf.local|etc/sysctl.d/*nefi*|etc/audit/rules.d/*nefi*|etc/ssh/sshd_config.d/*nefi*|\
    usr/bin/nefi-*|usr/lib/nefi/*|opt/nefi/*|usr/share/nefi/*|usr/share/applications/nefi-*|\
    etc/xdg/autostart/nefi-*|etc/systemd/system/nefi-*|etc/udev/rules.d/*nefi*|\
    usr/share/icons/*/nefi-security-center.*)
      pkg=nefi-security-center ;;
    usr/share/plasma/*|usr/share/color-schemes/*|usr/share/wallpapers/*|usr/share/icons/*|\
    etc/xdg/*|etc/sddm.conf.d/*|usr/share/sddm/*|usr/share/plymouth/*|etc/skel/*|usr/share/pixmaps/*)
      pkg=nefi-desktop ;;
    etc/live/*|var/lib/AccountsService/*)
      echo "   solo per la live, escluso: $f"; continue ;;
    *)
      echo "   NON ASSEGNATO (mandamelo): $f"; continue ;;
  esac
  mkdir -p "$pkg/$(dirname "$f")"
  cp -a "$SRC/$f" "$pkg/$f"
  if grep -qxF "/$f" "$OWNED"; then echo "/$f" >> "$TMPD/$pkg.divert"; fi
done < "$TMPD/files"

# Sul sistema installato niente accesso automatico dell'utente live
for c in nefi-desktop/etc/sddm.conf.d/*.conf; do
  [ -f "$c" ] || continue
  awk '/^\[/{skip=($0=="[Autologin]")} !skip' "$c" > "$TMPD/sddm" && cat "$TMPD/sddm" > "$c"
done

# Schermata di avvio Plymouth: serve "splash" nella riga di avvio del kernel
mkdir -p nefi-desktop/etc/default/grub.d
cat > nefi-desktop/etc/default/grub.d/nefi-splash.cfg << 'EOF'
# NEFI OS - schermata di avvio grafica (Plymouth)
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
EOF

# 2. Gli hook di live-build diventano script d'installazione (/usr/share/nefi/setup)
#    - "set -e" diventa "set +e": un comando che fallisce non deve bloccare l'installazione
#    - le righe sul nome macchina valgono solo per la live: l'utente lo sceglie nell'installer
hook() {
  local pkg="$1" name="$2" src="$HOOKS/$2.hook.chroot" dst="$1/usr/share/nefi/setup/$2.sh"
  [ -f "$src" ] || { echo "   hook $name non trovato, salto"; return 0; }
  mkdir -p "$(dirname "$dst")"
  sed -E -e 's/^([[:space:]]*)set -e.*$/\1set +e/' \
         -e 's/^([[:space:]]*)(.*(\/etc\/hostname|\/etc\/hosts|hostnamectl).*)$/\1: # solo live: \2/' \
         "$src" > "$dst"
  chmod 755 "$dst"
  bash -n "$dst" || echo "   ATTENZIONE: $name ha un errore di sintassi dopo la conversione (mandamelo)"
  echo "$name" >> "$TMPD/$pkg.setup"
}
hook nefi-security-center 0010-hardening
hook nefi-security-center 0020-configure-tools
hook nefi-security-center 0030-nefi-setup
hook nefi-ollama          0025-ollama
hook nefi-desktop         0040-nefi-branding

# 3. File DEBIAN di ogni pacchetto
control() { # control <pkg> <arch> <section> <depends> <recommends> <suggests> <descr. breve> <descr. lunga>
  {
    echo "Package: $1"
    echo "Version: $VER"
    echo "Architecture: $2"
    echo "Maintainer: $MAINT"
    echo "Section: $3"
    echo "Priority: optional"
    [ -n "$4" ] && echo "Depends: $4"
    [ -n "$5" ] && echo "Recommends: $5"
    [ -n "$6" ] && echo "Suggests: $6"
    echo "Description: $7"
    echo " $8"
  } > "$1/DEBIAN/control"
}
scripts() { # scripts <pkg> <comandi extra per postinst>
  local pkg="$1" extra="$2" dv="$TMPD/$1.divert" su="$TMPD/$1.setup"
  {
    echo '#!/bin/sh'; echo 'set -e'
    echo 'if [ "$1" = install ] || [ "$1" = upgrade ]; then'
    if [ -f "$dv" ]; then while read -r f; do
      echo "  dpkg-divert --package $pkg --rename --divert $f.debian --add $f"
    done < "$dv"; fi
    echo '  :'; echo 'fi'
  } > "$pkg/DEBIAN/preinst"
  {
    echo '#!/bin/sh'; echo 'set -e'
    echo 'if [ "$1" = configure ]; then'
    if [ -f "$su" ]; then
      echo '  if [ -z "$2" ]; then  # solo alla prima installazione'
      echo '    mkdir -p /var/log/nefi-setup'
      echo "    for s in $(tr '\n' ' ' < "$su"); do"
      echo '      bash "/usr/share/nefi/setup/$s.sh" < /dev/null > "/var/log/nefi-setup/$s.log" 2>&1 || echo "NEFI: $s con errori, vedi /var/log/nefi-setup/$s.log"'
      echo '    done'
      echo '  fi'
    fi
    echo "$extra"
    echo 'fi'
    echo 'exit 0'
  } > "$pkg/DEBIAN/postinst"
  {
    echo '#!/bin/sh'; echo 'set -e'
    echo 'if [ "$1" = remove ] || [ "$1" = abort-install ]; then'
    if [ -f "$dv" ]; then while read -r f; do
      echo "  dpkg-divert --package $pkg --rename --remove $f || true"
    done < "$dv"; fi
    echo '  :'; echo 'fi'
  } > "$pkg/DEBIAN/postrm"
  chmod 755 "$pkg/DEBIAN" "$pkg/DEBIAN/preinst" "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/postrm"
  # i file in /etc sono file di configurazione: agli aggiornamenti non si perdono le modifiche
  ( cd "$pkg" && find etc -type f 2>/dev/null | sed 's|^|/|' ) > "$pkg/DEBIAN/conffiles" || true
  [ -s "$pkg/DEBIAN/conffiles" ] || rm -f "$pkg/DEBIAN/conffiles"
  chmod -R go-w "$pkg"
  # programmi e script devono restare eseguibili
  find "$pkg/usr/bin" "$pkg/usr/local/bin" -type f -exec chmod 755 {} + 2>/dev/null || true
  find "$pkg/opt" \( -name '*.sh' -o -name '*.py' \) -type f -exec chmod 755 {} + 2>/dev/null || true
}

control nefi-security-center all admin \
  "python3, python3-pyqt6, python3-pyqt6.qtsvg, python3-psutil, python3-requests, pkexec, polkitd, udisks2, util-linux, iproute2, apparmor, auditd, nftables, aide, aide-common" \
  "python3-twisted, netcat-openbsd, firejail, snapper, btrfs-progs, mokutil, keepassxc, lynis, fonts-noto-color-emoji" \
  "nefi-ollama, suricata, yara, clamav, rkhunter, chkrootkit" \
  "NEFI Security Center - unified Blue Team console" \
  "PyQt6 console of NEFI OS with all the security modules and their helper scripts."
scripts nefi-security-center '  systemctl daemon-reload 2>/dev/null || true
  systemctl enable nftables.service 2>/dev/null || true
  sysctl --system > /dev/null 2>&1 || true
  augenrules --load > /dev/null 2>&1 || true
  udevadm control --reload-rules 2>/dev/null || true
  gtk-update-icon-cache -q -f /usr/share/icons/hicolor 2>/dev/null || true'

control nefi-desktop all x11 \
  "kde-plasma-desktop, sddm, plymouth, plymouth-themes" \
  "plasma-widgets-addons, fonts-noto-color-emoji, nefi-branding" "" \
  "NEFI OS desktop - KDE Plasma customization" \
  "Global theme, color scheme, Plasma theme, wallpapers, panels, SDDM, splash and Plymouth of NEFI OS."
scripts nefi-desktop '  gtk-update-icon-cache -q -f /usr/share/icons/hicolor 2>/dev/null || true
  if command -v plymouth-set-default-theme > /dev/null && [ -d /usr/share/plymouth/themes/nefi ]; then
    plymouth-set-default-theme nefi || true
    update-initramfs -u > /dev/null 2>&1 || true
  fi
  if [ -x /usr/sbin/update-grub ] && [ -e /boot/grub/grub.cfg ]; then update-grub > /dev/null 2>&1 || true; fi'

control nefi-ollama amd64 misc \
  "ca-certificates" "curl" "" \
  "Ollama engine for NEFI Guardian" \
  "Local AI engine (Ollama with CPU/CUDA/Vulkan libraries) used by the Guardian module. The model is downloaded with nefi-ollama-setup."
scripts nefi-ollama '  systemctl daemon-reload 2>/dev/null || true
  systemctl enable ollama.service 2>/dev/null || true'

# 4. Riepilogo
for p in $PKGS; do
  n="$(find "$p" -path "$p/DEBIAN" -prune -o -type f -print | wc -l)"
  d="$( [ -f "$TMPD/$p.divert" ] && wc -l < "$TMPD/$p.divert" || echo 0)"
  echo "[NEFI] $p: $n file ($(du -sh --exclude=DEBIAN "$p" | cut -f1)), deviati da Debian: $d"
done
