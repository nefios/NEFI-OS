#!/bin/bash
# NEFI OS - password per il menu di avvio GRUB (Lynis BOOT-5122)
#
#   sudo /opt/nefi/hardening/grub-password.sh          imposta (o cambia) la password
#   sudo /opt/nefi/hardening/grub-password.sh remove   la toglie
#
# Il sistema si avvia normalmente SENZA password. La password serve solo per
# modificare le voci del menu (tasto "e") o aprire la riga di comando di GRUB,
# cioe' per impedire a chi ha il PC davanti di avviare in "single user" e diventare root.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Lancialo con sudo"; exit 1; }
PWFILE=/etc/grub.d/01_nefi_password
LINUX=/etc/grub.d/10_linux
GRUBUSER=nefiadmin

if [ "${1:-}" = remove ]; then
    rm -f "$PWFILE"
    sed -i 's/ --unrestricted"$/"/' "$LINUX"
    update-grub
    echo "[NEFI] Password di GRUB rimossa."
    exit 0
fi

read -rsp "Nuova password di GRUB: " p1; echo
read -rsp "Ripeti la password: " p2; echo
[ "$p1" = "$p2" ] || { echo "Le password non coincidono."; exit 1; }
[ "${#p1}" -ge 12 ] || { echo "Usa almeno 12 caratteri."; exit 1; }

HASH="$(printf '%s\n%s\n' "$p1" "$p1" | grub-mkpasswd-pbkdf2 | grep -o 'grub\.pbkdf2\.sha512\.[^ ]*')"
unset p1 p2
[ -n "$HASH" ] || { echo "Errore nella creazione della password."; exit 1; }

umask 077
cat > "$PWFILE" << EOF
#!/bin/sh
# NEFI OS - password del menu di GRUB (creato da grub-password.sh)
cat << 'GRUBEOF'
set superusers="$GRUBUSER"
password_pbkdf2 $GRUBUSER $HASH
GRUBEOF
EOF
chmod 700 "$PWFILE"

# le voci normali restano avviabili senza password (--unrestricted)
if ! grep -q -- '--unrestricted' "$LINUX"; then
    sed -i -E 's/^(CLASS="--class gnu-linux --class gnu --class os)"$/\1 --unrestricted"/' "$LINUX"
fi
grep -q -- '--unrestricted' "$LINUX" \
    || echo "[NEFI] ATTENZIONE: non ho trovato la riga CLASS in $LINUX: all'avvio verra' chiesta la password."

update-grub
chmod 400 /boot/grub/grub.cfg 2>/dev/null || true
echo "[NEFI] Password di GRUB impostata. Utente: $GRUBUSER"
echo "[NEFI] Serve solo per modificare le voci del menu, non per l'avvio normale."
