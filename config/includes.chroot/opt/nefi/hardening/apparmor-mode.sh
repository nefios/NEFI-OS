#!/bin/bash
# NEFI OS - porta in modalita' "enforce" SOLO i profili AppArmor che ne hanno senso,
# e permette di tornare indietro.
#
#   apparmor-mode.sh enforce <file-elenco>   enforce dei profili in "complain";
#                                            salva in <file-elenco> quelli cambiati
#   apparmor-mode.sh restore <file-elenco>   rimette in "complain" i profili dell'elenco
#
# Non tocca MAI:
#  - i profili "unconfined" (Debian 13 ne ha tanti, es. firefox: servono solo a
#    permettere la sandbox del programma; forzati in enforce bloccano tutto)
#  - i profili disattivati (/etc/apparmor.d/disable)
#  - i profili gia' in enforce
set -u
DIR=/etc/apparmor.d
MODE="${1:-}"
LIST="${2:-}"
[ -n "$LIST" ] || { echo "uso: $0 enforce|restore <file-elenco>"; exit 2; }
mkdir -p "$(dirname "$LIST")"
command -v aa-enforce > /dev/null || { echo "[NEFI] AppArmor tools not installed - skipped"; exit 0; }

case "$MODE" in
  enforce)
    : > "$LIST.tmp"
    for f in "$DIR"/*; do
      [ -f "$f" ] || continue
      name="$(basename "$f")"
      [ -e "$DIR/disable/$name" ] && continue
      grep -qE 'flags=\([^)]*unconfined' "$f" && continue
      if grep -qE 'flags=\([^)]*complain' "$f" || [ -e "$DIR/force-complain/$name" ]; then
        if aa-enforce "$f" > /dev/null 2>&1; then
          echo "$f" >> "$LIST.tmp"
          echo "[NEFI] AppArmor enforce: $name"
        fi
      fi
    done
    # se l'elenco esiste gia' (attivazione ripetuta) lo unisco, senza duplicati
    cat "$LIST" "$LIST.tmp" 2>/dev/null | sort -u > "$LIST.new"
    mv "$LIST.new" "$LIST"; rm -f "$LIST.tmp"
    echo "[NEFI] AppArmor: $(wc -l < "$LIST") profiles in enforce mode (unconfined profiles untouched)"
    ;;
  restore)
    [ -f "$LIST" ] || { echo "[NEFI] AppArmor: nothing to restore"; exit 0; }
    while IFS= read -r f; do
      case "$f" in "$DIR"/*) ;; *) continue ;; esac   # solo file in /etc/apparmor.d
      [ -f "$f" ] && aa-complain "$f" > /dev/null 2>&1 && echo "[NEFI] AppArmor complain: $(basename "$f")"
    done < "$LIST"
    rm -f "$LIST"
    ;;
  *)
    echo "uso: $0 enforce|restore <file-elenco>"; exit 2 ;;
esac
exit 0
