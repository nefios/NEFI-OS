#!/bin/bash
# NEFI OS - verifica delle difese contro l'escalation a root (Passo 2)
# Uso: sudo /opt/nefi/hardening/verify-antiroot.sh
# Stampa PASS / WARN / FAIL per ogni controllo e un riepilogo finale.
# Non modifica niente.
set -u
[ "$(id -u)" -eq 0 ] || { echo "Lancialo con sudo: sudo $0"; exit 1; }

PASS=0; WARN=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; WARN=$((WARN+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
sec()  { printf '\n== %s ==\n' "$*"; }

# utente normale con cui fare le prove (chi ha lanciato sudo)
TUSER="${SUDO_USER:-}"
if [ -z "$TUSER" ] || [ "$TUSER" = root ]; then
    TUSER="$(getent passwd 1000 | cut -d: -f1)"
fi

sec "sudo"
if [ -f /etc/sudoers.d/50-nefi-hardening ] && visudo -c > /dev/null 2>&1; then
    ok "regole NEFI presenti e configurazione sudo valida"
else
    bad "regole /etc/sudoers.d/50-nefi-hardening mancanti o sudoers non valido"
fi
nopw="$(grep -rhsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ || true)"
[ -z "$nopw" ] && ok "nessuna regola NOPASSWD" || bad "regole NOPASSWD trovate: $nopw"
for d in use_pty timestamp_timeout=5 'logfile="/var/log/sudo.log"'; do
    grep -qsF "Defaults $d" /etc/sudoers.d/50-nefi-hardening && ok "sudo: $d" || bad "sudo: manca $d"
done

sec "su"
grep -qE '^[^#]*pam_wheel\.so.*group=sudo' /etc/pam.d/su \
    && ok "su permesso solo al gruppo sudo (pam_wheel)" \
    || bad "su non limitato (pam_wheel mancante in /etc/pam.d/su)"
if passwd -S root 2>/dev/null | awk '{exit !($2=="L" || $2=="NP")}'; then
    ok "account root bloccato (nessuna password di root)"
else
    warn "root ha una password: meglio usare solo sudo (sudo passwd -l root)"
fi

sec "programmi SUID"
REMOVED="/usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/newgrp /usr/lib/openssh/ssh-keysign /usr/sbin/pppd /usr/lib/xorg/Xorg.wrap /usr/bin/ntfs-3g"
for b in $REMOVED; do
    [ -e "$b" ] || continue
    if [ -u "$b" ]; then bad "ancora SUID: $b"; else ok "SUID rimosso: $b"; fi
done
mapfile -t SUIDS < <(find / -xdev -perm -4000 -type f 2>/dev/null | sort)
echo "        programmi SUID rimasti: ${#SUIDS[@]}"
printf '          %s\n' "${SUIDS[@]}"

sec "kernel"
chk() { # chk <chiave> <valore atteso> <descrizione>
    local v; v="$(sysctl -n "$1" 2>/dev/null)"
    if [ -z "$v" ]; then warn "$3: $1 non disponibile in questo kernel"
    elif [ "$v" = "$2" ]; then ok "$3 ($1 = $v)"
    else bad "$3 ($1 = $v, atteso $2)"; fi
}
chk kernel.kexec_load_disabled 1 "kexec disattivato"
chk kernel.perf_event_paranoid 3 "perf vietato agli utenti"
chk net.core.bpf_jit_harden 2 "JIT di BPF protetto"
chk kernel.unprivileged_bpf_disabled 2 "BPF vietato agli utenti"
chk vm.unprivileged_userfaultfd 0 "userfaultfd vietato agli utenti"
chk kernel.io_uring_disabled 2 "io_uring disattivato"
chk dev.tty.ldisc_autoload 0 "line discipline non caricate in automatico"
chk kernel.kptr_restrict 2 "indirizzi del kernel nascosti"
chk kernel.dmesg_restrict 1 "dmesg solo per root"
chk kernel.yama.ptrace_scope 1 "ptrace limitato"
chk fs.suid_dumpable 0 "niente core dump dei programmi SUID"
chk fs.protected_symlinks 1 "symlink protetti"
chk fs.protected_hardlinks 1 "hardlink protetti"

sec "namespace utente"
if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    chk kernel.apparmor_restrict_unprivileged_userns 1 "namespace limitati da AppArmor"
elif [ "$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null)" = 0 ]; then
    ok "namespace utente vietati agli utenti normali (profilo Paranoid)"
else
    warn "namespace utente permessi: si chiudono con il profilo Paranoid (Chromium/Flatpak non funzioneranno)"
fi
if [ -n "$TUSER" ]; then
    if runuser -u "$TUSER" -- unshare -Ur true > /dev/null 2>&1; then
        warn "l'utente $TUSER puo' creare un namespace utente (unshare -Ur funziona)"
    else
        ok "l'utente $TUSER NON puo' creare un namespace utente (unshare -Ur bloccato)"
    fi
fi

sec "core dump"
grep -qs 'hard *core *0' /etc/security/limits.d/90-nefi-nocore.conf && ok "core dump vietati (limits.d)" || bad "limite core dump mancante"
grep -qs 'Storage=none' /etc/systemd/coredump.conf.d/90-nefi.conf && ok "systemd-coredump non salva niente" || warn "systemd-coredump puo' salvare dump"

sec "avvio sicuro (solo informazioni)"
lk="$(cat /sys/kernel/security/lockdown 2>/dev/null)"
case "$lk" in
    *"[integrity]"*|*"[confidentiality]"*) ok "kernel lockdown attivo: $lk" ;;
    "") warn "lockdown non disponibile" ;;
    *) warn "kernel lockdown spento ($lk) - si attiva da solo con Secure Boot" ;;
esac
if command -v mokutil > /dev/null; then
    mokutil --sb-state 2>/dev/null | grep -qi enabled && ok "Secure Boot attivo" || warn "Secure Boot spento"
fi

printf '\n== RIEPILOGO: %s PASS, %s WARN, %s FAIL ==\n' "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -eq 0 ]
