#!/usr/bin/env python3
"""NEFI OS - applica le correzioni proposte dai controlli (eseguito come root via pkexec).

  fix.py <id-correzione> [<id-correzione> ...]     es.  sysctl:kernel.kptr_restrict  ssh:X11Forwarding
  fix.py undo <id-correzione> [...]                annulla una correzione applicata da qui

Solo correzioni presenti nelle tabelle qui sotto (whitelist): nessun valore arriva dall'interfaccia.
  sysctl:<chiave>   -> /etc/sysctl.d/95-nefi-fixes.conf + applicazione immediata
  ssh:<opzione>     -> /etc/ssh/sshd_config.d/40-nefi-fixes.conf, verificato con 'sshd -t',
                       se non valido viene annullato; poi reload di sshd
  modules           -> /etc/modprobe.d/nefi-blacklist.conf
Alla fine riesegue i controlli, cosi' la pagina mostra subito il risultato.
Ogni correzione applicata e' annotata in /var/lib/nefi/prevention/applied.json (chi, quando, valore di
prima): "undo" toglie la riga dal file NEFI e rimette il valore di prima.
"""
import grp
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

SYSCTL_FILE = "/etc/sysctl.d/95-nefi-fixes.conf"
SSH_FILE = "/etc/ssh/sshd_config.d/40-nefi-fixes.conf"   # 40 < 50: per sshd vince il primo valore letto
MODPROBE_FILE = "/etc/modprobe.d/nefi-blacklist.conf"
COLLECTOR = "/opt/nefi/system/collect.py"
APPLIED = "/var/lib/nefi/prevention/applied.json"
PATH_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}

SYSCTL_FIX = {
    "kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1", "kernel.yama.ptrace_scope": "1",
    "kernel.unprivileged_bpf_disabled": "2", "kernel.kexec_load_disabled": "1",
    "kernel.perf_event_paranoid": "3", "kernel.randomize_va_space": "2", "kernel.io_uring_disabled": "2",
    "vm.unprivileged_userfaultfd": "0", "fs.protected_symlinks": "1", "fs.protected_hardlinks": "1",
    "fs.protected_fifos": "2", "fs.protected_regular": "2", "fs.suid_dumpable": "0",
    "net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.all.accept_source_route": "0",
}

STRONG_CRYPTO = {
    "Ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
               "aes256-ctr,aes192-ctr,aes128-ctr",
    "MACs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
    "KexAlgorithms": "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,"
                     "curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
}
SSH_FIX = {
    "PermitRootLogin": {"PermitRootLogin": "no"},
    "PermitEmptyPasswords": {"PermitEmptyPasswords": "no"},
    "PasswordAuthentication": {"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no"},
    "MaxAuthTries": {"MaxAuthTries": "3"},
    "LoginGraceTime": {"LoginGraceTime": "30"},
    "X11Forwarding": {"X11Forwarding": "no"},
    "AllowTcpForwarding": {"AllowTcpForwarding": "no"},
    "AllowAgentForwarding": {"AllowAgentForwarding": "no"},
    "LogLevel": {"LogLevel": "VERBOSE"},
    "ClientAlive": {"ClientAliveInterval": "300", "ClientAliveCountMax": "2"},
    "Crypto": STRONG_CRYPTO,
}
MODULES = ["dccp", "sctp", "rds", "tipc", "firewire-core", "firewire-ohci", "firewire-sbp2", "thunderbolt-net"]


def run(args, timeout=60):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=PATH_ENV)
        return r.returncode, r.stdout + r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def write_atomic(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def set_kv(path, sep, items, header):
    """Aggiorna/aggiunge righe 'chiave<sep>valore' in un file di configurazione NEFI."""
    try:
        lines = open(path).read().splitlines()
    except OSError:
        lines = [header]
    keys = {k.lower() for k in items}
    lines = [l for l in lines if not (l.strip() and not l.lstrip().startswith("#")
                                      and re.split(r"\s*=\s*|\s+", l.strip(), maxsplit=1)[0].lower() in keys)]
    lines += [f"{k}{sep}{v}" for k, v in items.items()]
    write_atomic(path, "\n".join(lines) + "\n")


def actor():
    for var in ("PKEXEC_UID", "SUDO_UID"):
        uid = os.environ.get(var, "")
        if uid.isdigit():
            try:
                return pwd.getpwuid(int(uid)).pw_name
            except KeyError:
                return f"uid {uid}"
    return "root"


def load_applied():
    try:
        with open(APPLIED) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_applied(data):
    os.makedirs(os.path.dirname(APPLIED), mode=0o755, exist_ok=True)
    write_atomic(APPLIED, json.dumps(data, indent=1, sort_keys=True) + "\n", 0o640)
    try:
        os.chown(APPLIED, 0, grp.getgrnam("sudo").gr_gid)
    except (KeyError, OSError):
        pass


def remember(fix_id, summary, previous=None):
    data = load_applied()
    old = data.get(fix_id, {})
    data[fix_id] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "by": actor(), "summary": summary,
                    "previous": old.get("previous", previous)}    # il valore ORIGINALE, non quello di un secondo "apply"
    save_applied(data)


def forget(fix_id):
    data = load_applied()
    if data.pop(fix_id, None) is not None:
        save_applied(data)


def drop_keys(path, keys):
    """Toglie da un file NEFI le righe delle chiavi indicate; file senza piu' impostazioni = cancellato."""
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return
    low = {k.lower() for k in keys}
    keep = [l for l in lines if not (l.strip() and not l.lstrip().startswith("#")
                                     and re.split(r"\s*=\s*|\s+", l.strip(), maxsplit=1)[0].lower() in low)]
    if any(l.strip() and not l.lstrip().startswith("#") for l in keep):
        write_atomic(path, "\n".join(keep) + "\n")
    else:
        os.remove(path)


def fix_sysctl(key):
    if key not in SYSCTL_FIX:
        return False, f"unknown sysctl fix: {key}"
    val = SYSCTL_FIX[key]
    rc0, before = run(["sysctl", "-n", key])
    remember(f"sysctl:{key}", f"{key} = {val}", before.strip() if rc0 == 0 else None)
    set_kv(SYSCTL_FILE, " = ", {key: val}, "# NEFI OS - values applied from Security Center (Prevention)")
    rc, out = run(["sysctl", "-w", f"{key}={val}"])
    return rc == 0, out.strip() or f"{key} = {val}"


def has_ssh_key_for_admin():
    """Prima di vietare le password SSH: almeno un amministratore deve avere una chiave autorizzata."""
    try:
        import grp
        import pwd
        members = set(grp.getgrnam("sudo").gr_mem)
    except KeyError:
        return False
    for user in members:
        try:
            home = pwd.getpwnam(user).pw_dir
        except KeyError:
            continue
        ak = os.path.join(home, ".ssh", "authorized_keys")
        try:
            if any(l.strip() and not l.startswith("#") for l in open(ak)):
                return True
        except OSError:
            continue
    return False


def supported_crypto():
    """Algoritmi forti filtrati con quelli che QUESTA versione di OpenSSH conosce (ssh -Q)."""
    out = {}
    for key, query in (("Ciphers", "cipher"), ("MACs", "mac"), ("KexAlgorithms", "kex")):
        rc, txt = run(["ssh", "-Q", query])
        known = set(txt.split()) if rc == 0 else None
        algs = [a for a in STRONG_CRYPTO[key].split(",") if known is None or a in known]
        out[key] = ",".join(algs)
    return out


def fix_ssh(opt):
    if opt not in SSH_FIX:
        return False, f"unknown SSH fix: {opt}"
    if opt == "Crypto":
        SSH_FIX["Crypto"] = supported_crypto()
    if not os.path.exists("/usr/sbin/sshd"):
        return False, "SSH server not installed"
    if opt == "PasswordAuthentication" and not has_ssh_key_for_admin():
        return False, ("Refused: no administrator has an SSH key in ~/.ssh/authorized_keys. Disabling passwords "
                       "now would lock you out. Add a key first (ssh-copy-id), then apply this fix.")
    backup = None
    if os.path.exists(SSH_FILE):
        backup = SSH_FILE + ".bak"
        shutil.copy2(SSH_FILE, backup)
    set_kv(SSH_FILE, " ", SSH_FIX[opt], "# NEFI OS - SSH settings applied from Security Center (Prevention)")
    os.makedirs("/run/sshd", exist_ok=True)
    rc, out = run(["sshd", "-t"])
    if rc != 0:                                  # configurazione non valida: torno indietro
        if backup:
            shutil.move(backup, SSH_FILE)
        else:
            os.remove(SSH_FILE)
        return False, f"sshd rejected the new setting, change undone: {out.strip()[:300]}"
    if backup:
        os.remove(backup)
    run(["systemctl", "reload", "ssh.service"])
    remember(f"ssh:{opt}", ", ".join(f"{k} {v}" for k, v in SSH_FIX[opt].items()))
    return True, f"{', '.join(f'{k} {v}' for k, v in SSH_FIX[opt].items())} (sshd reloaded)"


def fix_modules():
    try:
        lines = open(MODPROBE_FILE).read().splitlines()
    except OSError:
        lines = ["# NEFI OS - kernel modules disabled"]
    have = {l.split()[1] for l in lines if l.startswith("install ") and len(l.split()) > 1}
    added = [m for m in MODULES if m not in have]
    lines += [f"install {m} /bin/false" for m in added]
    write_atomic(MODPROBE_FILE, "\n".join(lines) + "\n")
    remember("modules", "blocked: " + ", ".join(MODULES), added)
    return True, "blocked: " + ", ".join(MODULES)


def undo(fix_id):
    """Annulla una correzione registrata in applied.json. -> (ok, messaggio)"""
    rec = load_applied().get(fix_id)
    if rec is None:
        return False, "this fix was not applied from the Security Center (nothing to undo)"
    kind, _, name = fix_id.partition(":")
    if kind == "sysctl" and name in SYSCTL_FIX:
        drop_keys(SYSCTL_FILE, [name])
        prev = rec.get("previous")
        msg = "removed from the NEFI file"
        if prev not in (None, "") and re.fullmatch(r"[0-9 \t-]{1,40}", str(prev)):
            rc, out = run(["sysctl", "-w", f"{name}={prev}"])
            msg += f"; value restored to {prev}" if rc == 0 else \
                f"; the running value could not be restored now ({out.strip()[:80]}): it returns at the next reboot"
        else:
            msg += "; the previous value returns at the next reboot"
    elif kind == "ssh" and name in SSH_FIX:
        if not os.path.exists(SSH_FILE):
            forget(fix_id)
            return True, "already removed"
        backup = SSH_FILE + ".bak"
        shutil.copy2(SSH_FILE, backup)
        drop_keys(SSH_FILE, list(SSH_FIX[name]) if name != "Crypto" else list(STRONG_CRYPTO))
        os.makedirs("/run/sshd", exist_ok=True)
        rc, out = run(["sshd", "-t"])
        if rc != 0:
            shutil.move(backup, SSH_FILE)
            return False, f"sshd rejected the configuration without this setting, nothing changed: {out.strip()[:200]}"
        os.remove(backup)
        run(["systemctl", "reload", "ssh.service"])
        msg = "setting removed, sshd reloaded (the value of the other configuration files applies again)"
    elif fix_id == "modules":
        added = rec.get("previous") or []
        try:
            lines = open(MODPROBE_FILE).read().splitlines()
        except OSError:
            lines = []
        keep = [l for l in lines if not (l.startswith("install ") and len(l.split()) > 1 and l.split()[1] in added)]
        if any(l.startswith("install ") for l in keep):
            write_atomic(MODPROBE_FILE, "\n".join(keep) + "\n")
        elif os.path.exists(MODPROBE_FILE):
            os.remove(MODPROBE_FILE)
        msg = "modules no longer blocked by this fix: " + (", ".join(added) or "none")
    else:
        return False, f"unknown fix: {fix_id}"
    forget(fix_id)
    return True, msg


def apply(fix_id):
    if fix_id.startswith("sysctl:"):
        return fix_sysctl(fix_id.split(":", 1)[1])
    if fix_id.startswith("ssh:"):
        return fix_ssh(fix_id.split(":", 1)[1])
    if fix_id == "modules":
        return fix_modules()
    return False, f"unknown fix: {fix_id}"


def main():
    if os.geteuid() != 0:
        sys.exit("NEFI: run as root (pkexec)")
    ids = [a for a in sys.argv[1:] if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", a)]
    if not ids:
        sys.exit(__doc__)
    ok_all = True
    undoing = ids[0] == "undo"
    if undoing:
        ids = ids[1:]
        if not ids:
            sys.exit(__doc__)
    for fid in ids:
        ok, msg = undo(fid) if undoing else apply(fid)
        ok_all &= ok
        word = ("UNDONE" if ok else "NOT UNDONE") if undoing else ("APPLIED" if ok else "NOT APPLIED")
        print(f"[NEFI] {word} {fid}: {msg}")
    print("[NEFI] Re-running the checks...")
    run(["python3", COLLECTOR], timeout=1800)
    print("[NEFI] Done.")
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
