"""NEFI OS - Detection: inventario dello stato del sistema e controlli periodici (root).

collect_items() fotografa tutto cio' che un intruso tocca per restare o salire di privilegi:
file critici, punti di persistenza, programmi SUID, account, amministratori, porte in ascolto.
Il demone confronta la fotografia con la baseline APPROVATA: le differenze diventano eventi e
restano "in attesa" finche' un amministratore non le approva (la baseline non si aggiorna da sola).
"""
import glob
import hashlib
import os
import pwd
import re
import stat
import subprocess

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}


def run(args, timeout=60):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=ENV, errors="replace")
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def sha256(path, limit=64 * 1024 * 1024):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            done = 0
            while done < limit:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                done += len(chunk)
        return h.hexdigest()
    except OSError:
        return None


def file_value(path, with_hash=True):
    """Firma di un file: tipo, permessi, proprietario e contenuto. None se non esiste."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode):
        try:
            return "link->" + os.readlink(path)
        except OSError:
            return "link"
    if not stat.S_ISREG(st.st_mode):
        return f"special:{stat.S_IFMT(st.st_mode):o}"
    digest = sha256(path) if with_hash else f"size{st.st_size}"
    return f"{stat.S_IMODE(st.st_mode):04o}:{st.st_uid}:{st.st_gid}:{digest}"


# classe -> (tecnica MITRE, descrizione, [percorsi o glob]); "~" = casa di ogni utente con login
WATCH = {
    "integrity": ("T1565", "Critical system file", [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/*",
        "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*", "/etc/pam.d/*", "/etc/security/*.conf",
        "/etc/login.defs", "/etc/hosts", "/etc/fstab", "/etc/nftables.conf", "/etc/nefi/firewall.d/*",
        "/etc/audit/auditd.conf", "/etc/audit/rules.d/*", "/etc/default/grub", "/etc/sysctl.conf",
        "/etc/sysctl.d/*", "/etc/ld.so.conf", "/etc/ld.so.conf.d/*", "/etc/nsswitch.conf",
        "/etc/apt/sources.list", "/etc/apt/sources.list.d/*", "/etc/apt/trusted.gpg.d/*",
        "/usr/bin/nefi-*", "/usr/lib/nefi/modules/*.py", "/opt/nefi/*/*", "/usr/share/nefi/detection/rules/*",
        "/etc/nefi/detection/*.json", "/etc/nefi/detection/rules.d/*", "/etc/falco/falco.yaml",
        "/etc/falco/falco_rules.local.yaml", "/etc/crowdsec/config.yaml",
    ]),
    "persistence.systemd": ("T1543.002", "systemd unit", [
        "/etc/systemd/system/*", "/etc/systemd/system/*/*", "/etc/systemd/user/*", "/etc/systemd/user/*/*",
        "~/.config/systemd/user/*", "~/.config/systemd/user/*/*", "/etc/systemd/system-generators/*",
    ]),
    "persistence.cron": ("T1053.003", "Scheduled job", [
        "/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*",
        "/etc/cron.monthly/*", "/var/spool/cron/crontabs/*", "/etc/anacrontab", "/var/spool/cron/atjobs/*",
    ]),
    "persistence.autostart": ("T1547.013", "Desktop autostart entry", [
        "/etc/xdg/autostart/*", "~/.config/autostart/*", "~/.config/plasma-workspace/env/*",
        "~/.config/autostart-scripts/*",
    ]),
    "persistence.shell": ("T1546.004", "Shell startup file", [
        "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/environment", "/etc/zsh/*",
        "~/.bashrc", "~/.profile", "~/.bash_profile", "~/.bash_login", "~/.bash_logout", "~/.zshrc", "~/.zprofile",
        "~/.pam_environment",
    ]),
    "persistence.ssh_keys": ("T1098.004", "SSH authorized keys", [
        "~/.ssh/authorized_keys", "~/.ssh/authorized_keys2", "~/.ssh/rc", "/etc/ssh/authorized_keys/*",
    ]),
    "persistence.preload": ("T1574.006", "Dynamic linker preload", ["/etc/ld.so.preload"]),
    "persistence.modules": ("T1547.006", "Kernel module configuration", [
        "/etc/modules", "/etc/modules-load.d/*", "/etc/modprobe.d/*",
    ]),
    "persistence.boot": ("T1037", "Boot or login script", [
        "/etc/rc.local", "/etc/init.d/*", "/etc/udev/rules.d/*", "/etc/NetworkManager/dispatcher.d/*",
        "/etc/update-motd.d/*", "/etc/apt/apt.conf.d/*",
    ]),
}
CLASS_INFO = {k: (v[0], v[1]) for k, v in WATCH.items()}
CLASS_INFO.update({
    "suid": ("T1548.001", "SUID/SGID program"), "account": ("T1136.001", "Local account"),
    "admin": ("T1098", "Administrator (sudo group member)"), "listener": ("T1571", "Listening network port"),
})


def login_homes():
    homes = []
    for p in pwd.getpwall():
        if (p.pw_uid == 0 or p.pw_uid >= 1000) and p.pw_dir and os.path.isdir(p.pw_dir) \
                and not p.pw_shell.endswith(("nologin", "false")):
            homes.append(p.pw_dir)
    return sorted(set(homes))


def collect_files():
    items = {}
    homes = login_homes()
    for cls, (_tech, _label, patterns) in WATCH.items():
        for pat in patterns:
            expanded = [pat.replace("~", h, 1) for h in homes] if pat.startswith("~") else [pat]
            for one in expanded:
                for path in glob.glob(one):
                    if os.path.isdir(path) and not os.path.islink(path):
                        continue
                    val = file_value(path)
                    if val is not None:
                        items[f"{cls}:{path}"] = val
    return items


def collect_suid():
    """Programmi SUID/SGID sui filesystem locali (lento: il demone lo fa ogni 6 ore)."""
    items = {}
    rc, out = run(["find", "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f",
                   "-not", "-path", "/proc/*", "-not", "-path", "/var/lib/docker/*", "-not", "-path", "/snap/*",
                   "-print"], timeout=600)
    for path in out.splitlines():
        val = file_value(path)
        if val is not None:
            items[f"suid:{path}"] = val
    return items


def collect_accounts():
    items = {}
    try:
        for p in pwd.getpwall():
            items[f"account:{p.pw_name}"] = f"uid{p.pw_uid}:gid{p.pw_gid}:{p.pw_dir}:{p.pw_shell}"
    except OSError:
        pass
    try:
        import grp
        for g in ("sudo", "adm", "root", "wheel", "docker", "shadow", "disk"):
            try:
                for member in grp.getgrnam(g).gr_mem:
                    items[f"admin:{g}/{member}"] = "member"
            except KeyError:
                continue
    except OSError:
        pass
    return items


_SS_USERS = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def collect_listeners():
    """Porte in ascolto raggiungibili da fuori (non solo 127.0.0.1): porta -> programma."""
    items = {}
    rc, out = run(["ss", "-H", "-tulnp"], timeout=20)
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto, local = f[0], f[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if addr.startswith("127.") or addr == "::1":
            continue
        m = _SS_USERS.search(line)
        exe = ""
        if m:
            try:
                exe = os.readlink(f"/proc/{m.group(2)}/exe")
            except OSError:
                exe = m.group(1)
        items[f"listener:{proto}/{port}"] = exe or "unknown program"
    return items


def diff(base_items, current, prefixes):
    """Differenze limitate alle classi indicate -> [(tipo, id, vecchio, nuovo)]."""
    out = []
    def mine(k):
        return k.split(":", 1)[0].split(".")[0] in prefixes
    for k, v in current.items():
        if mine(k):
            if k not in base_items:
                out.append(("new", k, None, v))
            elif base_items[k] != v:
                out.append(("modified", k, base_items[k], v))
    for k, v in base_items.items():
        if mine(k) and k not in current:
            out.append(("removed", k, v, None))
    return out


# ── il file corrisponde a quello del pacchetto Debian? ──────────────────
def package_verified(path):
    """True = contenuto identico a quello distribuito dal pacchetto; False = diverso; None = non di un pacchetto."""
    rc, out = run(["dpkg", "-S", path], timeout=20)
    if rc != 0 or ":" not in out:
        return None
    pkg = out.split(":", 1)[0].split(",")[0].strip()
    try:
        with open(path, "rb") as f:
            md5 = hashlib.md5(f.read()).hexdigest()
    except OSError:
        return None
    rel = path.lstrip("/")
    for cand in glob.glob(f"/var/lib/dpkg/info/{pkg}.md5sums") + glob.glob(f"/var/lib/dpkg/info/{pkg}:*.md5sums"):
        try:
            with open(cand, errors="replace") as f:
                for line in f:
                    h, _, name = line.strip().partition("  ")
                    if name == rel:
                        return h == md5
        except OSError:
            continue
    rc, out = run(["dpkg-query", "-W", "-f=${Conffiles}\n", pkg], timeout=20)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == path:
            return parts[1] == md5
    return None


# ── indicatori di rootkit ───────────────────────────────────────────────
def rootkit_indicators():
    """Controlli veloci, senza strumenti esterni -> [(indicatore, dettaglio)]."""
    found = []
    # 1. moduli del kernel visibili in /sys/module ma non in /proc/modules (o viceversa)
    try:
        with open("/proc/modules") as f:
            listed = {l.split()[0] for l in f if l.strip()}
        loaded = {m for m in os.listdir("/sys/module") if os.path.exists(f"/sys/module/{m}/initstate")}
        for m in sorted(loaded - listed):
            found.append(("hidden_module", f"module '{m}' is loaded (/sys/module) but missing from /proc/modules"))
        for m in sorted(listed - loaded):
            found.append(("hidden_module", f"module '{m}' is in /proc/modules but missing from /sys/module"))
    except OSError:
        pass
    # 2. processi che esistono ma non compaiono nell'elenco di /proc
    try:
        visible = {int(p) for p in os.listdir("/proc") if p.isdigit()}
        with open("/proc/sys/kernel/pid_max") as f:
            pid_max = min(int(f.read()), 4194304)
        hidden = []
        for pid in range(2, min(pid_max, 131072)):
            if pid in visible:
                continue
            try:
                with open(f"/proc/{pid}/status") as f:
                    text = f.read()
            except OSError:
                continue
            tgid = re.search(r"^Tgid:\s+(\d+)", text, re.M)
            if tgid and int(tgid.group(1)) == pid and os.path.isdir(f"/proc/{pid}") \
                    and str(pid) not in os.listdir("/proc"):
                name = re.search(r"^Name:\s+(.+)", text, re.M)
                hidden.append(f"{pid} ({name.group(1) if name else '?'})")
        if hidden:
            found.append(("hidden_process", "processes not listed in /proc: " + ", ".join(hidden[:10])))
    except (OSError, ValueError):
        pass
    # 3. interfacce di rete in modalita' promiscua (sniffing)
    for flags_file in glob.glob("/sys/class/net/*/flags"):
        try:
            with open(flags_file) as f:
                if int(f.read().strip(), 16) & 0x100:
                    found.append(("promiscuous_interface", f"interface {flags_file.split('/')[4]} is in promiscuous mode"))
        except (OSError, ValueError):
            continue
    # 4. kernel "tainted" da moduli non firmati o fuori dall'albero
    try:
        with open("/proc/sys/kernel/tainted") as f:
            taint = int(f.read().strip())
        if taint & (1 << 13):
            found.append(("unsigned_module", "an unsigned kernel module was loaded (taint flag E)"))
        if taint & (1 << 12):
            found.append(("out_of_tree_module", "an out-of-tree kernel module was loaded (taint flag O)"))
    except (OSError, ValueError):
        pass
    return found


def rootkit_tools():
    """rkhunter e chkrootkit (se installati): solo le righe di avviso -> [(strumento, messaggio)]."""
    out_all = []
    if os.path.exists("/usr/bin/rkhunter"):
        rc, out = run(["rkhunter", "--check", "--skip-keypress", "--report-warnings-only", "--nocolors"], timeout=1800)
        for line in out.splitlines():
            line = line.strip()
            if line.lower().startswith("warning:"):
                out_all.append(("rkhunter", line[8:].strip()[:300]))
    if os.path.exists("/usr/sbin/chkrootkit"):
        rc, out = run(["chkrootkit", "-q"], timeout=1800)
        for line in out.splitlines():
            line = line.strip()
            if line and ("INFECTED" in line or "Warning" in line or "suspicious" in line.lower()):
                out_all.append(("chkrootkit", line[:300]))
    return out_all[:40]
