#!/usr/bin/env python3
"""NEFI OS - System Assessment collector (gira come ROOT).

Esegue i controlli di sicurezza del sistema e scrive /var/lib/nefi/system/report.json
(root:sudo 0640). Lo usano il Security Score e le pagine del modulo System.

  collect.py            esegue tutti i controlli (i piu' lenti usano la cache, vedi TTL)
  collect.py --full     ignora la cache

Ogni controllo produce:
  status   pass | warn | fail | unknown   (unknown = NON verificabile: escluso dal punteggio)
  evidence cosa e' stato letto/misurato (la prova)
  method   comando o file usato per verificarlo
  weight   peso nel Security Score (documentato in WEIGHTS_DOC)
Regola: un controllo passa solo se l'effetto e' verificato (es. firewall = regole caricate con
policy drop, non solo "servizio attivo").
"""
import glob
import grp
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

OUT_DIR = "/var/lib/nefi/system"
REPORT = os.path.join(OUT_DIR, "report.json")
CACHE = os.path.join(OUT_DIR, "cache.json")
VERSION = 1

CATEGORIES = {
    "hardware":  "Hardware Security",
    "boot":      "Boot Integrity",
    "kernel":    "Kernel Security",
    "integrity": "System Integrity",
    "services":  "Security Services",
    "packages":  "Package Security",
    "config":    "Configuration Audit",
    "backup":    "Backup & Recovery",
    "updates":   "Update Health",
}

WEIGHTS_DOC = {
    "scale": "Each check has a weight from 1 (minor hardening) to 10 (core protection).",
    "formula": "Score = (sum of weights of passed checks + half the weight of warnings) / "
               "(sum of weights of verifiable checks) x 100. Checks that cannot be verified "
               "are excluded from the score and reported separately with the reason.",
    "coverage": "Coverage = weight of verifiable checks / weight of all checks.",
}


# ── utilita' ────────────────────────────────────────────────────────────
def run(args, timeout=20, env=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           env=env or {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 126, "", str(e)


def read(path, default=None):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return default


def sysctl(key):
    v = read("/proc/sys/" + key.replace(".", "/"))
    return v.strip() if v is not None else None


def have(cmd):
    return shutil.which(cmd, path="/usr/sbin:/usr/bin:/sbin:/bin") is not None


def svc_active(name):
    return run(["systemctl", "is-active", name], 10)[1].strip() == "active"


def pkg_installed(name):
    rc, out, _ = run(["dpkg-query", "-W", "-f=${Status}", name], 10)
    return rc == 0 and "install ok installed" in out


def age_days(path):
    try:
        return (time.time() - os.stat(path).st_mtime) / 86400
    except OSError:
        return None


def R(status, evidence, method=""):
    return {"status": status, "evidence": str(evidence)[:2000], "method": method}


# ── registro dei controlli ──────────────────────────────────────────────
CHECKS = []   # (id, categoria, titolo, peso, ttl_secondi, funzione, perche')


def check(cid, cat, title, weight, why, ttl=0):
    def deco(fn):
        CHECKS.append((cid, cat, title, weight, ttl, fn, why))
        return fn
    return deco


# ════════════════════════ HARDWARE ════════════════════════
def is_vm():
    return "hypervisor" in (read("/proc/cpuinfo", "") or "")


@check("hw.tpm", "hardware", "TPM 2.0 present", 3,
       "A TPM stores keys in hardware and enables measured boot and TPM-bound disk unlock.")
def _():
    if not os.path.exists("/sys/class/tpm/tpm0"):
        return R("fail", "No TPM device found (/sys/class/tpm/tpm0 missing)", "/sys/class/tpm")
    major = (read("/sys/class/tpm/tpm0/tpm_version_major", "") or "").strip()
    if major == "2":
        return R("pass", "TPM 2.0 detected", "/sys/class/tpm/tpm0/tpm_version_major")
    return R("warn", f"TPM version {major or 'unknown'} (2.0 recommended)", "/sys/class/tpm/tpm0")


@check("hw.cpu_vulns", "hardware", "CPU vulnerabilities mitigated", 6,
       "Unmitigated CPU flaws (Spectre, Meltdown, MDS...) let processes read other processes' memory.")
def _():
    files = sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*"))
    if not files:
        return R("unknown", "Kernel does not expose CPU vulnerability status", "/sys/devices/system/cpu/vulnerabilities")
    bad, lines = [], []
    for f in files:
        v = (read(f, "") or "").strip()
        lines.append(f"{os.path.basename(f)}: {v}")
        if v.startswith("Vulnerable"):
            bad.append(os.path.basename(f))
    if bad:
        return R("fail", f"Vulnerable: {', '.join(bad)}\n" + "\n".join(lines), "/sys/devices/system/cpu/vulnerabilities/*")
    return R("pass", f"{len(files)} known issues: all mitigated or not affected\n" + "\n".join(lines),
             "/sys/devices/system/cpu/vulnerabilities/*")


@check("hw.microcode", "hardware", "CPU microcode package installed", 3,
       "Microcode updates fix CPU security bugs; they are loaded at every boot.")
def _():
    if is_vm():
        return R("unknown", "Virtual machine: microcode is managed by the host", "/proc/cpuinfo (hypervisor flag)")
    info = read("/proc/cpuinfo", "") or ""
    vendor = "intel" if "GenuineIntel" in info else "amd" if "AuthenticAMD" in info else None
    if vendor is None:
        return R("unknown", "CPU vendor not recognised", "/proc/cpuinfo")
    pkg = "intel-microcode" if vendor == "intel" else "amd64-microcode"
    m = re.search(r"^microcode\s*:\s*(\S+)", info, re.M)
    rev = m.group(1) if m else "?"
    if pkg_installed(pkg):
        return R("pass", f"{pkg} installed, running revision {rev}", f"dpkg-query {pkg}")
    return R("fail", f"{pkg} not installed (running revision {rev})", f"dpkg-query {pkg}")


@check("hw.iommu", "hardware", "IOMMU (DMA protection) active", 2,
       "The IOMMU stops malicious devices (Thunderbolt, PCIe) from reading memory via DMA.")
def _():
    groups = glob.glob("/sys/kernel/iommu_groups/*")
    if groups:
        return R("pass", f"IOMMU active: {len(groups)} groups", "/sys/kernel/iommu_groups")
    if is_vm():
        return R("unknown", "Virtual machine without a virtual IOMMU", "/sys/kernel/iommu_groups")
    return R("warn", "IOMMU not active: enable VT-d / AMD-Vi in the firmware settings", "/sys/kernel/iommu_groups")


@check("hw.firmware", "hardware", "Firmware updates checked (fwupd)", 2,
       "Firmware (UEFI, SSD, Thunderbolt) bugs are fixed only by firmware updates.", ttl=21600)
def _():
    if not have("fwupdmgr"):
        return R("unknown", "fwupd is not installed", "which fwupdmgr")
    rc, out, err = run(["fwupdmgr", "get-updates", "--json", "--no-unreported-check"], 60)
    try:
        data = json.loads(out or "{}")
    except ValueError:
        data = None
    if data is None:
        msg = (err or out).strip().splitlines()[:1]
        return R("unknown", f"fwupd could not check: {msg[0] if msg else rc}", "fwupdmgr get-updates")
    devs = [d.get("Name", "?") for d in data.get("Devices", []) if d.get("Releases")]
    if devs:
        return R("warn", f"Firmware updates available for: {', '.join(devs[:6])}", "fwupdmgr get-updates")
    return R("pass", "No firmware updates pending", "fwupdmgr get-updates")


# ════════════════════════ BOOT ════════════════════════
@check("boot.uefi", "boot", "Booted in UEFI mode", 2,
       "Secure Boot and modern boot protections need UEFI; legacy BIOS boot cannot be verified.")
def _():
    if os.path.isdir("/sys/firmware/efi"):
        return R("pass", "UEFI boot (/sys/firmware/efi present)", "/sys/firmware/efi")
    return R("fail", "Legacy BIOS boot", "/sys/firmware/efi")


@check("boot.secureboot", "boot", "Secure Boot enabled", 8,
       "Secure Boot verifies the signatures of the bootloader and kernel before running them.")
def _():
    if not os.path.isdir("/sys/firmware/efi"):
        return R("fail", "Legacy BIOS boot: Secure Boot is not possible", "/sys/firmware/efi")
    rc, out, err = run(["mokutil", "--sb-state"], 10)
    text = (out + err).strip()
    if "enabled" in text.lower():
        return R("pass", text, "mokutil --sb-state")
    if rc == 127:
        return R("unknown", "mokutil not installed", "mokutil --sb-state")
    return R("fail", text or "Secure Boot disabled", "mokutil --sb-state")


@check("boot.lockdown", "boot", "Kernel lockdown active", 5,
       "Lockdown stops even root from modifying the running kernel (unsigned modules, /dev/mem, kexec).")
def _():
    v = (read("/sys/kernel/security/lockdown", "") or "").strip()
    if not v:
        return R("unknown", "Lockdown interface not available", "/sys/kernel/security/lockdown")
    sel = re.search(r"\[(\w+)\]", v)
    mode = sel.group(1) if sel else "?"
    return R("pass" if mode in ("integrity", "confidentiality") else "fail", f"mode: {mode} ({v})",
             "/sys/kernel/security/lockdown")


@check("boot.module_sig", "boot", "Only signed kernel modules can load", 4,
       "Unsigned modules are the classic way to install a kernel rootkit.")
def _():
    enforce = (read("/sys/module/module/parameters/sig_enforce", "") or "").strip()
    lock = read("/sys/kernel/security/lockdown", "") or ""
    if enforce == "Y":
        return R("pass", "module.sig_enforce=Y", "/sys/module/module/parameters/sig_enforce")
    if "[integrity]" in lock or "[confidentiality]" in lock:
        return R("pass", "Enforced by kernel lockdown", "/sys/kernel/security/lockdown")
    return R("fail", "Unsigned modules can be loaded (no sig_enforce, no lockdown)", "/sys/module/module/parameters/sig_enforce")


@check("boot.grub_password", "boot", "GRUB menu protected by a password", 3,
       "Without it, anyone at the keyboard can edit the boot entry and get a root shell.")
def _():
    cfg = read("/boot/grub/grub.cfg")
    if cfg is None:
        return R("unknown", "/boot/grub/grub.cfg not readable", "/boot/grub/grub.cfg")
    if "password_pbkdf2" in cfg:
        return R("pass", "password_pbkdf2 set in grub.cfg", "/boot/grub/grub.cfg")
    return R("warn", "No GRUB password (set one with: sudo /opt/nefi/hardening/grub-password.sh)", "/boot/grub/grub.cfg")


@check("boot.grub_perms", "boot", "grub.cfg not readable by users", 1,
       "grub.cfg can contain the password hash and boot details.")
def _():
    try:
        mode = stat.S_IMODE(os.stat("/boot/grub/grub.cfg").st_mode)
    except OSError:
        return R("unknown", "/boot/grub/grub.cfg missing", "stat")
    return R("pass" if not mode & 0o004 else "warn", f"mode {oct(mode)}", "stat /boot/grub/grub.cfg")


# ════════════════════════ KERNEL ════════════════════════
SYSCTL_CHECKS = [
    # chiave, valore minimo/atteso, confronto, peso, titolo, perche'
    ("kernel.kptr_restrict", 2, "eq", 2, "Kernel pointers hidden", "Kernel addresses help exploits bypass KASLR."),
    ("kernel.dmesg_restrict", 1, "eq", 1, "dmesg restricted to root", "Kernel logs leak addresses and hardware details."),
    ("kernel.yama.ptrace_scope", 1, "ge", 3, "ptrace restricted", "Stops a process from reading another process' memory (password theft)."),
    ("kernel.unprivileged_bpf_disabled", 1, "ge", 2, "BPF restricted to root", "Unprivileged BPF has been a frequent source of kernel exploits."),
    ("kernel.kexec_load_disabled", 1, "eq", 2, "kexec disabled", "Prevents replacing the running kernel."),
    ("kernel.perf_event_paranoid", 2, "ge", 1, "perf restricted", "perf exposes kernel internals to users."),
    ("kernel.randomize_va_space", 2, "eq", 3, "Full ASLR", "Address randomisation makes memory exploits much harder."),
    ("kernel.io_uring_disabled", 1, "ge", 1, "io_uring restricted", "io_uring had many privilege-escalation bugs."),
    ("vm.unprivileged_userfaultfd", 0, "eq", 1, "userfaultfd restricted", "Used by exploits to win race conditions."),
    ("fs.protected_symlinks", 1, "eq", 2, "Symlink protection", "Blocks /tmp symlink attacks against root."),
    ("fs.protected_hardlinks", 1, "eq", 2, "Hardlink protection", "Blocks hardlink attacks against privileged programs."),
    ("fs.protected_fifos", 1, "ge", 1, "FIFO protection", "Blocks FIFO spoofing in sticky directories."),
    ("fs.protected_regular", 1, "ge", 1, "Regular file protection", "Blocks file spoofing in sticky directories."),
    ("fs.suid_dumpable", 0, "eq", 1, "No core dumps of SUID programs", "Core dumps of privileged programs can leak secrets."),
    ("net.ipv4.tcp_syncookies", 1, "eq", 1, "TCP SYN cookies", "Protects against SYN flood denial of service."),
    ("net.ipv4.conf.all.rp_filter", 1, "ge", 1, "Reverse path filtering", "Drops spoofed packets."),
    ("net.ipv4.conf.all.accept_redirects", 0, "eq", 1, "ICMP redirects ignored", "Redirects can be used to reroute traffic (MITM)."),
    ("net.ipv4.conf.all.accept_source_route", 0, "eq", 1, "Source routing disabled", "Source-routed packets bypass network controls."),
]


def _mk_sysctl(key, want, op, weight, title, why):
    @check("sysctl." + key, "kernel", title, weight, why)
    def _():
        v = sysctl(key)
        if v is None:
            return R("unknown", f"{key} not available in this kernel", f"/proc/sys/{key.replace('.', '/')}")
        try:
            n = int(v.split()[0])
        except ValueError:
            return R("unknown", f"{key} = {v}", "sysctl")
        ok = n == want if op == "eq" else n >= want
        return R("pass" if ok else "fail", f"{key} = {n} (expected {'' if op == 'eq' else '>= '}{want})",
                 f"/proc/sys/{key.replace('.', '/')}")


for _args in SYSCTL_CHECKS:
    _mk_sysctl(*_args)


@check("kernel.apparmor", "kernel", "AppArmor enforcing profiles", 8,
       "Mandatory access control limits what a compromised program can do.")
def _():
    if (read("/sys/module/apparmor/parameters/enabled", "") or "").strip() != "Y":
        return R("fail", "AppArmor is not enabled in the kernel", "/sys/module/apparmor/parameters/enabled")
    rc, out, _ = run(["aa-status", "--json"], 20)
    try:
        data = json.loads(out)
        profiles = data.get("profiles", {})
        enforce = sum(1 for m in profiles.values() if m == "enforce")
        complain = sum(1 for m in profiles.values() if m == "complain")
        procs = data.get("processes", {})
        confined = sum(len(v) for v in procs.values()) if isinstance(procs, dict) else 0
    except (ValueError, AttributeError):
        return R("unknown", "aa-status output not readable", "aa-status --json")
    ev = f"{enforce} profiles in enforce mode, {complain} in complain mode, {confined} processes confined"
    return R("pass" if enforce >= 10 else "warn" if enforce else "fail", ev, "aa-status --json")


@check("kernel.audit", "kernel", "Kernel audit rules loaded", 5,
       "Audit rules record changes to identity files, privileged commands and module loading.")
def _():
    rc, out, err = run(["auditctl", "-s"], 10)
    if rc == 127:
        return R("fail", "auditd not installed", "auditctl -s")
    enabled = re.search(r"enabled\s+(\d)", out)
    rc2, rules, _ = run(["auditctl", "-l"], 10)
    n = 0 if "No rules" in rules else len([l for l in rules.splitlines() if l.strip()])
    if enabled and enabled.group(1) in ("1", "2") and n > 0:
        return R("pass", f"audit enabled={enabled.group(1)}, {n} rules loaded", "auditctl -s / -l")
    return R("fail", f"audit enabled={enabled.group(1) if enabled else '?'}, {n} rules loaded", "auditctl -s / -l")


@check("kernel.modules_blacklist", "kernel", "Risky kernel modules blocked", 2,
       "Rare network protocols and FireWire have a long history of kernel bugs and DMA attacks.")
def _():
    blocked, open_ = [], []
    for mod in ("dccp", "sctp", "rds", "tipc", "firewire-core"):
        rc, out, _ = run(["modprobe", "-n", "-v", mod], 10)
        (blocked if "/bin/false" in out or "/bin/true" in out else open_).append(mod)
    if not open_:
        return R("pass", f"blocked: {', '.join(blocked)}", "modprobe -n -v")
    return R("warn", f"loadable: {', '.join(open_)}; blocked: {', '.join(blocked) or 'none'}", "modprobe -n -v")


# ════════════════════════ INTEGRITY ════════════════════════
@check("int.aide_db", "integrity", "AIDE baseline exists and is recent", 4,
       "AIDE compares files with a known-good baseline to detect tampering.")
def _():
    a = age_days("/var/lib/aide/aide.db")
    if a is None:
        return R("fail", "No AIDE database (/var/lib/aide/aide.db)", "/var/lib/aide/aide.db")
    if a > 90:
        return R("warn", f"Baseline is {a:.0f} days old: update it after verifying the system", "/var/lib/aide/aide.db")
    return R("pass", f"Baseline created {a:.0f} days ago", "/var/lib/aide/aide.db")


@check("int.aide_check", "integrity", "AIDE check run recently", 2,
       "A baseline is useful only if the system is compared with it regularly.")
def _():
    logs = sorted(glob.glob("/var/log/nefi/aide-check-*.log") + glob.glob("/var/log/aide/aide.log*"),
                  key=lambda p: os.stat(p).st_mtime)
    if not logs:
        return R("warn", "No AIDE check found (run it from DFIR > Integrity Control)", "/var/log/nefi/aide-check-*.log")
    a = age_days(logs[-1])
    return R("pass" if a <= 7 else "warn", f"Last check {a:.1f} days ago ({os.path.basename(logs[-1])})", logs[-1])


@check("int.dpkg_verify", "integrity", "System files match their packages", 6,
       "Detects modified or replaced system binaries and libraries (checksums of every installed package).",
       ttl=86400)
def _():
    rc, out, err = run(["nice", "-n", "19", "dpkg", "--verify"], 900)
    if rc == 124:
        return R("unknown", "dpkg --verify timed out", "dpkg --verify")
    changed = []
    for line in out.splitlines():
        parts = line.split()
        # formato: ??5?????? [c] /percorso  ->  'c' = file di configurazione (modifiche lecite)
        if len(parts) >= 2 and parts[0][2:3] == "5" and parts[1] != "c":
            changed.append(parts[-1])
    if changed:
        return R("fail", f"{len(changed)} non-config files differ from their package:\n" + "\n".join(changed[:30]),
                 "dpkg --verify")
    return R("pass", "All non-configuration package files match their checksums", "dpkg --verify")


KNOWN_SUID = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/pkexec", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/fusermount3", "/usr/bin/fusermount", "/usr/bin/firejail", "/usr/sbin/exim4",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/lib/openssh/ssh-keysign",
    "/usr/sbin/pppd", "/usr/lib/xorg/Xorg.wrap", "/usr/bin/ntfs-3g", "/usr/lib/chromium/chrome-sandbox",
}


@check("int.suid", "integrity", "No unexpected SUID programs", 4,
       "A new SUID-root program is a typical backdoor left by an attacker.", ttl=21600)
def _():
    rc, out, _ = run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"], 300)
    found = sorted(out.split())
    extra = [f for f in found if f not in KNOWN_SUID]
    ev = f"{len(found)} SUID programs" + (f"; unexpected: {', '.join(extra[:15])}" if extra else "; all expected")
    return R("warn" if extra else "pass", ev, "find / -xdev -perm -4000")


@check("int.critical_perms", "integrity", "Critical files have safe permissions", 4,
       "Writable or readable identity files allow account takeover.")
def _():
    rules = [("/etc/passwd", 0o644, False), ("/etc/group", 0o644, False),
             ("/etc/shadow", 0o640, True), ("/etc/gshadow", 0o640, True), ("/etc/sudoers", 0o440, True)]
    bad, ok = [], []
    for path, maxmode, secret in rules:
        try:
            st = os.stat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        if st.st_uid != 0 or mode & ~maxmode or (secret and mode & 0o004):
            bad.append(f"{path} {oct(mode)} uid={st.st_uid}")
        else:
            ok.append(f"{path} {oct(mode)}")
    return R("fail" if bad else "pass", ("WRONG: " + "; ".join(bad) + "\n" if bad else "") + "; ".join(ok), "stat")


@check("int.world_writable", "integrity", "No world-writable files in /etc and /usr", 4,
       "Any user could modify a world-writable system file.", ttl=21600)
def _():
    rc, out, _ = run(["find", "/etc", "/usr", "-xdev", "-type", "f", "-perm", "-0002"], 300)
    files = out.split()
    return R("fail" if files else "pass",
             f"{len(files)} world-writable: {', '.join(files[:10])}" if files else "none found",
             "find /etc /usr -perm -0002")


# ════════════════════════ SERVICES (verifica del funzionamento) ════════════════════════
@check("svc.firewall", "services", "Firewall blocks incoming traffic", 10,
       "Checks the LOADED rules, not just the service: an input chain with policy drop must exist.")
def _():
    rc, out, err = run(["nft", "list", "ruleset"], 15)
    if rc != 0:
        return R("fail", f"nft list ruleset failed: {err.strip()[:200]}", "nft list ruleset")
    drops = re.findall(r"type filter hook input priority [^;]+; policy drop", out)
    tables = re.findall(r"^table (\S+ \S+)", out, re.M)
    if drops:
        return R("pass", f"input chain with policy drop loaded; tables: {', '.join(tables)}", "nft list ruleset")
    return R("fail", f"No input chain with policy drop; tables: {', '.join(tables) or 'none'}", "nft list ruleset")


@check("svc.fail2ban", "services", "fail2ban responding with active jails", 3,
       "Bans addresses after repeated failed logins.")
def _():
    if not have("fail2ban-client"):
        return R("fail", "fail2ban not installed", "fail2ban-client")
    rc, out, _ = run(["fail2ban-client", "ping"], 10)
    if "pong" not in out:
        return R("fail", "fail2ban server not responding", "fail2ban-client ping")
    rc, out, _ = run(["fail2ban-client", "status"], 10)
    m = re.search(r"Jail list:\s*(.*)", out)
    jails = [j.strip() for j in (m.group(1) if m else "").split(",") if j.strip()]
    return R("pass" if jails else "warn", f"jails: {', '.join(jails) or 'none'}", "fail2ban-client status")


@check("svc.falco", "services", "Falco runtime detection running", 4,
       "Detects suspicious activity on the system in real time.")
def _():
    if not os.path.exists("/usr/bin/falco"):
        return R("warn", "Falco not installed (Detection > Runtime Alerts > Install Falco)", "/usr/bin/falco")
    act = svc_active("falco-modern-bpf.service")
    rc, out, _ = run(["pgrep", "-x", "falco"], 5)
    return R("pass" if act and out.strip() else "fail",
             f"service {'active' if act else 'not active'}, process {'running' if out.strip() else 'not running'}",
             "systemctl / pgrep falco")


@check("svc.crowdsec", "services", "CrowdSec engine and firewall bouncer working", 4,
       "Blocks hostile addresses automatically; the bouncer must be connected to the engine.")
def _():
    if not os.path.exists("/usr/bin/cscli"):
        return R("warn", "CrowdSec not installed (Response > Threat Blocking > Install CrowdSec)", "/usr/bin/cscli")
    eng, bnc = svc_active("crowdsec.service"), svc_active("crowdsec-firewall-bouncer.service")
    rc, out, err = run(["cscli", "lapi", "status"], 20)
    lapi = rc == 0
    rc2, nft, _ = run(["nft", "list", "tables"], 10)
    tbl = "crowdsec" in nft
    ok = eng and bnc and lapi and tbl
    return R("pass" if ok else "fail",
             f"engine {'active' if eng else 'DOWN'}, bouncer {'active' if bnc else 'DOWN'}, "
             f"local API {'ok' if lapi else 'error'}, firewall table {'present' if tbl else 'missing'}",
             "systemctl / cscli lapi status / nft list tables")


@check("svc.clamav", "services", "Antivirus signatures up to date", 2,
       "ClamAV detects known malware only with fresh signatures.")
def _():
    dbs = glob.glob("/var/lib/clamav/daily.c[lv]d")
    if not dbs:
        return R("fail" if pkg_installed("clamav") else "warn", "No ClamAV signature database", "/var/lib/clamav")
    a = min(age_days(p) for p in dbs)
    return R("pass" if a <= 3 else "warn", f"daily signatures {a:.1f} days old", "/var/lib/clamav/daily.*")


@check("svc.suricata", "services", "Suricata IDS running", 2,
       "Network intrusion detection on the traffic of this machine.")
def _():
    if not pkg_installed("suricata"):
        return R("warn", "Suricata not installed", "dpkg-query suricata")
    rc, out, _ = run(["pgrep", "-x", "Suricata-Main"], 5)
    rc2, out2, _ = run(["pgrep", "-x", "suricata"], 5)
    act = svc_active("suricata.service")
    running = bool(out.strip() or out2.strip())
    return R("pass" if act and running else "fail", f"service {'active' if act else 'not active'}, "
             f"process {'running' if running else 'not running'}", "systemctl / pgrep")


# ════════════════════════ PACKAGES ════════════════════════
@check("pkg.vulnerable", "packages", "No installed packages with fixed vulnerabilities", 7,
       "debsecan compares installed versions with the Debian security tracker.", ttl=21600)
def _():
    if not have("debsecan"):
        return R("unknown", "debsecan not installed", "which debsecan")
    code = (read("/etc/os-release", "") or "")
    m = re.search(r"^VERSION_CODENAME=(\S+)", code, re.M)
    suite = m.group(1) if m else "trixie"
    rc, out, err = run(["debsecan", f"--suite={suite}", "--only-fixed", "--format=packages"], 180)
    if rc != 0:
        return R("unknown", f"debsecan failed (needs Internet): {err.strip()[:150]}", "debsecan")
    pkgs = out.split()
    if pkgs:
        return R("fail", f"{len(pkgs)} packages have security fixes available: {', '.join(pkgs[:20])}",
                 f"debsecan --suite={suite} --only-fixed")
    return R("pass", "No known fixed vulnerabilities in installed packages", f"debsecan --suite={suite} --only-fixed")


@check("pkg.restart", "packages", "No services running outdated libraries", 3,
       "After an update, services keep using the old vulnerable code until restarted.")
def _():
    if not have("needrestart"):
        return R("unknown", "needrestart not installed", "which needrestart")
    rc, out, _ = run(["needrestart", "-b", "-r", "l"], 60)
    ksta = re.search(r"NEEDRESTART-KSTA:\s*(\d)", out)
    svcs = re.findall(r"NEEDRESTART-SVC:\s*(\S+)", out)
    kern = ksta.group(1) if ksta else "0"
    issues = []
    if kern in ("2", "3"):
        issues.append("a newer kernel is installed (reboot needed)")
    if svcs:
        issues.append(f"services to restart: {', '.join(svcs[:10])}")
    return R("warn" if issues else "pass", "; ".join(issues) or "Kernel and services are current", "needrestart -b")


@check("pkg.repos", "packages", "Package sources are signed", 5,
       "Unsigned or 'trusted=yes' sources let anyone on the network inject packages.")
def _():
    files = ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*")
    bad, n = [], 0
    for f in files:
        txt = read(f, "") or ""
        for line in txt.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            n += 1
            if re.search(r"trusted\s*[=:]\s*yes", s, re.I) or re.search(r"allow-insecure\s*[=:]\s*yes", s, re.I):
                bad.append(f"{os.path.basename(f)}: {s[:120]}")
    return R("fail" if bad else "pass", "\n".join(bad) if bad else f"{n} source entries, none marked trusted/insecure",
             "/etc/apt/sources.list*")


@check("pkg.dpkg_state", "packages", "Package database consistent", 2,
       "Half-installed packages can leave security fixes not applied.")
def _():
    rc, out, _ = run(["dpkg", "--audit"], 60)
    held_rc, held, _ = run(["apt-mark", "showhold"], 30)
    issues = []
    if out.strip():
        issues.append("dpkg --audit: " + out.strip().splitlines()[0])
    if held.strip():
        issues.append("held packages (not updated): " + ", ".join(held.split()[:10]))
    return R("warn" if issues else "pass", "\n".join(issues) or "No broken or held packages", "dpkg --audit / apt-mark showhold")


# ════════════════════════ CONFIG ════════════════════════
@check("cfg.encryption", "config", "System disk encrypted (LUKS)", 8,
       "Without encryption, anyone with the disk can read every file.")
def _():
    rc, src, _ = run(["findmnt", "-no", "SOURCE", "/"], 10)
    src = src.strip()
    rc, tree, _ = run(["lsblk", "-s", "-no", "NAME,TYPE", src], 10)
    if "crypt" in tree:
        return R("pass", f"/ on {src}, encrypted ({' > '.join(l.split()[0].strip('└─├│ ') for l in tree.splitlines())})",
                 "findmnt / lsblk -s")
    return R("fail", f"/ on {src}: not on an encrypted device", "findmnt / lsblk -s")


@check("cfg.ssh", "config", "SSH server hardened (or not installed)", 5,
       "An exposed SSH server must refuse root and limit login attempts.")
def _():
    if not os.path.exists("/usr/sbin/sshd"):
        return R("pass", "SSH server not installed: nothing exposed", "/usr/sbin/sshd")
    rc, out, err = run(["sshd", "-T"], 15)
    if rc != 0:
        return R("unknown", f"sshd -T failed: {err.strip()[:150]}", "sshd -T")
    conf = dict(l.split(None, 1) for l in out.splitlines() if " " in l)
    problems = []
    if conf.get("permitrootlogin") not in ("no",):
        problems.append(f"permitrootlogin {conf.get('permitrootlogin')}")
    if int(conf.get("maxauthtries", "6")) > 4:
        problems.append(f"maxauthtries {conf.get('maxauthtries')}")
    if conf.get("x11forwarding") == "yes":
        problems.append("x11forwarding yes")
    if conf.get("permitemptypasswords") == "yes":
        problems.append("permitemptypasswords yes")
    ev = (f"permitrootlogin={conf.get('permitrootlogin')}, maxauthtries={conf.get('maxauthtries')}, "
          f"passwordauthentication={conf.get('passwordauthentication')}, x11forwarding={conf.get('x11forwarding')}")
    return R("fail" if problems else "pass", ("Problems: " + ", ".join(problems) + "\n" if problems else "") + ev, "sshd -T")


@check("cfg.sudo", "config", "sudo hardened (no NOPASSWD, logging, use_pty)", 5,
       "Passwordless sudo turns any compromised user account into root.")
def _():
    texts = [read("/etc/sudoers", "") or ""] + [read(f, "") or "" for f in glob.glob("/etc/sudoers.d/*")]
    allt = "\n".join(l for t in texts for l in t.splitlines() if not l.strip().startswith("#"))
    nopw = [l.strip() for l in allt.splitlines() if "NOPASSWD" in l]
    missing = [d for d in ("use_pty", "logfile") if d not in allt]
    if nopw:
        return R("fail", "NOPASSWD rules: " + " | ".join(nopw[:5]), "/etc/sudoers*")
    return R("warn" if missing else "pass",
             f"no NOPASSWD rules; missing defaults: {', '.join(missing)}" if missing else "no NOPASSWD, use_pty and logfile set",
             "/etc/sudoers*")


@check("cfg.accounts", "config", "Accounts safe (single UID 0, no empty passwords, root locked)", 7,
       "Extra UID 0 accounts and empty passwords are classic backdoors.")
def _():
    uid0 = [l.split(":")[0] for l in (read("/etc/passwd", "") or "").splitlines() if l.split(":")[2:3] == ["0"]]
    empty = [l.split(":")[0] for l in (read("/etc/shadow", "") or "").splitlines() if l.split(":")[1:2] == [""]]
    rc, out, _ = run(["passwd", "-S", "root"], 10)
    root_state = out.split()[1] if len(out.split()) > 1 else "?"
    problems = []
    if uid0 != ["root"]:
        problems.append(f"UID 0 accounts: {', '.join(uid0)}")
    if empty:
        problems.append(f"empty passwords: {', '.join(empty)}")
    if root_state not in ("L", "NP"):
        problems.append("root has a usable password (prefer sudo only)")
    status = "fail" if (uid0 != ["root"] or empty) else ("warn" if problems else "pass")
    return R(status, "; ".join(problems) or "only root has UID 0, no empty passwords, root locked",
             "/etc/passwd /etc/shadow passwd -S")


@check("cfg.password_policy", "config", "Password policy (quality, expiry, umask)", 3,
       "Weak or never-changing passwords and permissive umask expose accounts and files.")
def _():
    defs = read("/etc/login.defs", "") or ""
    def val(k):
        m = re.search(rf"^{k}\s+(\S+)", defs, re.M)
        return m.group(1) if m else None
    pwq = "pam_pwquality" in (read("/etc/pam.d/common-password", "") or "")
    maxd, umask = val("PASS_MAX_DAYS"), val("UMASK")
    probs = []
    if not pwq:
        probs.append("no pam_pwquality")
    if not maxd or int(maxd) > 365:
        probs.append(f"PASS_MAX_DAYS {maxd}")
    if umask not in ("027", "077", "0027", "0077"):
        probs.append(f"UMASK {umask}")
    return R("warn" if probs else "pass",
             ", ".join(probs) if probs else f"pam_pwquality on, PASS_MAX_DAYS {maxd}, UMASK {umask}",
             "/etc/login.defs /etc/pam.d/common-password")


@check("cfg.listening", "config", "No unexpected network services listening", 3,
       "Every listening service is a door; the firewall must cover what is open.")
def _():
    rc, out, _ = run(["ss", "-H", "-tulnp"], 10)
    exposed = []
    for l in out.splitlines():
        p = l.split()
        if len(p) < 5:
            continue
        local = p[4]
        if local.startswith(("127.", "[::1]", "::1", "localhost")) or local.startswith("%lo"):
            continue
        proc = re.search(r'users:\(\("([^"]+)"', l)
        exposed.append(f"{p[0]} {local} ({proc.group(1) if proc else '?'})")
    allowed = [e for e in exposed if ":22 " in e and "sshd" in e]
    others = [e for e in exposed if e not in allowed]
    return R("warn" if others else "pass",
             ("Listening on the network: " + "; ".join(others[:12])) if others else
             ("Only SSH listens on the network" if allowed else "No service listens on the network"),
             "ss -tulnp")


# ════════════════════════ BACKUP ════════════════════════
@check("bk.snapshots", "backup", "Recent system snapshot or backup", 5,
       "Snapshots let you roll back after a compromise, a bad update or ransomware.")
def _():
    rc, fs, _ = run(["findmnt", "-no", "FSTYPE", "/"], 10)
    fs = fs.strip()
    if fs == "btrfs" and have("snapper"):
        rc, out, _ = run(["snapper", "--csvout", "-c", "root", "list", "--columns", "number,date"], 30)
        rows = [l.split(",") for l in out.splitlines()[1:] if l and not l.startswith("0,")]
        if rows:
            newest = rows[-1][1]
            try:
                ts = time.mktime(time.strptime(newest[:19], "%Y-%m-%d %H:%M:%S"))
                a = (time.time() - ts) / 86400
            except ValueError:
                a = None
            ev = f"{len(rows)} snapper snapshots, newest {newest}"
            return R("pass" if a is not None and a <= 7 else "warn", ev, "snapper list")
        return R("fail", "Btrfs with snapper but no snapshots (System > Snapshots)", "snapper list")
    tsconf = read("/etc/timeshift/timeshift.json")
    if tsconf:
        snaps = sorted(glob.glob("/timeshift/snapshots/*") + glob.glob("/run/timeshift/*/backup/timeshift/snapshots/*"))
        if snaps:
            a = age_days(snaps[-1])
            return R("pass" if a is not None and a <= 7 else "warn", f"Timeshift: {len(snaps)} snapshots, newest "
                     f"{a:.1f} days old" if a is not None else "Timeshift configured", "timeshift snapshots")
        return R("warn", "Timeshift configured but no snapshot found", "/etc/timeshift/timeshift.json")
    return R("fail", f"No snapshot/backup tool configured (root filesystem: {fs})", "findmnt / snapper / timeshift")


@check("bk.restore_test", "backup", "Restore tested in the last 90 days", 1,
       "An untested backup may not restore. Mark a restore test from System > Backup & Recovery.")
def _():
    a = age_days("/var/lib/nefi/backup/last-restore-test")
    if a is None:
        return R("warn", "No restore test recorded", "/var/lib/nefi/backup/last-restore-test")
    return R("pass" if a <= 90 else "warn", f"Last restore test {a:.0f} days ago", "/var/lib/nefi/backup/last-restore-test")


# ════════════════════════ UPDATES ════════════════════════
@check("up.lists", "updates", "Package lists refreshed recently", 2,
       "Without fresh package lists, available security updates are not even known.")
def _():
    lists = glob.glob("/var/lib/apt/lists/*_InRelease")
    if not lists:
        return R("fail", "No package lists", "/var/lib/apt/lists")
    a = min(age_days(p) for p in lists)
    return R("pass" if a <= 2 else "warn", f"Newest package list {a:.1f} days old", "/var/lib/apt/lists/*_InRelease")


@check("up.security_pending", "updates", "No pending security updates", 8,
       "Installed packages with a published security fix are the most common way in.")
def _():
    if not glob.glob("/var/lib/apt/lists/*_InRelease"):
        return R("unknown", "No package lists: cannot know which updates exist (run apt update)", "/var/lib/apt/lists")
    rc, out, _ = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], 120)
    sec = [l.split()[1] for l in out.splitlines() if l.startswith("Inst ") and "-security" in l]
    allup = [l for l in out.splitlines() if l.startswith("Inst ")]
    if sec:
        return R("fail", f"{len(sec)} security updates pending: {', '.join(sec[:15])}", "apt-get -s upgrade")
    return R("pass", f"No security updates pending ({len(allup)} other updates available)", "apt-get -s upgrade")


@check("up.automatic", "updates", "Automatic security updates working", 5,
       "unattended-upgrades must be enabled AND have run recently.")
def _():
    if not pkg_installed("unattended-upgrades"):
        return R("fail", "unattended-upgrades not installed", "dpkg-query")
    rc, out, _ = run(["apt-config", "dump"], 15)
    enabled = re.search(r'APT::Periodic::Unattended-Upgrade "(\d+)"', out)
    timer = svc_active("apt-daily-upgrade.timer")
    a = age_days("/var/log/unattended-upgrades/unattended-upgrades.log")
    ev = (f"enabled={enabled.group(1) if enabled else '0'}, apt-daily-upgrade.timer "
          f"{'active' if timer else 'inactive'}, last run "
          f"{'%.1f days ago' % a if a is not None else 'never'}")
    if not (enabled and enabled.group(1) != "0" and timer):
        return R("fail", ev, "apt-config dump / systemctl / unattended-upgrades.log")
    return R("pass" if a is not None and a <= 3 else "warn", ev, "apt-config dump / systemctl / unattended-upgrades.log")


@check("up.reboot", "updates", "No reboot pending", 2,
       "Kernel and core library updates take effect only after a reboot.")
def _():
    if os.path.exists("/run/reboot-required"):
        pk = (read("/run/reboot-required.pkgs", "") or "").split()
        return R("warn", "Reboot required" + (f" by: {', '.join(pk[:8])}" if pk else ""), "/run/reboot-required")
    return R("pass", "No reboot required", "/run/reboot-required")


@check("up.release", "updates", "Debian release supported", 3,
       "An end-of-life release receives no security updates.")
def _():
    osr = read("/etc/os-release", "") or ""
    m = re.search(r"^VERSION_CODENAME=(\S+)", osr, re.M)
    code = m.group(1) if m else "?"
    supported = {"trixie", "forky", "bookworm"}
    return R("pass" if code in supported else "warn", f"Debian codename: {code}", "/etc/os-release")


# ── esecuzione ──────────────────────────────────────────────────────────
def write_atomic(path, data, mode=0o640, group="sudo"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1)
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        gid = 0
    os.chown(tmp, 0, gid)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def score_of(results):
    total = sum(r["weight"] for r in results)
    verif = [r for r in results if r["status"] != "unknown"]
    vw = sum(r["weight"] for r in verif)
    got = sum(r["weight"] * (1 if r["status"] == "pass" else 0.5 if r["status"] == "warn" else 0) for r in verif)
    return {
        "score": round(100 * got / vw) if vw else None,
        "coverage": round(100 * vw / total) if total else 0,
        "passed": sum(1 for r in results if r["status"] == "pass"),
        "warnings": sum(1 for r in results if r["status"] == "warn"),
        "failed": sum(1 for r in results if r["status"] == "fail"),
        "unknown": sum(1 for r in results if r["status"] == "unknown"),
        "total": len(results),
    }


def main():
    if os.geteuid() != 0:
        sys.exit("NEFI: run as root")
    full = "--full" in sys.argv
    try:
        with open(CACHE) as f:
            cache = json.load(f)
    except (OSError, ValueError):
        cache = {}
    now = time.time()
    results = []
    for cid, cat, title, weight, ttl, fn, why in CHECKS:
        c = cache.get(cid)
        if ttl and not full and c and now - c.get("at", 0) < ttl:
            r = dict(c["result"])
            r["cached_at"] = c["at"]
        else:
            t0 = time.time()
            try:
                r = fn()
            except Exception as e:     # un controllo rotto non deve fermare gli altri
                r = R("unknown", f"check error: {type(e).__name__}: {e}", "")
            r["duration"] = round(time.time() - t0, 2)
            if ttl:
                cache[cid] = {"at": now, "result": r}
        r.update({"id": cid, "category": cat, "title": title, "weight": weight, "why": why})
        results.append(r)
    report = {
        "version": VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hostname": os.uname().nodename,
        "summary": score_of(results),
        "categories": {k: dict(name=v, **score_of([r for r in results if r["category"] == k]))
                       for k, v in CATEGORIES.items()},
        "weights_doc": WEIGHTS_DOC,
        "checks": results,
    }
    write_atomic(REPORT, report)
    write_atomic(CACHE, cache, mode=0o600, group="root")
    s = report["summary"]
    print(f"[NEFI] Security Score {s['score']}/100  coverage {s['coverage']}%  "
          f"pass {s['passed']}  warn {s['warnings']}  fail {s['failed']}  not verifiable {s['unknown']}")


if __name__ == "__main__":
    main()
