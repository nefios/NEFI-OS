#!/usr/bin/env python3
"""NEFI OS - DFIR: raccolta, custodia, memoria, timeline e dischi (root, lanciato dal Security Center con pkexec).

Prove e catena di custodia
  dfir.py collect <caso> <operatore> <motivo>          raccolta live (collect.sh) + manifest firmato
  dfir.py verify <ID>                                  firma del manifest + SHA-256 di ogni oggetto + registro
  dfir.py export <ID> <cartella>                       copia verificata su un altro disco, con chiave pubblica
  dfir.py note <ID> <operatore> <testo>                annotazione nel registro di custodia (es. consegna)
  dfir.py delete <ID> <operatore> <motivo>             elimina la prova (la riga nel registro resta)
  dfir.py store <cartella>                             dove salvare le prove (meglio un disco esterno)
  dfir.py key-export <cartella>                        chiave pubblica che verifica le firme
  dfir.py custody-verify                               controlla la catena del registro di custodia
Memoria
  dfir.py memory <caso> <operatore> <motivo>           acquisizione completa della RAM con AVML, verificata
  dfir.py vol <ID> <plugin>                            analisi con Volatility 3 (plugin in elenco)
Timeline
  dfir.py timeline <giorni> <fonti,separate,da,virgole> <caso> <operatore> [immagine]
  dfir.py plaso <ID>                                   super-timeline con Plaso di una raccolta o di un'immagine
Dischi
  dfir.py writeblock <on|off>                          i dischi USB collegati da ora in poi sono in sola lettura
  dfir.py image <dispositivo> <cartella> <e01|raw> <caso> <operatore> <motivo>
  dfir.py analyze <ID> <mmls|fsstat|fls|foremost|bulk_extractor>

Ogni operazione finisce nel registro di custodia con l'account che l'ha lanciata.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import custody as cu   # noqa: E402
import timeline as tl  # noqa: E402

COLLECT = "/opt/nefi/forensics/collect.sh"
VOL = "/opt/nefi/forensics/vol3/bin/vol"
WRITEBLOCK_RULE = "/etc/udev/rules.d/01-nefi-writeblock.rules"
VOL_PLUGINS = ["banners.Banners", "linux.pslist.PsList", "linux.pstree.PsTree", "linux.psaux.PsAux",
               "linux.bash.Bash", "linux.lsmod.Lsmod", "linux.check_modules.Check_modules",
               "linux.check_syscall.Check_syscall", "linux.sockstat.Sockstat", "linux.malfind.Malfind",
               "linux.envars.Envars", "linux.lsof.Lsof", "linux.mountinfo.MountInfo"]
ANALYSIS = {
    "mmls": (["mmls"], "Partition table"),
    "fsstat": (["fsstat"], "File system details"),
    "fls": (["fls", "-r", "-p", "-l"], "All files, including deleted ones"),
    "foremost": (["foremost", "-q", "-i"], "File carving"),
    "bulk_extractor": (["bulk_extractor", "-o"], "Artifact extraction (e-mail, URLs, card numbers...)"),
}


def say(msg):
    print(f"[NEFI] {msg}", flush=True)


def fail(msg):
    print(f"[NEFI] ERROR: {msg}", flush=True)
    sys.exit(1)


def stream(cmd, env=None, timeout=None):
    """Esegue mostrando l'uscita riga per riga. -> (codice, testo)"""
    lines = []
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
                             env=env or cu.ENV)
    except OSError as e:
        return 127, str(e)
    last = 0
    for line in p.stdout:
        line = line.rstrip()
        lines.append(line)
        if line.strip() and (time.time() - last > 1 or "Status:" not in line):
            print(line, flush=True)
            last = time.time()
    p.wait()
    return p.returncode, "\n".join(lines)


def free_bytes(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def tool_version(args):
    rc, out, err = cu.run(args, 20)
    return ((out or err).strip().splitlines() or [""])[0][:120]


def base_manifest(eid, kind, case, operator, reason, description):
    return {"evidence_id": eid, "kind": kind, "case": case, "operator": operator, "account": cu.account(),
            "reason": reason, "description": description, "collected_utc": cu.utc_now(),
            "time": cu.time_context(), "host": cu.host_context(), "objects": [], "tools": {},
            "format": "NEFI evidence manifest v1"}


def add_object(manifest, path, name=None, files=None):
    say(f"hashing {os.path.basename(path)} (SHA-256)...")
    obj = {"name": name or os.path.basename(path), "path": path, "size": os.path.getsize(path),
           "sha256": cu.sha256_file(path)}
    if files is not None:
        obj["contents"] = files
    manifest["objects"].append(obj)
    return obj


# ── raccolta live ───────────────────────────────────────────────────────
def collect(case, operator, reason):
    store = cu.ensure_store()
    eid = cu.new_id("EV")
    manifest = base_manifest(eid, "live-collection", case, operator, reason,
                             "Live response collection: system, processes, network, logs, hashes, persistence")
    cu.custody("collection-started", eid, operator, case=case, reason=reason)
    env = dict(cu.ENV, NEFI_EV_BASE=store, NEFI_EV_NAME=eid)
    rc, out = stream(["bash", COLLECT], env=env)
    archive = os.path.join(store, eid + ".tar.gz")
    if rc != 0 or not os.path.isfile(archive):
        cu.custody("collection-failed", eid, operator, exit_code=rc)
        fail("the collection did not complete; nothing was signed")
    folder, contents = os.path.join(store, eid), []
    for root, _dirs, names in os.walk(folder):
        for n in sorted(names):
            p = os.path.join(root, n)
            if os.path.isfile(p) and not os.path.islink(p):
                contents.append({"path": os.path.relpath(p, folder), "size": os.path.getsize(p),
                                 "sha256": cu.sha256_file(p)})
    add_object(manifest, archive, files=contents)
    manifest["tools"] = {"collector": "NEFI collect.sh", "tar": tool_version(["tar", "--version"])}
    cu.write_manifest(manifest)
    cu.custody("collected", eid, operator, case=case, sha256=manifest["objects"][0]["sha256"], files=len(contents))
    say(f"Evidence {eid}: {len(contents)} files, manifest signed.")
    say(f"Stored in {store}")
    return eid


# ── verifica ────────────────────────────────────────────────────────────
def verify(eid, quiet=False):
    try:
        m = cu.load_manifest(eid)
    except (OSError, ValueError) as e:
        fail(f"manifest of {eid} not readable: {e}")
    problems = []
    ok, info = cu.verify_signature(cu.manifest_path(eid))
    say(f"manifest signature: {'VALID, key ' + info if ok else 'INVALID - ' + info}")
    if not ok:
        problems.append("signature")
    elif m.get("signing_key") and m["signing_key"] != info:
        say(f"WARNING: signed by {info}, but the manifest names {m['signing_key']}")
        problems.append("signing key mismatch")
    for obj in m.get("objects", []):
        path = obj.get("path", "")
        if not os.path.isfile(path):
            say(f"{obj.get('name')}: MISSING at {path} (moved or exported? verify the copy with its own manifest)")
            problems.append(f"missing {obj.get('name')}")
            continue
        digest = cu.sha256_file(path)
        good = digest == obj.get("sha256")
        say(f"{obj.get('name')}: {'intact' if good else 'CHANGED'} (SHA-256 {digest})")
        if not good:
            problems.append(f"hash {obj.get('name')}")
    cok, n, msg = cu.verify_custody()
    say(f"custody log: {'OK' if cok else 'TAMPERED'} - {msg}")
    if not cok:
        problems.append("custody log")
    if not quiet:
        cu.custody("verified", eid, result="intact" if not problems else "FAILED: " + ", ".join(problems))
    say("RESULT: evidence intact." if not problems else "RESULT: VERIFICATION FAILED (" + ", ".join(problems) + ")")
    return not problems


def check_dest(dest):
    dest = os.path.realpath(dest)
    if not os.path.isdir(dest):
        fail(f"{dest} is not an existing folder (mount the disk first)")
    if dest == "/" or dest.startswith(("/proc", "/sys", "/dev", "/run/user", "/boot", "/etc", "/usr", "/bin", "/sbin")):
        fail("this folder cannot hold evidence")
    return dest


def export(eid, dest):
    dest = check_dest(dest)
    m = cu.load_manifest(eid)
    need = sum(o.get("size", 0) for o in m["objects"])
    if free_bytes(dest) < need + 16 * 1024 * 1024:
        fail(f"not enough free space in {dest}: {need // 2**20} MB needed")
    target = os.path.join(dest, eid)
    os.makedirs(target, mode=0o700, exist_ok=True)
    for obj in m["objects"]:
        if not os.path.isfile(obj["path"]):
            fail(f"{obj['name']} is not in the store any more")
        out = os.path.join(target, obj["name"])
        say(f"copying {obj['name']} ({obj['size'] // 2**20} MB)...")
        shutil.copyfile(obj["path"], out)
        if cu.sha256_file(out) != obj["sha256"]:
            os.remove(out)
            cu.custody("export-failed", eid, destination=target, object=obj["name"])
            fail(f"the copy of {obj['name']} does not match the original: export aborted")
    for extra in (cu.manifest_path(eid), cu.manifest_path(eid) + ".asc"):
        shutil.copyfile(extra, os.path.join(target, os.path.basename(extra)))
    fpr = cu.export_public_key(os.path.join(target, "NEFI-EVIDENCE-KEY.asc"))
    with open(cu.custody_path(), encoding="utf-8") as f:
        mine = [l for l in f if f'"evidence": "{eid}"' in l]
    with open(os.path.join(target, "custody-extract.jsonl"), "w", encoding="utf-8") as f:
        f.writelines(mine)
    with open(os.path.join(target, "HOW-TO-VERIFY.txt"), "w") as f:
        f.write(f"""NEFI OS evidence {eid}

Verify on any computer with GnuPG and sha256sum:

  gpg --import NEFI-EVIDENCE-KEY.asc
  gpg --verify {eid}.manifest.json.asc {eid}.manifest.json
  sha256sum <object>        compare with "sha256" in {eid}.manifest.json

Signing key fingerprint: {fpr}
Compare this fingerprint with the one you recorded when the key was created:
a copy of the key kept away from the examined machine is what makes the signature trustworthy.
""")
    cu.custody("exported", eid, destination=target, objects=len(m["objects"]))
    say(f"Exported and verified: {target}")


def note(eid, operator, text):
    cu.load_manifest(eid)
    cu.custody("note", eid, operator, text=text)
    say("Note recorded in the custody log.")


def delete(eid, operator, reason):
    m = cu.load_manifest(eid)
    store = cu.store_dir()
    removed = []
    for obj in m["objects"]:
        p = os.path.realpath(obj.get("path", ""))
        if os.path.isfile(p) and (p.startswith(store + "/") or obj.get("external")):
            os.remove(p)
            removed.append(obj["name"])
    folder = os.path.join(store, eid)
    if os.path.isdir(folder) and not os.path.islink(folder):
        shutil.rmtree(folder)
    for extra in (cu.manifest_path(eid), cu.manifest_path(eid) + ".asc"):
        if os.path.exists(extra):
            os.remove(extra)
    # immagini su un altro disco: tolgo anche log e copia del manifest lasciati accanto all'immagine
    for obj in m["objects"]:
        folder = os.path.dirname(os.path.realpath(obj.get("path", "")))
        if obj.get("external") and os.path.isdir(folder):
            for name in os.listdir(folder):
                if name.startswith(eid + ".") and os.path.isfile(os.path.join(folder, name)):
                    os.remove(os.path.join(folder, name))
    cu.custody("deleted", eid, operator, reason=reason, objects=removed,
               sha256=[o.get("sha256") for o in m["objects"]])
    cu.rebuild_index()
    say(f"Evidence {eid} deleted; the custody log keeps the record of its existence and of this deletion.")


def set_store(path):
    path = check_dest(path)
    old = cu.store_dir()
    os.makedirs(os.path.dirname(cu.CONF), exist_ok=True)
    cu.write_file(cu.CONF, json.dumps({"store": path}) + "\n", 0o644, admin=False)
    cu.ensure_store(path)
    cu.rebuild_index()
    # anche il nuovo archivio e' sorvegliato dal kernel (auditd)
    if re.fullmatch(r"[A-Za-z0-9_./@+-]+", path):
        with open("/etc/audit/rules.d/56-nefi-forensics-store.rules", "w") as f:
            f.write(f"## NEFI OS - archivio delle prove scelto dall'amministratore\n-w {path}/ -p rwa -k nefi_evidence\n")
        cu.run(["augenrules", "--load"], 60)
    cu.custody("store-changed", "-", previous=old, new=path)
    say(f"New evidence is saved in {path}. Evidence already collected stays in {old}.")


# ── memoria ─────────────────────────────────────────────────────────────
def lockdown():
    try:
        with open("/sys/kernel/security/lockdown") as f:
            m = re.search(r"\[(\w+)\]", f.read())
            return m.group(1) if m else "none"
    except OSError:
        return "none"


def memory(case, operator, reason):
    avml = shutil.which("avml", path=cu.ENV["PATH"] + ":/usr/local/bin")
    if not avml:
        fail("AVML is not installed. Install the memory tools from DFIR > Memory Forensics.")
    store = cu.ensure_store()
    with open("/proc/meminfo") as f:
        total = int(re.search(r"MemTotal:\s+(\d+)", f.read()).group(1)) * 1024
    if free_bytes(store) < total * 1.05:
        fail(f"not enough free space in {store}: about {total // 2**30 + 1} GB needed for the RAM image. "
             f"Choose an external disk as evidence store.")
    eid = cu.new_id("MEM")
    out = os.path.join(store, eid + ".lime")
    cu.custody("memory-acquisition-started", eid, operator, case=case, reason=reason)
    say(f"Acquiring {total // 2**20} MB of RAM with AVML (kernel lockdown: {lockdown()})...")
    old = os.umask(0o077)
    rc, text = stream([avml, out])
    os.umask(old)
    if rc != 0 or not os.path.isfile(out) or os.path.getsize(out) == 0:
        if os.path.exists(out):
            os.remove(out)
        cu.custody("memory-acquisition-failed", eid, operator, exit_code=rc)
        hint = ""
        if lockdown() != "none":
            hint = (" The kernel is in lockdown mode (Secure Boot): it blocks every way to read physical memory "
                    "from inside the running system. Acquire the memory from the hypervisor (VM snapshot) or boot "
                    "once with Secure Boot disabled.")
        fail("AVML could not read the memory." + hint)
    # verifica dell'acquisizione: formato LiME e dimensione coerente con la RAM
    with open(out, "rb") as f:
        magic = f.read(4)
    size = os.path.getsize(out)
    checks = {"lime_header": magic == b"EMiL", "size_bytes": size, "ram_bytes": total,
              "coverage_percent": round(size * 100 / total, 1)}
    if not checks["lime_header"]:
        say("WARNING: the image does not start with a LiME header.")
    if size < total * 0.6:
        say(f"WARNING: the image is only {checks['coverage_percent']}% of the RAM size: probably incomplete.")
    manifest = base_manifest(eid, "memory", case, operator, reason, f"Full RAM image, LiME format ({size // 2**20} MB)")
    add_object(manifest, out)
    manifest["tools"] = {"avml": tool_version([avml, "--version"])}
    manifest["acquisition_checks"] = checks
    manifest["kernel_lockdown"] = lockdown()
    cu.write_manifest(manifest)
    cu.custody("memory-acquired", eid, operator, case=case, sha256=manifest["objects"][0]["sha256"], size=size)
    say(f"Memory image {eid}: {size // 2**20} MB ({checks['coverage_percent']}% of RAM), LiME header "
        f"{'OK' if checks['lime_header'] else 'MISSING'}, manifest signed.")


def vol(eid, plugin):
    if plugin not in VOL_PLUGINS:
        fail("plugin not in the allowed list")
    if not os.path.exists(VOL):
        fail("Volatility 3 is not installed. Install the memory tools from DFIR > Memory Forensics.")
    m = cu.load_manifest(eid)
    if m.get("kind") != "memory":
        fail("this evidence is not a memory image")
    image = m["objects"][0]["path"]
    out_dir = os.path.join(cu.store_dir(), "analysis", eid)
    os.makedirs(out_dir, mode=0o750, exist_ok=True)
    os.chown(out_dir, 0, cu.admin_gid())
    out = os.path.join(out_dir, f"vol-{plugin}.txt")
    say(f"Volatility 3: {plugin} on {os.path.basename(image)} (this can take minutes)...")
    env = dict(cu.ENV, HOME="/root", XDG_CACHE_HOME="/var/cache/nefi-vol3")
    r = subprocess.run([VOL, "-q", "-s", "/opt/nefi/forensics/symbols", "-f", image, plugin], capture_output=True,
                       text=True, errors="replace", env=env, timeout=3600)
    text = r.stdout + ("\n" + r.stderr if r.returncode != 0 else "")
    cu.write_file(out, text)
    print(text[:20000], flush=True)
    if r.returncode != 0 and "symbol" in (r.stderr + r.stdout).lower():
        say("Volatility needs the symbol table of THIS kernel. Create it with: "
            "sudo /opt/nefi/forensics/install-memory-tools.sh symbols")
    cu.custody("analysed", eid, tool="volatility3", plugin=plugin, output=out, exit_code=r.returncode)
    say(f"Output saved in {out}")


# ── timeline ────────────────────────────────────────────────────────────
def timeline(days, sources, case, operator, image=None):
    wanted = [s for s in sources.split(",") if s]
    if not wanted or any(s not in tl.SOURCES for s in wanted):
        fail("sources: " + ", ".join(tl.SOURCES))
    store = cu.ensure_store()
    offset = None
    if image:
        image = os.path.realpath(image)
        if not os.path.isfile(image):
            fail("image file not found")
        if not shutil.which("fls", path=cu.ENV["PATH"]):
            fail("The Sleuth Kit (fls) is not installed")
    eid = cu.new_id("TL")
    out = os.path.join(store, "timelines", eid + ".jsonl")
    say(f"Building the timeline: last {days} days, sources {', '.join(wanted)}" + (f", image {image}" if image else ""))
    old = os.umask(0o027)
    summary = tl.build(wanted, days, out, image, offset, log=lambda m: print(m, flush=True))
    tl.to_csv(out, out[:-6] + ".csv")
    os.umask(old)
    for p in (out, out[:-6] + ".csv"):
        os.chown(p, 0, cu.admin_gid())
        os.chmod(p, 0o640)
    manifest = base_manifest(eid, "timeline", case, operator, "timeline analysis",
                             f"Timeline of the last {days} days: {summary['events']} events from {', '.join(wanted)}")
    add_object(manifest, out)
    add_object(manifest, out[:-6] + ".csv")
    manifest["timeline"] = dict(summary, days=days, sources=wanted, image=image)
    cu.write_manifest(manifest)
    cu.custody("timeline-built", eid, operator, case=case, events=summary["events"], image=image)
    say(f"Timeline {eid}: {summary['events']} events from {summary['first']} to {summary['last']}")
    for s, n in sorted(summary["by_source"].items(), key=lambda x: -x[1]):
        say(f"  {s}: {n}")
    say(f"Files: {out} (JSONL, importable in Timesketch) and .csv")


def plaso(eid):
    """Super-timeline con Plaso (log2timeline + psort) su una raccolta live o su un'immagine disco."""
    # Il pacchetto Debian installa plaso-log2timeline / plaso-psort; pip installa log2timeline(.py) / psort(.py)
    def find(*names):
        return next((p for p in (shutil.which(n, path=cu.ENV["PATH"]) for n in names) if p), None)
    l2t = find("plaso-log2timeline", "log2timeline.py", "log2timeline")
    psort = find("plaso-psort", "psort.py", "psort")
    if not l2t or not psort:
        fail("Plaso is not installed (sudo apt install plaso)")
    m = cu.load_manifest(eid)
    if m.get("kind") == "disk-image":
        source = m["objects"][0]["path"]
    elif m.get("kind") == "live-collection":
        source = os.path.join(cu.store_dir(), eid)
    else:
        fail("Plaso works on a live collection or on a disk image")
    if not os.path.exists(source):
        fail(f"{source} not found")
    out_dir = os.path.join(cu.store_dir(), "timelines")
    storage = os.path.join(out_dir, f"{eid}.plaso")
    result = os.path.join(out_dir, f"{eid}.plaso.jsonl")
    for p in (storage, result):
        if os.path.exists(p):
            os.remove(p)
    say(f"Plaso: extracting events from {source} (this can take a long time)...")
    env = dict(cu.ENV, HOME="/root")
    rc, _ = stream([l2t, "--status_view", "none", "--unattended", "--storage-file", storage, source], env=env)
    if rc != 0 or not os.path.exists(storage):
        rc, _ = stream([l2t, "--status_view", "none", storage, source], env=env)       # sintassi delle versioni vecchie
    if rc != 0 or not os.path.exists(storage):
        fail("log2timeline failed")
    say("Plaso: sorting and writing the timeline...")
    rc, _ = stream([psort, "--status_view", "none", "-o", "json_line", "-w", result, storage], env=env)
    if rc != 0 or not os.path.exists(result):
        fail("psort failed")
    for p in (storage, result):
        os.chown(p, 0, cu.admin_gid())
        os.chmod(p, 0o640)
    cu.custody("analysed", eid, tool="plaso", output=result, sha256=cu.sha256_file(result))
    say(f"Plaso timeline: {result} (JSON lines, importable in Timesketch); storage file {storage}")


# ── dischi ──────────────────────────────────────────────────────────────
def lsblk(dev=None):
    cols = "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,RO,RM,MOUNTPOINTS,FSTYPE,PKNAME,VENDOR,WWN"
    rc, out, _ = cu.run(["lsblk", "-J", "-b", "-o", cols] + ([dev] if dev else []), 30)
    try:
        return json.loads(out).get("blockdevices", [])
    except ValueError:
        return []


def flatten(nodes):
    for n in nodes:
        yield n
        yield from flatten(n.get("children", []))


def system_disks():
    """I dischi su cui gira questo sistema (/, /boot, swap): non si acquisiscono a caldo da qui."""
    busy = set()
    for disk in lsblk():
        for n in flatten([disk]):
            mps = [m for m in (n.get("mountpoints") or []) if m]
            if any(m in ("/", "/boot", "/boot/efi", "/home", "/var", "/usr", "[SWAP]") for m in mps):
                busy.add(disk.get("path"))
    return busy


def set_readonly(dev):
    """Blocco di scrittura software: sola lettura a livello di dispositivo, poi VERIFICA con un tentativo di scrittura."""
    nodes = [n.get("path") for n in flatten(lsblk(dev)) if n.get("path")]
    for p in nodes:
        cu.run(["blockdev", "--setro", p], 20)
    state = {}
    for p in nodes:
        rc, out, _ = cu.run(["blockdev", "--getro", p], 20)
        flag = out.strip() == "1"
        try:
            with open(f"/sys/class/block/{os.path.basename(p)}/ro") as f:
                flag = flag and f.read().strip() == "1"
        except OSError:
            pass
        # prova reale: riscrivo il primo settore con gli STESSI byte appena letti. Il kernel deve rifiutare;
        # se per errore accettasse, il contenuto del disco resterebbe comunque identico.
        refused = False
        if flag:
            try:
                fd = os.open(p, os.O_RDWR)
                try:
                    first = os.pread(fd, 512, 0)
                    os.pwrite(fd, first, 0)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                refused = True
        state[p] = {"read_only_flag": flag, "write_open_refused": refused}
    return state


def writeblock(on):
    if on:
        with open(WRITEBLOCK_RULE, "w") as f:
            f.write('# NEFI OS - forensic write blocker: every USB/removable disk is set read-only as soon as it appears\n'
                    'ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sd*|nvme*|mmcblk*", ENV{ID_BUS}=="usb", '
                    'RUN+="/usr/sbin/blockdev --setro /dev/%k"\n'
                    'ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sd*|mmcblk*", ATTRS{removable}=="1", '
                    'RUN+="/usr/sbin/blockdev --setro /dev/%k"\n'
                    '# and the desktop must not mount them automatically\n'
                    'SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_AUTO}="0"\n')
        os.chmod(WRITEBLOCK_RULE, 0o644)
    elif os.path.exists(WRITEBLOCK_RULE):
        os.remove(WRITEBLOCK_RULE)
    cu.run(["udevadm", "control", "--reload-rules"], 20)
    cu.custody("write-blocker-" + ("enabled" if on else "disabled"), "-")
    say("Write blocker ON: disks connected FROM NOW ON are read-only and are not mounted automatically. "
        "Disks already connected are not affected: unplug and reconnect them." if on else
        "Write blocker OFF: disks connected from now on are writable again.")


def image(dev, dest, fmt, case, operator, reason):
    dev = os.path.realpath(dev)
    try:
        if not stat.S_ISBLK(os.stat(dev).st_mode):
            fail(f"{dev} is not a disk")
    except OSError:
        fail(f"{dev} not found")
    if fmt not in ("e01", "raw"):
        fail("format must be e01 or raw")
    info = lsblk(dev)
    if not info:
        fail("cannot read the disk properties")
    info = info[0]
    parent = info.get("pkname")
    top = f"/dev/{parent}" if parent else dev
    if top in system_disks() or dev in system_disks():
        fail("this is the disk the system is running from. To image it, boot NEFI from another medium "
             "and attach this disk as a second drive.")
    mounted = [(n.get("path"), m) for n in flatten([info]) for m in (n.get("mountpoints") or []) if m]
    if mounted:
        fail("unmount the disk first (it is mounted at " + ", ".join(m for _p, m in mounted) + "): "
             "a mounted file system can change while it is copied")
    dest = check_dest(dest)
    rc, out, _ = cu.run(["findmnt", "-n", "-o", "SOURCE", "--target", dest], 20)
    if out.strip() and (out.strip() == dev or out.strip().startswith(top)):
        fail("the destination is on the disk being imaged")
    size = int(info.get("size") or 0)
    if fmt == "raw" and free_bytes(dest) < size * 1.01:
        fail(f"not enough free space in {dest}: {size // 2**30 + 1} GB needed for a raw image")
    if fmt == "e01" and not shutil.which("ewfacquire", path=cu.ENV["PATH"]):
        fail("ewf-tools is not installed (sudo apt install ewf-tools)")

    eid = cu.new_id("DSK")
    cu.custody("disk-acquisition-started", eid, operator, case=case, reason=reason, device=dev,
               model=info.get("model"), serial=info.get("serial"), size=size)
    say(f"Write blocking {dev}...")
    wb = set_readonly(dev)
    blocked = all(s["read_only_flag"] and s["write_open_refused"] for s in wb.values())
    for p, s in wb.items():
        say(f"  {p}: read-only flag {'set' if s['read_only_flag'] else 'NOT SET'}, "
            f"write attempt {'refused' if s['write_open_refused'] else 'ACCEPTED'}")
    if not blocked:
        cu.custody("disk-acquisition-aborted", eid, operator, reason="write blocking could not be verified")
        fail("the write block could not be verified: acquisition aborted, the disk was not read")
    say("Write block verified. Hashing the source and acquiring...")
    base = os.path.join(dest, eid)
    manifest = base_manifest(eid, "disk-image", case, operator, reason,
                             f"{'E01' if fmt == 'e01' else 'raw'} image of {dev} "
                             f"({(info.get('vendor') or '').strip()} {(info.get('model') or '').strip()}, {size // 2**30} GB)")
    manifest["source_device"] = {k: info.get(k) for k in ("path", "model", "vendor", "serial", "wwn", "tran", "size", "type", "rm")}
    manifest["write_block"] = {"method": "blockdev --setro (software), verified by a refused write of the first sector",
                               "devices": wb, "verified": True}
    old = os.umask(0o077)
    if fmt == "e01":
        cmd = ["ewfacquire", "-u", "-t", base, "-f", "encase6", "-c", "deflate:fast", "-M", "physical",
               "-m", "removable" if str(info.get("rm")) in ("1", "True", "true") else "fixed", "-d", "sha256",
               "-S", "2GiB", "-C", case, "-E", eid, "-e", operator, "-D", manifest["description"], "-N", reason,
               "-l", base + ".acquire.log", dev]
        rc, text = stream(cmd)
        segs = sorted(p for p in os.listdir(dest) if re.fullmatch(re.escape(eid) + r"\.E\d\d|" + re.escape(eid) + r"\.E[A-Z]{2}", p))
        if rc != 0 or not segs:
            os.umask(old)
            cu.custody("disk-acquisition-failed", eid, operator, exit_code=rc)
            fail("ewfacquire failed")
        m5 = re.search(r"MD5 hash calculated over data:\s+([0-9a-f]{32})", text)
        s256 = re.search(r"SHA256 hash calculated over data:\s+([0-9a-f]{64})", text)
        say("Verifying the image against the hashes stored inside it (ewfverify)...")
        vrc, vtext = stream(["ewfverify", "-d", "sha256", "-l", base + ".verify.log", os.path.join(dest, segs[0])])
        verified = vrc == 0 and "SUCCESS" in vtext
        manifest["source_hashes"] = {"md5": m5.group(1) if m5 else None, "sha256": s256.group(1) if s256 else None}
        manifest["image_verification"] = {"tool": "ewfverify", "passed": verified}
        for sname in segs:
            add_object(manifest, os.path.join(dest, sname))["external"] = True
        manifest["tools"] = {"ewfacquire": tool_version(["ewfacquire", "-V"])}
    else:
        import hashlib
        out, h, done, last = base + ".dd", hashlib.sha256(), 0, 0
        errors = 0
        with open(dev, "rb", buffering=0) as src, open(out, "wb") as dst:
            while done < size:
                want = min(4 * 1024 * 1024, size - done)
                try:
                    chunk = src.read(want)
                except OSError:                       # settore illeggibile: zeri, e lo scrivo nel manifest
                    chunk = b"\0" * want
                    src.seek(done + want)
                    errors += 1
                if not chunk:
                    break
                dst.write(chunk)
                h.update(chunk)
                done += len(chunk)
                if time.time() - last > 2:
                    say(f"  {done * 100 // max(size, 1)}% ({done // 2**20} MB)")
                    last = time.time()
        source_hash = h.hexdigest()
        say("Verifying the image (reading it back)...")
        image_hash = cu.sha256_file(out)
        verified = image_hash == source_hash and done == size
        manifest["source_hashes"] = {"sha256": source_hash}
        manifest["image_verification"] = {"tool": "read-back SHA-256", "passed": verified, "read_errors": errors,
                                          "bytes": done}
        obj = add_object(manifest, out)
        obj["external"] = True
        manifest["tools"] = {"imager": "NEFI dfir.py raw imager"}
    os.umask(old)
    cu.write_manifest(manifest)
    for extra in (cu.manifest_path(eid), cu.manifest_path(eid) + ".asc"):
        shutil.copyfile(extra, os.path.join(dest, os.path.basename(extra)))
    cu.custody("disk-acquired", eid, operator, case=case, device=dev, serial=info.get("serial"),
               source_sha256=manifest["source_hashes"].get("sha256"), verified=verified, destination=dest)
    say(f"Image {eid} in {dest}: verification {'PASSED' if verified else 'FAILED'}; manifest signed.")
    say("The disk stays read-only until it is unplugged.")
    if not verified:
        sys.exit(1)


def analyze(eid, tool):
    if tool not in ANALYSIS:
        fail("tool: " + ", ".join(ANALYSIS))
    m = cu.load_manifest(eid)
    if m.get("kind") != "disk-image":
        fail("this evidence is not a disk image")
    img = m["objects"][0]["path"]
    if not os.path.isfile(img):
        fail(f"image not found at {img} (is the disk with the images connected?)")
    cmd, label = ANALYSIS[tool]
    if not shutil.which(cmd[0], path=cu.ENV["PATH"]):
        fail(f"{cmd[0]} is not installed (it is in the 'large' software selection)")
    out_dir = os.path.join(cu.store_dir(), "analysis", eid)
    os.makedirs(out_dir, mode=0o750, exist_ok=True)
    os.chown(out_dir, 0, cu.admin_gid())
    say(f"{label}: {tool} on {os.path.basename(img)} (the image is opened read-only)...")
    if tool in ("foremost", "bulk_extractor"):
        target = os.path.join(out_dir, f"{tool}-{time.strftime('%Y%m%d-%H%M%S')}")
        full = ["foremost", "-q", "-i", img, "-o", target] if tool == "foremost" else ["bulk_extractor", "-o", target, img]
        rc, text = stream(full)
        cu.run(["chmod", "-R", "u=rwX,g=rX,o=", target], 60)
        cu.run(["chgrp", "-R", "sudo", target], 60)
        out = target
    else:
        r = subprocess.run(cmd + [img], capture_output=True, text=True, errors="replace", env=cu.ENV, timeout=3600)
        rc, text = r.returncode, r.stdout + r.stderr
        out = os.path.join(out_dir, f"{tool}.txt")
        cu.write_file(out, text)
        print(text[:15000], flush=True)
        if rc != 0 and tool != "mmls":
            say("If this image holds a whole disk, look at the partition table first (mmls).")
    cu.custody("analysed", eid, tool=tool, output=out, exit_code=rc)
    say(f"Output saved in {out}")


def main():
    if os.geteuid() != 0:
        sys.exit("NEFI: run as root (pkexec)")
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    cmd, args = a[0], a[1:]
    try:
        cu.ensure_store()
        if cmd == "collect" and len(args) == 3:
            collect(cu.clean(args[0], "case"), cu.clean(args[1], "operator"), cu.clean(args[2], "reason"))
        elif cmd == "verify" and len(args) == 1:
            sys.exit(0 if verify(args[0]) else 1)
        elif cmd == "export" and len(args) == 2:
            export(args[0], args[1])
        elif cmd == "note" and len(args) == 3:
            note(args[0], cu.clean(args[1], "operator"), cu.clean(args[2], "note"))
        elif cmd == "delete" and len(args) == 3:
            delete(args[0], cu.clean(args[1], "operator"), cu.clean(args[2], "reason"))
        elif cmd == "store" and len(args) == 1:
            set_store(args[0])
        elif cmd == "key-export" and len(args) == 1:
            dest = check_dest(args[0])
            fpr = cu.export_public_key(os.path.join(dest, "NEFI-EVIDENCE-KEY.asc"))
            cu.custody("public-key-exported", "-", destination=dest, fingerprint=fpr)
            say(f"Public key saved in {dest}/NEFI-EVIDENCE-KEY.asc")
            say(f"Fingerprint: {fpr}  (write it down and keep it away from this machine)")
        elif cmd == "custody-verify" and not args:
            ok, n, msg = cu.verify_custody()
            say(f"custody log: {'OK' if ok else 'TAMPERED'} - {msg}")
            sys.exit(0 if ok else 1)
        elif cmd == "memory" and len(args) == 3:
            memory(cu.clean(args[0], "case"), cu.clean(args[1], "operator"), cu.clean(args[2], "reason"))
        elif cmd == "vol" and len(args) == 2:
            vol(args[0], args[1])
        elif cmd == "timeline" and len(args) in (4, 5) and args[0].isdigit() and 0 <= int(args[0]) <= 3650:
            timeline(int(args[0]), args[1], cu.clean(args[2], "case"), cu.clean(args[3], "operator"),
                     args[4] if len(args) == 5 else None)
        elif cmd == "plaso" and len(args) == 1:
            plaso(args[0])
        elif cmd == "writeblock" and args in (["on"], ["off"]):
            writeblock(args[0] == "on")
        elif cmd == "image" and len(args) == 6:
            image(args[0], args[1], args[2], cu.clean(args[3], "case"), cu.clean(args[4], "operator"),
                  cu.clean(args[5], "reason"))
        elif cmd == "analyze" and len(args) == 2:
            analyze(args[0], args[1])
        else:
            sys.exit(__doc__)
    except (ValueError, RuntimeError, OSError) as e:
        fail(str(e))


if __name__ == "__main__":
    main()
