#!/usr/bin/env python3
"""NEFI OS - Incident Response: comandi privilegiati (root, da pkexec).

Casi
  irctl.py case-open SEVERITY CATEGORY TITLE [DESCRIPTION [ALERT-ID]]
  irctl.py case-set ID severity|category|status|assignee VALUE
  irctl.py case-note ID TEXT
  irctl.py case-link ID evidence|alert|capture REF
  irctl.py case-close ID SUMMARY
  irctl.py case-verify ID                      integrita' della cronologia
Playbook e ripristino
  irctl.py playbook-start ID PLAYBOOK
  irctl.py playbook-step ID STEP done|skipped|todo [NOTE]
  irctl.py playbook-run ID STEP                esegue l'azione automatica del passo
  irctl.py recovery-check ID
  irctl.py recovery-set ID ITEM done|na|todo
Contenimento  (--case ID davanti al comando lo scrive nella cronologia del caso)
  irctl.py [--case ID] proc-freeze|proc-resume|proc-kill PID:STARTTIME
  irctl.py [--case ID] quarantine PATH [REASON]
  irctl.py [--case ID] quarantine-restore|quarantine-delete QID
  irctl.py [--case ID] ioc-add ip|domain|sha256 VALUE [NOTE]
  irctl.py [--case ID] ioc-del ip|domain|sha256 VALUE
  irctl.py [--case ID] ioc-sweep               cerca i file con gli hash bloccati

Ogni azione finisce in un registro concatenato (chi, quando, cosa). Un processo si indica con
PID:STARTTIME e i segnali passano da un pidfd: non si puo' colpire un altro programma che ha
preso lo stesso PID nel frattempo.
"""
import json
import os
import signal
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import irlib as ir   # noqa: E402

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
DETECT_CTL = "/opt/nefi/detection/ctl.py"
DFIR = "/opt/nefi/forensics/dfir.py"
NETMON = "/opt/nefi/netmon/netmon.py"
STATE_FILE = "/var/lib/nefi/ir/ir-state.conf"
HOSTS = "/etc/hosts"
LOG_ACTIONS = ("host-isolated", "host-isolation-confirmed", "host-released", "host-released-auto",
               "host-isolation-reapplied")
SWEEP_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/srv", "/opt"]
SWEEP_MAX_FILES = 40000


def say(msg):
    print(f"[NEFI] {msg}", flush=True)


def fail(msg):
    print(f"[NEFI] ERROR: {msg}", flush=True)
    sys.exit(1)


def run(args, timeout=120):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=ENV, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)


def stream(cmd):
    """Esegue mostrando l'uscita; l'account vero (PKEXEC_UID) passa al comando figlio."""
    env = dict(ENV, **{k: os.environ[k] for k in ("PKEXEC_UID", "SUDO_UID") if k in os.environ})
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", env=env)
    except OSError as e:
        print(str(e), flush=True)
        return 127
    for line in p.stdout:
        if line.strip():
            print(line.rstrip(), flush=True)
    return p.wait()


# ── processi ────────────────────────────────────────────────────────────
def own_pids():
    pids, pid = set(), os.getpid()
    for _ in range(40):
        pids.add(pid)
        try:
            pid = ir.proc_info(pid)["ppid"]
        except ir.IRError:
            break
        if pid <= 1:
            break
    return pids


def target(token):
    """-> (info, pidfd) del processo, dopo aver verificato che sia ancora quello indicato."""
    pid, start = ir.parse_target(token)
    try:
        fd = os.pidfd_open(pid)
    except OSError:
        raise ir.IRError(f"process {pid} is not running")
    info = ir.proc_info(pid)
    if info["starttime"] != start:
        os.close(fd)
        raise ir.IRError(f"PID {pid} now belongs to a different program ({info['name']}): nothing was done")
    why = ir.protected_reason(info, own_pids())
    if why:
        os.close(fd)
        raise ir.IRError(why)
    return info, fd


def exe_hash(pid):
    try:
        return ir.sha256_file(f"/proc/{pid}/exe")     # il programma in memoria, anche se il file e' stato cancellato
    except OSError:
        return ""


def user_name(uid):
    import pwd
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def proc_freeze(token, case):
    info, fd = target(token)
    digest = exe_hash(info["pid"])
    signal.pidfd_send_signal(fd, signal.SIGSTOP)
    os.close(fd)
    items = [f for f in ir.read_json(ir.FROZEN, []) if f.get("pid") != info["pid"]]
    items.insert(0, {"pid": info["pid"], "starttime": info["starttime"], "name": info["name"], "exe": info["exe"],
                     "cmdline": info["cmdline"], "user": user_name(info["uid"]), "sha256": digest,
                     "by": ir.account(), "ts": ir.now(), "case": case})
    ir.write_json(ir.FROZEN, items)
    ir.record("process-frozen", case, pid=info["pid"], name=info["name"], exe=info["exe"], sha256=digest,
              cmdline=info["cmdline"], user=user_name(info["uid"]), ppid=info["ppid"])
    say(f"Process {info['pid']} ({info['name']}) suspended: it keeps its memory and files but does not run.")
    say("Collect evidence now (DFIR), then terminate or resume it.")


def prune_frozen():
    keep = []
    for f in ir.read_json(ir.FROZEN, []):
        try:
            info = ir.proc_info(f["pid"])
        except ir.IRError:
            continue
        if info["starttime"] == f.get("starttime") and info["state"] in ("T", "t"):
            keep.append(f)
    ir.write_json(ir.FROZEN, keep)
    return keep


def proc_resume(token, case):
    info, fd = target(token)
    signal.pidfd_send_signal(fd, signal.SIGCONT)
    os.close(fd)
    prune_frozen()
    ir.record("process-resumed", case, pid=info["pid"], name=info["name"], exe=info["exe"])
    say(f"Process {info['pid']} ({info['name']}) resumed.")


def proc_kill(token, case):
    info, fd = target(token)
    digest = exe_hash(info["pid"])
    stopped = info["state"] in ("T", "t")
    # un processo sospeso non riceve SIGTERM finche' non riparte: si termina direttamente
    signal.pidfd_send_signal(fd, signal.SIGKILL if stopped else signal.SIGTERM)
    how = "SIGKILL" if stopped else "SIGTERM"
    if not stopped:
        import select
        if not select.select([fd], [], [], 4)[0]:        # il pidfd diventa leggibile quando il processo esce
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            how = "SIGTERM, then SIGKILL"
    os.close(fd)
    prune_frozen()
    ir.record("process-terminated", case, pid=info["pid"], name=info["name"], exe=info["exe"], sha256=digest,
              cmdline=info["cmdline"], user=user_name(info["uid"]), ppid=info["ppid"], signal=how)
    say(f"Process {info['pid']} ({info['name']}) terminated ({how}). SHA-256 of the program: {digest[:16] or '?'}…")


# ── quarantena ──────────────────────────────────────────────────────────
def quarantine(path, reason, case):
    real = ir.quarantine_check(path)
    rc, out, _ = run(["dpkg", "-S", real], 30)
    if rc == 0 and out.strip():
        pkg = out.split(":")[0]
        fail(f"{real} belongs to the Debian package '{pkg}'. Moving it away would break the system: "
             f"restore the original instead with  apt install --reinstall {pkg}")
    e = ir.quarantine(real, case, ir.clean(reason, "reason") if reason.strip() else "")
    say(f"{real} moved to quarantine as {e['id']} (SHA-256 {e['sha256'][:16]}…). It can no longer run.")


# ── indicatori ──────────────────────────────────────────────────────────
def apply_domains():
    domains = [i["value"] for i in ir.read_json(ir.IOCS, []) if i.get("type") == "domain"]
    with open(HOSTS, encoding="utf-8", errors="replace") as f:
        text = f.read()
    new = ir.render_hosts(text, domains)
    if new != text:
        tmp = HOSTS + ".nefi-tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(new)
        os.chmod(tmp, 0o644)
        os.replace(tmp, HOSTS)
        sync_detection_baseline(HOSTS)
    return len(domains)


def sync_detection_baseline(*paths):
    """/etc/hosts e' un file sorvegliato dal rilevamento: una modifica fatta DA QUI (gia' scritta nel registro
    delle azioni di risposta) entra nella baseline, non deve comparire tra i cambi da approvare."""
    try:
        sys.path.insert(0, "/opt/nefi/detection")
        import ctl
        ctl.sync_baseline(*paths)
    except Exception:                                  # rilevamento non installato o baseline assente
        pass


def ioc_add(kind, value, note, case):
    value = ir.check_ioc(kind, value)
    items = ir.read_json(ir.IOCS, [])
    if any(i.get("type") == kind and i.get("value") == value for i in items):
        fail("this indicator is already in the list")
    if kind == "domain" and value == os.uname().nodename.lower():
        fail("this is the name of this machine")
    if kind == "ip":
        if not os.path.exists(DETECT_CTL):
            fail("the detection engine is not installed: IP blocking is not available")
        if stream(["/usr/bin/python3", DETECT_CTL, "block-ip", value]) != 0:
            sys.exit(1)
    items.insert(0, {"type": kind, "value": value, "note": ir.clean(note, "note", 200) if note.strip() else "",
                     "by": ir.account(), "ts": ir.now(), "case": case})
    ir.write_json(ir.IOCS, items)
    if kind == "domain":
        apply_domains()
        say(f"{value} now resolves to nowhere on this machine (/etc/hosts). Subdomains are NOT covered; "
            f"a browser using DNS-over-HTTPS ignores this block.")
    elif kind == "sha256":
        say("Hash added. Run 'Sweep' to look for files and running programs with this hash.")
    ir.record("ioc-blocked", case, type=kind, value=value, note=note.strip())


def ioc_del(kind, value, case):
    value = ir.check_ioc(kind, value)
    items = ir.read_json(ir.IOCS, [])
    keep = [i for i in items if not (i.get("type") == kind and i.get("value") == value)]
    if kind == "ip" and os.path.exists(DETECT_CTL):
        # l'elenco degli indirizzi bloccati e' uno solo, quello del firewall (anche i blocchi fatti da Detection)
        rc = stream(["/usr/bin/python3", DETECT_CTL, "unblock-ip", value])
        if rc != 0 and len(keep) == len(items):
            sys.exit(1)
    elif len(keep) == len(items):
        fail("indicator not in the list")
    ir.write_json(ir.IOCS, keep)
    if kind == "domain":
        apply_domains()
    ir.record("ioc-unblocked", case, type=kind, value=value)
    say(f"{kind} {value} removed from the block list.")


def sweep_files():
    n = 0
    for pid in os.listdir("/proc"):
        if pid.isdigit() and os.path.exists(f"/proc/{pid}/exe"):
            yield f"/proc/{pid}/exe"
    for top in SWEEP_DIRS:
        for root, dirs, names in os.walk(top, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.ismount(os.path.join(root, d)) or root == "/"]
            for name in names:
                p = os.path.join(root, name)
                if not os.path.islink(p):
                    n += 1
                    if n > SWEEP_MAX_FILES:
                        return
                    yield p


def ioc_sweep(case):
    hashes = [i["value"] for i in ir.read_json(ir.IOCS, []) if i.get("type") == "sha256"]
    if not hashes:
        fail("no SHA-256 indicator in the list: add one first")
    say(f"Looking for {len(hashes)} hash(es) in running programs and in {', '.join(SWEEP_DIRS)} …")
    checked, matches = 0, []

    def counted():
        nonlocal checked
        for p in sweep_files():
            checked += 1
            if checked % 5000 == 0:
                say(f"{checked} files checked…")
            yield p
    for path, digest in ir.sweep(hashes, counted()):
        entry = {"path": path, "sha256": digest}
        if path.startswith("/proc/"):
            pid = path.split("/")[2]
            try:
                info = ir.proc_info(pid)
                entry.update(pid=info["pid"], starttime=info["starttime"], path=info["exe"], running=True)
            except ir.IRError:
                continue
        matches.append(entry)
        say(f"MATCH: {entry['path']}" + (f" (running, PID {entry['pid']})" if entry.get("running") else ""))
    ir.write_json(ir.SWEEP, {"ts": ir.now(), "checked": checked, "hashes": len(hashes), "matches": matches,
                             "by": ir.account()})
    ir.record("ioc-sweep", case, checked=checked, hashes=len(hashes), matches=len(matches))
    if checked >= SWEEP_MAX_FILES:
        say(f"Stopped at the limit of {SWEEP_MAX_FILES} files: the largest folders were not searched completely.")
    say(f"{checked} files checked, {len(matches)} match(es)."
        + (" Freeze or terminate the programs and quarantine the files from Response > Containment." if matches else ""))


# ── ripristino ──────────────────────────────────────────────────────────
def isolation_state():
    state = {}
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    state[k] = v
    except OSError:
        pass
    table = run(["nft", "list", "table", "inet", "nefi_ir"], 15)[0] == 0
    return state.get("IR_ACTIVE", "").lower() == "true" or table


def recovery_check(cid):
    case = ir.load_case(cid)
    auto = {}
    auto["isolation_released"] = not isolation_state()
    out = run(["lsattr", "/var/log/syslog", "/var/log/auth.log"], 15)[1]
    auto["logs_unlocked"] = not any("i" in line.split()[0] for line in out.splitlines() if line.split())
    auto["processes_resumed"] = not prune_frozen()
    auto["monitoring_active"] = all(run(["systemctl", "is-active", u], 15)[1].strip() == "active"
                                    for u in ("nefi-detectd.service", "auditd.service"))
    evidence = list(case.get("links", {}).get("evidence", []))
    try:
        sys.path.insert(0, "/opt/nefi/forensics")
        import custody as cu
        index = ir.read_json(os.path.join(cu.store_dir(), "index.json"), [])
        evidence += [x.get("evidence_id") for x in index if x.get("case") == cid]
    except Exception:
        pass
    auto["evidence_preserved"] = bool(evidence)
    say("Verifying installed programs against their Debian packages (about a minute)…")
    rc, out, _ = run(["dpkg", "--verify"], 900)
    changed = [l.split(None, 2)[-1] for l in out.splitlines()
               if len(l) > 3 and l[2] == "5" and " c /" not in l[:14]]
    auto["system_integrity"] = rc in (0, 1) and not changed
    labels = {r[0]: r[1] for r in ir.RECOVERY}
    for rid, ok in auto.items():
        say(f"{'OK  ' if ok else 'TODO'}  {labels[rid]}")
    for path in changed[:15]:
        say(f"      changed program file: {path}")
    case = ir.load_case(cid)
    case["auto"] = dict(auto, checked=ir.now(), changed_files=changed[:50])
    ir.save_case(case)
    ir.record("recovery-check", cid, **{k: ("ok" if v else "todo") for k, v in auto.items()})
    left = [labels[rid] for rid, st in ir.recovery_state(case).items() if st == "todo"]
    say(f"{len(left)} item(s) still open." if left else "Every item is complete: the incident can be closed.")


# ── playbook ────────────────────────────────────────────────────────────
def default_iface():
    rc, out, _ = run(["ip", "-j", "route", "show", "default"], 10)
    try:
        return (json.loads(out or "[]") or [{}])[0].get("dev", "")
    except (ValueError, AttributeError):
        return ""


def playbook_run(cid, step_id):
    case = ir.load_case(cid)
    books, _ = ir.load_playbooks()
    pb = books.get((case.get("playbook") or {}).get("id", ""))
    step = next((s for s in (pb or {}).get("steps", []) if s["id"] == step_id), None)
    if not step or not step.get("action"):
        fail("this step has no automatic action")
    who, why = ir.account(), f"Playbook '{pb['title']}', step '{step['title']}'"
    action = step["action"]
    ir.record("playbook-action-started", cid, step=step_id, action=action)
    if action == "isolate":
        rc = stream(["/bin/bash", "/opt/nefi/ir/activate.sh", "--case", cid, "--rollback", "15"])
    elif action == "collect-evidence":
        rc = stream(["/usr/bin/python3", DFIR, "collect", cid, who, why])
    elif action == "memory":
        rc = stream(["/usr/bin/python3", DFIR, "memory", cid, who, why])
    elif action == "capture":
        iface = default_iface()
        if not iface:
            say("No default network route (is the host isolated?): capture skipped.")
            rc = 1
        else:
            rc = stream(["/usr/bin/python3", NETMON, "capture-start", iface, "10", "200", "-", "-", "-", cid, why])
    elif action == "ioc-sweep":
        ioc_sweep(cid)
        rc = 0
    elif action == "recovery-check":
        recovery_check(cid)
        rc = 0
    else:
        fail("action not allowed")
    ir.step_set(cid, step_id, "done" if rc == 0 else "failed", "automatic action" if rc == 0 else
                f"automatic action failed (exit code {rc})", pb)
    say(f"Step '{step['title']}': {'done' if rc == 0 else 'FAILED - do it by hand or skip it with a reason'}.")
    sys.exit(0 if rc == 0 else 1)


def main():
    if os.geteuid() != 0:
        sys.exit("NEFI: run as root (pkexec)")
    a = sys.argv[1:]
    case = ""
    if len(a) >= 2 and a[0] == "--case":
        case, a = a[1], a[2:]
    cmd, args = (a[0], a[1:]) if a else ("", [])
    try:
        ir.ensure_dirs()
        if case:
            ir.load_case(case)
        if cmd == "case-open" and len(args) in (3, 4, 5):
            c = ir.open_case(args[0], args[1], args[2], args[3] if len(args) >= 4 else "")
            if len(args) == 5 and args[4]:
                ir.link(c["id"], "alert", args[4])
            say(f"Incident {c['id']} opened ({c['severity']}, {ir.CATEGORIES[c['category']]}).")
        elif cmd == "case-set" and len(args) == 3:
            ir.set_field(*args)
            say(f"{args[1]} set to {args[2]}.")
        elif cmd == "case-note" and len(args) == 2:
            ir.add_note(*args)
            say("Note added to the timeline.")
        elif cmd == "case-link" and len(args) == 3:
            ir.link(*args)
            say(f"{args[1]} {args[2]} linked.")
        elif cmd == "case-close" and len(args) == 2:
            ir.close_case(*args)
            say(f"Incident {args[0]} closed.")
        elif cmd == "case-verify" and len(args) == 1:
            ok, _n, msg = ir.verify_chain(ir.timeline_path(args[0]))
            ok2, _n2, msg2 = ir.verify_chain(ir.ACTIONS)
            say(f"timeline of {args[0]}: {'OK' if ok else 'TAMPERED'} - {msg}")
            say(f"response action log: {'OK' if ok2 else 'TAMPERED'} - {msg2}")
            sys.exit(0 if ok and ok2 else 1)
        elif cmd == "playbook-start" and len(args) == 2:
            pb = ir.load_playbooks()[0].get(args[1])
            if not pb:
                fail("playbook not found")
            ir.start_playbook(args[0], pb)
            say(f"Playbook '{pb['title']}' started: {len(pb['steps'])} steps.")
        elif cmd == "playbook-step" and len(args) in (3, 4):
            ir.step_set(args[0], args[1], args[2], args[3] if len(args) == 4 else "")
            say(f"Step {args[1]}: {args[2]}.")
        elif cmd == "playbook-run" and len(args) == 2:
            playbook_run(*args)
        elif cmd == "recovery-check" and len(args) == 1:
            recovery_check(args[0])
        elif cmd == "recovery-set" and len(args) == 3:
            ir.recovery_set(*args)
            say(f"{args[1]}: {args[2]}.")
        elif cmd in ("proc-freeze", "proc-resume", "proc-kill") and len(args) == 1:
            {"proc-freeze": proc_freeze, "proc-resume": proc_resume, "proc-kill": proc_kill}[cmd](args[0], case)
        elif cmd == "quarantine" and len(args) in (1, 2):
            quarantine(args[0], args[1] if len(args) == 2 else "", case)
        elif cmd == "quarantine-restore" and len(args) == 1:
            e = ir.quarantine_restore(args[0], case)
            say(f"{e['path']} restored with its original owner, permissions and date.")
        elif cmd == "quarantine-delete" and len(args) == 1:
            e = ir.quarantine_delete(args[0], case)
            say(f"Quarantined copy of {e['path']} deleted for good.")
        elif cmd == "ioc-add" and len(args) in (2, 3):
            ioc_add(args[0], args[1], args[2] if len(args) == 3 else "", case)
        elif cmd == "ioc-del" and len(args) == 2:
            ioc_del(args[0], args[1], case)
        elif cmd == "ioc-sweep" and not args:
            ioc_sweep(case)
        elif cmd == "log" and args and args[0] in LOG_ACTIONS:
            details = dict(x.split("=", 1) for x in args[1:] if "=" in x)
            ir.record(args[0], case, **{k: ir.clean(v, k, 120) for k, v in details.items() if v.strip()})
        else:
            sys.exit(__doc__)
    except (ir.IRError, ValueError, OSError) as e:
        fail(str(e))


if __name__ == "__main__":
    main()
