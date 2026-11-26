"""NEFI OS - Incident Response: casi, cronologia, playbook, contenimento (logica, senza comandi di sistema).

Dati in /var/lib/nefi/ir (root:sudo, sola lettura per gli amministratori):
  cases/<ID>.json            il caso: classificazione, stato, playbook, ripristino, collegamenti
  cases/<ID>.timeline.jsonl  cronologia del caso, solo in aggiunta, ogni riga porta l'hash della precedente
  cases/index.json           elenco per il Security Center (ricostruito dai casi, mai il contrario)
  containment/actions.jsonl  registro di TUTTE le azioni di risposta (anche senza caso), concatenato
  containment/iocs.json      indicatori bloccati;  frozen.json  processi sospesi;  quarantine.json
I file in quarantena stanno in /var/lib/nefi/quarantine (solo root).

Qui non si lancia nessun comando: le funzioni si provano con tests/test_response.py.
I comandi veri (segnali, nftables, /etc/hosts) sono in irctl.py.
"""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time

def _env(name, default):
    """Percorsi alternativi solo per i test (mai quando si gira come root)."""
    return os.environ.get(name, default) if os.geteuid() != 0 else default


BASE = _env("NEFI_IR_BASE", "/var/lib/nefi/ir")
CASES = os.path.join(BASE, "cases")
CONT = os.path.join(BASE, "containment")
QUAR = _env("NEFI_QUARANTINE", "/var/lib/nefi/quarantine")
ACTIONS = os.path.join(CONT, "actions.jsonl")
IOCS = os.path.join(CONT, "iocs.json")
FROZEN = os.path.join(CONT, "frozen.json")
QINDEX = os.path.join(CONT, "quarantine.json")
SWEEP = os.path.join(CONT, "sweep.json")
PLAYBOOK_DIRS = [_env("NEFI_IR_PLAYBOOKS", "/usr/share/nefi/ir/playbooks"), "/etc/nefi/ir/playbooks"]
GENESIS = "0" * 64

CASE_RE = re.compile(r"NEFI-INC-\d{8}-[0-9a-f]{4}")
QID_RE = re.compile(r"NEFI-Q-\d{8}-\d{6}-[0-9a-f]{4}")
TEXT_RE = re.compile(r"[^\x00-\x1f\x7f]{1,500}")
STEP_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
DOMAIN_RE = re.compile(r"(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_HELP = {
    "low": "No sign of compromise: policy violation, blocked attempt, unwanted program.",
    "medium": "One account or program affected, no sensitive data involved, no spread.",
    "high": "Confirmed compromise of this machine, or sensitive data possibly exposed.",
    "critical": "Active attacker, ransomware, or data confirmed stolen: act immediately.",
}
CATEGORIES = {
    "malware": "Malware", "ransomware": "Ransomware", "unauthorized-access": "Unauthorized access",
    "account-compromise": "Compromised account", "data-exposure": "Data leak or exposure",
    "network-intrusion": "Suspicious network activity", "denial-of-service": "Denial of service",
    "phishing": "Phishing or social engineering", "policy-violation": "Policy violation",
    "lost-device": "Lost or stolen device", "other": "Other",
}
STATUSES = ["new", "investigating", "contained", "eradicated", "recovering", "closed"]
ACTIONS_ALLOWED = ("isolate", "collect-evidence", "memory", "capture", "ioc-sweep", "recovery-check")
# (id, testo, verificato automaticamente?, come si fa)
RECOVERY = [
    ("evidence_preserved", "Evidence collected and preserved", True,
     "At least one piece of evidence is stored for this case (DFIR > Evidence & Custody)."),
    ("root_cause", "Root cause understood", False,
     "You know how it started (which program, account or vulnerability). Write it in a note."),
    ("threat_removed", "Threat removed", False,
     "Malicious files quarantined or deleted, persistence removed (Detection > Integrity & Persistence)."),
    ("credentials_rotated", "Passwords and keys changed", False,
     "Change the passwords and SSH keys of every account used on this machine during the incident."),
    ("system_integrity", "System files verified", True,
     "No installed program differs from its Debian package (dpkg --verify)."),
    ("updates_applied", "Security updates installed", False,
     "System > Update Health shows no pending security update."),
    ("processes_resumed", "No process left suspended", True,
     "Every process frozen during containment was terminated or resumed."),
    ("quarantine_reviewed", "Quarantine reviewed", False,
     "Each quarantined file was either deleted for good or restored on purpose."),
    ("iocs_reviewed", "Blocked indicators reviewed", False,
     "Decide which blocked addresses and domains stay blocked after the incident."),
    ("logs_unlocked", "Logs writable again", True, "The log files protected during isolation are unlocked."),
    ("isolation_released", "Network isolation removed", True, "The host is connected again."),
    ("monitoring_active", "Monitoring running", True, "The detection engine and auditd are active."),
    ("lessons_learned", "Lessons learned written", False,
     "Add a note: what worked, what did not, what to change so it does not happen again."),
]
RECOVERY_IDS = [r[0] for r in RECOVERY]
RECOVERY_AUTO = {r[0] for r in RECOVERY if r[2]}
# percorsi che non si mettono in quarantena: senza di loro il sistema (o NEFI) non parte
PROTECTED_PATHS = ("/proc/", "/sys/", "/dev/", "/run/", "/boot/", "/usr/lib/nefi/", "/opt/nefi/",
                   "/var/lib/nefi/", "/etc/nefi/", "/var/lib/dpkg/")
PROTECTED_NAMES = {"systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "dbus-daemon", "dbus-broker",
                   "sddm", "sddm-helper", "kwin_wayland", "kwin_x11", "Xorg", "Xwayland", "polkitd", "auditd",
                   "login", "agetty"}


class IRError(Exception):
    pass


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def admin_gid():
    import grp
    try:
        return grp.getgrnam("sudo").gr_gid
    except KeyError:
        return 0


def account():
    import pwd
    for var in ("PKEXEC_UID", "SUDO_UID"):
        uid = os.environ.get(var)
        if uid and uid.isdigit():
            try:
                return pwd.getpwuid(int(uid)).pw_name
            except KeyError:
                return f"uid {uid}"
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return str(os.geteuid())


def _own(path, mode):
    os.chmod(path, mode)
    if os.geteuid() == 0:
        os.chown(path, 0, admin_gid() if mode & 0o040 else 0)


def ensure_dirs():
    for d, mode in ((BASE, 0o750), (CASES, 0o750), (CONT, 0o750), (QUAR, 0o700)):
        os.makedirs(d, exist_ok=True)
        _own(d, mode)


def clean(text, what, maxlen=500):
    text = " ".join(str(text).split())
    if not TEXT_RE.fullmatch(text) or len(text) > maxlen:
        raise IRError(f"{what}: 1-{maxlen} printable characters required")
    return text


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o640):
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False, sort_keys=True)
    _own(tmp, mode)
    os.replace(tmp, path)


# ── registri concatenati ────────────────────────────────────────────────
def _last_hash(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 65536))
            lines = [l for l in f.read().split(b"\n") if l.strip()]
        return hashlib.sha256(lines[-1]).hexdigest() if lines else GENESIS
    except OSError:
        return GENESIS


def chain_append(path, rec):
    rec = dict(rec, prev=_last_hash(path))
    line = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
    new = not os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, line + b"\n")
    finally:
        os.close(fd)
    if new:
        _own(path, 0o640)
    return rec


def verify_chain(path):
    """-> (integro?, righe, messaggio)"""
    prev, n = None, 0
    try:
        with open(path, "rb") as f:
            for raw in f:
                raw = raw.rstrip(b"\n")
                if not raw.strip():
                    continue
                n += 1
                try:
                    rec = json.loads(raw)
                except ValueError:
                    return False, n, f"line {n} is not valid JSON"
                if rec.get("prev") != (GENESIS if prev is None else prev):
                    return False, n, f"chain broken at line {n}: a record was removed or changed"
                prev = hashlib.sha256(raw).hexdigest()
    except FileNotFoundError:
        return True, 0, "no records yet"
    return True, n, f"{n} records, chain intact"


def read_chain(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


# ── casi ────────────────────────────────────────────────────────────────
def case_path(cid):
    if not CASE_RE.fullmatch(cid or ""):
        raise IRError("invalid incident id")
    return os.path.join(CASES, cid + ".json")


def timeline_path(cid):
    return case_path(cid)[:-5] + ".timeline.jsonl"


def load_case(cid):
    case = read_json(case_path(cid), None)
    if not case:
        raise IRError(f"incident {cid} not found")
    return case


def save_case(case):
    case["updated"] = now()
    write_json(case_path(case["id"]), case)
    rebuild_index()


def rebuild_index():
    items = []
    for name in sorted(os.listdir(CASES)):
        if name.endswith(".json") and CASE_RE.fullmatch(name[:-5]):
            c = read_json(os.path.join(CASES, name), None)
            if c:
                items.append({k: c.get(k) for k in ("id", "title", "severity", "category", "status", "opened",
                                                    "opened_by", "closed", "updated", "assignee")})
    items.sort(key=lambda c: c.get("opened") or "", reverse=True)
    write_json(os.path.join(CASES, "index.json"), items)
    return items


def record(action, case_id="", **details):
    """Ogni azione di risposta: nel registro generale e, se c'e' un caso, nella sua cronologia."""
    details = {k: v for k, v in details.items() if v not in (None, "")}
    rec = {"ts": now(), "account": account(), "action": action, "case": case_id, "details": details}
    chain_append(ACTIONS, rec)
    if case_id:
        chain_append(timeline_path(case_id), {k: v for k, v in rec.items() if k != "case"})
    return rec


def open_case(severity, category, title, description=""):
    if severity not in SEVERITIES:
        raise IRError("severity must be one of: " + ", ".join(SEVERITIES))
    if category not in CATEGORIES:
        raise IRError("unknown category")
    ensure_dirs()
    cid = f"NEFI-INC-{time.strftime('%Y%m%d')}-{secrets.token_hex(2)}"
    while os.path.exists(case_path(cid)):                # stesso giorno, stesso suffisso: se ne prende un altro
        cid = f"NEFI-INC-{time.strftime('%Y%m%d')}-{secrets.token_hex(2)}"
    case = {"id": cid, "title": clean(title, "title", 160), "severity": severity, "category": category,
            "description": clean(description, "description") if description.strip() else "",
            "status": "new", "opened": now(), "opened_by": account(), "assignee": account(), "closed": "",
            "summary": "", "links": {"evidence": [], "alert": [], "capture": []}, "playbook": {},
            "recovery": {}, "auto": {}, "format": "NEFI incident v1"}
    save_case(case)
    record("incident-opened", cid, title=case["title"], severity=severity, category=category,
           description=case["description"])
    return case


def set_field(cid, field, value):
    case = load_case(cid)
    if case["status"] == "closed":
        raise IRError("this incident is closed")
    allowed = {"severity": SEVERITIES, "category": list(CATEGORIES), "status": STATUSES[:-1]}
    if field == "assignee":
        value = clean(value, "assignee", 80)
    elif field not in allowed or value not in allowed[field]:
        raise IRError(f"{field}: value not allowed")
    old = case.get(field)
    if old != value:
        case[field] = value
        save_case(case)
        record(f"{field}-changed", cid, old=old, new=value)
    return case


def add_note(cid, text):
    load_case(cid)
    return record("note", cid, text=clean(text, "note"))


def link(cid, kind, ref):
    case = load_case(cid)
    if kind not in ("evidence", "alert", "capture") or not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", ref or ""):
        raise IRError("invalid link")
    if ref not in case["links"].setdefault(kind, []):
        case["links"][kind].append(ref)
        save_case(case)
        record("linked", cid, kind=kind, ref=ref)
    return case


def recovery_state(case):
    """-> {id: 'done'|'na'|'todo'}: le voci automatiche valgono 'done' se l'ultima verifica e' passata."""
    out = {}
    for rid in RECOVERY_IDS:
        manual = (case.get("recovery", {}).get(rid) or {}).get("state", "todo")
        if rid in RECOVERY_AUTO and manual != "na":
            out[rid] = "done" if case.get("auto", {}).get(rid) is True else "todo"
        else:
            out[rid] = manual
    return out


def recovery_set(cid, item, state):
    case = load_case(cid)
    if item not in RECOVERY_IDS or state not in ("done", "na", "todo"):
        raise IRError("invalid recovery item or state")
    if item in RECOVERY_AUTO and state == "done":
        raise IRError("this item is verified by NEFI: run the recovery checks (or mark it 'not applicable')")
    case.setdefault("recovery", {})[item] = {"state": state, "by": account(), "ts": now()}
    save_case(case)
    record("recovery-item", cid, item=item, state=state)
    return case


def close_case(cid, summary):
    case = load_case(cid)
    if case["status"] == "closed":
        raise IRError("this incident is already closed")
    missing = [label for rid, label, _a, _h in RECOVERY if recovery_state(case)[rid] == "todo"]
    if missing:
        raise IRError("the recovery checklist is not complete: " + "; ".join(missing))
    case.update(status="closed", closed=now(), summary=clean(summary, "summary"))
    save_case(case)
    record("incident-closed", cid, summary=case["summary"])
    return case


# ── playbook ────────────────────────────────────────────────────────────
def validate_playbook(doc):
    """Controlla un playbook; -> il documento normalizzato oppure IRError."""
    if not isinstance(doc, dict) or not STEP_RE.fullmatch(str(doc.get("id", ""))):
        raise IRError("playbook: missing or invalid 'id'")
    steps = doc.get("steps")
    if not isinstance(steps, list) or not steps:
        raise IRError(f"playbook {doc['id']}: no steps")
    seen = set()
    for s in steps:
        if not isinstance(s, dict) or not STEP_RE.fullmatch(str(s.get("id", ""))) or s["id"] in seen:
            raise IRError(f"playbook {doc['id']}: step with missing or duplicate id")
        seen.add(s["id"])
        if not s.get("title"):
            raise IRError(f"playbook {doc['id']}: step {s['id']} has no title")
        if s.get("action") and s["action"] not in ACTIONS_ALLOWED:
            raise IRError(f"playbook {doc['id']}: step {s['id']}: action '{s['action']}' is not allowed")
    return {"id": doc["id"], "title": str(doc.get("title", doc["id"])), "description": str(doc.get("description", "")),
            "categories": [c for c in doc.get("categories", []) if c in CATEGORIES],
            "steps": [{"id": s["id"], "phase": str(s.get("phase", "")), "title": str(s["title"]),
                       "help": str(s.get("help", "")), "action": s.get("action", ""),
                       "page": str(s.get("page", ""))} for s in steps]}


def load_playbooks():
    """-> ({id: playbook}, [errori]) dalle cartelle dei playbook (.yml, .yaml, .json)."""
    books, errors = {}, []
    for d in PLAYBOOK_DIRS:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            path = os.path.join(d, name)
            try:
                with open(path, encoding="utf-8") as f:
                    if name.endswith(".json"):
                        doc = json.load(f)
                    elif name.endswith((".yml", ".yaml")):
                        import yaml
                        doc = yaml.safe_load(f)
                    else:
                        continue
                pb = validate_playbook(doc)
                books[pb["id"]] = pb
            except (OSError, ValueError, IRError, ImportError) as e:
                errors.append(f"{name}: {e}")
            except Exception as e:                       # errore di sintassi YAML
                errors.append(f"{name}: {e}")
    return books, errors


def start_playbook(cid, pb):
    case = load_case(cid)
    if case["status"] == "closed":
        raise IRError("this incident is closed")
    case["playbook"] = {"id": pb["id"], "title": pb["title"], "started": now(), "steps": {}}
    save_case(case)
    record("playbook-started", cid, playbook=pb["id"], title=pb["title"])
    return case


def step_set(cid, step_id, state, note="", pb=None):
    case = load_case(cid)
    book = case.get("playbook") or {}
    if not book.get("id"):
        raise IRError("no playbook was started for this incident")
    pb = pb or load_playbooks()[0].get(book["id"])
    step = next((s for s in (pb or {}).get("steps", []) if s["id"] == step_id), None)
    if not step:
        raise IRError("this step is not part of the playbook")
    if state not in ("done", "skipped", "todo", "failed"):
        raise IRError("invalid step state")
    if state == "skipped" and not note.strip():
        raise IRError("write why the step is skipped")
    book["steps"][step_id] = {"state": state, "by": account(), "ts": now(),
                              "note": clean(note, "note") if note.strip() else ""}
    save_case(case)
    record("playbook-step", cid, step=step_id, title=step["title"], state=state, note=note.strip())
    return case, step


def playbook_progress(case, pb):
    steps = (case.get("playbook") or {}).get("steps", {})
    done = sum(1 for s in pb["steps"] if steps.get(s["id"], {}).get("state") in ("done", "skipped"))
    return done, len(pb["steps"])


# ── processi ────────────────────────────────────────────────────────────
def proc_info(pid, proc="/proc"):
    """Dati di un processo da /proc; IRError se non c'e' piu'."""
    pid = int(pid)
    try:
        with open(f"{proc}/{pid}/stat") as f:
            stat = f.read()
        name = stat[stat.index("(") + 1:stat.rindex(")")]
        rest = stat[stat.rindex(")") + 2:].split()
        with open(f"{proc}/{pid}/cmdline", "rb") as f:
            cmdline = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        uid = os.stat(f"{proc}/{pid}").st_uid
    except (OSError, ValueError, IndexError):
        raise IRError(f"process {pid} is not running")
    try:
        exe = os.readlink(f"{proc}/{pid}/exe")
    except OSError:
        exe = ""
    return {"pid": pid, "name": name, "state": rest[0], "ppid": int(rest[1]), "starttime": rest[19],
            "exe": exe, "cmdline": cmdline[:500], "uid": uid}


def parse_target(token):
    """'PID:STARTTIME' -> (pid, starttime). Il solo PID non basta: i PID vengono riusati."""
    m = re.fullmatch(r"(\d{1,10}):(\d{1,20})", token or "")
    if not m:
        raise IRError("process must be given as PID:STARTTIME")
    return int(m.group(1)), m.group(2)


def protected_reason(info, own_pids=()):
    """Perche' questo processo non si tocca, oppure ''."""
    if info["pid"] <= 2 or info["ppid"] == 2 or not info["exe"]:
        return "kernel thread or init: cannot be contained"
    if info["pid"] in own_pids:
        return "this is the Security Center (or the session running it)"
    if info["name"] in PROTECTED_NAMES or os.path.basename(info["exe"].replace(" (deleted)", "")) in PROTECTED_NAMES:
        return f"{info['name']} is a core system process: stopping it would lock you out of the machine"
    return ""


# ── quarantena ──────────────────────────────────────────────────────────
def quarantine_check(path):
    """Percorso reale del file se si puo' mettere in quarantena, altrimenti IRError."""
    if not path.startswith("/") or "\0" in path:
        raise IRError("give the full path of the file")
    if os.path.islink(path):
        raise IRError("this is a symbolic link: quarantine the file it points to")
    real = os.path.realpath(path)
    if not os.path.isfile(real):
        raise IRError("not a regular file (or it does not exist)")
    if any((real + "/").startswith(p) or real.startswith(p) for p in PROTECTED_PATHS):
        raise IRError("this path is protected: moving it would break the system or NEFI itself")
    if os.path.getsize(real) > 4 * 1024 ** 3:
        raise IRError("file larger than 4 GB: image it with DFIR > Disk Forensics instead")
    return real


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def quarantine(path, case_id="", reason=""):
    import shutil
    real = quarantine_check(path)
    ensure_dirs()
    st = os.stat(real)
    digest = sha256_file(real)
    qid = f"NEFI-Q-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"
    dest = os.path.join(QUAR, qid + ".bin")
    try:
        os.rename(real, dest)
    except OSError:                                    # altro file system: copia, verifica, poi cancella
        shutil.copyfile(real, dest)
        if sha256_file(dest) != digest:
            os.unlink(dest)
            raise IRError("the copy does not match the original: the file was left where it is")
        os.unlink(real)
    os.chmod(dest, 0o000)                               # non eseguibile e non leggibile
    if os.geteuid() == 0:
        os.chown(dest, 0, 0)
    entry = {"id": qid, "path": real, "sha256": digest, "size": st.st_size, "mode": st.st_mode & 0o7777,
             "uid": st.st_uid, "gid": st.st_gid, "mtime": st.st_mtime, "by": account(), "ts": now(),
             "case": case_id, "reason": reason, "stored": dest}
    items = read_json(QINDEX, [])
    items.insert(0, entry)
    write_json(QINDEX, items)
    record("file-quarantined", case_id, id=qid, path=real, sha256=digest, size=st.st_size, reason=reason)
    return entry


def _qfind(qid):
    if not QID_RE.fullmatch(qid or ""):
        raise IRError("invalid quarantine id")
    items = read_json(QINDEX, [])
    entry = next((e for e in items if e.get("id") == qid), None)
    if not entry:
        raise IRError("quarantine entry not found")
    return items, entry


def quarantine_restore(qid, case_id=""):
    import shutil
    items, e = _qfind(qid)
    if os.path.lexists(e["path"]):
        raise IRError(f"{e['path']} exists again: move it away first, nothing was restored")
    if not os.path.isdir(os.path.dirname(e["path"])):
        raise IRError("the original folder no longer exists")
    os.chmod(e["stored"], 0o600)
    if sha256_file(e["stored"]) != e["sha256"]:
        os.chmod(e["stored"], 0o000)
        raise IRError("the quarantined copy no longer matches its recorded hash: not restored")
    shutil.move(e["stored"], e["path"])
    if os.geteuid() == 0:
        os.chown(e["path"], e["uid"], e["gid"])
    os.chmod(e["path"], e["mode"])
    os.utime(e["path"], (e["mtime"], e["mtime"]))
    write_json(QINDEX, [x for x in items if x["id"] != qid])
    record("file-restored", case_id or e.get("case", ""), id=qid, path=e["path"], sha256=e["sha256"])
    return e


def quarantine_delete(qid, case_id=""):
    items, e = _qfind(qid)
    try:
        os.unlink(e["stored"])
    except FileNotFoundError:
        pass
    write_json(QINDEX, [x for x in items if x["id"] != qid])
    record("quarantined-file-deleted", case_id or e.get("case", ""), id=qid, path=e["path"], sha256=e["sha256"])
    return e


# ── indicatori (IOC) ────────────────────────────────────────────────────
def check_ioc(kind, value):
    value = str(value).strip().lower()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise IRError("not a valid IP address")
    if kind == "domain":
        value = value.rstrip(".")
        if not DOMAIN_RE.fullmatch(value) or value in ("localhost.localdomain",) \
                or value.endswith((".local", ".localhost", ".debian.org")):
            raise IRError("not a domain name that can be blocked")
        return value
    if kind == "sha256":
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise IRError("a SHA-256 hash is 64 hexadecimal characters")
        return value
    raise IRError("indicator type must be ip, domain or sha256")


HOSTS_BEGIN = "# BEGIN NEFI IOC BLOCK (managed by NEFI Security Center: do not edit)"
HOSTS_END = "# END NEFI IOC BLOCK"


def render_hosts(text, domains):
    """Testo di /etc/hosts con il blocco NEFI riscritto (il resto del file non viene toccato)."""
    out, skip = [], False
    for line in text.splitlines():
        if line.strip() == HOSTS_BEGIN:
            skip = True
        elif line.strip() == HOSTS_END:
            skip = False
        elif not skip:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    if domains:
        out += ["", HOSTS_BEGIN]
        for d in sorted(set(domains)):
            out += [f"0.0.0.0 {d}", f":: {d}"]
        out.append(HOSTS_END)
    return "\n".join(out) + "\n"


def sweep(hashes, files, max_size=200 * 1024 * 1024):
    """Cerca i file con uno degli hash dati. files: iterabile di percorsi. -> [(percorso, sha256)]"""
    hashes, found, seen = set(hashes), [], set()
    for path in files:
        try:
            st = os.stat(path)
            key = (st.st_dev, st.st_ino)
            if key in seen or not os.path.isfile(path) or st.st_size == 0 or st.st_size > max_size:
                continue
            seen.add(key)
            digest = sha256_file(path)
        except OSError:
            continue
        if digest in hashes:
            found.append((path, digest))
    return found
