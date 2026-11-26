"""NEFI OS - Detection: archiviazione protetta (usato da detectd.py e ctl.py, entrambi root).

  registro a sola aggiunta   ogni riga JSON contiene "prev" = SHA-256 della riga precedente (catena):
                             togliere o cambiare una riga rompe la catena e verify_chain() lo trova.
                             Il file ha anche l'attributo 'a' (append-only) dove il filesystem lo permette.
  baseline protetta          /var/lib/nefi/detection/baseline.json, root 0600 + attributo 'i' (immutabile);
                             si cambia SOLO con approve() da ctl.py, e ogni cambio finisce nel registro audit.
"""
import grp
import hashlib
import json
import os
import subprocess
import tempfile
import time

STATE = "/var/lib/nefi/detection"
LOGDIR = "/var/log/nefi/detection"
CONF = "/etc/nefi/detection"
BASELINE = STATE + "/baseline.json"
PENDING = STATE + "/pending.json"
AUDIT = STATE + "/audit.jsonl"            # chi ha approvato/soppresso cosa e quando
STATUS = STATE + "/status.json"
PROCESSES = STATE + "/processes.jsonl"
ALERTS = LOGDIR + "/alerts.jsonl"
SUPPRESSIONS = CONF + "/suppressions.json"
DISABLED = CONF + "/disabled.json"
RULES_D = CONF + "/rules.d"
GENESIS = "0" * 64


def admin_gid():
    try:
        return grp.getgrnam("sudo").gr_gid
    except KeyError:
        return 0


def ensure_dirs():
    for d, mode in ((STATE, 0o750), (LOGDIR, 0o750), (CONF, 0o755), (RULES_D, 0o755)):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, mode)
        os.chown(d, 0, admin_gid() if mode == 0o750 else 0)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def chattr(flag, path):
    try:
        subprocess.run(["chattr", flag, path], capture_output=True, timeout=10,
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    except (OSError, subprocess.SubprocessError):
        pass


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o640, group_admin=True, immutable=False):
    """Scrittura atomica; con immutable=True toglie e rimette l'attributo 'i'."""
    if immutable and os.path.exists(path):
        chattr("-i", path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(tmp, mode)
    os.chown(tmp, 0, admin_gid() if group_admin else 0)
    os.replace(tmp, path)
    if immutable:
        chattr("+i", path)


# ── registro a sola aggiunta con catena di hash ─────────────────────────
def _last_hash(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = [l for l in f.read().split(b"\n") if l.strip()]
        return hashlib.sha256(lines[-1]).hexdigest() if lines else GENESIS
    except OSError:
        return GENESIS


class ChainLog:
    def __init__(self, path, mode=0o640):
        self.path, self.mode = path, mode
        self.last = _last_hash(path)

    def append(self, record):
        record = dict(record)
        record["prev"] = self.last
        line = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
        new = not os.path.exists(self.path)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, self.mode)
        try:
            os.write(fd, line + b"\n")
        finally:
            os.close(fd)
        if new:
            os.chmod(self.path, self.mode)
            if os.geteuid() == 0:          # i test girano senza root
                os.chown(self.path, 0, admin_gid())
            chattr("+a", self.path)
        self.last = hashlib.sha256(line).hexdigest()
        return record


def verify_chain(path):
    """-> (ok, righe, messaggio). File mancante = ok (nessun evento ancora)."""
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
                if prev is not None and rec.get("prev") != prev:
                    return False, n, f"chain broken at line {n}: a record was removed or changed"
                prev = hashlib.sha256(raw).hexdigest()
    except FileNotFoundError:
        return True, 0, "no records yet"
    except OSError as e:
        return False, n, str(e)
    return True, n, f"{n} records, chain intact"


def rotate(path, max_bytes):
    """Ruota un registro troppo grande (path -> path.1); la nuova catena riparte dall'ultimo hash."""
    try:
        if os.path.getsize(path) < max_bytes:
            return False
    except OSError:
        return False
    chattr("-a", path)
    old = path + ".1"
    if os.path.exists(old):
        chattr("-a", old)
        chattr("-i", old)
    os.replace(path, old)
    chattr("+i", old)          # l'archivio non si tocca piu'
    return True


# ── baseline ────────────────────────────────────────────────────────────
def load_baseline():
    return read_json(BASELINE, None)


def save_baseline(base):
    write_json(BASELINE, base, mode=0o600, group_admin=False, immutable=True)


def audit(action, actor, **details):
    rec = {"ts": now_iso(), "action": action, "actor": actor}
    rec.update(details)
    return ChainLog(AUDIT).append(rec)


def actor_name():
    """Chi ha lanciato l'helper con pkexec/sudo (per il registro audit)."""
    import pwd
    for var in ("PKEXEC_UID", "SUDO_UID"):
        uid = os.environ.get(var)
        if uid and uid.isdigit():
            try:
                return pwd.getpwuid(int(uid)).pw_name
            except KeyError:
                return f"uid {uid}"
    return "root"
