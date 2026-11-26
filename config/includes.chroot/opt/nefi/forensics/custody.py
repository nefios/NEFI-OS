"""NEFI OS - DFIR: catena di custodia delle prove (usato da dfir.py, come root).

  archivio delle prove   cartella scelta dall'amministratore (default /var/lib/nefi/forensics, meglio un
                         disco esterno): /etc/nefi/forensics.json {"store": "/percorso"}
  manifest               <ID>.manifest.json: chi, quando, perche', con quale strumento, SHA-256 di ogni file
  firma                  <ID>.manifest.json.asc: firma GPG staccata, chiave dedicata alle prove
                         (/var/lib/nefi/forensics-keys, solo root). La chiave pubblica va conservata FUORI
                         dalla macchina: con quella chiunque verifica che il manifest non e' stato cambiato.
  registro di custodia   custody.jsonl: ogni operazione (raccolta, verifica, esportazione, nota, cancellazione)
                         con operatore e ora; a sola aggiunta, ogni riga contiene l'hash della precedente.
"""
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import subprocess
import tempfile
import time

CONF = "/etc/nefi/forensics.json"
DEFAULT_STORE = "/var/lib/nefi/forensics"
KEYS = "/var/lib/nefi/forensics-keys"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "GNUPGHOME": KEYS}
ID_RE = re.compile(r"NEFI-(EV|MEM|DSK|TL)-\d{8}-\d{6}-[0-9a-f]{4}")
TEXT_RE = re.compile(r"[^\x00-\x1f\x7f]{1,200}")
GENESIS = "0" * 64


def run(args, timeout=120, stdin=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=ENV, input=stdin, errors="replace")
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)


def admin_gid():
    try:
        return grp.getgrnam("sudo").gr_gid
    except KeyError:
        return 0


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def store_dir():
    try:
        with open(CONF) as f:
            path = json.load(f).get("store") or DEFAULT_STORE
    except (OSError, ValueError):
        path = DEFAULT_STORE
    return path if path.startswith("/") else DEFAULT_STORE


def ensure_store(path=None):
    path = path or store_dir()
    os.makedirs(path, mode=0o750, exist_ok=True)
    os.chown(path, 0, admin_gid())
    os.chmod(path, 0o750)
    for sub in ("timelines", "analysis"):
        os.makedirs(os.path.join(path, sub), mode=0o750, exist_ok=True)
        os.chown(os.path.join(path, sub), 0, admin_gid())
    return path


def new_id(kind):
    return f"NEFI-{kind}-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets.token_hex(2)}"


def account():
    """L'account che ha lanciato l'operazione (pkexec/sudo), non 'root'."""
    for var in ("PKEXEC_UID", "SUDO_UID"):
        uid = os.environ.get(var)
        if uid and uid.isdigit():
            try:
                return pwd.getpwuid(int(uid)).pw_name
            except KeyError:
                return f"uid {uid}"
    return "root"


def clean(text, what):
    text = " ".join(str(text).split())
    if not TEXT_RE.fullmatch(text):
        raise ValueError(f"{what}: 1-200 printable characters required")
    return text


def sha256_file(path, progress=None):
    h, done = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done)
    return h.hexdigest()


def write_file(path, data, mode=0o640, admin=True):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.chown(tmp, 0, admin_gid() if admin else 0)
    os.replace(tmp, path)


# ── ora: quanto ci si puo' fidare dell'orologio ──
def time_context():
    rc, out, _ = run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone", "-p", "NTP"], 15)
    info = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    try:
        with open("/proc/uptime") as f:
            uptime = int(float(f.read().split()[0]))
    except (OSError, ValueError):
        uptime = None
    return {"utc": utc_now(), "local": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "timezone": info.get("Timezone", ""),
            "ntp_enabled": info.get("NTP") == "yes", "ntp_synchronized": info.get("NTPSynchronized") == "yes",
            "uptime_seconds": uptime,
            "note": ("clock synchronised with a network time source" if info.get("NTPSynchronized") == "yes" else
                     "clock NOT synchronised with a network time source: times are those of the local clock")}


def host_context():
    def read(p):
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError:
            return ""
    u = os.uname()
    osr = dict(l.split("=", 1) for l in read("/etc/os-release").splitlines() if "=" in l)
    return {"hostname": u.nodename, "kernel": u.release, "machine_id": read("/etc/machine-id"),
            "os": osr.get("PRETTY_NAME", "").strip('"'), "boot_id": read("/proc/sys/kernel/random/boot_id")}


# ── chiave di firma ──
def key_fingerprint(create=True):
    os.makedirs(KEYS, mode=0o700, exist_ok=True)
    os.chmod(KEYS, 0o700)
    rc, out, _ = run(["gpg", "--batch", "--list-secret-keys", "--with-colons"], 30)
    fpr = [l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:")]
    if fpr:
        return fpr[0]
    if not create:
        return None
    uid = f"NEFI Evidence Signing ({os.uname().nodename}) <evidence@{os.uname().nodename}>"
    rc, _, err = run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                      "--quick-generate-key", uid, "ed25519", "sign", "never"], 120)
    if rc != 0:
        raise RuntimeError(f"cannot create the evidence signing key: {err.strip()[:200]}")
    return key_fingerprint(create=False)


def export_public_key(dest):
    fpr = key_fingerprint()
    rc, out, err = run(["gpg", "--batch", "--armor", "--export", fpr], 30)
    if rc != 0 or "BEGIN PGP PUBLIC KEY" not in out:
        raise RuntimeError("cannot export the public key")
    write_file(dest, out, 0o644)
    return fpr


def sign(path):
    fpr = key_fingerprint()
    rc, _, err = run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--armor",
                      "--local-user", fpr, "--output", path + ".asc", "--detach-sign", path], 60)
    if rc != 0:
        raise RuntimeError(f"signing failed: {err.strip()[:200]}")
    os.chmod(path + ".asc", 0o640)
    os.chown(path + ".asc", 0, admin_gid())
    return fpr


def verify_signature(path):
    """-> (ok, impronta della chiave o messaggio)"""
    if not os.path.exists(path + ".asc"):
        return False, "signature file missing"
    rc, out, err = run(["gpg", "--batch", "--status-fd", "1", "--verify", path + ".asc", path], 60)
    m = re.search(r"^\[GNUPG:\] VALIDSIG (\S+)", out, re.M)
    if rc == 0 and m:
        return True, m.group(1)
    if "BADSIG" in out:
        return False, "BAD signature: the manifest was changed after signing"
    if "NO_PUBKEY" in out or "ERRSIG" in out:
        return False, "signed with a key this machine does not know"
    return False, (err.strip().splitlines() or ["verification failed"])[-1][:200]


# ── registro di custodia (catena di hash) ──
def _chattr(flag, path):
    run(["chattr", flag, path], 10)


def custody_path(store=None):
    return os.path.join(store or store_dir(), "custody.jsonl")


def _last_hash(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 65536))
            lines = [l for l in f.read().split(b"\n") if l.strip()]
        return hashlib.sha256(lines[-1]).hexdigest() if lines else GENESIS
    except OSError:
        return GENESIS


def custody(action, evidence_id, operator="", **details):
    path = custody_path()
    rec = {"ts": utc_now(), "action": action, "evidence": evidence_id, "account": account(),
           "operator": operator, "host": os.uname().nodename, "prev": _last_hash(path)}
    rec.update({k: v for k, v in details.items() if v not in (None, "")})
    line = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
    new = not os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, line + b"\n")
    finally:
        os.close(fd)
    if new:
        os.chmod(path, 0o640)
        if os.geteuid() == 0:
            os.chown(path, 0, admin_gid())
        _chattr("+a", path)
    return rec


def verify_custody(path=None):
    path = path or custody_path()
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
    return True, n, f"{n} records, chain intact"


# ── manifest e indice ──
def manifest_path(eid, store=None):
    return os.path.join(store or store_dir(), eid + ".manifest.json")


def write_manifest(manifest):
    path = manifest_path(manifest["evidence_id"])
    manifest["signing_key"] = key_fingerprint()
    write_file(path, json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    sign(path)
    rebuild_index()
    return path


def load_manifest(eid):
    if not ID_RE.fullmatch(eid or ""):
        raise ValueError("invalid evidence id")
    with open(manifest_path(eid), encoding="utf-8") as f:
        return json.load(f)


def rebuild_index():
    """index.json: l'elenco che il Security Center mostra (ricostruito dai manifest, mai il contrario)."""
    store, items = store_dir(), []
    for name in sorted(os.listdir(store)):
        if not name.endswith(".manifest.json") or not ID_RE.fullmatch(name[:-14]):
            continue
        try:
            with open(os.path.join(store, name), encoding="utf-8") as f:
                m = json.load(f)
        except (OSError, ValueError):
            continue
        items.append({k: m.get(k) for k in ("evidence_id", "kind", "case", "operator", "account", "reason",
                                             "collected_utc", "description")}
                     | {"size": sum(f.get("size", 0) for f in m.get("objects", [])),
                        "objects": [{"name": o.get("name"), "path": o.get("path"), "size": o.get("size")}
                                    for o in m.get("objects", [])],
                        "signed": os.path.exists(os.path.join(store, name + ".asc")),
                        "ntp_synchronized": m.get("time", {}).get("ntp_synchronized")})
    items.sort(key=lambda x: x.get("collected_utc") or "", reverse=True)
    write_file(os.path.join(store, "index.json"), json.dumps(items, indent=1))
    return items
