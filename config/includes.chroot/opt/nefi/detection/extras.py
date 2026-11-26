"""NEFI OS - Detection: funzioni aggiuntive usate dal demone (detectd.py) e dall'helper (ctl.py), come root.

  blocco IP        tabella nftables "inet nefi_block" (ingresso e uscita), elenco in blocked.json
  YARA             scansione dei file sospetti con le regole scaricate da Threat Intelligence
  inoltro dei log  avvisi e registro audit verso un server syslog esterno (TCP, meglio TLS)
  canary           file esca sorvegliati da auditd: chi li apre genera un avviso
  SigmaHQ          scarica le regole Sigma ufficiali per Linux e tiene solo quelle che il motore capisce
"""
import io
import ipaddress
import json
import os
import pwd
import queue
import re
import secrets
import shutil
import socket
import ssl
import threading
import time
import zipfile

import engine
import scan
import store

BLOCKED = store.CONF + "/blocked.json"
FORWARD = store.CONF + "/forward.json"
FORWARD_STATE = store.STATE + "/forward-state.json"
CANARIES = store.CONF + "/canaries.json"
CANARY_RULES = "/etc/audit/rules.d/61-nefi-canary.rules"
SIGMA_INFO = store.STATE + "/sigma-info.json"
SIGMA_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip"
YARA_DIR = "/var/lib/nefi/threat-intel/yara-rules"


# ── blocco di un indirizzo IP ───────────────────────────────────────────
def own_addresses():
    """Indirizzi di questa macchina e del gateway: non si bloccano (ci si taglierebbe fuori)."""
    own = set()
    rc, out = scan.run(["ip", "-j", "addr"], 10)
    try:
        for iface in json.loads(out or "[]"):
            for a in iface.get("addr_info", []):
                own.add(a.get("local"))
    except ValueError:
        pass
    rc, out = scan.run(["ip", "-j", "route", "show", "default"], 10)
    try:
        for r in json.loads(out or "[]"):
            own.add(r.get("gateway"))
    except ValueError:
        pass
    return {x for x in own if x}


def check_block_ip(text):
    """-> (indirizzo normalizzato, None) oppure (None, motivo del rifiuto)."""
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None, "not a valid IP address"
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return None, "loopback, link-local and multicast addresses cannot be blocked"
    if str(ip) in own_addresses():
        return None, "this is an address of this machine or its gateway: blocking it would cut the network"
    return str(ip), None


def apply_blocklist():
    """Ricrea la tabella nefi_block dall'elenco salvato. -> (ok, messaggio)"""
    entries = store.read_json(BLOCKED, [])
    v4, v6 = [], []
    for e in entries:
        try:
            ip = ipaddress.ip_address(e.get("ip", ""))
        except ValueError:
            continue
        (v4 if ip.version == 4 else v6).append(str(ip))
    script = ["table inet nefi_block", "delete table inet nefi_block"]
    if v4 or v6:
        script += ["table inet nefi_block {"]
        if v4:
            script += ["  set v4 { type ipv4_addr; elements = { " + ", ".join(sorted(set(v4))) + " } }"]
        if v6:
            script += ["  set v6 { type ipv6_addr; elements = { " + ", ".join(sorted(set(v6))) + " } }"]
        script += ["  chain input { type filter hook input priority -20; policy accept;"]
        script += ["    ip saddr @v4 counter drop"] if v4 else []
        script += ["    ip6 saddr @v6 counter drop"] if v6 else []
        script += ["  }", "  chain output { type filter hook output priority -20; policy accept;"]
        script += ["    ip daddr @v4 counter drop"] if v4 else []
        script += ["    ip6 daddr @v6 counter drop"] if v6 else []
        script += ["  }", "}"]
    import subprocess
    try:
        r = subprocess.run(["nft", "-f", "-"], input="\n".join(script) + "\n", capture_output=True, text=True,
                           timeout=20, env=scan.ENV)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return r.returncode == 0, (r.stderr.strip() or f"{len(v4) + len(v6)} address(es) blocked")


def blocklist_active():
    rc, _ = scan.run(["nft", "list", "table", "inet", "nefi_block"], 10)
    return rc == 0


# ── YARA ────────────────────────────────────────────────────────────────
class YaraScanner(threading.Thread):
    """Coda di file da controllare; i risultati tornano al demone con results.get_nowait()."""
    MAX_SIZE = 64 * 1024 * 1024

    def __init__(self):
        super().__init__(daemon=True, name="yara")
        self.todo, self.results = queue.Queue(maxsize=200), queue.Queue()
        self.rules, self.rules_sig, self.cache = [], None, {}
        self.scanned = self.matched = 0
        self.available = shutil.which("yara", path=scan.ENV["PATH"]) is not None

    def submit(self, path, context):
        if not self.available or not path or not path.startswith("/"):
            return
        try:
            self.todo.put_nowait((path, context))
        except queue.Full:
            pass

    def load_rules(self):
        try:
            files = sorted(os.path.join(YARA_DIR, f) for f in os.listdir(YARA_DIR) if f.endswith((".yar", ".yara")))
            sig = [(f, os.stat(f).st_mtime_ns) for f in files]
        except OSError:
            files, sig = [], None
        if sig == self.rules_sig:
            return
        self.rules_sig, good = sig, []
        for f in files[:600]:
            rc, _ = scan.run(["yara", "-w", f, "/dev/null"], 30)     # regola che non compila: scartata
            if rc == 0:
                good.append(f)
        self.rules, self.cache = good, {}

    def scan_file(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        if not os.path.isfile(path) or st.st_size == 0 or st.st_size > self.MAX_SIZE:
            return None
        key = (path, st.st_size, st.st_mtime_ns)
        if key in self.cache:
            return None                                   # gia' controllato, stesso contenuto
        self.load_rules()
        if not self.rules:
            return None
        names = set()
        for i in range(0, len(self.rules), 60):           # a gruppi, ognuno nel suo "namespace"
            args = ["yara", "-w"] + [f"n{i + j}:{f}" for j, f in enumerate(self.rules[i:i + 60])] + [path]
            rc, out = scan.run(args, 120)
            for line in out.splitlines():
                parts = line.split(" ", 1)
                if len(parts) == 2 and parts[1].strip() == path:
                    names.add(parts[0].split(":")[-1])
        self.cache[key] = True
        if len(self.cache) > 5000:
            self.cache.clear()
        self.scanned += 1
        return sorted(names)

    def run(self):
        while True:
            path, context = self.todo.get()
            try:
                names = self.scan_file(path)
                if names:
                    self.matched += 1
                    self.results.put((path, names, scan.sha256(path), context))
            except Exception:
                pass


# ── inoltro verso un server di log esterno ──────────────────────────────
SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "informational": 6}


def syslog_frame(record, host, kind):
    """Messaggio RFC 5424 con il JSON dell'avviso, in formato 'octet counting' (RFC 6587)."""
    sev = SEVERITY.get(record.get("level"), 5)
    ts = record.get("ts") or store.now_iso()
    if re.fullmatch(r".*[+-]\d{4}", ts):
        ts = ts[:-2] + ":" + ts[-2:]
    body = json.dumps(record, ensure_ascii=False, sort_keys=True)
    msg = f"<{13 * 8 + sev}>1 {ts} {host} nefi-detectd - {kind} - @cee:{body}".encode("utf-8")
    return str(len(msg)).encode() + b" " + msg


class Forwarder(threading.Thread):
    """Copia avvisi e registro audit su un server syslog remoto: un intruso che diventa root qui
    non puo' cancellare cio' che e' gia' partito. Riprende da dove era rimasto dopo ogni interruzione."""
    FILES = (("ALERT", store.ALERTS), ("AUDIT", store.AUDIT))

    def __init__(self):
        super().__init__(daemon=True, name="forwarder")
        self.status = {"enabled": False, "connected": False, "sent": 0, "error": "", "target": ""}
        self.sock = None

    def connect(self, conf):
        raw = socket.create_connection((conf["host"], int(conf["port"])), timeout=15)
        if conf.get("tls", True):
            ctx = ssl.create_default_context(cafile=conf.get("ca") or None)
            raw = ctx.wrap_socket(raw, server_hostname=conf["host"])
        raw.settimeout(15)
        return raw

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None
        self.status["connected"] = False

    def pump(self, conf, state):
        host = os.uname().nodename
        sent = 0
        for kind, path in self.FILES:
            st = state.setdefault(kind, {})
            try:
                with open(path, "rb") as f:
                    ino = os.fstat(f.fileno()).st_ino
                    if st.get("inode") != ino:
                        st.update(inode=ino, pos=0)          # file nuovo o ruotato: dall'inizio
                    f.seek(st.get("pos", 0))
                    while True:
                        line = f.readline()
                        if not line.endswith(b"\n"):
                            break
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            rec = None
                        if isinstance(rec, dict):
                            self.sock.sendall(syslog_frame(rec, host, kind))
                            sent += 1
                        st["pos"] = f.tell()
                        if sent and sent % 200 == 0:
                            store.write_json(FORWARD_STATE, state, mode=0o600, group_admin=False)
            except FileNotFoundError:
                continue
        if sent:
            store.write_json(FORWARD_STATE, state, mode=0o600, group_admin=False)
            self.status["sent"] += sent

    def run(self):
        state = store.read_json(FORWARD_STATE, {})
        wait = 5
        while True:
            conf = store.read_json(FORWARD, {})
            self.status["enabled"] = bool(conf.get("enabled") and conf.get("host"))
            if not self.status["enabled"]:
                self.close()
                self.status.update(error="", target="")
                time.sleep(10)
                continue
            self.status["target"] = f"{conf['host']}:{conf.get('port')} ({'TLS' if conf.get('tls', True) else 'plain TCP'})"
            try:
                if self.sock is None:
                    self.sock = self.connect(conf)
                    self.status.update(connected=True, error="")
                self.pump(conf, state)
                wait = 5
                time.sleep(5)
            except (OSError, ssl.SSLError, ValueError, KeyError) as e:
                self.close()
                self.status["error"] = f"{type(e).__name__}: {e}"[:200]
                time.sleep(wait)
                wait = min(wait * 2, 300)


def check_forward_target(host, port, mode, ca=""):
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[0-9a-fA-F:]{2,39}", host or ""):
        return None, "invalid host name or address"
    if not str(port).isdigit() or not 1 <= int(port) <= 65535:
        return None, "invalid port"
    if mode not in ("tls", "tcp"):
        return None, "mode must be tls or tcp"
    if ca and not (ca.startswith("/") and os.path.isfile(ca)):
        return None, "CA certificate file not found"
    return {"enabled": True, "host": host, "port": int(port), "tls": mode == "tls", "ca": ca}, None


# ── file esca (canary) ──────────────────────────────────────────────────
def _fake_secrets():
    rows = ["# Access list - internal use only", ""]
    for host in ("vpn-gateway", "backup-nas", "db-prod-01", "mail-admin", "router-core"):
        rows.append(f"{host:14} admin   {secrets.token_urlsafe(12)}")
    rows += ["", f"api_token = {secrets.token_hex(20)}", f"recovery_code = {secrets.token_hex(8)}", ""]
    return "\n".join(rows)


def canary_plan():
    """Dove mettere le esche: -> [(percorso, uid, gid)]. Nomi che un intruso apre per primi."""
    plan = [("/root/.backup/root-passwords.txt", 0, 0), ("/var/backups/credentials-old.txt", 0, 0),
            ("/opt/backup/db-credentials.env", 0, 0)]
    for home in scan.login_homes():
        if home == "/root":
            continue
        try:
            st = os.stat(home)
            pwd.getpwuid(st.st_uid)
        except (OSError, KeyError):
            continue
        plan.append((os.path.join(home, ".backup", "passwords-backup.txt"), st.st_uid, st.st_gid))
        if os.path.isdir(os.path.join(home, ".ssh")):
            plan.append((os.path.join(home, ".ssh", "id_rsa.old"), st.st_uid, st.st_gid))
    return plan


def canary_setup():
    """Crea le esche mancanti e le regole audit. -> elenco dei percorsi"""
    created = []
    for path, uid, gid in canary_plan():
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.makedirs(folder, mode=0o700, exist_ok=True)
            os.chown(folder, uid, gid)
        if os.path.islink(path):
            continue
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                if path.endswith("id_rsa.old"):
                    body = secrets.token_urlsafe(1200)
                    f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                            + "\n".join(body[i:i + 70] for i in range(0, len(body), 70))
                            + "\n-----END OPENSSH PRIVATE KEY-----\n")
                else:
                    f.write(_fake_secrets())
            os.chown(path, uid, gid)
            past = time.time() - secrets.randbelow(200) * 86400 - 30 * 86400      # non sembra creato oggi
            os.utime(path, (past, past))
        created.append(path)
    store.write_json(CANARIES, created, mode=0o600, group_admin=False)
    lines = ["## NEFI OS - file esca (canary): chi li apre, li cambia o li cancella genera un avviso critico",
             "## Generato da /opt/nefi/detection/ctl.py canary-setup: non modificare a mano"]
    lines += [f"-w {p} -p rwa -k nefi_canary" for p in created if re.fullmatch(r"[A-Za-z0-9_./@+-]+", p)]
    with open(CANARY_RULES, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(CANARY_RULES, 0o640)
    scan.run(["augenrules", "--load"], 60)
    return created


def canary_remove():
    removed = []
    for path in store.read_json(CANARIES, []):
        try:
            if os.path.isfile(path) and not os.path.islink(path):
                os.remove(path)
                removed.append(path)
        except OSError:
            pass
    for f in (CANARY_RULES, CANARIES):
        try:
            os.remove(f)
        except OSError:
            pass
    scan.run(["augenrules", "--load"], 60)
    return removed


# ── regole SigmaHQ ──────────────────────────────────────────────────────
SIGMA_MEMBER = re.compile(r"^rules/linux/(process_creation|file_event|network_connection)/([A-Za-z0-9_.-]+\.yml)$")
SIGMA_MIN_LEVEL = "medium"


def sigma_select(zip_bytes):
    """Dall'archivio ufficiale tiene solo le regole Linux che il motore sa applicare.
    -> ({nome file: testo}, {motivo: quante scartate}, versione)"""
    keep, skipped, version = {}, {}, ""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            if info.filename == "version.txt" and info.file_size < 4096:
                version = z.read(info).decode("utf-8", "replace").strip()
            m = SIGMA_MEMBER.match(info.filename)
            if not m or info.file_size > 64 * 1024:
                continue
            text = z.read(info).decode("utf-8", "replace")
            try:
                docs = [d for d in engine.yaml.safe_load_all(text) if d]
                rules = [engine.Rule(d, "sigma") for d in docs]
            except Exception as e:
                reason = "not supported by the engine: " + str(e).split(":")[0][:60]
                skipped[reason] = skipped.get(reason, 0) + 1
                continue
            status = str(docs[0].get("status", "")).lower() if docs else ""
            if status in ("deprecated", "unsupported", "experimental"):
                skipped[f"status {status}"] = skipped.get(f"status {status}", 0) + 1
                continue
            if any(engine.LEVELS.index(r.level) < engine.LEVELS.index(SIGMA_MIN_LEVEL) for r in rules) or not rules:
                skipped["level below medium"] = skipped.get("level below medium", 0) + 1
                continue
            keep[f"{m.group(1)}__{m.group(2)}"] = text
    return keep, skipped, version


def sigma_update(url=SIGMA_URL):
    """Scarica e installa. -> dict con il riepilogo (anche in SIGMA_INFO)."""
    import urllib.request
    if engine.yaml is None:
        raise RuntimeError("python3-yaml is not installed")
    req = urllib.request.Request(url, headers={"User-Agent": "nefi-os-detection"})
    with urllib.request.urlopen(req, timeout=60) as r:
        if not r.geturl().startswith("https://"):
            raise RuntimeError("refusing a non-HTTPS download")
        data = r.read(30 * 1024 * 1024 + 1)
    if len(data) > 30 * 1024 * 1024:
        raise RuntimeError("archive larger than expected")
    keep, skipped, version = sigma_select(data)
    if not keep:
        raise RuntimeError("no usable rule found in the archive")
    new = engine.SIGMA_DIR + ".new"
    shutil.rmtree(new, ignore_errors=True)
    os.makedirs(new, mode=0o755)
    for name, text in keep.items():
        with open(os.path.join(new, name), "w", encoding="utf-8") as f:
            f.write(text)
    old = engine.SIGMA_DIR + ".old"
    shutil.rmtree(old, ignore_errors=True)
    if os.path.isdir(engine.SIGMA_DIR):
        os.replace(engine.SIGMA_DIR, old)
    os.replace(new, engine.SIGMA_DIR)
    shutil.rmtree(old, ignore_errors=True)
    info = {"updated": store.now_iso(), "rules": len(keep), "skipped": skipped, "version": version, "source": url}
    store.write_json(SIGMA_INFO, info)
    return info
