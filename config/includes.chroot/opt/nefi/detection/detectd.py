#!/usr/bin/env python3
"""NEFI OS - Detection engine (servizio root nefi-detectd).

Fonti di telemetria -> eventi normalizzati -> regole (Sigma) -> soppressioni -> avvisi -> correlazione

  auditd      /var/log/audit/audit.log   esecuzione di programmi (albero dei processi), accesso a file
                                         sensibili, caricamento di moduli: telemetria del kernel
  Falco       /var/log/falco/events.json comportamento a runtime (se installato)
  Suricata    /var/log/suricata/eve.json richieste DNS e avvisi di rete (se attivo)
  scansioni   ogni 5 minuti: file critici e persistenza contro la baseline APPROVATA, account,
              porte in ascolto, indicatori di rootkit; ogni 6 ore: programmi SUID; ogni giorno: rkhunter
  rete        ogni 20 secondi: nuove connessioni TCP con il programma che le ha aperte

Risultati (leggibili dagli amministratori, gruppo sudo):
  /var/log/nefi/detection/alerts.jsonl   avvisi, registro a sola aggiunta con catena di hash
  /var/lib/nefi/detection/pending.json   modifiche in attesa di approvazione (la baseline NON cambia da sola)
  /var/lib/nefi/detection/status.json    stato del motore
  /var/lib/nefi/detection/processes.jsonl programmi eseguiti (per ricostruire l'albero dei processi)
"""
import collections
import json
import math
import os
import pwd
import re
import signal
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine   # noqa: E402
import extras   # noqa: E402
import scan     # noqa: E402
import store    # noqa: E402

AUDIT_LOG = "/var/log/audit/audit.log"
FALCO_LOG = "/var/log/falco/events.json"
EVE_LOG = "/var/log/suricata/eve.json"
OSQUERY_LOG = "/var/log/osquery/osqueryd.results.log"
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
TI_IPS = "/var/lib/nefi/threat-intel/ioc/compromised-ips.txt"
TI_URLS = "/var/lib/nefi/threat-intel/ioc/malicious-urls.txt"
OFFSETS = store.STATE + "/offsets.json"
NETSEEN = store.STATE + "/network-programs.json"

SCAN_EVERY = 300            # file critici, persistenza, account, porte, rootkit veloce
SUID_EVERY = 6 * 3600
TOOLS_EVERY = 24 * 3600     # rkhunter / chkrootkit
NET_EVERY = 20
LEARNING = 24 * 3600        # dopo la prima baseline: i programmi che usano la rete vengono solo imparati
DEDUP = 600                 # stesso avviso ripetuto: uno ogni 10 minuti
PROC_MAX = 20000
FALCO_LEVEL = {"emergency": "critical", "alert": "critical", "critical": "critical", "error": "high",
               "warning": "medium", "notice": "low", "informational": "informational", "debug": "informational"}


def log(msg):
    print(f"[nefi-detectd] {msg}", flush=True)


# ── lettura incrementale dei file di log ────────────────────────────────
class Tail:
    """Legge le righe nuove di un file, sopravvive alla rotazione e ricorda la posizione tra i riavvii."""
    def __init__(self, path, saved=None):
        self.path, self.f, self.inode, self.buf = path, None, None, b""
        self.saved = saved or {}
        self.lines = 0

    def _open(self):
        try:
            f = open(self.path, "rb")
        except OSError:
            return False
        st = os.fstat(f.fileno())
        if self.inode is None and self.saved.get("inode") == st.st_ino and self.saved.get("pos", 0) <= st.st_size:
            f.seek(self.saved["pos"])           # riavvio del demone: riprendo da dove ero
        elif self.inode is None:
            f.seek(0, os.SEEK_END)              # primo avvio: solo gli eventi nuovi
        self.f, self.inode, self.buf = f, st.st_ino, b""
        return True

    def read(self, max_lines=20000):
        if self.f is None and not self._open():
            return []
        out = []
        data = self.f.read(4 * 1024 * 1024)
        if not data:
            try:
                st = os.stat(self.path)
                if st.st_ino != self.inode or st.st_size < self.f.tell():   # ruotato o troncato
                    self.f.close()
                    self.f = None
                    self.inode = -1
                    self._open()
            except OSError:
                pass
            return out
        self.buf += data
        parts = self.buf.split(b"\n")
        self.buf = parts.pop()
        for raw in parts[:max_lines]:
            out.append(raw.decode("utf-8", "replace"))
        self.lines += len(out)
        return out

    def state(self):
        if self.f is None:
            return {}
        return {"inode": self.inode, "pos": self.f.tell() - len(self.buf)}

    @property
    def available(self):
        return self.f is not None or os.path.exists(self.path)


# ── auditd ──────────────────────────────────────────────────────────────
_AUDIT_HEAD = re.compile(r"^type=(\S+) msg=audit\((\d+\.\d+):(\d+)\): ?(.*)$")
_AUDIT_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_HEX_FIELDS = re.compile(r"^(a\d+|name|comm|exe|cwd|key|proctitle)$")


def _audit_value(key, raw):
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1]
    if raw in ("(null)", "?"):
        return ""
    if _HEX_FIELDS.match(key) and len(raw) >= 4 and _HEX.match(raw) and not raw.isdigit():
        try:
            return bytes.fromhex(raw).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            return raw
    return raw


def parse_audit_line(line):
    """-> (id evento, ts, tipo, campi) oppure None."""
    m = _AUDIT_HEAD.match(line)
    if not m:
        return None
    rtype, ts, eid, rest = m.groups()
    rest = rest.split("\x1d", 1)[0]          # log_format=ENRICHED: la parte tradotta non serve
    fields = {k: _audit_value(k, v) for k, v in _AUDIT_KV.findall(rest)}
    return eid, float(ts), rtype, fields


class AuditAssembler:
    """Mette insieme i record (SYSCALL, EXECVE, CWD, PATH) che formano un evento audit."""
    def __init__(self):
        self.open = collections.OrderedDict()     # id -> {"ts", "records": [(tipo, campi)], "seen"}

    def feed(self, line):
        p = parse_audit_line(line)
        done = []
        if not p:
            return done
        eid, ts, rtype, fields = p
        if rtype == "EOE":
            if eid in self.open:
                done.append(self.open.pop(eid))
            return done
        ev = self.open.get(eid)
        if ev is None:
            ev = self.open[eid] = {"ts": ts, "records": [], "seen": time.monotonic()}
            # gli eventi precedenti sono quasi sempre completi quando ne inizia uno nuovo
            while len(self.open) > 4:
                done.append(self.open.popitem(last=False)[1])
        ev["records"].append((rtype, fields))
        return done

    def flush(self, older_than=1.5):
        now, done = time.monotonic(), []
        for eid in list(self.open):
            if now - self.open[eid]["seen"] >= older_than:
                done.append(self.open.pop(eid))
        return done


_users = {}


def user_name(uid):
    if uid in ("", None):
        return ""
    if uid in ("4294967295", "-1"):
        return "unset"
    if uid not in _users:
        try:
            _users[uid] = pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError):
            _users[uid] = str(uid)
    return _users[uid]


def audit_to_event(ev):
    """Evento audit assemblato -> evento NEFI (campi con i nomi usati da Sigma), oppure None."""
    sysc = next((f for t, f in ev["records"] if t == "SYSCALL"), None)
    if sysc is None:
        return None
    key = sysc.get("key", "")
    if not key:
        return None
    base = {
        "ts": ev["ts"], "source": "auditd", "AuditKey": key, "Image": sysc.get("exe", ""),
        "ProcessName": sysc.get("comm", ""), "pid": sysc.get("pid", ""), "ppid": sysc.get("ppid", ""),
        "User": user_name(sysc.get("uid")), "EffectiveUser": user_name(sysc.get("euid")),
        "LoginUser": user_name(sysc.get("auid")), "Tty": sysc.get("tty", ""),
        "Success": sysc.get("success", ""),
    }
    cwd = next((f.get("cwd", "") for t, f in ev["records"] if t == "CWD"), "")
    if "nefi_exec" in key:
        if sysc.get("success") == "no":
            return None
        execve = next((f for t, f in ev["records"] if t == "EXECVE"), {})
        args = [execve[k] for k in sorted((k for k in execve if re.fullmatch(r"a\d+", k)), key=lambda k: int(k[1:]))]
        base.update({"category": "process", "CommandLine": " ".join(args)[:4000] or sysc.get("comm", ""),
                     "CurrentDirectory": cwd})
        return base
    paths = [f for t, f in ev["records"] if t == "PATH" and f.get("nametype") != "PARENT"]
    name = paths[-1].get("name", "") if paths else ""
    if name and not name.startswith("/") and cwd:
        name = os.path.normpath(os.path.join(cwd, name))
    if "modules" in key.split("\x01") or key == "modules":
        base.update({"category": "file", "TargetFilename": name, "EventType": "module_load"})
        return base
    base.update({"category": "file", "TargetFilename": name})
    return base


# ── utilita' per DNS e rete ─────────────────────────────────────────────
def entropy(text):
    if not text:
        return 0.0
    counts = collections.Counter(text)
    n = len(text)
    return round(-sum(c / n * math.log2(c / n) for c in counts.values()), 2)


def load_ti():
    ips, hosts = set(), set()
    try:
        with open(TI_IPS, errors="replace") as f:
            ips = {l.strip() for l in f if l.strip() and not l.startswith("#")}
    except OSError:
        pass
    try:
        with open(TI_URLS, errors="replace") as f:
            for l in f:
                m = re.match(r"^https?://([^/:\s]+)", l.strip())
                if m and not re.fullmatch(r"[\d.]+", m.group(1)):
                    hosts.add(m.group(1).lower())
                elif m:
                    ips.add(m.group(1))
    except OSError:
        pass
    return ips, hosts


def is_private(ip):
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False


# ── il motore ───────────────────────────────────────────────────────────
class Detectd:
    def __init__(self):
        store.ensure_dirs()
        self.started = time.time()
        self.alerts = store.ChainLog(store.ALERTS)
        saved = store.read_json(OFFSETS, {})
        self.audit = Tail(AUDIT_LOG, saved.get("audit"))
        self.falco = Tail(FALCO_LOG, saved.get("falco"))
        self.eve = Tail(EVE_LOG, saved.get("eve"))
        self.osquery = Tail(OSQUERY_LOG, saved.get("osquery"))
        self.yara = extras.YaraScanner()
        self.yara.start()
        self.forwarder = extras.Forwarder()
        self.forwarder.start()
        self.assembler = AuditAssembler()
        self.procs = collections.OrderedDict()      # pid -> info dell'ultimo programma eseguito
        self.proc_log = None
        self.rules, self.rule_errors, self.by_cat, self.by_src = [], [], {}, {}
        self.correlator = engine.Correlator([])
        self.suppressions, self.disabled = [], set()
        self.conf_sig = None
        self.hits = collections.Counter()
        self.suppressed_count = 0
        self.last_alert = {}                        # (regola, chiave) -> ts
        self.next = {"scan": time.time() + 20, "suid": time.time() + 180, "tools": time.time() + 1800,
                     "net": time.time() + 10, "status": 0, "chain": time.time() + 60, "ti": 0}
        self.pending = {p["id"]: p for p in store.read_json(store.PENDING, [])}
        self.base_sig = None
        self.baseline = None
        self.conns = {}                             # connessioni viste -> ts
        self.net_programs = set(store.read_json(NETSEEN, []))
        self.ti_ips, self.ti_hosts = set(), set()
        self.rootkit_seen = {}
        self.chain_ok = (True, 0, "not checked yet")
        self.scan_info = {}
        self.events_seen = collections.Counter()
        self.stop = False
        self.rescan = False
        self.reload_config(force=True)

    # ── configurazione: regole, regole disattivate, soppressioni ──
    def reload_config(self, force=False):
        sig = []
        for path in (engine.BUILTIN_DIR, engine.SIGMA_DIR, store.RULES_D, store.SUPPRESSIONS, store.DISABLED):
            try:
                sig.append(os.stat(path).st_mtime_ns)
                if os.path.isdir(path):
                    sig += [os.stat(os.path.join(path, f)).st_mtime_ns for f in sorted(os.listdir(path))]
            except OSError:
                sig.append(0)
        if not force and sig == self.conf_sig:
            return
        self.conf_sig = sig
        rules, self.rule_errors = engine.load_rules()
        self.disabled = set(store.read_json(store.DISABLED, []))
        self.suppressions = store.read_json(store.SUPPRESSIONS, [])
        self.rules = rules
        active = [r for r in rules if r.id not in self.disabled]
        self.by_cat, self.by_src = {}, {}
        for r in active:
            if r.correlation:
                continue
            if r.category:
                self.by_cat.setdefault(r.category, []).append(r)
            else:
                self.by_src.setdefault(r.service, []).append(r)
        self.correlator = engine.Correlator(active)
        log(f"{len(active)} rules active ({len(rules) - len(active)} disabled, {len(self.rule_errors)} not loaded), "
            f"{len(self.suppressions)} suppressions")

    # ── albero dei processi ──
    def remember_process(self, ev):
        pid = str(ev.get("pid", ""))
        parent = self.procs.get(str(ev.get("ppid", "")))
        if parent:
            ev["ParentImage"], ev["ParentCommandLine"] = parent["Image"], parent["CommandLine"]
            ev["ParentUser"] = parent["User"]
        else:
            try:
                ev["ParentImage"] = os.readlink(f"/proc/{ev.get('ppid')}/exe")
                with open(f"/proc/{ev.get('ppid')}/cmdline", "rb") as f:
                    ev["ParentCommandLine"] = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()[:2000]
            except OSError:
                ev.setdefault("ParentImage", "")
                ev.setdefault("ParentCommandLine", "")
        rec = {"ts": ev["ts"], "pid": pid, "ppid": str(ev.get("ppid", "")), "Image": ev.get("Image", ""),
               "CommandLine": ev.get("CommandLine", ""), "User": ev.get("User", ""),
               "ParentImage": ev.get("ParentImage", "")}
        self.procs[pid] = rec
        self.procs.move_to_end(pid)
        while len(self.procs) > PROC_MAX:
            self.procs.popitem(last=False)
        try:
            if self.proc_log is None:
                new = not os.path.exists(store.PROCESSES)
                self.proc_log = open(store.PROCESSES, "a", encoding="utf-8")
                if new:
                    os.chmod(store.PROCESSES, 0o640)
                    os.chown(store.PROCESSES, 0, store.admin_gid())
            self.proc_log.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def ancestors(self, ev, limit=12):
        chain, seen = [], set()
        pid = str(ev.get("ppid", "") or "")
        if ev.get("category") != "process":
            pid = str(ev.get("pid", "") or "")
        while pid and pid not in seen and pid != "0" and len(chain) < limit:
            seen.add(pid)
            rec = self.procs.get(pid)
            if rec is None:
                try:
                    with open(f"/proc/{pid}/stat") as f:
                        stat = f.read()
                    ppid = stat.rsplit(")", 1)[1].split()[1]
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                    rec = {"pid": pid, "ppid": ppid, "Image": os.readlink(f"/proc/{pid}/exe"),
                           "CommandLine": cmd[:500], "User": ""}
                except (OSError, IndexError):
                    break
            chain.append({"pid": rec["pid"], "Image": rec.get("Image", ""), "User": rec.get("User", ""),
                          "CommandLine": rec.get("CommandLine", "")[:500]})
            pid = rec.get("ppid", "")
        return chain

    # ── dal singolo evento all'avviso ──
    def process(self, ev):
        self.events_seen[ev.get("source", "?")] += 1
        if ev.get("category") == "process":
            if str(ev.get("ppid")) == str(os.getpid()):
                return                              # i comandi lanciati dal motore stesso
            self.remember_process(ev)
            if str(ev.get("Image", "")).startswith(TEMP_DIRS):
                self.yara.submit(ev["Image"], {"pid": ev.get("pid", ""), "ppid": ev.get("ppid", ""),
                                               "User": ev.get("User", ""), "CommandLine": ev.get("CommandLine", ""),
                                               "Trigger": "program run from a temporary directory"})
        for r in self.by_cat.get(ev.get("category"), []) + self.by_src.get(ev.get("source"), []):
            if not r.applies(ev):
                continue
            try:
                if r.match(ev):
                    self.detect(r, ev)
            except Exception as e:                  # una regola rotta non ferma le altre
                log(f"rule {r.id} failed: {e}")

    def detect(self, rule, ev, extra=None):
        ts = ev.get("ts") or time.time()
        self.hits[rule.id] += 1
        sup = engine.suppressed_by(rule.id, ev, self.suppressions)
        if sup:
            self.suppressed_count += 1
            return
        if not rule.silent:
            keys = rule.dedup or ["Image", "TargetFilename", "Item", "DestinationIp", "QueryName", "FalcoRule",
                                  "Signature", "Indicator"]
            dk = (rule.id,) + tuple(str(ev.get(k, "")) for k in keys)
            if time.time() - self.last_alert.get(dk, 0) >= DEDUP:
                self.last_alert[dk] = time.time()
                self.write_alert(rule, ev, ts, extra)
        ctx = dict(ev)
        ctx["RuleId"] = rule.id
        ctx["Tactic"] = [t["name"] for t in rule.mitre["tactics"]]
        ctx.setdefault("Host", os.uname().nodename)
        for corr, group, n, detail in self.correlator.feed(rule.id, ctx, time.time()):
            if engine.suppressed_by(corr.id, ctx, self.suppressions):
                self.suppressed_count += 1
                continue
            self.hits[corr.id] += 1
            self.write_alert(corr, ev, ts, {"correlation": detail, "group": group, "count": n,
                                            "last_rule": rule.id})

    def write_alert(self, rule, ev, ts, extra=None):
        mitre = {"tactics": list(rule.mitre["tactics"]), "techniques": list(rule.mitre["techniques"])}
        level, title = rule.level, rule.title
        tmpl = rule.doc.get("nefi_title")
        if tmpl:
            try:
                title = str(tmpl).format_map(collections.defaultdict(str, {k: str(v) for k, v in ev.items()}))
            except (ValueError, IndexError):
                pass
        if ev.get("Technique"):                     # tecnica decisa dalla scansione (dipende dal percorso)
            mitre["techniques"] += engine.mitre_from_tags(["attack." + str(ev["Technique"])])["techniques"]
        if rule.doc.get("nefi_mitre_from_tags") and ev.get("Tags"):
            more = engine.mitre_from_tags(ev["Tags"])
            mitre["tactics"] += [t for t in more["tactics"] if t not in mitre["tactics"]]
            mitre["techniques"] += [t for t in more["techniques"] if t not in mitre["techniques"]]
        if rule.doc.get("nefi_level_from") and ev.get(rule.doc["nefi_level_from"]) in engine.LEVELS:
            level = ev[rule.doc["nefi_level_from"]]
        fields = {k: (v if isinstance(v, (int, float, list)) else str(v)[:2000])
                  for k, v in ev.items() if k not in ("ts", "category", "source") and v not in ("", None)}
        rec = {
            "id": uuid.uuid4().hex[:12], "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)),
            "rule_id": rule.id, "title": title, "level": level, "description": rule.description,
            "mitre": mitre, "source": ev.get("source", ""), "category": ev.get("category", ""),
            "event": fields, "process_tree": self.ancestors(ev), "falsepositives": rule.falsepositives,
            "origin": rule.origin,
        }
        if extra:
            rec.update(extra)
        self.alerts.append(rec)

    # ── fonti ──
    def poll_audit(self):
        done = []
        for line in self.audit.read():
            done += self.assembler.feed(line)
        done += self.assembler.flush()
        me = str(os.getpid())
        for raw in done:
            ev = audit_to_event(raw)
            if ev and ev.get("pid") != me:          # non gli accessi fatti dal motore stesso
                self.process(ev)

    def poll_falco(self):
        for line in self.falco.read():
            try:
                f = json.loads(line)
            except ValueError:
                continue
            of = f.get("output_fields") or {}
            ev = {
                "ts": time.time(), "source": "falco", "category": "falco", "FalcoRule": f.get("rule", ""),
                "Priority": str(f.get("priority", "")), "Output": str(f.get("output", ""))[:1500],
                "Level": FALCO_LEVEL.get(str(f.get("priority", "")).lower(), "low"),
                "Tags": f.get("tags") or [], "Image": of.get("proc.exepath") or of.get("proc.exe") or "",
                "ProcessName": of.get("proc.name", ""), "CommandLine": of.get("proc.cmdline", ""),
                "ParentName": of.get("proc.pname", ""), "User": of.get("user.name", ""),
                "TargetFilename": of.get("fd.name", ""), "pid": of.get("proc.pid", ""),
                "ppid": of.get("proc.ppid", ""), "Container": of.get("container.name", ""),
            }
            self.process(ev)

    def poll_eve(self):
        for line in self.eve.read():
            if '"event_type":"dns"' not in line and '"event_type":"alert"' not in line \
                    and '"event_type": "dns"' not in line and '"event_type": "alert"' not in line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event_type") == "dns":
                d = e.get("dns") or {}
                queries = d.get("queries") or [d]
                name = str((queries[0] or {}).get("rrname") or d.get("rrname") or "").lower().rstrip(".")
                if not name:
                    continue
                labels = name.split(".")
                longest = max(labels, key=len)
                parent = ".".join(labels[-2:])
                self.process({
                    "ts": time.time(), "source": "suricata", "category": "dns", "QueryName": name,
                    "QueryType": str((queries[0] or {}).get("rrtype") or d.get("rrtype") or ""),
                    "DnsType": str(d.get("type", "")), "Rcode": str(d.get("rcode", "")),
                    "SourceIp": e.get("src_ip", ""), "DestinationIp": e.get("dest_ip", ""),
                    "QueryLength": len(name), "LongestLabel": len(longest), "LabelEntropy": entropy(longest),
                    "Subdomains": max(0, len(labels) - 2), "ParentDomain": parent,
                    "ThreatIntel": "true" if (name in self.ti_hosts or parent in self.ti_hosts) else "false",
                })
            else:
                a = e.get("alert") or {}
                meta = a.get("metadata") or {}
                tags = [str(x) for k in ("mitre_technique_id", "mitre_tactic_name") for x in (meta.get(k) or [])]
                sev = {1: "high", 2: "medium", 3: "low"}.get(a.get("severity"), "low")
                self.process({
                    "ts": time.time(), "source": "suricata", "category": "ids", "Signature": a.get("signature", ""),
                    "SignatureId": a.get("signature_id", ""), "AlertCategory": a.get("category", ""),
                    "Level": sev, "Tags": tags, "SourceIp": e.get("src_ip", ""), "SourcePort": e.get("src_port", ""),
                    "DestinationIp": e.get("dest_ip", ""), "DestinationPort": e.get("dest_port", ""),
                    "Protocol": e.get("proto", ""), "Action": a.get("action", ""),
                })

    def poll_osquery(self):
        """Risultati differenziali delle query pianificate di osquery (se installato)."""
        for line in self.osquery.read():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if str(r.get("counter", "1")) == "0":    # primo giro di una query: e' l'inventario iniziale
                continue
            cols = r.get("columns") or {}
            name = re.sub(r"^(pack_)?nefi_", "", str(r.get("name", "")))
            ev = {k: str(v)[:1000] for k, v in cols.items() if isinstance(k, str) and k.isidentifier()}
            ev.update({
                "ts": time.time(), "source": "osquery", "category": "osquery", "OsqueryName": name,
                "Action": str(r.get("action", "")), "Image": cols.get("path", "") or cols.get("name", ""),
                "Item": ", ".join(f"{k}={v}" for k, v in list(cols.items())[:6])[:400],
            })
            self.process(ev)

    def poll_yara(self):
        while True:
            try:
                path, names, digest, ctx = self.yara.results.get_nowait()
            except Exception:
                return
            ev = {"ts": time.time(), "source": "nefi", "category": "yara", "Item": path, "Image": path,
                  "YaraRule": names, "YaraRules": ", ".join(names)[:300], "Sha256": digest or ""}
            ev.update(ctx)
            self.process(ev)

    def poll_network(self):
        rc, out = scan.run(["ss", "-H", "-tnp", "state", "established"], timeout=15)
        if rc != 0:
            return
        now = time.time()
        listening = {k.split("/", 1)[1] for k in scan.collect_listeners()}
        learning = (self.baseline is None) or now - self.baseline.get("created_ts", now) < LEARNING
        for line in out.splitlines():
            f = line.split()
            if len(f) < 4:
                continue
            local, peer = f[2], f[3]
            lip, _, lport = local.rpartition(":")
            pip, _, pport = peer.rpartition(":")
            pip = pip.strip("[]").split("%")[0].replace("::ffff:", "")
            m = scan._SS_USERS.search(line)
            if not m or pip.startswith("127.") or pip == "::1":
                continue
            key = (m.group(2), pip, pport, lport)
            if key in self.conns:
                self.conns[key] = now
                continue
            self.conns[key] = now
            try:
                exe = os.readlink(f"/proc/{m.group(2)}/exe")
            except OSError:
                exe = m.group(1)
            inbound = lport in listening
            first = exe not in self.net_programs
            if first:
                self.net_programs.add(exe)
            self.process({
                "ts": now, "source": "nefi", "category": "network", "Image": exe, "ProcessName": m.group(1),
                "pid": m.group(2), "DestinationIp": pip, "DestinationPort": pport, "SourcePort": lport,
                "Initiated": "false" if inbound else "true",
                "DestinationIsPrivate": "true" if is_private(pip) else "false",
                "ThreatIntel": "true" if pip in self.ti_ips else "false",
                "FirstSeenProgram": "true" if (first and not learning and not inbound) else "false",
            })
        for key in [k for k, t in self.conns.items() if now - t > 300]:
            del self.conns[key]
        if len(self.net_programs) < 5000:
            store.write_json(NETSEEN, sorted(self.net_programs), mode=0o600, group_admin=False)

    # ── baseline e scansioni periodiche ──
    def load_baseline(self):
        try:
            sig = os.stat(store.BASELINE).st_mtime_ns
        except OSError:
            sig = None
        if sig != self.base_sig or self.baseline is None:
            self.base_sig = sig
            self.baseline = store.load_baseline()
            # approvazioni fatte da ctl.py: tolgo dall'elenco "in attesa" cio' che ora coincide
            self.pending = {p["id"]: p for p in store.read_json(store.PENDING, [])}
        return self.baseline

    def first_baseline(self, with_suid=True):
        """Prima fotografia: e' il momento piu' affidabile (sistema appena installato)."""
        items = {}
        items.update(scan.collect_files())
        items.update(scan.collect_accounts())
        items.update(scan.collect_listeners())
        if with_suid:
            items.update(scan.collect_suid())
        verified = unverified = 0
        for key in items:
            cls, _, path = key.partition(":")
            if cls in ("integrity", "suid") and path.startswith(("/usr/", "/opt/", "/bin/", "/sbin/")):
                if scan.package_verified(path):
                    verified += 1
                else:
                    unverified += 1
        base = {"version": 1, "created": store.now_iso(), "created_ts": time.time(), "items": items,
                "verification": {"package_verified": verified, "not_from_a_package": unverified}}
        store.save_baseline(base)
        store.audit("baseline-created", "nefi-detectd", items=len(items), package_verified=verified,
                    not_package_verified=unverified)
        log(f"baseline created: {len(items)} items, {verified} program files match their Debian package")
        self.baseline, self.pending = base, {}
        store.write_json(store.PENDING, [])
        try:
            self.base_sig = os.stat(store.BASELINE).st_mtime_ns
        except OSError:
            pass

    def scan_state(self, classes, current):
        base = self.load_baseline()
        if base is None:
            self.first_baseline()
            return
        changes = scan.diff(base["items"], current, classes)
        still = set()
        for kind, key, old, new in changes:
            cls, _, path = key.partition(":")
            pid = f"{key}"
            still.add(pid)
            known = self.pending.get(pid)
            if known and known.get("new") == new and known.get("kind") == kind:
                continue                                    # gia' segnalato, ancora in attesa
            verified = None
            if kind != "removed" and cls in ("integrity", "suid") and os.path.isfile(path):
                verified = scan.package_verified(path)
            tech, label = scan.CLASS_INFO.get(cls, ("", cls))
            entry = {"id": pid, "class": cls, "kind": kind, "item": path, "old": old, "new": new,
                     "first_seen": store.now_iso(), "package_verified": verified, "technique": tech,
                     "label": label}
            if verified is True and cls == "integrity" and kind == "modified" and path.startswith(("/usr/", "/opt/")):
                # programma aggiornato dal gestore dei pacchetti e identico al pacchetto: approvazione automatica
                self.auto_approve(entry)
                continue
            self.pending[pid] = entry
            if kind != "removed" and cls.split(".")[0] in ("persistence", "suid") and path.startswith("/"):
                self.yara.submit(path, {"Trigger": f"new or changed {label.lower()}"})
            self.process({
                "ts": time.time(), "source": "nefi", "category": "state", "EventType": f"item_{kind}",
                "Class": cls, "ClassGroup": cls.split(".")[0], "Item": path, "ItemLabel": label,
                "Technique": tech, "PackageVerified": {True: "true", False: "false", None: "unknown"}[verified],
                "OldValue": old or "", "NewValue": new or "",
            })
        for pid in [p for p in self.pending if p.split(":", 1)[0].split(".")[0] in classes and p not in still]:
            del self.pending[pid]                           # tornato come nella baseline (o approvato)
        store.write_json(store.PENDING, sorted(self.pending.values(), key=lambda p: p["first_seen"], reverse=True))

    def auto_approve(self, entry):
        base = store.load_baseline()
        if base is None:
            return
        base["items"][entry["id"]] = entry["new"]
        store.save_baseline(base)
        store.audit("auto-approved", "nefi-detectd", item=entry["id"], old=entry["old"], new=entry["new"],
                    reason="content matches the installed Debian package")
        self.baseline = base
        try:
            self.base_sig = os.stat(store.BASELINE).st_mtime_ns
        except OSError:
            pass

    def scan_periodic(self):
        t0 = time.time()
        current = {}
        current.update(scan.collect_files())
        current.update(scan.collect_accounts())
        current.update(scan.collect_listeners())
        self.scan_state({"integrity", "persistence", "account", "admin", "listener"}, current)
        for indicator, detail in scan.rootkit_indicators():
            if time.time() - self.rootkit_seen.get((indicator, detail), 0) > 86400:
                self.rootkit_seen[(indicator, detail)] = time.time()
                self.process({"ts": time.time(), "source": "nefi", "category": "rootkit", "Indicator": indicator,
                              "Item": detail, "Tool": "nefi"})
        self.scan_info["state"] = {"at": store.now_iso(), "items": len(current), "seconds": round(time.time() - t0, 1)}
        # indirizzi bloccati dagli avvisi: la tabella deve esserci anche dopo un riavvio o un "flush"
        if store.read_json(extras.BLOCKED, []) and not extras.blocklist_active():
            extras.apply_blocklist()

    def scan_suid(self):
        t0 = time.time()
        if self.load_baseline() is None:
            return
        self.scan_state({"suid"}, scan.collect_suid())
        self.scan_info["suid"] = {"at": store.now_iso(), "seconds": round(time.time() - t0, 1)}

    def scan_tools(self):
        t0 = time.time()
        found = scan.rootkit_tools()
        for tool, msg in found:
            self.process({"ts": time.time(), "source": "nefi", "category": "rootkit", "Indicator": "tool_warning",
                          "Tool": tool, "Item": msg})
        self.scan_info["rootkit_tools"] = {"at": store.now_iso(), "warnings": len(found),
                                           "seconds": round(time.time() - t0, 1)}

    # ── stato per il Security Center ──
    def write_status(self):
        base = self.baseline or {}
        store.write_json(store.STATUS, {
            "generated": store.now_iso(), "started": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.started)),
            "pid": os.getpid(),
            "sources": {
                "auditd": {"available": self.audit.available, "lines": self.audit.lines,
                           "events": self.events_seen.get("auditd", 0)},
                "falco": {"available": self.falco.available, "events": self.events_seen.get("falco", 0)},
                "suricata": {"available": self.eve.available, "events": self.events_seen.get("suricata", 0)},
                "nefi": {"available": True, "events": self.events_seen.get("nefi", 0)},
                "osquery": {"available": self.osquery.available, "events": self.events_seen.get("osquery", 0)},
            },
            "yara": {"available": self.yara.available, "rules": len(self.yara.rules),
                     "scanned": self.yara.scanned, "matched": self.yara.matched},
            "forward": dict(self.forwarder.status),
            "canaries": store.read_json(extras.CANARIES, []),
            "blocked": store.read_json(extras.BLOCKED, []),
            "sigma": store.read_json(extras.SIGMA_INFO, {}),
            "rules": [dict(r.summary(), enabled=r.id not in self.disabled, hits=self.hits.get(r.id, 0))
                      for r in sorted(self.rules, key=lambda r: (r.origin, r.title))],
            "rule_errors": [{"file": f, "error": e} for f, e in self.rule_errors],
            "suppressions": self.suppressions, "suppressed_events": self.suppressed_count,
            "baseline": {"created": base.get("created"), "items": len(base.get("items", {})),
                         "verification": base.get("verification", {}), "pending": len(self.pending),
                         "learning_network": bool(base) and time.time() - base.get("created_ts", 0) < LEARNING},
            "scans": self.scan_info, "log_chain": {"ok": self.chain_ok[0], "records": self.chain_ok[1],
                                                   "message": self.chain_ok[2]},
            "processes_tracked": len(self.procs), "threat_intel": {"ips": len(self.ti_ips), "hosts": len(self.ti_hosts)},
        })
        store.write_json(OFFSETS, {"audit": self.audit.state(), "falco": self.falco.state(), "eve": self.eve.state(),
                                   "osquery": self.osquery.state()},
                         mode=0o600, group_admin=False)
        if self.proc_log:
            self.proc_log.flush()
            if store.rotate(store.PROCESSES, 30 * 1024 * 1024):
                self.proc_log.close()
                self.proc_log = None

    def check_chain(self):
        ok = store.verify_chain(store.ALERTS)
        ok2 = store.verify_chain(store.AUDIT)
        was_ok = self.chain_ok[0]
        self.chain_ok = ok if not ok[0] else (ok2 if not ok2[0] else ok)
        if not self.chain_ok[0] and was_ok:
            self.process({"ts": time.time(), "source": "nefi", "category": "selfcheck", "EventType": "log_tampered",
                          "Item": self.chain_ok[2]})
        if store.rotate(store.ALERTS, 50 * 1024 * 1024):
            self.alerts = store.ChainLog(store.ALERTS)
            self.alerts.last = store._last_hash(store.ALERTS + ".1")

    def run(self):
        log("started")
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "stop", True))
        signal.signal(signal.SIGUSR1, lambda *_: setattr(self, "rescan", True))
        while not self.stop:
            now = time.time()
            try:
                self.reload_config()
                self.poll_audit()
                self.poll_falco()
                self.poll_eve()
                self.poll_osquery()
                self.poll_yara()
                if now >= self.next["ti"]:
                    self.ti_ips, self.ti_hosts = load_ti()
                    self.next["ti"] = now + 1800
                if now >= self.next["net"]:
                    self.poll_network()
                    self.next["net"] = now + NET_EVERY
                if now >= self.next["scan"] or self.rescan:
                    self.rescan = False
                    self.scan_periodic()
                    self.next["scan"] = time.time() + SCAN_EVERY
                    self.next["status"] = 0
                if now >= self.next["suid"]:
                    self.scan_suid()
                    self.next["suid"] = time.time() + SUID_EVERY
                if now >= self.next["tools"]:
                    self.next["tools"] = time.time() + TOOLS_EVERY
                    self.scan_tools()
                if now >= self.next["chain"]:
                    self.check_chain()
                    self.next["chain"] = now + 3600
                    self.correlator.prune()
                    self.last_alert = {k: t for k, t in self.last_alert.items() if now - t < DEDUP}
                if now >= self.next["status"]:
                    self.write_status()
                    self.next["status"] = now + 15
            except Exception as e:                  # il motore non deve mai fermarsi per un errore
                log(f"error in main loop: {type(e).__name__}: {e}")
                time.sleep(2)
            time.sleep(1)
        self.write_status()
        log("stopped")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("nefi-detectd must run as root")
    Detectd().run()
