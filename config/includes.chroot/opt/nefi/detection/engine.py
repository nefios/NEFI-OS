"""NEFI OS - Detection engine: regole (formato Sigma, sottoinsieme), soppressioni, correlazione, MITRE ATT&CK.

Modulo puro (nessun accesso al sistema oltre alla lettura dei file di regole): usato dal demone
detectd.py, dall'helper ctl.py, dal Security Center e dai test (tests/test_detection.py).

Regole: file YAML (anche piu' documenti per file) in
    /usr/share/nefi/detection/rules/   regole NEFI (pacchetto)
    /etc/nefi/detection/rules.d/       regole personali / Sigma importate
Sottoinsieme Sigma supportato:
    logsource   product: linux; category: process_creation | file_event | network_connection | dns_query
                oppure service: auditd | falco | suricata | nefi
    detection   selezioni con campi e modificatori contains, startswith, endswith, re, all, cidr,
                gt, gte, lt, lte; caratteri jolly * e ?; liste = OR; parole chiave (lista di stringhe)
    condition   and, or, not, parentesi, "1 of sel*", "all of sel*", "1 of them", "all of them"
    correlation (Sigma v2) type: event_count | value_count | temporal
Le aggregazioni vecchio stile ("| count() ...") non sono supportate: la regola viene saltata con il motivo.
"""
import fnmatch
import glob
import ipaddress
import json
import os
import re
import time

try:
    import yaml
except ImportError:          # python3-yaml mancante: solo regole .json
    yaml = None

BUILTIN_DIR = "/usr/share/nefi/detection/rules"
CUSTOM_DIR = "/etc/nefi/detection/rules.d"
SIGMA_DIR = "/var/lib/nefi/detection/sigma"        # regole SigmaHQ scaricate (ctl.py sigma-update)
LEVELS = ["informational", "low", "medium", "high", "critical"]

# ── MITRE ATT&CK ────────────────────────────────────────────────────────
TACTICS = [   # (chiave nei tag Sigma, id, nome)
    ("reconnaissance", "TA0043", "Reconnaissance"), ("resource_development", "TA0042", "Resource Development"),
    ("initial_access", "TA0001", "Initial Access"), ("execution", "TA0002", "Execution"),
    ("persistence", "TA0003", "Persistence"), ("privilege_escalation", "TA0004", "Privilege Escalation"),
    ("defense_evasion", "TA0005", "Defense Evasion"), ("credential_access", "TA0006", "Credential Access"),
    ("discovery", "TA0007", "Discovery"), ("lateral_movement", "TA0008", "Lateral Movement"),
    ("collection", "TA0009", "Collection"), ("command_and_control", "TA0011", "Command and Control"),
    ("exfiltration", "TA0010", "Exfiltration"), ("impact", "TA0040", "Impact"),
]
TACTIC_BY_KEY = {k: (i, n) for k, i, n in TACTICS}
TECHNIQUES = {   # solo quelle usate dalle regole NEFI e dai tag piu' comuni di Falco
    "T1003": "OS Credential Dumping", "T1003.008": "/etc/passwd and /etc/shadow",
    "T1014": "Rootkit", "T1021.004": "Remote Services: SSH", "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading", "T1037": "Boot or Logon Initialization Scripts", "T1040": "Network Sniffing",
    "T1046": "Network Service Discovery", "T1048": "Exfiltration Over Alternative Protocol",
    "T1053.002": "Scheduled Task/Job: At", "T1053.003": "Scheduled Task/Job: Cron",
    "T1053.006": "Scheduled Task/Job: Systemd Timers", "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Unix Shell", "T1068": "Exploitation for Privilege Escalation",
    "T1070": "Indicator Removal", "T1070.002": "Clear Linux or Mac System Logs", "T1070.004": "File Deletion",
    "T1083": "File and Directory Discovery", "T1200": "Hardware Additions", "T1565.001": "Stored Data Manipulation",
    "T1195": "Supply Chain Compromise", "T1587.001": "Malware", "T1552.001": "Credentials In Files",
    "T1071": "Application Layer Protocol", "T1071.004": "Application Layer Protocol: DNS",
    "T1078": "Valid Accounts", "T1098": "Account Manipulation", "T1098.004": "SSH Authorized Keys",
    "T1105": "Ingress Tool Transfer", "T1110": "Brute Force", "T1136": "Create Account",
    "T1136.001": "Create Account: Local Account", "T1190": "Exploit Public-Facing Application",
    "T1204": "User Execution", "T1222": "File and Directory Permissions Modification",
    "T1485": "Data Destruction", "T1486": "Data Encrypted for Impact", "T1496": "Resource Hijacking",
    "T1505.003": "Web Shell", "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1546": "Event Triggered Execution", "T1546.004": "Unix Shell Configuration Modification",
    "T1547.006": "Kernel Modules and Extensions", "T1547.013": "XDG Autostart Entries",
    "T1548": "Abuse Elevation Control Mechanism", "T1548.001": "Setuid and Setgid",
    "T1548.003": "Sudo and Sudo Caching", "T1552": "Unsecured Credentials",
    "T1552.004": "Unsecured Credentials: Private Keys", "T1553": "Subvert Trust Controls",
    "T1556": "Modify Authentication Process", "T1556.003": "Pluggable Authentication Modules",
    "T1562": "Impair Defenses", "T1562.001": "Disable or Modify Tools",
    "T1562.004": "Disable or Modify System Firewall", "T1562.012": "Disable or Modify Linux Audit System",
    "T1565": "Data Manipulation", "T1568.002": "Domain Generation Algorithms", "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling", "T1574.006": "Dynamic Linker Hijacking", "T1611": "Escape to Host",
}
_TECH_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.I)


def mitre_from_tags(tags):
    """Tag Sigma (attack.persistence, attack.t1053.003) o Falco (mitre_persistence, T1053.003) -> dict."""
    tactics, techs = [], []
    for raw in tags or []:
        t = str(raw).strip().lower()
        for prefix in ("attack.", "mitre_", "mitre."):
            if t.startswith(prefix):
                t = t[len(prefix):]
        key = t.replace("-", "_").replace(" ", "_")
        if key in TACTIC_BY_KEY:
            tid, name = TACTIC_BY_KEY[key]
            if tid not in [x["id"] for x in tactics]:
                tactics.append({"id": tid, "name": name})
        elif _TECH_RE.match(t):
            tid = t.upper()
            if tid not in [x["id"] for x in techs]:
                techs.append({"id": tid, "name": TECHNIQUES.get(tid, TECHNIQUES.get(tid.split(".")[0], ""))})
    return {"tactics": tactics, "techniques": techs}


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


# ── regole ──────────────────────────────────────────────────────────────
CATEGORY_MAP = {   # logsource.category Sigma -> categoria degli eventi NEFI
    "process_creation": "process", "file_event": "file", "file_change": "file", "file_access": "file",
    "network_connection": "network", "dns_query": "dns", "dns": "dns",
}
SERVICES = {"auditd", "falco", "suricata", "nefi", "osquery"}


class RuleError(ValueError):
    pass


def _parse_span(text):
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(text))
    if not m:
        raise RuleError(f"invalid timespan: {text}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


class Matcher:
    """Una coppia campo|modificatori: valore/i di una selezione Sigma."""
    def __init__(self, key, value):
        parts = str(key).split("|")
        self.field, mods = parts[0], [m.lower() for m in parts[1:]]
        self.all = "all" in mods
        ops = [m for m in mods if m != "all"]
        if len(ops) > 1:
            raise RuleError(f"unsupported modifier chain: {key}")
        self.op = ops[0] if ops else "equals"
        if self.op not in ("equals", "contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte",
                           "exists"):
            raise RuleError(f"unsupported modifier: {self.op}")
        self.values = value if isinstance(value, list) else [value]
        if self.op == "re":
            try:
                self.regex = [re.compile(str(v)) for v in self.values]
            except re.error as e:
                raise RuleError(f"invalid regex in {key}: {e}")
        if self.op == "cidr":
            try:
                self.nets = [ipaddress.ip_network(str(v), strict=False) for v in self.values]
            except ValueError as e:
                raise RuleError(f"invalid CIDR in {key}: {e}")

    def _one(self, i, v, actual):
        if self.op == "exists":
            return (actual is not None) == bool(v)
        if actual is None:
            return v is None
        if v is None:
            return actual in ("", None)
        if self.op in ("gt", "gte", "lt", "lte"):
            try:
                a, b = float(actual), float(v)
            except (TypeError, ValueError):
                return False
            return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[self.op]
        if self.op == "cidr":
            try:
                return ipaddress.ip_address(str(actual)) in self.nets[i]
            except ValueError:
                return False
        if self.op == "re":
            return self.regex[i].search(str(actual)) is not None
        a, b = str(actual).lower(), str(v).lower()
        if self.op == "contains":
            return fnmatch.fnmatchcase(a, "*" + b + "*") if ("*" in b or "?" in b) else b in a
        if self.op == "startswith":
            return a.startswith(b)
        if self.op == "endswith":
            return a.endswith(b)
        if "*" in b or "?" in b:
            return fnmatch.fnmatchcase(a, b)
        return a == b

    def match(self, event):
        actual = event.get(self.field)
        if isinstance(actual, list):      # campo a piu' valori (es. tag): basta che uno corrisponda
            res = [any(self._one(i, v, x) for x in actual) for i, v in enumerate(self.values)]
        else:
            res = [self._one(i, v, actual) for i, v in enumerate(self.values)]
        return all(res) if self.all else any(res)


class Selection:
    def __init__(self, spec):
        self.groups, self.keywords = [], []      # OR tra i gruppi, AND dentro il gruppo
        if isinstance(spec, dict):
            self.groups.append([Matcher(k, v) for k, v in spec.items()])
        elif isinstance(spec, list):
            for item in spec:
                if isinstance(item, dict):
                    self.groups.append([Matcher(k, v) for k, v in item.items()])
                else:
                    self.keywords.append(str(item).lower())
        else:
            raise RuleError("a selection must be a mapping or a list")

    def match(self, event):
        if any(all(m.match(event) for m in g) for g in self.groups):
            return True
        if self.keywords:
            text = " ".join(str(v) for v in event.values()).lower()
            return any(k in text for k in self.keywords)
        return False


def _tokenize(cond):
    return re.findall(r"\(|\)|[^\s()]+", cond)


class Condition:
    """Parser a discesa ricorsiva per la 'condition' Sigma."""
    def __init__(self, text, names):
        if "|" in text:
            raise RuleError("aggregations in 'condition' are not supported (use a correlation rule)")
        self.tok, self.pos, self.names = _tokenize(text), 0, names
        self.tree = self._or()
        if self.pos != len(self.tok):
            raise RuleError(f"unexpected token in condition: {self.tok[self.pos]}")

    def _peek(self):
        return self.tok[self.pos].lower() if self.pos < len(self.tok) else None

    def _next(self):
        self.pos += 1
        return self.tok[self.pos - 1]

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self._next()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self._next()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if self._peek() == "not":
            self._next()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        t = self._peek()
        if t is None:
            raise RuleError("incomplete condition")
        if t == "(":
            self._next()
            node = self._or()
            if self._peek() != ")":
                raise RuleError("missing ) in condition")
            self._next()
            return node
        if t in ("1", "all", "any") and self.pos + 2 < len(self.tok) + 1 and \
                self.pos + 1 < len(self.tok) and self.tok[self.pos + 1].lower() == "of":
            quant = "all" if self._next().lower() == "all" else "any"
            self._next()
            pat = self._next()
            sel = list(self.names) if pat.lower() == "them" else [n for n in self.names if fnmatch.fnmatchcase(n, pat)]
            if not sel:
                raise RuleError(f"no selection matches '{pat}'")
            return (quant, sel)
        name = self._next()
        if name not in self.names:
            raise RuleError(f"unknown selection in condition: {name}")
        return ("sel", name)

    def eval(self, hits, node=None):
        node = node or self.tree
        kind = node[0]
        if kind == "sel":
            return hits(node[1])
        if kind == "not":
            return not self.eval(hits, node[1])
        if kind == "and":
            return self.eval(hits, node[1]) and self.eval(hits, node[2])
        if kind == "or":
            return self.eval(hits, node[1]) or self.eval(hits, node[2])
        if kind == "any":
            return any(hits(n) for n in node[1])
        return all(hits(n) for n in node[1])


class Rule:
    def __init__(self, doc, origin="builtin", path=""):
        if not isinstance(doc, dict):
            raise RuleError("rule is not a mapping")
        self.doc, self.origin, self.path = doc, origin, path
        self.title = str(doc.get("title") or "").strip()
        self.id = str(doc.get("id") or "").strip()
        if not self.title or not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", self.id):
            raise RuleError("a rule needs a title and an id (letters, digits, . _ -)")
        self.description = str(doc.get("description") or "").strip()
        self.level = str(doc.get("level") or "medium").lower()
        if self.level == "info":
            self.level = "informational"
        if self.level not in LEVELS:
            raise RuleError(f"invalid level: {self.level}")
        self.tags = [str(t) for t in (doc.get("tags") or [])]
        self.mitre = mitre_from_tags(self.tags)
        self.falsepositives = [str(x) for x in (doc.get("falsepositives") or [])]
        self.silent = bool(doc.get("nefi_silent"))          # conta per la correlazione ma non crea avvisi
        self.dedup = [str(x) for x in (doc.get("nefi_dedup") or [])]
        self.correlation = None
        if "correlation" in doc:
            self._init_correlation(doc["correlation"])
        else:
            self._init_detection(doc)

    def _init_detection(self, doc):
        ls = doc.get("logsource") or {}
        product = str(ls.get("product") or "linux").lower()
        if product != "linux":
            raise RuleError(f"logsource product '{product}' is not Linux")
        self.category = self.service = None
        cat, svc = ls.get("category"), ls.get("service")
        if cat:
            if str(cat).lower() not in CATEGORY_MAP:
                raise RuleError(f"unsupported logsource category: {cat}")
            self.category = CATEGORY_MAP[str(cat).lower()]
        if svc:
            if str(svc).lower() not in SERVICES:
                raise RuleError(f"unsupported logsource service: {svc}")
            self.service = str(svc).lower()
        if not self.category and not self.service:
            raise RuleError("logsource needs a category or a service")
        det = doc.get("detection")
        if not isinstance(det, dict) or "condition" not in det:
            raise RuleError("missing detection/condition")
        self.selections = {k: Selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
        cond = det["condition"]
        if isinstance(cond, list):
            cond = " or ".join(f"({c})" for c in cond)
        self.condition = Condition(str(cond), list(self.selections))

    def _init_correlation(self, c):
        if not isinstance(c, dict):
            raise RuleError("correlation must be a mapping")
        kind = str(c.get("type") or "")
        if kind not in ("event_count", "value_count", "temporal"):
            raise RuleError(f"unsupported correlation type: {kind}")
        rules = c.get("rules") or []
        if not isinstance(rules, list) or not rules:
            raise RuleError("correlation needs a list of rules")
        cond = c.get("condition") or {}
        self.correlation = {
            "type": kind, "rules": [str(r) for r in rules],
            "group_by": [str(g) for g in (c.get("group-by") or c.get("group_by") or [])],
            "timespan": _parse_span(c.get("timespan", "5m")),
            "field": str(cond.get("field") or c.get("field") or ""),
            "gte": int(cond.get("gte", cond.get("gt", 0) + 1 if "gt" in cond else 1)),
        }
        if kind == "value_count" and not self.correlation["field"]:
            raise RuleError("value_count needs condition.field")

    def applies(self, event):
        if self.correlation:
            return False
        if self.category and event.get("category") != self.category:
            return False
        if self.service and event.get("source") != self.service:
            return False
        return True

    def match(self, event):
        cache = {}

        def hits(name):
            if name not in cache:
                cache[name] = self.selections[name].match(event)
            return cache[name]
        return self.condition.eval(hits)

    def summary(self):
        return {"id": self.id, "title": self.title, "level": self.level, "description": self.description,
                "origin": self.origin, "path": self.path, "mitre": self.mitre, "tags": self.tags,
                "kind": "correlation" if self.correlation else "detection",
                "logsource": (self.doc.get("logsource") or {}), "falsepositives": self.falsepositives,
                "silent": self.silent}


def load_documents(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith(".json"):
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    if yaml is None:
        raise RuleError("python3-yaml is not installed")
    try:
        return [d for d in yaml.safe_load_all(text) if d]
    except yaml.YAMLError as e:
        raise RuleError(f"invalid YAML: {e}")


def load_rules(builtin_dir=BUILTIN_DIR, custom_dir=CUSTOM_DIR, sigma_dir=SIGMA_DIR):
    """-> (regole valide, [(file, errore)]). Una regola personale con lo stesso id sostituisce le altre."""
    rules, errors = {}, []
    for origin, folder in (("builtin", builtin_dir), ("sigma", sigma_dir), ("custom", custom_dir)):
        files = sorted(glob.glob(os.path.join(folder, "*.yml")) + glob.glob(os.path.join(folder, "*.yaml"))
                       + glob.glob(os.path.join(folder, "*.json")))
        for path in files:
            try:
                docs = load_documents(path)
            except (OSError, ValueError) as e:
                errors.append((path, str(e)))
                continue
            for doc in docs:
                try:
                    r = Rule(doc, origin, path)
                    rules[r.id] = r
                except RuleError as e:
                    title = doc.get("title", "?") if isinstance(doc, dict) else "?"
                    errors.append((path, f"{title}: {e}"))
    return list(rules.values()), errors


# ── soppressioni (falsi positivi) ───────────────────────────────────────
SUPPRESS_FIELDS = ["Image", "ParentImage", "CommandLine", "TargetFilename", "User", "Item", "DestinationIp",
                   "DestinationPort", "QueryName", "FalcoRule", "Signature", "Unit"]


def suppressed_by(rule_id, event, suppressions):
    """-> id della soppressione che copre questo evento, oppure None."""
    for s in suppressions:
        if s.get("rule_id") not in ("*", rule_id):
            continue
        field, value = s.get("field"), str(s.get("value", ""))
        if not field:                     # tutta la regola
            return s.get("id")
        actual = event.get(field)
        if actual is None:
            continue
        a, b = str(actual).lower(), value.lower()
        if fnmatch.fnmatchcase(a, b) if ("*" in b or "?" in b) else a == b:
            return s.get("id")
    return None


# ── correlazione ────────────────────────────────────────────────────────
class Correlator:
    """Tiene in memoria gli ultimi rilevamenti e fa scattare le regole di correlazione."""
    def __init__(self, rules):
        self.rules = [r for r in rules if r.correlation]
        self.window = {r.id: {} for r in self.rules}     # id regola -> {gruppo: [(ts, id regola base, valore)]}
        self.fired = {}                                  # (id, gruppo) -> ts dell'ultimo avviso

    def feed(self, rule_id, event, ts=None):
        """Un rilevamento della regola rule_id: -> [(regola di correlazione, gruppo, quanti, dettagli)]."""
        ts = ts or time.time()
        out = []
        for r in self.rules:
            c = r.correlation
            if rule_id not in c["rules"] and "*" not in c["rules"]:
                continue
            group = tuple(str(event.get(g, "")) for g in c["group_by"])
            buf = self.window[r.id].setdefault(group, [])
            value = event.get(c["field"]) if c["field"] else None
            if isinstance(value, list):
                for v in value:
                    buf.append((ts, rule_id, str(v)))
            else:
                buf.append((ts, rule_id, None if value is None else str(value)))
            buf[:] = [x for x in buf if ts - x[0] <= c["timespan"]][-5000:]
            if c["type"] == "event_count":
                n, ok = len(buf), len(buf) >= c["gte"]
                detail = f"{n} events in {c['timespan']} s"
            elif c["type"] == "value_count":
                vals = sorted({x[2] for x in buf if x[2] not in (None, "")})
                n, ok = len(vals), len(vals) >= c["gte"]
                detail = f"{n} different {c['field']}: " + ", ".join(vals[:12])
            else:
                seen = {x[1] for x in buf}
                n, ok = len(seen), all(x in seen for x in c["rules"])
                detail = "rules seen together: " + ", ".join(sorted(seen))
            if ok and ts - self.fired.get((r.id, group), float("-inf")) > c["timespan"]:
                self.fired[(r.id, group)] = ts
                buf.clear()
                out.append((r, dict(zip(c["group_by"], group)), n, detail))
        return out

    def prune(self, now=None):
        now = now or time.time()
        for r in self.rules:
            span = r.correlation["timespan"]
            for group in list(self.window[r.id]):
                buf = [x for x in self.window[r.id][group] if now - x[0] <= span]
                if buf:
                    self.window[r.id][group] = buf
                else:
                    del self.window[r.id][group]
