"""NEFI OS - Network Security Monitoring: aggregazione degli eventi di Suricata (eve.json).

Suricata scrive in eve.json avvisi, richieste DNS, flussi, TLS e HTTP. Qui gli eventi diventano
"secchi" orari (un file JSON per ora) con contatori gia' pronti per il Security Center:
host remoti, porte, protocolli, domini, nomi TLS, firme IDS. I secchi restano 30 giorni:
sono lo storico della rete senza dover conservare i pacchetti.

Solo funzioni pure (niente root, niente rete): si provano con tests/test_monitoring.py.
"""
import collections
import ipaddress
import json
import math
import os
import re
import time

# percorso alternativo solo per i test (mai quando si gira come root)
BASE = os.environ.get("NEFI_NETMON_BASE", "/var/lib/nefi/netmon") if os.geteuid() != 0 else "/var/lib/nefi/netmon"
BUCKETS = os.path.join(BASE, "buckets")
PCAP_DIR = os.path.join(BASE, "pcap")
CAPTURES = os.path.join(BASE, "captures.json")
STATUS = os.path.join(BASE, "status.json")
ALERTS = os.path.join(BASE, "alerts.jsonl")
OFFSET = os.path.join(BASE, "offset.json")
EVE = "/var/log/suricata/eve.json"
SURICATA_YAML = "/etc/suricata/suricata.yaml"
KEEP_DAYS = 30
CAP = {"talkers": 300, "ports": 200, "dns": 600, "tls": 300, "http": 200, "alerts": 300, "alert_src": 200,
       "local": 100}
FLAG_CAP = 200
ALERTS_MAX = 4 * 1024 * 1024
# domini di secondo livello "pubblici" piu' comuni: basta per raggruppare i sottodomini
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br",
             "com.cn", "com.tr", "com.mx", "co.in", "co.za", "com.ar", "co.kr", "com.sg", "com.hk", "com.tw"}


def is_local(ip):
    """Indirizzo privato, di questa macchina o non instradabile (non e' un host 'remoto')."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified


def entropy(text):
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(text).values())


def base_domain(name):
    parts = name.rstrip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-3:]) if ".".join(parts[-2:]) in TWO_LEVEL else ".".join(parts[-2:])


def dns_flags(name):
    """Motivi per cui un nome DNS merita un'occhiata (indicatori, non prove)."""
    name = name.rstrip(".").lower()
    labels = name.split(".")
    sub = ".".join(labels[:-2]) if len(labels) > 2 else ""
    why = []
    if len(name) > 100 or any(len(l) > 50 for l in labels):
        why.append("very long name")
    longest = max(labels[:-1] or [""], key=len)
    if len(longest) >= 20 and entropy(longest) >= 3.8:
        why.append("random-looking label")
    if len(sub) > 60:
        why.append("long subdomain (possible data in DNS)")
    return why


def new_bucket(hour):
    return {"hour": hour, "events": 0, "flows": 0, "bytes_out": 0, "bytes_in": 0, "pkts": 0,
            "proto": {}, "app": {}, "talkers": {}, "local": {}, "ports": {}, "dns": {}, "dns_total": 0,
            "nxdomain": 0, "dns_flags": [], "subdomains": {}, "tls": {}, "http": {}, "alerts": {},
            "alert_src": {}, "alert_total": 0, "alert_high": 0}


def _add(d, key, *values):
    """d[key] = somma elemento per elemento (liste) oppure contatore semplice."""
    if len(values) == 1:
        d[key] = d.get(key, 0) + values[0]
    else:
        cur = d.get(key) or [0] * len(values)
        d[key] = [a + b for a, b in zip(cur, values)]


def _prune(d, cap):
    if len(d) > cap * 2:
        keep = sorted(d.items(), key=lambda kv: kv[1][0] if isinstance(kv[1], list) else kv[1], reverse=True)[:cap]
        d.clear()
        d.update(keep)


def event_hour(e):
    ts = str(e.get("timestamp", ""))
    return ts[:13] if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d", ts[:13]) else time.strftime("%Y-%m-%dT%H")


def dns_queries(e):
    """-> [(nome, tipo)] e codice di risposta; formati eve DNS v1/v2 (Suricata 6-7) e v3 (Suricata 8)."""
    d = e.get("dns") or {}
    out = []
    if isinstance(d.get("queries"), list):                       # v3
        if d.get("type") in ("request", "query"):
            out = [(q.get("rrname", ""), q.get("rrtype", "")) for q in d["queries"] if isinstance(q, dict)]
    elif d.get("type") == "query" and d.get("rrname"):
        out = [(d["rrname"], d.get("rrtype", ""))]
    rcode = d.get("rcode", "") if d.get("type") in ("answer", "response") else ""
    return out, rcode


def add_event(b, e):
    """Somma un evento eve nel secchio. -> riga per alerts.jsonl se e' un avviso IDS, altrimenti None."""
    kind = e.get("event_type")
    b["events"] += 1
    src, dst = str(e.get("src_ip", "")), str(e.get("dest_ip", ""))
    if kind == "flow":
        f = e.get("flow") or {}
        to_srv, to_cli = int(f.get("bytes_toserver", 0) or 0), int(f.get("bytes_toclient", 0) or 0)
        pkts = int(f.get("pkts_toserver", 0) or 0) + int(f.get("pkts_toclient", 0) or 0)
        total = to_srv + to_cli
        outbound = is_local(src)                     # chi ha aperto la connessione e' di qui?
        remote, local = (dst, src) if outbound else (src, dst)
        b["flows"] += 1
        b["pkts"] += pkts
        b["bytes_out"] += to_srv if outbound else to_cli
        b["bytes_in"] += to_cli if outbound else to_srv
        proto = str(e.get("proto", "?")).upper()
        _add(b["proto"], proto, total, 1)
        _add(b["app"], str(e.get("app_proto") or "unknown"), total, 1)
        if remote:
            _add(b["talkers"], remote, total, 1)
        if local:
            _add(b["local"], local, total, 1)
        if e.get("dest_port") not in (None, ""):
            _add(b["ports"], f"{e['dest_port']}/{proto}", total, 1)
    elif kind == "dns":
        queries, rcode = dns_queries(e)
        if rcode == "NXDOMAIN":
            b["nxdomain"] += 1
        for name, rtype in queries:
            name = str(name).rstrip(".").lower()
            if not name:
                continue
            b["dns_total"] += 1
            _add(b["dns"], name, 1)
            base = base_domain(name)
            subs = b["subdomains"].setdefault(base, [])
            if name != base and len(subs) < 400 and name not in subs:
                subs.append(name)
            why = dns_flags(name)
            if rtype in ("TXT", "NULL") and len(name) > 40:
                why.append(f"{rtype} query with a long name")
            if why and len(b["dns_flags"]) < FLAG_CAP and not any(x["name"] == name for x in b["dns_flags"]):
                b["dns_flags"].append({"name": name, "why": "; ".join(why), "ts": e.get("timestamp", ""),
                                       "src": src, "type": rtype})
    elif kind == "tls":
        sni = str((e.get("tls") or {}).get("sni", "")).lower()
        if sni:
            _add(b["tls"], sni, 1)
    elif kind == "http":
        host = str((e.get("http") or {}).get("hostname", "")).lower()
        if host:
            _add(b["http"], host, 1)
    elif kind == "alert":
        a = e.get("alert") or {}
        sev = int(a.get("severity", 3) or 3)
        key = json.dumps([a.get("signature_id", 0), a.get("signature", ""), sev, a.get("category", "")])
        _add(b["alerts"], key, 1)
        b["alert_total"] += 1
        b["alert_high"] += 1 if sev == 1 else 0
        attacker = dst if is_local(src) and not is_local(dst) else src
        if attacker:
            _add(b["alert_src"], attacker, 1)
        return {"ts": e.get("timestamp", ""), "sid": a.get("signature_id", 0), "signature": a.get("signature", ""),
                "severity": sev, "category": a.get("category", ""), "action": a.get("action", ""),
                "src": src, "sport": e.get("src_port", ""), "dst": dst, "dport": e.get("dest_port", ""),
                "proto": e.get("proto", ""), "app": e.get("app_proto", ""), "flow_id": e.get("flow_id", ""),
                "remote": attacker}
    for field, cap in CAP.items():
        _prune(b[field], cap)
    _prune(b["subdomains"], 300)
    return None


def finish_bucket(b):
    """Prima di salvare: i domini con moltissimi sottodomini diversi sono un indicatore di tunnel DNS."""
    for base, subs in b.get("subdomains", {}).items():
        if len(subs) >= 60 and not any(x["name"] == "*." + base for x in b["dns_flags"]) \
                and len(b["dns_flags"]) < FLAG_CAP:
            b["dns_flags"].append({"name": "*." + base, "why": f"{len(subs)}+ different subdomains in one hour",
                                   "ts": b["hour"], "src": "", "type": ""})
    return b


def bucket_path(hour):
    return os.path.join(BUCKETS, hour.replace("-", "").replace("T", "") + ".json")


def merge(buckets):
    """Piu' secchi orari -> un riepilogo solo (quello che le pagine mostrano)."""
    out = new_bucket("")
    out["hours"] = []
    for b in sorted(buckets, key=lambda x: x.get("hour", "")):
        out["hours"].append({"hour": b.get("hour", ""), "out": b.get("bytes_out", 0), "in": b.get("bytes_in", 0),
                             "alerts": b.get("alert_total", 0), "dns": b.get("dns_total", 0),
                             "flows": b.get("flows", 0)})
        for k in ("events", "flows", "bytes_out", "bytes_in", "pkts", "dns_total", "nxdomain", "alert_total",
                  "alert_high"):
            out[k] += b.get(k, 0)
        for field in ("proto", "app", "talkers", "local", "ports", "dns", "tls", "http", "alerts", "alert_src"):
            for key, val in (b.get(field) or {}).items():
                if isinstance(val, list):
                    _add(out[field], key, *val)
                else:
                    _add(out[field], key, val)
        seen = {x["name"] for x in out["dns_flags"]}
        out["dns_flags"] += [x for x in b.get("dns_flags", []) if x.get("name") not in seen]
    out.pop("subdomains", None)
    return out


def top(d, n=50):
    """dict contatore -> lista ordinata [(chiave, valore)], dal piu' grande."""
    return sorted(d.items(), key=lambda kv: kv[1][0] if isinstance(kv[1], list) else kv[1], reverse=True)[:n]


def hours_back(n, now=None):
    now = now or time.time()
    return [time.strftime("%Y-%m-%dT%H", time.localtime(now - 3600 * i)) for i in range(n)]


def load_range(hours, now=None):
    buckets = []
    for h in hours_back(hours, now):
        try:
            with open(bucket_path(h), encoding="utf-8") as f:
                buckets.append(json.load(f))
        except (OSError, ValueError):
            continue
    return merge(buckets)


def suricata_interface(text):
    """Interfaccia configurata in suricata.yaml (prima voce di af-packet), oppure ''."""
    m = re.search(r"^af-packet:\s*\n(?:[ \t]*#.*\n|[ \t]*\n)*[ \t]*-[ \t]*interface:[ \t]*(\S+)", text, re.M)
    return m.group(1) if m else ""


def set_suricata_interface(text, iface):
    """Testo di suricata.yaml con la prima interfaccia af-packet cambiata. -> (testo, cambiato?)"""
    pat = re.compile(r"(^af-packet:\s*\n(?:[ \t]*#.*\n|[ \t]*\n)*[ \t]*-[ \t]*interface:[ \t]*)(\S+)", re.M)
    if not pat.search(text):
        return text, False
    return pat.sub(lambda m: m.group(1) + iface, text, count=1), True


def capture_filter(host="", port="", proto=""):
    """Filtro BPF costruito SOLO da pezzi validati (mai testo libero dell'utente)."""
    parts = []
    if proto:
        if proto not in ("tcp", "udp", "icmp"):
            raise ValueError("protocol must be tcp, udp or icmp")
        parts.append(proto)
    if host:
        parts.append("host " + str(ipaddress.ip_address(host.strip())))
    if port:
        if not str(port).isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("port must be a number between 1 and 65535")
        if proto == "icmp":
            raise ValueError("ICMP has no ports")
        parts.append(f"port {int(port)}")
    return " and ".join(parts)
