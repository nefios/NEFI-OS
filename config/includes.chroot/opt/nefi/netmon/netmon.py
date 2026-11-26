#!/usr/bin/env python3
"""NEFI OS - Network Security Monitoring: comandi privilegiati (root, da pkexec o dal timer).

  netmon.py summarize                         legge i nuovi eventi di Suricata e aggiorna lo storico (timer)
  netmon.py capture-start IFACE MIN MB HOST PORT PROTO CASE REASON     ("-" = campo vuoto)
  netmon.py capture-stop ID
  netmon.py capture-delete ID
  netmon.py capture-preserve ID CASE OPERATOR REASON    copia firmata nell'archivio prove (DFIR)
  netmon.py suricata-iface IFACE|auto         interfaccia su cui Suricata ascolta
  netmon.py suricata-update                   aggiorna le regole IDS (suricata-update) e le ricarica
  netmon.py suricata-enable                   abilita e avvia Suricata

Le catture finiscono in /var/lib/nefi/netmon/pcap (root:sudo 0640): un amministratore le apre con
Wireshark SENZA diventare root. Durata e dimensione sono sempre limitate; il filtro e' costruito
da campi validati (indirizzo, porta, protocollo), mai da testo libero.
"""
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, "/opt/nefi/forensics")
import netlib as nl   # noqa: E402

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
ID_RE = re.compile(r"NEFI-PCAP-\d{8}-\d{6}-[0-9a-f]{4}")
IFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")
TEXT_RE = re.compile(r"[^\x00-\x1f\x7f]{1,200}")
MAX_RUNNING = 3
READ_MAX = 150 * 1024 * 1024
SELF = "/opt/nefi/netmon/netmon.py"


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
    return "root"


def ensure_dirs():
    for d in (nl.BASE, nl.BUCKETS, nl.PCAP_DIR):
        os.makedirs(d, mode=0o750, exist_ok=True)
        os.chmod(d, 0o750)
        os.chown(d, 0, admin_gid())


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    os.chmod(tmp, 0o640)
    os.chown(tmp, 0, admin_gid())
    os.replace(tmp, path)


def clean(text, what):
    text = " ".join(str(text).split())
    if not TEXT_RE.fullmatch(text):
        raise ValueError(f"{what}: 1-200 printable characters required")
    return text


def default_iface():
    rc, out, _ = run(["ip", "-j", "route", "show", "default"], 10)
    try:
        return (json.loads(out or "[]") or [{}])[0].get("dev", "")
    except (ValueError, AttributeError):
        return ""


def check_iface(name):
    if not IFACE_RE.fullmatch(name or "") or not os.path.isdir(f"/sys/class/net/{name}"):
        fail(f"network interface '{name}' does not exist")
    return name


# ── storico da Suricata ─────────────────────────────────────────────────
def summarize():
    ensure_dirs()
    saved = read_json(nl.OFFSET, {})
    touched, alerts, n = {}, [], 0
    try:
        st = os.stat(nl.EVE)
        pos = saved.get("pos", 0) if saved.get("inode") == st.st_ino and saved.get("pos", 0) <= st.st_size \
            else max(0, st.st_size - READ_MAX)
        with open(nl.EVE, "rb") as f:
            f.seek(pos)
            if pos and not saved.get("inode") == st.st_ino:
                f.readline()                                   # partito a meta' riga
            end = min(st.st_size, f.tell() + READ_MAX)
            while f.tell() < end:
                raw = f.readline()
                if not raw.endswith(b"\n"):
                    f.seek(-len(raw), os.SEEK_CUR)             # riga non ancora finita: al prossimo giro
                    break
                if b'"event_type":"stats"' in raw or b'"event_type": "stats"' in raw:
                    continue
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                if e.get("event_type") not in ("flow", "dns", "tls", "http", "alert"):
                    continue
                hour = nl.event_hour(e)
                if hour not in touched:
                    touched[hour] = read_json(nl.bucket_path(hour), None) or nl.new_bucket(hour)
                    touched[hour].setdefault("subdomains", {})
                row = nl.add_event(touched[hour], e)
                if row:
                    alerts.append(row)
                n += 1
            write_json(nl.OFFSET, {"inode": st.st_ino, "pos": f.tell()})
        eve_ok, eve_size, eve_mtime = True, st.st_size, st.st_mtime
    except OSError:
        eve_ok, eve_size, eve_mtime = False, 0, 0
    for hour, b in touched.items():
        write_json(nl.bucket_path(hour), nl.finish_bucket(b))
    if alerts:
        try:
            if os.path.getsize(nl.ALERTS) > nl.ALERTS_MAX:
                os.replace(nl.ALERTS, nl.ALERTS + ".1")
        except OSError:
            pass
        new = not os.path.exists(nl.ALERTS)
        with open(nl.ALERTS, "a", encoding="utf-8") as f:
            for a in alerts:
                f.write(json.dumps(a, ensure_ascii=False) + "\n")
        if new:
            os.chmod(nl.ALERTS, 0o640)
            os.chown(nl.ALERTS, 0, admin_gid())
    limit = time.strftime("%Y%m%d%H", time.localtime(time.time() - nl.KEEP_DAYS * 86400))
    for name in os.listdir(nl.BUCKETS):
        if name.endswith(".json") and name[:-5] < limit:
            os.unlink(os.path.join(nl.BUCKETS, name))
    try:
        with open(nl.SURICATA_YAML, encoding="utf-8", errors="replace") as f:
            conf_iface = nl.suricata_interface(f.read())
    except OSError:
        conf_iface = ""
    try:
        rules_time = os.stat("/var/lib/suricata/rules/suricata.rules").st_mtime
    except OSError:
        rules_time = 0
    dflt = default_iface()
    write_json(nl.STATUS, {
        "generated": time.time(), "eve_available": eve_ok, "eve_size": eve_size, "eve_mtime": eve_mtime,
        "events_last_run": n, "suricata_installed": bool(shutil.which("suricata", path=ENV["PATH"])),
        "suricata_active": run(["systemctl", "is-active", "suricata"], 10)[1].strip() == "active",
        "configured_iface": conf_iface, "default_iface": dflt,
        "iface_ok": bool(conf_iface) and os.path.isdir(f"/sys/class/net/{conf_iface}"),
        "rules_updated": rules_time,
        "tools": {t: bool(shutil.which(t, path=ENV["PATH"])) for t in
                  ("tcpdump", "dumpcap", "wireshark", "tshark", "zeek", "suricata-update")}})
    finalize_ended()


# ── catture di pacchetti ────────────────────────────────────────────────
def captures():
    return read_json(nl.CAPTURES, [])


def unit_name(cid):
    return "nefi-pcap-" + cid[10:].lower()


def unit_active(cid):
    return run(["systemctl", "is-active", unit_name(cid) + ".service"], 10)[1].strip() in ("active", "activating")


def find(cid):
    if not ID_RE.fullmatch(cid or ""):
        fail("invalid capture id")
    items = captures()
    item = next((c for c in items if c.get("id") == cid), None)
    if not item:
        fail("capture not found")
    return items, item


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def capture_start(iface, minutes, max_mb, host, port, proto, case, reason):
    ensure_dirs()
    check_iface(iface)
    if not (minutes.isdigit() and 1 <= int(minutes) <= 240):
        fail("duration: 1 to 240 minutes")
    if not (max_mb.isdigit() and 10 <= int(max_mb) <= 4096):
        fail("maximum size: 10 to 4096 MB")
    host, port, proto, case = (("" if x == "-" else x) for x in (host, port, proto, case))
    filt = nl.capture_filter(host, port, proto)
    case = clean(case, "case") if case else ""
    reason = clean(reason, "reason")
    items = captures()
    if sum(1 for c in items if c.get("status") == "running" and unit_active(c["id"])) >= MAX_RUNNING:
        fail(f"{MAX_RUNNING} captures are already running: stop one first")
    st = os.statvfs(nl.PCAP_DIR)
    if st.f_bavail * st.f_frsize < (int(max_mb) + 1024) * 1024 * 1024:
        fail("not enough free disk space for this capture (the size limit plus 1 GB must be free)")
    cid = f"NEFI-PCAP-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"
    path = os.path.join(nl.PCAP_DIR, cid + ".pcap")
    secs = int(minutes) * 60
    if shutil.which("dumpcap", path=ENV["PATH"]):
        tool = "dumpcap"
        cmd = ["dumpcap", "-i", iface, "-P", "-q", "-w", path, "-a", f"duration:{secs}",
               "-a", f"filesize:{int(max_mb) * 1000}"] + (["-f", filt] if filt else [])
    elif shutil.which("tcpdump", path=ENV["PATH"]):
        tool = "tcpdump"
        cmd = ["tcpdump", "-i", iface, "-n", "-U", "-s", "0", "-Z", "root", "-w", path, "-G", str(secs), "-W", "1"] \
            + filt.split()
    else:
        fail("neither dumpcap nor tcpdump is installed (apt install tcpdump)")
    rc, out, err = run(["systemd-run", "--unit", unit_name(cid), "--collect", "--quiet",
                        "--description", f"NEFI packet capture {cid}",
                        "-p", f"RuntimeMaxSec={secs + 30}", "-p", f"LimitFSIZE={int(max_mb) * 1024 * 1024}",
                        "-p", f"ExecStopPost=/usr/bin/python3 {SELF} capture-finalize {cid}"] + cmd, 30)
    if rc != 0:
        fail(f"the capture did not start: {(err or out).strip()[:300]}")
    items.insert(0, {"id": cid, "iface": iface, "filter": filt, "minutes": int(minutes), "max_mb": int(max_mb),
                     "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "by": account(), "case": case,
                     "reason": reason, "tool": tool, "file": path, "status": "running"})
    write_json(nl.CAPTURES, items)
    say(f"Capture {cid} started on {iface} ({filt or 'all traffic'}): stops after {minutes} min or {max_mb} MB.")


def finalize(cid, quiet=False):
    items, item = find(cid)
    if item.get("status") != "running":
        return
    path = item["file"]
    try:
        os.chmod(path, 0o640)
        os.chown(path, 0, admin_gid())
        item.update(size=os.path.getsize(path), sha256=sha256_file(path))
    except OSError:
        item.update(size=0, sha256="")
    item.update(status="stopped", stopped=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    write_json(nl.CAPTURES, items)
    if not quiet:
        say(f"Capture {cid} closed: {item['size']} bytes, SHA-256 {item['sha256'][:16]}…")


def finalize_ended():
    """Catture rimaste 'running' senza piu' il loro servizio (riavvio, arresto forzato)."""
    for c in captures():
        if c.get("status") == "running" and not unit_active(c["id"]):
            finalize(c["id"], quiet=True)


def capture_stop(cid):
    _items, item = find(cid)
    if item.get("status") != "running":
        fail("this capture is not running")
    run(["systemctl", "stop", unit_name(cid) + ".service"], 60)
    finalize(cid)


def capture_delete(cid):
    items, item = find(cid)
    if item.get("status") == "running" and unit_active(cid):
        fail("stop the capture before deleting it")
    try:
        os.unlink(item["file"])
    except OSError:
        pass
    write_json(nl.CAPTURES, [c for c in items if c.get("id") != cid])
    say(f"Capture {cid} deleted.")


def capture_preserve(cid, case, operator, reason):
    import custody as cu
    _items, item = find(cid)
    if item.get("status") != "stopped" or not item.get("size"):
        fail("only a finished, non-empty capture can be preserved as evidence")
    if sha256_file(item["file"]) != item.get("sha256"):
        fail("the capture file changed after it was closed: not preserved")
    store = cu.ensure_store()
    eid = cu.new_id("EV")
    dest = os.path.join(store, eid + ".pcap")
    cu.custody("capture-preservation-started", eid, operator, case=case, reason=reason, capture=cid)
    shutil.copyfile(item["file"], dest)
    os.chmod(dest, 0o640)
    os.chown(dest, 0, cu.admin_gid())
    digest = cu.sha256_file(dest)
    if digest != item["sha256"]:
        os.unlink(dest)
        fail("the copy does not match the original: nothing was signed")
    manifest = {"evidence_id": eid, "kind": "network-capture", "case": case, "operator": operator,
                "account": cu.account(), "reason": reason, "collected_utc": cu.utc_now(),
                "description": f"Packet capture {cid} on {item['iface']} ({item.get('filter') or 'all traffic'}), "
                               f"{item.get('started', '')} - {item.get('stopped', '')}",
                "time": cu.time_context(), "host": cu.host_context(), "tools": {"capture": item.get("tool", "")},
                "objects": [{"name": eid + ".pcap", "path": dest, "size": os.path.getsize(dest), "sha256": digest}],
                "source": {"capture_id": cid, "interface": item["iface"], "filter": item.get("filter", ""),
                           "started": item.get("started"), "stopped": item.get("stopped"),
                           "capture_reason": item.get("reason", ""), "started_by": item.get("by", "")},
                "format": "NEFI evidence manifest v1"}
    cu.write_manifest(manifest)
    cu.custody("collected", eid, operator, case=case, sha256=digest, capture=cid)
    say(f"Evidence {eid}: capture copied, hash verified, manifest signed.")


# ── Suricata ────────────────────────────────────────────────────────────
def suricata_iface(name):
    name = default_iface() if name == "auto" else name
    if not name:
        fail("no default network route: connect to a network first or choose the interface")
    check_iface(name)
    try:
        with open(nl.SURICATA_YAML, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        fail("Suricata is not installed (/etc/suricata/suricata.yaml not found)")
    new, changed = nl.set_suricata_interface(text, name)
    if not changed:
        fail("could not find the af-packet interface in suricata.yaml: edit it by hand")
    if new != text:
        shutil.copy2(nl.SURICATA_YAML, nl.SURICATA_YAML + ".nefi-backup")
        tmp = nl.SURICATA_YAML + ".nefi-tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(new)
        shutil.copymode(nl.SURICATA_YAML, tmp)
        rc, out, err = run(["suricata", "-T", "-c", tmp, "-i", name], 180)
        if rc != 0:
            os.unlink(tmp)
            fail(f"Suricata refused the new configuration, nothing changed: {(err or out).strip()[-300:]}")
        os.replace(tmp, nl.SURICATA_YAML)
    run(["systemctl", "enable", "suricata"], 30)
    rc, out, err = run(["systemctl", "restart", "suricata"], 120)
    if rc != 0:
        fail(f"Suricata did not restart: {(err or out).strip()[-300:]}")
    say(f"Suricata now listens on {name} (previous file saved as suricata.yaml.nefi-backup).")
    summarize()


def suricata_update():
    if not shutil.which("suricata-update", path=ENV["PATH"]):
        fail("suricata-update is not installed (apt install suricata-update)")
    p = subprocess.Popen(["suricata-update", "--no-test"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, errors="replace", env=dict(ENV, **{k: v for k, v in os.environ.items()
                                                                       if k.lower().endswith("_proxy")}))
    for line in p.stdout:
        if "<Info>" in line or "<Error>" in line or "<Warning>" in line:
            print(line.rstrip()[-200:], flush=True)
    if p.wait() != 0:
        fail("the rule update failed (is the network reachable?)")
    rc, out, err = run(["suricata", "-T", "-c", nl.SURICATA_YAML], 300)
    if rc != 0:
        fail(f"the new rules do not load, Suricata keeps the old ones: {(err or out).strip()[-300:]}")
    run(["systemctl", "reload-or-restart", "suricata"], 120)
    say("IDS rules updated and reloaded.")
    summarize()


def main():
    if os.geteuid() != 0:
        sys.exit("NEFI: run as root (pkexec)")
    a = sys.argv[1:]
    cmd, args = (a[0], a[1:]) if a else ("", [])
    try:
        if cmd == "summarize" and not args:
            summarize()
        elif cmd == "capture-start" and len(args) == 8:
            capture_start(*args)
        elif cmd == "capture-stop" and len(args) == 1:
            capture_stop(args[0])
        elif cmd == "capture-finalize" and len(args) == 1:
            finalize(args[0], quiet=True)
        elif cmd == "capture-delete" and len(args) == 1:
            capture_delete(args[0])
        elif cmd == "capture-preserve" and len(args) == 4:
            capture_preserve(args[0], clean(args[1], "case"), clean(args[2], "operator"), clean(args[3], "reason"))
        elif cmd == "suricata-iface" and len(args) == 1:
            suricata_iface(args[0])
        elif cmd == "suricata-update" and not args:
            suricata_update()
        elif cmd == "suricata-enable" and not args:
            rc, out, err = run(["systemctl", "enable", "--now", "suricata"], 120)
            say("Suricata enabled and started." if rc == 0 else f"ERROR: {(err or out).strip()[-300:]}")
            summarize()
            sys.exit(rc)
        else:
            sys.exit(__doc__)
    except (ValueError, RuntimeError, OSError) as e:
        fail(str(e))


if __name__ == "__main__":
    main()
