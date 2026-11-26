"""NEFI OS - DFIR: timeline forense strutturata (usato da dfir.py come root).

Ogni fonte produce eventi {timestamp (microsecondi UTC), timestamp_desc, source, message, ...}; tutto viene
ordinato in un unico file JSONL, che e' anche il formato importabile da Timesketch
(campi obbligatori: message, datetime, timestamp_desc).

Fonti:
  filesystem   tempi MACB dei file (modifica, accesso, cambio metadati, nascita) nelle cartelle scelte
  journal      registro di sistema (journald)
  auth         accessi, sudo, su, PAM, creazione di utenti (dal journal)
  systemd      servizi avviati, fermati, falliti (dal journal)
  logins       sessioni aperte e chiuse, tentativi falliti (wtmp/btmp con 'last')
  packages     pacchetti installati, aggiornati, rimossi (dpkg.log, apt history)
  shell        comandi delle cronologie che hanno un orario (bash con HISTTIMEFORMAT, zsh extended)
  browser      cronologia e download di Firefox e Chromium (lette da una COPIA dei database)
  detection    avvisi del motore di rilevamento NEFI
  process      programmi eseguiti (telemetria auditd del motore di rilevamento)
  image        tempi MACB dei file dentro un'immagine disco (The Sleuth Kit, 'fls')
"""
import csv
import glob
import gzip
import json
import os
import pwd
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "TZ": "UTC"}
SOURCES = ["filesystem", "journal", "auth", "systemd", "logins", "packages", "shell", "browser", "detection",
           "process"]
FS_ROOTS = ["/etc", "/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/usr/local", "/opt", "/srv",
            "/var/spool/cron", "/var/www", "/usr/bin", "/usr/sbin", "/usr/lib/systemd/system", "/boot"]
AUTH_IDS = {"sshd", "sshd-session", "sudo", "su", "login", "sddm", "sddm-helper", "polkitd", "pkexec", "passwd",
            "useradd", "usermod", "userdel", "groupadd", "gpasswd", "chage", "unix_chkpwd", "systemd-logind",
            "chpasswd", "doas", "runuser", "kscreenlocker_greet"}
MAX_PER_SOURCE = 400000


def ev(ts_us, desc, source, message, **extra):
    d = {"timestamp": int(ts_us), "timestamp_desc": desc, "source": source, "message": str(message)[:2000]}
    d.update({k: v for k, v in extra.items() if v not in (None, "")})
    return d


def iso(ts_us):
    return datetime.fromtimestamp(ts_us / 1e6, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def local_to_us(text, fmt):
    """Orario locale senza fuso (dpkg.log, apt) -> microsecondi UTC."""
    return int(time.mktime(time.strptime(text, fmt)) * 1e6)


# ── filesystem (MACB) ───────────────────────────────────────────────────
def macb_events(path, times, since_us, source, info=""):
    """times: {'m': s, 'a': s, 'c': s, 'b': s} -> un evento per ogni istante, con le lettere MACB come mactime."""
    by_ts = {}
    for letter, t in times.items():
        if t and t > 0:
            by_ts.setdefault(int(t), set()).add(letter)
    out = []
    for t, letters in by_ts.items():
        if t * 1_000_000 < since_us:
            continue
        flags = "".join(l if l in letters else "." for l in "macb")
        out.append(ev(t * 1_000_000, flags, source, f"{flags} {path}{info}", path=path))
    return out


def fs_source(since_us, roots=None):
    out = []
    roots = [r for r in (roots or FS_ROOTS) if os.path.isdir(r)]
    if not roots:
        return out
    cmd = ["find"] + roots + ["-xdev", "(", "-type", "f", "-o", "-type", "l", "-o", "-type", "d", ")",
                               "-printf", r"%T@|%A@|%C@|%B@|%s|%m|%u|%y|%p\0"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
    except OSError:
        return out
    buf = b""
    while True:
        chunk = p.stdout.read(1 << 20)
        if not chunk:
            break
        buf += chunk
        parts = buf.split(b"\0")
        buf = parts.pop()
        for raw in parts:
            f = raw.decode("utf-8", "replace").split("|", 8)
            if len(f) != 9:
                continue
            try:
                times = {"m": float(f[0]), "a": float(f[1]), "c": float(f[2]), "b": 0}
            except ValueError:
                continue
            try:                                  # la data di nascita manca su molti filesystem ("-" o -1)
                times["b"] = max(0.0, float(f[3]))
            except ValueError:
                pass
            out += macb_events(f[8], times, since_us, "filesystem", f" ({f[7]}, {f[4]} bytes, mode {f[5]}, {f[6]})")
            if len(out) >= MAX_PER_SOURCE * 2:
                p.kill()
                return out
    p.wait()
    return out


def image_source(image, since_us=0, offset=None):
    """Bodyfile di The Sleuth Kit: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime"""
    cmd = ["fls", "-r", "-m", "/"] + (["-o", str(int(offset))] if offset else []) + [image]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=ENV, errors="replace")
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"fls failed: {e}")
    if r.returncode != 0 and not r.stdout:
        raise RuntimeError(f"fls could not read the image: {r.stderr.strip()[:200]}")
    out = []
    for line in r.stdout.splitlines():
        f = line.split("|")
        if len(f) < 11:
            continue
        try:
            times = {"a": float(f[7]), "m": float(f[8]), "c": float(f[9]), "b": float(f[10])}
        except ValueError:
            continue
        out += macb_events(f[1], times, since_us, "image", f" (inode {f[2]}, {f[6]} bytes, {f[3]})")
    return out


# ── journal ─────────────────────────────────────────────────────────────
def journal_source(since_us, wanted):
    """Una sola lettura del journal produce tre fonti: journal, auth, systemd."""
    out = []
    since = f"@{since_us // 1_000_000}" if since_us else "@86400"
    try:
        p = subprocess.Popen(["journalctl", "-o", "json", "--no-pager", "--since", since], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env=ENV, text=True, errors="replace")
    except OSError:
        return out
    n = 0
    for line in p.stdout:
        try:
            j = json.loads(line)
            ts = int(j["__REALTIME_TIMESTAMP"])
        except (ValueError, KeyError):
            continue
        ident = str(j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or "")
        msg = j.get("MESSAGE")
        if isinstance(msg, list):
            msg = bytes(x for x in msg if isinstance(x, int)).decode("utf-8", "replace")
        msg = str(msg or "")
        extra = {"identifier": ident, "pid": j.get("_PID", ""), "uid": j.get("_UID", ""),
                 "unit": j.get("_SYSTEMD_UNIT", ""), "priority": j.get("PRIORITY", "")}
        if ident in AUTH_IDS or "pam_unix" in msg or "pam_sss" in msg:
            if "auth" in wanted:
                out.append(ev(ts, "Authentication event", "auth", f"{ident}: {msg}", **extra))
        elif ident == "systemd" and re.match(r"(Started|Stopped|Starting|Stopping|Failed|Reloaded|Created|Removed) ", msg):
            if "systemd" in wanted:
                out.append(ev(ts, "Service state change", "systemd", msg, **extra))
        elif "journal" in wanted:
            out.append(ev(ts, "Log entry", "journal", f"{ident}: {msg}", **extra))
        n += 1
        if n >= MAX_PER_SOURCE:
            p.kill()
            break
    return out


# ── sessioni (wtmp / btmp) ──────────────────────────────────────────────
_LAST = re.compile(r"^(\S+)\s+(\S+)\s+(\S*?)\s+(\d{4}-\d\d-\d\dT[\d:]+[+-][\d:]+)(?:\s+-\s+(\d{4}-\d\d-\d\dT[\d:]+[+-][\d:]+))?")


def _iso_us(text):
    return int(datetime.fromisoformat(text).timestamp() * 1e6)


def logins_source(since_us):
    out = []
    for tool, desc in (("last", "Session opened"), ("lastb", "Failed login")):
        try:
            r = subprocess.run([tool, "-F", "-w", "--time-format", "iso"], capture_output=True, text=True, timeout=60,
                               env=ENV, errors="replace")
        except (OSError, subprocess.SubprocessError):
            continue
        for line in r.stdout.splitlines():
            m = _LAST.match(line)
            if not m or m.group(1) in ("reboot", "wtmp", "btmp"):
                continue
            user, tty, host, start, end = m.groups()
            try:
                ts = _iso_us(start)
            except ValueError:
                continue
            if ts >= since_us:
                out.append(ev(ts, desc, "logins", f"{desc}: {user} on {tty}" + (f" from {host}" if host else ""),
                              user=user, tty=tty, remote_host=host))
            if end and tool == "last":
                try:
                    te = _iso_us(end)
                    if te >= since_us:
                        out.append(ev(te, "Session closed", "logins", f"Session closed: {user} on {tty}", user=user))
                except ValueError:
                    pass
    return out


# ── pacchetti ───────────────────────────────────────────────────────────
def _open_any(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, errors="replace")


def packages_source(since_us, dpkg_glob="/var/log/dpkg.log*", apt_glob="/var/log/apt/history.log*"):
    out = []
    for path in sorted(glob.glob(dpkg_glob)):
        try:
            with _open_any(path) as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 5 and p[2] in ("install", "upgrade", "remove", "purge"):
                        try:
                            ts = local_to_us(f"{p[0]} {p[1]}", "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            continue
                        if ts >= since_us:
                            out.append(ev(ts, f"Package {p[2]}", "packages",
                                          f"dpkg {p[2]} {p[3]} {' -> '.join(x for x in p[4:6] if x != '<none>')}",
                                          package=p[3]))
        except OSError:
            continue
    for path in sorted(glob.glob(apt_glob)):
        try:
            with _open_any(path) as f:
                block = {}
                for line in list(f) + [""]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        block[k.strip()] = v.strip()
                    elif block:
                        try:
                            ts = local_to_us(" ".join(block.get("Start-Date", "").split()), "%Y-%m-%d %H:%M:%S")
                            if ts >= since_us and block.get("Commandline"):
                                out.append(ev(ts, "APT command", "packages", f"apt: {block['Commandline']}"
                                              + (f" (requested by {block['Requested-By']})" if block.get("Requested-By") else "")))
                        except ValueError:
                            pass
                        block = {}
        except OSError:
            continue
    return out


# ── cronologie della shell (solo le righe con un orario) ─────────────────
def login_homes():
    homes = []
    for p in pwd.getpwall():
        if (p.pw_uid == 0 or p.pw_uid >= 1000) and os.path.isdir(p.pw_dir) and not p.pw_shell.endswith(("nologin", "false")):
            homes.append((p.pw_name, p.pw_dir))
    return homes


def shell_source(since_us, homes=None):
    out = []
    for user, home in (homes if homes is not None else login_homes()):
        for name in (".bash_history", ".zsh_history"):
            path = os.path.join(home, name)
            try:
                with open(path, errors="replace") as f:
                    pending = None
                    for line in f:
                        line = line.rstrip("\n")
                        m = re.fullmatch(r"#(\d{9,11})", line)
                        z = re.match(r": (\d{9,11}):\d+;(.*)", line)
                        if m:
                            pending = int(m.group(1))
                        elif z:
                            ts = int(z.group(1)) * 1_000_000
                            if ts >= since_us:
                                out.append(ev(ts, "Shell command", "shell", f"{user}$ {z.group(2)}", user=user))
                        elif pending is not None:
                            if pending * 1_000_000 >= since_us:
                                out.append(ev(pending * 1_000_000, "Shell command", "shell", f"{user}$ {line}", user=user))
                            pending = None
            except OSError:
                continue
    return out


# ── browser ─────────────────────────────────────────────────────────────
def _query_copy(db, sql):
    """Interroga una COPIA del database (l'originale puo' essere in uso e non va toccato)."""
    tmp = tempfile.mkdtemp(prefix="nefi-tl-")
    try:
        dst = os.path.join(tmp, "db.sqlite")
        shutil.copy2(db, dst)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db + suffix):
                shutil.copy2(db + suffix, dst + suffix)
        con = sqlite3.connect(dst)
        try:
            return con.execute(sql).fetchall()
        finally:
            con.close()
    except (sqlite3.Error, OSError):
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def browser_source(since_us, homes=None):
    out = []
    for user, home in (homes if homes is not None else login_homes()):
        for db in glob.glob(os.path.join(home, ".mozilla/firefox/*/places.sqlite")) + \
                glob.glob(os.path.join(home, "snap/firefox/common/.mozilla/firefox/*/places.sqlite")):
            for ts, url, title in _query_copy(db, "SELECT v.visit_date, p.url, p.title FROM moz_historyvisits v "
                                                  "JOIN moz_places p ON p.id = v.place_id"):
                if ts and ts >= since_us:
                    out.append(ev(ts, "Web page visited", "browser", f"Firefox ({user}): {url} {title or ''}".strip(),
                                  user=user, url=url, browser="firefox"))
            for ts, target, url in _query_copy(db, "SELECT a.dateAdded, a.content, p.url FROM moz_annos a "
                                                   "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
                                                   "JOIN moz_places p ON p.id = a.place_id "
                                                   "WHERE n.name = 'downloads/destinationFileURI'"):
                if ts and ts >= since_us:
                    out.append(ev(ts, "File downloaded", "browser", f"Firefox ({user}) downloaded {url} -> {target}",
                                  user=user, url=url, path=target, browser="firefox"))
        for base in (".config/chromium", ".config/google-chrome", ".config/BraveSoftware/Brave-Browser"):
            for db in glob.glob(os.path.join(home, base, "*/History")):
                name = base.split("/")[-1]
                epoch = 11644473600 * 1_000_000          # Chromium conta i microsecondi dal 1601
                for ts, url, title in _query_copy(db, "SELECT v.visit_time, u.url, u.title FROM visits v "
                                                      "JOIN urls u ON u.id = v.url"):
                    if ts and ts - epoch >= since_us:
                        out.append(ev(ts - epoch, "Web page visited", "browser", f"{name} ({user}): {url} {title or ''}".strip(),
                                      user=user, url=url, browser=name))
                for ts, target, url in _query_copy(db, "SELECT start_time, target_path, tab_url FROM downloads"):
                    if ts and ts - epoch >= since_us:
                        out.append(ev(ts - epoch, "File downloaded", "browser", f"{name} ({user}) downloaded {url} -> {target}",
                                      user=user, url=url, path=target, browser=name))
    return out


# ── motore di rilevamento NEFI ──────────────────────────────────────────
def detection_source(since_us, alerts="/var/log/nefi/detection/alerts.jsonl"):
    out = []
    for path in (alerts + ".1", alerts):
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    try:
                        a = json.loads(line)
                        ts = int(datetime.strptime(a["ts"], "%Y-%m-%dT%H:%M:%S%z").timestamp() * 1e6)
                    except (ValueError, KeyError):
                        continue
                    if ts >= since_us:
                        tech = ", ".join(t.get("id", "") for t in a.get("mitre", {}).get("techniques", []))
                        out.append(ev(ts, "NEFI detection alert", "detection",
                                      f"[{a.get('level', '')}] {a.get('title', '')}" + (f" ({tech})" if tech else ""),
                                      alert_id=a.get("id"), rule=a.get("rule_id"), level=a.get("level")))
        except OSError:
            continue
    return out


def process_source(since_us, history="/var/lib/nefi/detection/processes.jsonl"):
    out = []
    for path in (history + ".1", history):
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                        ts = int(float(r["ts"]) * 1e6)
                    except (ValueError, KeyError):
                        continue
                    if ts >= since_us:
                        out.append(ev(ts, "Program executed", "process",
                                      f"{r.get('User') or '?'} ran {r.get('Image', '')}: {r.get('CommandLine', '')}",
                                      pid=r.get("pid"), ppid=r.get("ppid"), user=r.get("User"), path=r.get("Image")))
                        if len(out) >= MAX_PER_SOURCE:
                            return out
        except OSError:
            continue
    return out


# ── costruzione ─────────────────────────────────────────────────────────
def build(sources, days, out_jsonl, image=None, image_offset=None, log=print):
    """Scrive la timeline ordinata. -> riepilogo {events, by_source, first, last}"""
    since_us = int((time.time() - days * 86400) * 1e6) if days else 0
    events = []
    wanted = set(sources)

    def add(name, fn):
        t0 = time.time()
        try:
            got = fn()
        except Exception as e:                       # una fonte che fallisce non blocca le altre
            log(f"[NEFI] source {name}: FAILED ({type(e).__name__}: {e})")
            return
        events.extend(got)
        log(f"[NEFI] source {name}: {len(got)} events in {time.time() - t0:.1f} s")

    if image:
        add("image", lambda: image_source(image, since_us, image_offset))
    if "filesystem" in wanted:
        add("filesystem", lambda: fs_source(since_us))
    if wanted & {"journal", "auth", "systemd"}:
        add("journal/auth/systemd", lambda: journal_source(since_us, wanted))
    for name, fn in (("logins", logins_source), ("packages", packages_source), ("shell", shell_source),
                     ("browser", browser_source), ("detection", detection_source), ("process", process_source)):
        if name in wanted:
            add(name, lambda fn=fn: fn(since_us))
    events.sort(key=lambda e: e["timestamp"])
    by_source = {}
    with open(out_jsonl, "w", encoding="utf-8") as f:
        for e in events:
            e["datetime"] = iso(e["timestamp"])
            by_source[e["source"]] = by_source.get(e["source"], 0) + 1
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return {"events": len(events), "by_source": by_source,
            "first": iso(events[0]["timestamp"]) if events else None,
            "last": iso(events[-1]["timestamp"]) if events else None}


def to_csv(jsonl, out_csv):
    """CSV per fogli di calcolo e per Timesketch (colonne: datetime, timestamp_desc, message, source)."""
    with open(jsonl, encoding="utf-8") as f, open(out_csv, "w", newline="", encoding="utf-8") as o:
        w = csv.writer(o)
        w.writerow(["datetime", "timestamp_desc", "message", "source"])
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            w.writerow([e.get("datetime"), e.get("timestamp_desc"), e.get("message"), e.get("source")])
