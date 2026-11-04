#!/usr/bin/env python3
"""NEFI OS - CrowdSec helper (eseguito come root: dal timer di export o via pkexec).

  helper.py export              scrive /var/lib/nefi/crowdsec/state.json (blocchi + avvisi),
                                leggibile dal gruppo sudo: il Security Center lo legge senza password
  helper.py unblock <ip>        toglie il blocco a un indirizzo
  helper.py allow <ip>          lo toglie e lo mette nella lista "sempre consentito"
  helper.py disallow <ip>       lo toglie dalla lista "sempre consentito"
  helper.py block <ip> <ore>    blocca a mano un indirizzo per <ore> ore (1-720)

Sicurezza: niente shell, indirizzi validati con il modulo ipaddress, file scritti in modo atomico.
"""
import grp
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import time

CSCLI = "/usr/bin/cscli"
STATE_DIR = "/var/lib/nefi/crowdsec"
STATE = os.path.join(STATE_DIR, "state.json")
ALLOW_FILE = "/etc/crowdsec/parsers/s02-enrich/nefi-allowlist.yaml"
ALLOW_DB = os.path.join(STATE_DIR, "allowlist.json")


def run(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(args, 1, "", str(e))


def cscli_json(*args):
    r = run([CSCLI, *args, "-o", "json"])
    if r.returncode != 0:
        return []
    try:
        data = json.loads(r.stdout or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def valid_ip(text):
    """Indirizzo IPv4/IPv6 singolo, normalizzato; altrimenti esce con errore."""
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        sys.exit(f"NEFI: invalid IP address: {text!r}")


def write_atomic(path, text, mode=0o640, group="sudo"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        gid = 0
    os.chown(tmp, 0, gid)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_allow():
    try:
        with open(ALLOW_DB) as f:
            data = json.load(f)
        return sorted({valid_ip(x) for x in data if isinstance(x, str)})
    except (OSError, ValueError):
        return []


def save_allow(ips):
    write_atomic(ALLOW_DB, json.dumps(sorted(set(ips)), indent=2))
    # lista "sempre consentito" nel formato whitelist di CrowdSec (file tolto se la lista e' vuota)
    ips = sorted(set(ips))
    if ips:
        lines = ["# NEFI OS - addresses always allowed (managed by NEFI Security Center)",
                 "name: nefi/allowlist",
                 "description: \"Addresses the NEFI user chose to always allow\"",
                 "whitelist:",
                 "  reason: \"allowed by the NEFI user\"",
                 "  ip:"] + [f"    - \"{ip}\"" for ip in ips]
        write_atomic(ALLOW_FILE, "\n".join(lines) + "\n", mode=0o644, group="root")
    elif os.path.exists(ALLOW_FILE):
        os.remove(ALLOW_FILE)
    run(["systemctl", "reload-or-restart", "crowdsec.service"], timeout=60)


def export():
    decisions = []
    for alert in cscli_json("decisions", "list"):
        for d in alert.get("decisions") or []:
            decisions.append({
                "id": d.get("id"),
                "ip": d.get("value"),
                "scope": d.get("scope"),
                "type": d.get("type"),
                "reason": d.get("scenario") or alert.get("scenario"),
                "origin": d.get("origin"),
                "duration": d.get("duration"),
                "country": (alert.get("source") or {}).get("cn"),
                "as_name": (alert.get("source") or {}).get("as_name"),
                "events": alert.get("events_count"),
                "created": alert.get("created_at"),
            })
    alerts = []
    for a in cscli_json("alerts", "list", "--limit", "50"):
        src = a.get("source") or {}
        alerts.append({
            "id": a.get("id"),
            "time": a.get("created_at"),
            "scenario": a.get("scenario"),
            "ip": src.get("ip") or src.get("value"),
            "country": src.get("cn"),
            "events": a.get("events_count"),
            "decisions": len(a.get("decisions") or []),
        })
    active = run(["systemctl", "is-active", "crowdsec.service"]).stdout.strip()
    bouncer = run(["systemctl", "is-active", "crowdsec-firewall-bouncer.service"]).stdout.strip()
    state = {"updated": time.strftime("%Y-%m-%dT%H:%M:%S"), "crowdsec": active, "bouncer": bouncer,
             "decisions": decisions, "alerts": alerts, "allowlist": load_allow()}
    write_atomic(STATE, json.dumps(state, indent=1))


def main():
    if os.geteuid() != 0:
        sys.exit("NEFI: run as root (pkexec)")
    if not os.path.exists(CSCLI):
        sys.exit("NEFI: CrowdSec is not installed")
    args = sys.argv[1:]
    if args == ["export"]:
        export()
        return
    if len(args) == 2 and args[0] in ("unblock", "allow", "disallow"):
        ip = valid_ip(args[1])
        if args[0] in ("unblock", "allow"):
            r = run([CSCLI, "decisions", "delete", "--ip", ip])
            print(r.stdout.strip() or r.stderr.strip())
        if args[0] == "allow":
            save_allow(load_allow() + [ip])
            print(f"NEFI: {ip} will always be allowed")
        if args[0] == "disallow":
            save_allow([x for x in load_allow() if x != ip])
            print(f"NEFI: {ip} removed from the allow list")
    elif len(args) == 3 and args[0] == "block":
        ip = valid_ip(args[1])
        if not args[2].isdigit() or not 1 <= int(args[2]) <= 720:
            sys.exit("NEFI: duration must be 1-720 hours")
        if ip in load_allow():
            sys.exit(f"NEFI: {ip} is in the allow list: remove it first")
        r = run([CSCLI, "decisions", "add", "--ip", ip, "--duration", f"{int(args[2])}h",
                 "--reason", "blocked manually from NEFI Security Center"])
        print(r.stdout.strip() or r.stderr.strip())
    else:
        sys.exit(__doc__)
    export()


if __name__ == "__main__":
    main()
