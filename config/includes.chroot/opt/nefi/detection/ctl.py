#!/usr/bin/env python3
"""NEFI OS - Detection: azioni dell'amministratore (root, lanciato dal Security Center con pkexec).

  ctl.py approve <id> [<id> ...]      approva modifiche in attesa: entrano nella baseline
  ctl.py approve-all                  approva tutte le modifiche in attesa
  ctl.py baseline-rebuild             nuova baseline dallo stato attuale (da usare con giudizio)
  ctl.py suppress-add <regola> <campo> <valore> [commento]   falso positivo: non avvisare piu' per questo caso
                                      (<campo> "-" = tutta la regola; nel valore * e ? sono caratteri jolly)
  ctl.py suppress-del <id>
  ctl.py rule-enable <id> | rule-disable <id>
  ctl.py rule-import <file.yml>       regola Sigma personale: controllata e copiata in /etc/nefi/detection/rules.d
  ctl.py rule-delete <id>             solo regole personali
  ctl.py verify                       controlla la catena di hash dei registri
  ctl.py scan                         chiede al motore una scansione immediata
Risposta a un avviso (sempre decisa dall'amministratore):
  ctl.py kill <id avviso>             termina il processo dell'avviso (solo se e' ancora lo stesso programma)
  ctl.py block-ip <ip> [id avviso]    blocca l'indirizzo in ingresso e in uscita (tabella nftables nefi_block)
  ctl.py unblock-ip <ip>
Impostazioni:
  ctl.py canary-setup | canary-remove file esca sorvegliati da auditd
  ctl.py forward-set <host> <porta> <tls|tcp> [file CA]   copia avvisi e audit su un server syslog esterno
  ctl.py forward-off
  ctl.py sigma-update | sigma-clear   regole SigmaHQ per Linux
  ctl.py sigma-auto <on|off>          aggiornamento settimanale automatico

Ogni azione e' scritta nel registro audit a sola aggiunta (/var/lib/nefi/detection/audit.jsonl) con il
nome dell'amministratore che l'ha fatta. Tutti gli argomenti sono validati qui: l'interfaccia non e' fidata.
"""
import os
import re
import subprocess
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine   # noqa: E402
import extras   # noqa: E402
import scan     # noqa: E402
import store    # noqa: E402

ID_RE = re.compile(r"[A-Za-z0-9_.-]{3,80}")
ITEM_RE = re.compile(r"[a-z_.]{3,40}:[^\x00-\x1f]{1,600}")


def fail(msg):
    print(f"[NEFI] ERROR: {msg}")
    sys.exit(1)


def poke_daemon():
    subprocess.run(["systemctl", "kill", "-s", "USR1", "nefi-detectd.service"], capture_output=True,
                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})


def current_value(item_id):
    """Valore ATTUALE dell'elemento, ricalcolato qui: non mi fido di quello scritto in pending.json."""
    cls, _, path = item_id.partition(":")
    if cls == "account":
        return scan.collect_accounts().get(item_id)
    if cls == "admin":
        return scan.collect_accounts().get(item_id)
    if cls == "listener":
        return scan.collect_listeners().get(item_id)
    return scan.file_value(path)


def sync_baseline(*paths):
    """Un file di configurazione del rilevamento cambiato DA QUI (azione gia' scritta nel registro audit)
    entra subito nella baseline: non deve comparire tra le modifiche da approvare."""
    base = store.load_baseline()
    if base is None:
        return
    for path in paths:
        key, val = f"integrity:{path}", scan.file_value(path)
        if val is None:
            base["items"].pop(key, None)
        else:
            base["items"][key] = val
    store.save_baseline(base)


def approve(ids):
    base = store.load_baseline()
    if base is None:
        fail("no baseline yet (the detection engine creates it at first start)")
    pending = {p["id"]: p for p in store.read_json(store.PENDING, [])}
    who, done = store.actor_name(), 0
    for item in ids:
        if not ITEM_RE.fullmatch(item) or item not in pending:
            print(f"[NEFI] skipped (not pending): {item}")
            continue
        old = base["items"].get(item)
        new = current_value(item)
        if new is None:
            base["items"].pop(item, None)
        else:
            base["items"][item] = new
        store.audit("approved", who, item=item, old=old, new=new, kind=pending[item].get("kind"))
        del pending[item]
        done += 1
        print(f"[NEFI] approved: {item}")
    store.save_baseline(base)
    store.write_json(store.PENDING, sorted(pending.values(), key=lambda p: p.get("first_seen", ""), reverse=True))
    print(f"[NEFI] {done} change(s) approved by {who}; baseline updated.")
    poke_daemon()


def baseline_rebuild():
    items = {}
    items.update(scan.collect_files())
    items.update(scan.collect_accounts())
    items.update(scan.collect_listeners())
    items.update(scan.collect_suid())
    old = store.load_baseline() or {}
    import time
    base = {"version": 1, "created": store.now_iso(), "created_ts": old.get("created_ts", time.time()),
            "rebuilt": store.now_iso(), "items": items, "verification": old.get("verification", {})}
    store.save_baseline(base)
    store.write_json(store.PENDING, [])
    store.audit("baseline-rebuilt", store.actor_name(), items=len(items), previous_items=len(old.get("items", {})))
    print(f"[NEFI] baseline rebuilt with {len(items)} items by {store.actor_name()}.")
    poke_daemon()


def suppress_add(rule_id, field, value, comment=""):
    if rule_id != "*" and not ID_RE.fullmatch(rule_id):
        fail("invalid rule id")
    if field == "-":
        field, value = "", ""
    elif field not in engine.SUPPRESS_FIELDS:
        fail(f"field must be one of: {', '.join(engine.SUPPRESS_FIELDS)}")
    if field and (not value or len(value) > 500 or re.search(r"[\x00-\x1f]", value)):
        fail("invalid value")
    if field and value.strip("*? ") == "":
        fail("the value cannot be only wildcards")
    if rule_id == "*" and not field:
        fail("refusing to suppress every rule")
    comment = re.sub(r"[\x00-\x1f]", " ", comment)[:200]
    sups = store.read_json(store.SUPPRESSIONS, [])
    entry = {"id": uuid.uuid4().hex[:10], "rule_id": rule_id, "field": field, "value": value,
             "comment": comment, "created": store.now_iso(), "by": store.actor_name()}
    sups.append(entry)
    store.write_json(store.SUPPRESSIONS, sups, mode=0o644, group_admin=False)
    store.audit("suppression-added", entry["by"], **{k: entry[k] for k in ("id", "rule_id", "field", "value", "comment")})
    sync_baseline(store.SUPPRESSIONS)
    print(f"[NEFI] suppression {entry['id']} added: rule {rule_id}" + (f", {field} = {value}" if field else " (whole rule)"))


def suppress_del(sid):
    sups = store.read_json(store.SUPPRESSIONS, [])
    keep = [s for s in sups if s.get("id") != sid]
    if len(keep) == len(sups):
        fail("suppression not found")
    store.write_json(store.SUPPRESSIONS, keep, mode=0o644, group_admin=False)
    store.audit("suppression-removed", store.actor_name(), id=sid)
    sync_baseline(store.SUPPRESSIONS)
    print(f"[NEFI] suppression {sid} removed.")


def rule_toggle(rule_id, enable):
    if not ID_RE.fullmatch(rule_id):
        fail("invalid rule id")
    known = {r.id for r in engine.load_rules()[0]}
    if rule_id not in known:
        fail("unknown rule")
    disabled = set(store.read_json(store.DISABLED, []))
    (disabled.discard if enable else disabled.add)(rule_id)
    store.write_json(store.DISABLED, sorted(disabled), mode=0o644, group_admin=False)
    store.audit("rule-enabled" if enable else "rule-disabled", store.actor_name(), rule=rule_id)
    sync_baseline(store.DISABLED)
    print(f"[NEFI] rule {rule_id} {'enabled' if enable else 'disabled'}.")


def rule_import(path):
    try:
        st = os.stat(path)
    except OSError as e:
        fail(str(e))
    if not os.path.isfile(path) or st.st_size > 256 * 1024:
        fail("the rule file must be a regular file smaller than 256 KB")
    try:
        docs = engine.load_documents(path)
    except (OSError, ValueError) as e:
        fail(f"cannot read the rule: {e}")
    if not docs:
        fail("no rule found in the file")
    ok = []
    for doc in docs:
        try:
            ok.append(engine.Rule(doc, "custom", path))
        except engine.RuleError as e:
            title = doc.get("title", "?") if isinstance(doc, dict) else "?"
            fail(f"rule '{title}' not accepted: {e}")
    builtin = {r.id for r in engine.load_rules(custom_dir="/nonexistent", sigma_dir="/nonexistent")[0]}
    for r in ok:
        if r.id in builtin or r.id.startswith("nefi-"):
            fail(f"id '{r.id}' is reserved for the built-in rules")
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", ok[0].id)[:80] + (".json" if path.endswith(".json") else ".yml")
    dest = os.path.join(store.RULES_D, name)
    with open(path, "rb") as f:
        data = f.read()
    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o644)
    os.chown(tmp, 0, 0)
    os.replace(tmp, dest)
    store.audit("rule-imported", store.actor_name(), rules=[r.id for r in ok], file=dest)
    sync_baseline(dest)
    print(f"[NEFI] imported {len(ok)} rule(s): " + ", ".join(r.title for r in ok))


def rule_delete(rule_id):
    if not ID_RE.fullmatch(rule_id):
        fail("invalid rule id")
    for r in engine.load_rules()[0]:
        if r.id == rule_id:
            if r.origin != "custom" or not os.path.realpath(r.path).startswith(store.RULES_D + "/"):
                fail("built-in rules cannot be deleted (disable them instead)")
            os.remove(r.path)
            store.audit("rule-deleted", store.actor_name(), rule=rule_id, file=r.path)
            sync_baseline(r.path)
            print(f"[NEFI] rule file {r.path} deleted.")
            return
    fail("unknown rule")


def verify():
    bad = False
    for name, path in (("alerts", store.ALERTS), ("audit", store.AUDIT)):
        ok, n, msg = store.verify_chain(path)
        print(f"[NEFI] {name} log: {'OK' if ok else 'TAMPERED'} - {msg}")
        bad |= not ok
    sys.exit(1 if bad else 0)


def find_alert(alert_id):
    if not re.fullmatch(r"[0-9a-f]{12}", alert_id or ""):
        fail("invalid alert id")
    import json
    for path in (store.ALERTS, store.ALERTS + ".1"):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if alert_id in line:
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if rec.get("id") == alert_id:
                            return rec
        except OSError:
            continue
    fail("alert not found")


def kill_process(alert_id):
    """Termina il processo di un avviso. Il PID da solo non basta (i PID vengono riusati):
    deve essere ancora lo stesso programma registrato nell'avviso."""
    import signal
    alert = find_alert(alert_id)
    ev = alert.get("event", {})
    pid, image = str(ev.get("pid", "")), str(ev.get("Image", ""))
    if not pid.isdigit() or int(pid) < 2 or int(pid) == os.getpid():
        fail("this alert has no process that can be terminated")
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        fail(f"process {pid} is no longer running")
    if image and exe.replace(" (deleted)", "") != image:
        fail(f"process {pid} is now a different program ({exe}), not {image}: nothing was terminated")
    try:
        with open(f"/proc/{pid}/stat") as f:
            ppid = f.read().rsplit(")", 1)[1].split()[1]
    except (OSError, IndexError):
        ppid = "?"
    if int(pid) == 1 or exe.endswith(("/systemd", "/sddm", "/kwin_wayland", "/kwin_x11")):
        fail("refusing to terminate a core system process")
    os.kill(int(pid), signal.SIGKILL)
    store.audit("process-killed", store.actor_name(), alert=alert_id, pid=pid, image=exe, ppid=ppid,
                rule=alert.get("rule_id"))
    print(f"[NEFI] process {pid} ({exe}) terminated by {store.actor_name()}.")


def block_ip(ip_text, alert_id=""):
    ip, why = extras.check_block_ip(ip_text)
    if not ip:
        fail(why)
    if alert_id and not re.fullmatch(r"[0-9a-f]{12}", alert_id):
        fail("invalid alert id")
    entries = [e for e in store.read_json(extras.BLOCKED, []) if e.get("ip") != ip]
    entries.append({"ip": ip, "by": store.actor_name(), "created": store.now_iso(), "alert": alert_id})
    store.write_json(extras.BLOCKED, entries, mode=0o644, group_admin=False)
    ok, msg = extras.apply_blocklist()
    if not ok:
        store.write_json(extras.BLOCKED, entries[:-1], mode=0o644, group_admin=False)
        fail(f"nftables refused the rule: {msg}")
    store.audit("ip-blocked", store.actor_name(), ip=ip, alert=alert_id)
    sync_baseline(extras.BLOCKED)
    print(f"[NEFI] {ip} blocked in both directions (table inet nefi_block).")


def unblock_ip(ip_text):
    entries = store.read_json(extras.BLOCKED, [])
    keep = [e for e in entries if e.get("ip") != ip_text.strip()]
    if len(keep) == len(entries):
        fail("address not in the block list")
    store.write_json(extras.BLOCKED, keep, mode=0o644, group_admin=False)
    ok, msg = extras.apply_blocklist()
    store.audit("ip-unblocked", store.actor_name(), ip=ip_text.strip())
    sync_baseline(extras.BLOCKED)
    print(f"[NEFI] {ip_text.strip()} unblocked." if ok else f"[NEFI] ERROR: {msg}")


def canary(setup):
    if setup:
        files = extras.canary_setup()
        store.audit("canaries-created", store.actor_name(), files=files)
        sync_baseline(extras.CANARY_RULES, extras.CANARIES)
        print(f"[NEFI] {len(files)} canary files are in place and watched:")
        for f in files:
            print(f"[NEFI]   {f}")
        print("[NEFI] Do not open them: reading one raises a critical alert.")
    else:
        files = extras.canary_remove()
        store.audit("canaries-removed", store.actor_name(), files=files)
        sync_baseline(extras.CANARY_RULES, extras.CANARIES)
        print(f"[NEFI] {len(files)} canary files removed.")


def forward(args):
    if args is None:
        store.write_json(extras.FORWARD, {"enabled": False}, mode=0o644, group_admin=False)
        store.audit("log-forwarding-disabled", store.actor_name())
        print("[NEFI] log forwarding disabled.")
    else:
        conf, why = extras.check_forward_target(*args)
        if not conf:
            fail(why)
        store.write_json(extras.FORWARD, conf, mode=0o644, group_admin=False)
        store.audit("log-forwarding-set", store.actor_name(), host=conf["host"], port=conf["port"], tls=conf["tls"])
        print(f"[NEFI] alerts and audit trail will be sent to {conf['host']}:{conf['port']} "
              f"({'TLS' if conf['tls'] else 'plain TCP - NOT encrypted'}). Check the status on the page in a few seconds.")
    sync_baseline(extras.FORWARD)


def sigma(cmd, arg=None):
    if cmd == "update":
        try:
            info = extras.sigma_update()
        except Exception as e:
            fail(f"Sigma update failed: {e}")
        store.audit("sigma-updated", store.actor_name(), rules=info["rules"], version=info["version"][:120])
        print(f"[NEFI] {info['rules']} SigmaHQ rules for Linux installed.")
        for reason, n in info["skipped"].items():
            print(f"[NEFI]   skipped {n}: {reason}")
    elif cmd == "clear":
        import shutil
        shutil.rmtree(engine.SIGMA_DIR, ignore_errors=True)
        try:
            os.remove(extras.SIGMA_INFO)
        except OSError:
            pass
        store.audit("sigma-removed", store.actor_name())
        print("[NEFI] SigmaHQ rules removed.")
    else:
        on = arg == "on"
        r = subprocess.run(["systemctl", "enable" if on else "disable", "--now", "nefi-sigma-update.timer"],
                           capture_output=True, text=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        if r.returncode != 0:
            fail(r.stderr.strip()[:200])
        store.audit("sigma-auto-update", store.actor_name(), enabled=on)
        print(f"[NEFI] weekly Sigma update {'enabled' if on else 'disabled'}.")


def main():
    if os.geteuid() != 0:
        sys.exit("NEFI: run as root (pkexec)")
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    store.ensure_dirs()
    cmd, args = a[0], a[1:]
    if cmd == "approve" and args:
        approve(args)
    elif cmd == "approve-all" and not args:
        approve([p["id"] for p in store.read_json(store.PENDING, [])])
    elif cmd == "baseline-rebuild" and not args:
        baseline_rebuild()
    elif cmd == "suppress-add" and len(args) in (3, 4):
        suppress_add(*args)
    elif cmd == "suppress-del" and len(args) == 1 and ID_RE.fullmatch(args[0]):
        suppress_del(args[0])
    elif cmd in ("rule-enable", "rule-disable") and len(args) == 1:
        rule_toggle(args[0], cmd == "rule-enable")
    elif cmd == "rule-import" and len(args) == 1:
        rule_import(args[0])
    elif cmd == "rule-delete" and len(args) == 1:
        rule_delete(args[0])
    elif cmd == "verify" and not args:
        verify()
    elif cmd == "kill" and len(args) == 1:
        kill_process(args[0])
    elif cmd == "block-ip" and len(args) in (1, 2):
        block_ip(*args)
    elif cmd == "unblock-ip" and len(args) == 1:
        unblock_ip(args[0])
    elif cmd in ("canary-setup", "canary-remove") and not args:
        canary(cmd == "canary-setup")
    elif cmd == "forward-set" and len(args) in (3, 4):
        forward(args)
    elif cmd == "forward-off" and not args:
        forward(None)
    elif cmd in ("sigma-update", "sigma-clear") and not args:
        sigma(cmd.split("-")[1])
    elif cmd == "sigma-auto" and len(args) == 1 and args[0] in ("on", "off"):
        sigma("auto", args[0])
    elif cmd == "scan" and not args:
        poke_daemon()
        print("[NEFI] scan requested.")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
