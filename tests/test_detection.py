#!/usr/bin/env python3
"""Test del motore di rilevamento: regole Sigma, soppressioni, correlazione, MITRE, audit, catena di hash.

    python3 tests/test_detection.py        (dalla cartella del repo, non serve root)
"""
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "config", "includes.chroot")
sys.path.insert(0, os.path.join(ROOT, "opt", "nefi", "detection"))
import engine    # noqa: E402
import store     # noqa: E402
import detectd   # noqa: E402

RULES = os.path.join(ROOT, "usr", "share", "nefi", "detection", "rules")


def rule(text):
    import yaml
    return engine.Rule(yaml.safe_load(text))


class BuiltinRules(unittest.TestCase):
    def setUp(self):
        self.rules, self.errors = engine.load_rules(RULES, "/nonexistent", "/nonexistent")
        self.by_id = {r.id: r for r in self.rules}

    def test_all_builtin_rules_load(self):
        self.assertEqual(self.errors, [])
        self.assertGreaterEqual(len(self.rules), 40)

    def test_ids_unique_and_prefixed(self):
        self.assertTrue(all(r.id.startswith("nefi-") for r in self.rules))

    def test_non_silent_rules_have_mitre(self):
        missing = [r.id for r in self.rules if not r.silent and not r.correlation
                   and not (r.mitre["tactics"] or r.mitre["techniques"])
                   and not r.doc.get("nefi_mitre_from_tags") and "persistence" not in r.id]
        self.assertEqual(missing, [])

    def test_correlations_reference_existing_rules(self):
        for r in self.rules:
            if r.correlation:
                for rid in r.correlation["rules"]:
                    self.assertTrue(rid == "*" or rid in self.by_id, f"{r.id} -> {rid}")

    def ev(self, **kw):
        return kw

    def test_service_shell(self):
        r = self.by_id["nefi-proc-service-shell"]
        e = {"category": "process", "source": "auditd", "Image": "/usr/bin/dash", "ParentImage": "/usr/sbin/nginx"}
        self.assertTrue(r.applies(e) and r.match(e))
        e["ParentImage"] = "/usr/bin/konsole"
        self.assertFalse(r.match(e))

    def test_root_shell_needs_unprivileged_parent(self):
        r = self.by_id["nefi-proc-root-shell"]
        base = {"category": "process", "source": "auditd", "Image": "/usr/bin/bash", "User": "root"}
        self.assertFalse(r.match(dict(base)))                                             # parent unknown
        self.assertFalse(r.match(dict(base, ParentUser="anna", ParentImage="/usr/bin/sudo")))
        self.assertFalse(r.match(dict(base, ParentUser="root", ParentImage="/usr/bin/python3")))
        self.assertTrue(r.match(dict(base, ParentUser="anna", ParentImage="/home/anna/tool")))

    def test_cred_read_filters_auth_programs(self):
        r = self.by_id["nefi-audit-cred-read"]
        e = {"source": "auditd", "category": "file", "AuditKey": "nefi_cred", "Success": "yes", "Image": "/usr/sbin/unix_chkpwd"}
        self.assertFalse(r.match(e))
        e["Image"] = "/usr/bin/cat"
        self.assertTrue(r.applies(e) and r.match(e))

    def test_integrity_package_verified_is_not_alerted(self):
        r = self.by_id["nefi-state-integrity-modified"]
        e = {"source": "nefi", "category": "state", "ClassGroup": "integrity", "EventType": "item_modified",
             "PackageVerified": "true"}
        self.assertFalse(r.match(e))
        e["PackageVerified"] = "false"
        self.assertTrue(r.match(e))

    def test_dns_long_name(self):
        r = self.by_id["nefi-dns-long-name"]
        e = {"source": "suricata", "category": "dns", "DnsType": "query", "LongestLabel": 63, "QueryLength": 80}
        self.assertTrue(r.applies(e) and r.match(e))
        e["LongestLabel"] = 12
        self.assertFalse(r.match(e))


class SigmaSubset(unittest.TestCase):
    def test_modifiers_and_condition(self):
        r = rule("""
title: t
id: my-rule-1
level: high
tags: [attack.execution, attack.t1059.004]
logsource: {product: linux, category: process_creation}
detection:
  sel_a: {'Image|endswith': [/curl, /wget]}
  sel_b: {'CommandLine|contains|all': ['-o', '/tmp/']}
  sel_re: {'CommandLine|re': 'https?://\\d+\\.\\d+'}
  filter: {User: backup}
  condition: (sel_a and sel_b) or (1 of sel_r*) and not filter
""")
        self.assertTrue(r.match({"Image": "/usr/bin/curl", "CommandLine": "curl -o /tmp/x http://a"}))
        self.assertFalse(r.match({"Image": "/usr/bin/curl", "CommandLine": "curl http://example.org"}))
        self.assertTrue(r.match({"Image": "/usr/bin/python3", "CommandLine": "x http://10.0.0.1/a"}))
        self.assertEqual(r.mitre["tactics"][0]["id"], "TA0002")
        self.assertEqual(r.mitre["techniques"][0], {"id": "T1059.004", "name": "Unix Shell"})

    def test_wildcards_cidr_numbers_keywords(self):
        r = rule("""
title: t
id: my-rule-2
logsource: {product: linux, category: network_connection}
detection:
  net: {'DestinationIp|cidr': '10.0.0.0/8', 'DestinationPort|gte': 1024}
  wild: {Image: '/opt/*/bin/agent?'}
  keywords: ['very odd string']
  condition: net or wild or keywords
""")
        self.assertTrue(r.match({"DestinationIp": "10.2.3.4", "DestinationPort": "4444"}))
        self.assertFalse(r.match({"DestinationIp": "10.2.3.4", "DestinationPort": "443"}))
        self.assertTrue(r.match({"Image": "/opt/acme/bin/agent1"}))
        self.assertTrue(r.match({"CommandLine": "a VERY odd string b"}))

    def test_rejected_rules(self):
        for bad in (
            "title: t\nid: x1x\nlogsource: {product: windows, category: process_creation}\ndetection: {s: {a: b}, condition: s}",
            "title: t\nid: x2x\nlogsource: {product: linux, category: process_creation}\ndetection: {s: {a: b}, condition: 's | count() > 5'}",
            "title: t\nid: x3x\nlogsource: {product: linux, category: process_creation}\ndetection: {s: {a: b}, condition: s and nope}",
            "title: t\nid: 'bad id'\nlogsource: {product: linux, category: process_creation}\ndetection: {s: {a: b}, condition: s}",
            "title: t\nid: x5x\nlogsource: {product: linux, category: process_creation}\ndetection: {s: {'a|base64': b}, condition: s}",
        ):
            with self.assertRaises(engine.RuleError):
                rule(bad)


class SuppressionAndCorrelation(unittest.TestCase):
    def test_suppression(self):
        sup = [{"id": "s1", "rule_id": "r1", "field": "Image", "value": "/usr/bin/backup*"},
               {"id": "s2", "rule_id": "r2", "field": "", "value": ""}]
        self.assertEqual(engine.suppressed_by("r1", {"Image": "/usr/bin/backup-tool"}, sup), "s1")
        self.assertIsNone(engine.suppressed_by("r1", {"Image": "/usr/bin/other"}, sup))
        self.assertIsNone(engine.suppressed_by("r9", {"Image": "/usr/bin/backup-tool"}, sup))
        self.assertEqual(engine.suppressed_by("r2", {}, sup), "s2")

    def corr(self, text):
        return engine.Correlator([rule(text)])

    def test_event_count(self):
        c = self.corr("title: c\nid: corr-1\ncorrelation: {type: event_count, rules: [a], group-by: [User], timespan: 1m, condition: {gte: 3}}")
        self.assertEqual(c.feed("a", {"User": "u"}, 100), [])
        self.assertEqual(c.feed("a", {"User": "other"}, 101), [])
        self.assertEqual(c.feed("a", {"User": "u"}, 102), [])
        self.assertEqual(len(c.feed("a", {"User": "u"}, 103)), 1)
        self.assertEqual(c.feed("a", {"User": "u"}, 104), [])            # non ripete subito

    def test_event_count_outside_window(self):
        c = self.corr("title: c\nid: corr-2\ncorrelation: {type: event_count, rules: [a], timespan: 10s, condition: {gte: 2}}")
        c.feed("a", {}, 100)
        self.assertEqual(c.feed("a", {}, 200), [])

    def test_value_count_and_temporal(self):
        c = self.corr("title: c\nid: corr-3\ncorrelation: {type: value_count, rules: [a], timespan: 1m, condition: {field: Port, gte: 3}}")
        c.feed("a", {"Port": "1"}, 1)
        c.feed("a", {"Port": "1"}, 2)
        self.assertEqual(c.feed("a", {"Port": "2"}, 3), [])
        self.assertEqual(len(c.feed("a", {"Port": "3"}, 4)), 1)
        t = self.corr("title: c\nid: corr-4\ncorrelation: {type: temporal, rules: [a, b], timespan: 1m}")
        self.assertEqual(t.feed("a", {}, 1), [])
        self.assertEqual(len(t.feed("b", {}, 2)), 1)

    def test_mitre_from_falco_tags(self):
        m = engine.mitre_from_tags(["host", "mitre_persistence", "T1543.002", "container"])
        self.assertEqual(m["tactics"], [{"id": "TA0003", "name": "Persistence"}])
        self.assertEqual(m["techniques"][0]["id"], "T1543.002")


class AuditParsing(unittest.TestCase):
    LINES = [
        'type=SYSCALL msg=audit(1731312000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55 a1=7f items=2 '
        'ppid=1234 pid=1240 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 '
        'tty=pts0 ses=3 comm="mytool" exe="/tmp/my tool" subj=unconfined key="nefi_exec"',
        'type=EXECVE msg=audit(1731312000.123:456): argc=3 a0="mytool" a1=2D2D666C61672076616C7565 a2="x"',
        'type=CWD msg=audit(1731312000.123:456): cwd="/home/anna"',
        'type=PATH msg=audit(1731312000.123:456): item=0 name="/tmp/my tool" inode=1 nametype=NORMAL',
        'type=SYSCALL msg=audit(1731312001.000:457): arch=c000003e syscall=257 success=yes exit=3 ppid=1 pid=999 '
        'auid=4294967295 uid=0 gid=0 euid=0 tty=(none) comm="cat" exe="/usr/bin/cat" key="nefi_cred"',
        'type=CWD msg=audit(1731312001.000:457): cwd="/"',
        'type=PATH msg=audit(1731312001.000:457): item=0 name="/etc/shadow" inode=2 nametype=NORMAL',
    ]

    def events(self):
        asm, raw = detectd.AuditAssembler(), []
        for l in self.LINES:
            raw += asm.feed(l)
        raw += asm.flush(older_than=0)
        return [e for e in (detectd.audit_to_event(r) for r in raw) if e]

    def test_exec_and_file_events(self):
        evs = self.events()
        self.assertEqual(len(evs), 2)
        p = next(e for e in evs if e["category"] == "process")
        self.assertEqual(p["Image"], "/tmp/my tool")
        self.assertEqual(p["CommandLine"], "mytool --flag value x")       # argomento esadecimale decodificato
        self.assertEqual((p["pid"], p["ppid"], p["EffectiveUser"]), ("1240", "1234", "root"))
        f = next(e for e in evs if e["category"] == "file")
        self.assertEqual((f["TargetFilename"], f["AuditKey"], f["LoginUser"]), ("/etc/shadow", "nefi_cred", "unset"))

    def test_garbage_is_ignored(self):
        self.assertIsNone(detectd.parse_audit_line("not an audit line"))


class ChainLog(unittest.TestCase):
    def test_chain_detects_tampering(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "log.jsonl")
        log = store.ChainLog(path)
        for i in range(5):
            log.append({"n": i})
        self.assertTrue(store.verify_chain(path)[0])
        log2 = store.ChainLog(path)                      # riapertura: la catena continua
        log2.append({"n": 5})
        self.assertEqual(store.verify_chain(path)[:2], (True, 6))
        with open(path) as f:
            lines = f.read().splitlines()
        os.system(f"chattr -a {path} 2>/dev/null")
        with open(path, "w") as f:
            f.write("\n".join(lines[:2] + lines[3:]) + "\n")               # tolgo un record
        self.assertFalse(store.verify_chain(path)[0])
        rec = json.loads(lines[1])
        rec["n"] = 99
        with open(path, "w") as f:
            f.write("\n".join([lines[0], json.dumps(rec, sort_keys=True)] + lines[2:]) + "\n")
        self.assertFalse(store.verify_chain(path)[0])                        # cambio un record

class Extras(unittest.TestCase):
    def setUp(self):
        import extras
        self.x = extras

    def test_block_ip_validation(self):
        self.x.own_addresses = lambda: {"192.168.1.10", "192.168.1.1"}
        self.assertEqual(self.x.check_block_ip(" 203.0.113.7 ")[0], "203.0.113.7")
        self.assertEqual(self.x.check_block_ip("2001:DB8::5")[0], "2001:db8::5")
        for bad in ("127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "192.168.1.1", "192.168.1.10", "not-an-ip",
                    "1.2.3.4; nft flush ruleset", "1.2.3.0/24"):
            self.assertIsNone(self.x.check_block_ip(bad)[0], bad)

    def test_forward_target_validation(self):
        ok, _ = self.x.check_forward_target("logs.example.org", "6514", "tls")
        self.assertEqual((ok["host"], ok["port"], ok["tls"]), ("logs.example.org", 6514, True))
        for bad in (("bad host", "6514", "tls"), ("h", "0", "tls"), ("h", "70000", "tls"), ("h", "514", "udp"),
                    ("h;x", "514", "tcp"), ("h", "514", "tls", "/nonexistent/ca.pem")):
            self.assertIsNone(self.x.check_forward_target(*bad)[0], bad)

    def test_syslog_frame(self):
        frame = self.x.syslog_frame({"level": "critical", "ts": "2026-11-12T10:00:00+0100", "title": "t"}, "host1", "ALERT")
        size, _, msg = frame.partition(b" ")
        self.assertEqual(int(size), len(msg))
        self.assertTrue(msg.startswith(b"<106>1 2026-11-12T10:00:00+01:00 host1 nefi-detectd - ALERT - @cee:{"))

    def test_sigma_select_keeps_only_usable_linux_rules(self):
        import io
        import zipfile
        good = ("title: Good\nid: 11111111-2222-3333-4444-555555555555\nstatus: test\nlevel: high\n"
                "logsource: {product: linux, category: process_creation}\n"
                "detection: {sel: {'Image|endswith': /x}, condition: sel}\n")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("version.txt", "Release Date: test")
            z.writestr("rules/linux/process_creation/good.yml", good)
            z.writestr("rules/linux/process_creation/low.yml", good.replace("high", "low").replace("1111", "2222"))
            z.writestr("rules/linux/process_creation/old.yml", good.replace("status: test", "status: deprecated"))
            z.writestr("rules/linux/process_creation/agg.yml", good.replace("condition: sel", "condition: 'sel | count() > 3'"))
            z.writestr("rules/linux/auditd/raw.yml", good)                    # categoria non usabile dal motore
            z.writestr("rules/windows/process_creation/win.yml", good)
            z.writestr("rules/linux/process_creation/../../../evil.yml", good)  # percorso malevolo
        keep, skipped, version = self.x.sigma_select(buf.getvalue())
        self.assertEqual(list(keep), ["process_creation__good.yml"])
        self.assertEqual(sum(skipped.values()), 3)
        self.assertEqual(version, "Release Date: test")


if __name__ == "__main__":
    unittest.main(verbosity=1)
