#!/usr/bin/env python3
"""Test dell'Incident Response: casi, cronologia concatenata, playbook, quarantena, indicatori, rapporto.

    python3 tests/test_response.py          (dalla cartella del repo, da utente normale: NON come root)
"""
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "config", "includes.chroot")
TMP = tempfile.mkdtemp(prefix="nefi-ir-test-")
os.environ["NEFI_IR_BASE"] = os.path.join(TMP, "ir")
os.environ["NEFI_QUARANTINE"] = os.path.join(TMP, "quarantine")
os.environ["NEFI_IR_PLAYBOOKS"] = os.path.join(ROOT, "usr", "share", "nefi", "ir", "playbooks")
sys.path.insert(0, os.path.join(ROOT, "opt", "nefi", "ir"))
sys.path.insert(0, os.path.join(ROOT, "usr", "lib", "nefi", "modules"))
import irlib as ir       # noqa: E402
import ir_report         # noqa: E402


@unittest.skipIf(os.geteuid() == 0, "run as a normal user: as root the test paths are ignored on purpose")
class Base(unittest.TestCase):
    def setUp(self):
        ir.ensure_dirs()


class CaseTest(Base):
    def test_lifecycle_and_timeline(self):
        c = ir.open_case("high", "malware", "  Unknown   miner in /tmp ", "Found by a detection alert")
        cid = c["id"]
        self.assertRegex(cid, ir.CASE_RE)
        self.assertEqual(c["title"], "Unknown miner in /tmp")
        ir.set_field(cid, "status", "investigating")
        ir.set_field(cid, "status", "investigating")            # nessun cambio: nessuna riga in piu'
        ir.set_field(cid, "severity", "critical")
        ir.add_note(cid, "Started from a cron job of user bob")
        ir.link(cid, "evidence", "NEFI-EV-20261115-101500-ab12")
        tl = ir.read_chain(ir.timeline_path(cid))
        self.assertEqual([r["action"] for r in tl], ["incident-opened", "status-changed", "severity-changed", "note",
                                                    "linked"])
        self.assertEqual(tl[2]["details"], {"old": "high", "new": "critical"})
        self.assertTrue(ir.verify_chain(ir.timeline_path(cid))[0])
        self.assertTrue(ir.verify_chain(ir.ACTIONS)[0])
        index = ir.read_json(os.path.join(ir.CASES, "index.json"), [])
        self.assertEqual([(x["severity"], x["status"]) for x in index if x["id"] == cid], [("critical", "investigating")])
        for bad in (("status", "closed"), ("status", "whatever"), ("severity", "extreme"), ("title", "x")):
            with self.assertRaises(ir.IRError):
                ir.set_field(cid, *bad)

    def test_invalid_input(self):
        for args in (("extreme", "malware", "t"), ("low", "aliens", "t"), ("low", "other", ""),
                     ("low", "other", "bad\x07title")):
            with self.assertRaises(ir.IRError):
                ir.open_case(*args)
        for cid in ("../../etc/passwd", "NEFI-INC-1", "", None):
            with self.assertRaises(ir.IRError):
                ir.case_path(cid)

    def test_tampered_timeline_is_detected(self):
        cid = ir.open_case("low", "other", "Chain test")["id"]
        for i in range(3):
            ir.add_note(cid, f"note {i}")
        path = ir.timeline_path(cid)
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        with open(path, "w", encoding="utf-8") as f:              # una riga tolta
            f.write("\n".join(lines[:2] + lines[3:]) + "\n")
        self.assertFalse(ir.verify_chain(path)[0])
        with open(path, "w", encoding="utf-8") as f:              # una riga cambiata
            f.write("\n".join([lines[0], lines[1].replace("note 0", "note X")] + lines[2:]) + "\n")
        self.assertFalse(ir.verify_chain(path)[0])
        with open(path, "w", encoding="utf-8") as f:              # la prima riga tolta
            f.write("\n".join(lines[1:]) + "\n")
        self.assertFalse(ir.verify_chain(path)[0])

    def test_close_needs_the_recovery_checklist(self):
        cid = ir.open_case("medium", "other", "Close test")["id"]
        with self.assertRaises(ir.IRError) as e:
            ir.close_case(cid, "done")
        self.assertIn("recovery checklist", str(e.exception))
        with self.assertRaises(ir.IRError):                      # una voce automatica non si spunta a mano
            ir.recovery_set(cid, "system_integrity", "done")
        for rid in ir.RECOVERY_IDS:
            ir.recovery_set(cid, rid, "na" if rid in ir.RECOVERY_AUTO else "done")
        case = ir.load_case(cid)
        self.assertEqual(set(ir.recovery_state(case).values()), {"done", "na"})
        ir.recovery_set(cid, "isolation_released", "todo")      # torna automatica: serve la verifica
        self.assertEqual(ir.recovery_state(ir.load_case(cid))["isolation_released"], "todo")
        case = ir.load_case(cid)
        case["auto"] = {"isolation_released": True}
        ir.save_case(case)
        self.assertEqual(ir.recovery_state(ir.load_case(cid))["isolation_released"], "done")
        ir.close_case(cid, "False alarm, documented")
        self.assertEqual(ir.load_case(cid)["status"], "closed")
        for fn in (lambda: ir.set_field(cid, "severity", "low"), lambda: ir.close_case(cid, "again")):
            with self.assertRaises(ir.IRError):
                fn()


class PlaybookTest(Base):
    def test_builtin_playbooks_are_valid(self):
        books, errors = ir.load_playbooks()
        self.assertEqual(errors, [])
        self.assertEqual(set(books), {"malware", "account-compromise", "network-intrusion", "data-exposure", "generic"})
        covered = {c for b in books.values() for c in b["categories"]}
        self.assertEqual(covered, set(ir.CATEGORIES))            # ogni categoria ha un playbook suggerito
        for b in books.values():
            for s in b["steps"]:
                self.assertTrue(s["help"], f"{b['id']}/{s['id']} has no help text")
                self.assertIn(s["action"], ("",) + ir.ACTIONS_ALLOWED)

    def test_validation_refuses_unknown_actions(self):
        ok = {"id": "x", "steps": [{"id": "a", "title": "A", "action": "isolate"}]}
        self.assertEqual(ir.validate_playbook(ok)["steps"][0]["action"], "isolate")
        for bad in ({"id": "x", "steps": [{"id": "a", "title": "A", "action": "rm -rf /"}]},
                    {"id": "x", "steps": [{"id": "a", "title": "A"}, {"id": "a", "title": "B"}]},
                    {"id": "x", "steps": []}, {"id": "Bad Id", "steps": [{"id": "a", "title": "A"}]},
                    {"id": "x", "steps": [{"id": "a"}]}, [], None):
            with self.assertRaises(ir.IRError):
                ir.validate_playbook(bad)

    def test_progress(self):
        cid = ir.open_case("high", "malware", "Playbook test")["id"]
        pb = ir.load_playbooks()[0]["malware"]
        with self.assertRaises(ir.IRError):
            ir.step_set(cid, "classify", "done", pb=pb)          # playbook non ancora avviato
        ir.start_playbook(cid, pb)
        ir.step_set(cid, "classify", "done", pb=pb)
        with self.assertRaises(ir.IRError):
            ir.step_set(cid, "isolate", "skipped", pb=pb)        # saltare richiede il motivo
        ir.step_set(cid, "isolate", "skipped", "blocking the address was enough", pb=pb)
        with self.assertRaises(ir.IRError):
            ir.step_set(cid, "not-a-step", "done", pb=pb)
        self.assertEqual(ir.playbook_progress(ir.load_case(cid), pb), (2, len(pb["steps"])))
        actions = [r["action"] for r in ir.read_chain(ir.timeline_path(cid))]
        self.assertEqual(actions.count("playbook-step"), 2)


class ContainmentTest(Base):
    def test_quarantine_and_restore(self):
        d = tempfile.mkdtemp(dir=TMP)
        path = os.path.join(d, "dropper.bin")
        with open(path, "wb") as f:
            f.write(b"#!/bin/sh\necho not really malware\n")
        os.chmod(path, 0o755)
        os.utime(path, (1700000000, 1700000000))
        digest = ir.sha256_file(path)
        e = ir.quarantine(path, reason="test")
        self.assertFalse(os.path.exists(path))
        self.assertEqual(e["sha256"], digest)
        self.assertEqual(os.stat(e["stored"]).st_mode & 0o777, 0)
        self.assertEqual(len(ir.read_json(ir.QINDEX, [])), 1)
        open(path, "w").close()                                  # qualcuno ha rimesso un file li'
        with self.assertRaises(ir.IRError):
            ir.quarantine_restore(e["id"])
        os.unlink(path)
        ir.quarantine_restore(e["id"])
        st = os.stat(path)
        self.assertEqual((st.st_mode & 0o777, int(st.st_mtime), ir.sha256_file(path)), (0o755, 1700000000, digest))
        self.assertEqual(ir.read_json(ir.QINDEX, []), [])
        e = ir.quarantine(path)
        os.chmod(e["stored"], 0o600)
        with open(e["stored"], "ab") as f:                       # copia manomessa: non si ripristina
            f.write(b"x")
        with self.assertRaises(ir.IRError):
            ir.quarantine_restore(e["id"])
        ir.quarantine_delete(e["id"])
        self.assertFalse(os.path.exists(e["stored"]))

    def test_quarantine_refuses_dangerous_paths(self):
        d = tempfile.mkdtemp(dir=TMP)
        link = os.path.join(d, "link")
        os.symlink("/etc/passwd", link)
        for bad in ("relative/path", link, d, "/proc/self/status", "/opt/nefi/ir/irctl.py", "/nonexistent/file",
                    "/var/lib/dpkg/status"):
            with self.assertRaises(ir.IRError):
                ir.quarantine_check(bad)

    def test_ioc_validation(self):
        self.assertEqual(ir.check_ioc("ip", " 2001:DB8::1 "), "2001:db8::1")
        self.assertEqual(ir.check_ioc("domain", "Evil.Example.COM."), "evil.example.com")
        self.assertEqual(ir.check_ioc("sha256", "A" * 64), "a" * 64)
        for kind, bad in (("ip", "1.2.3"), ("ip", "1.2.3.4; reboot"), ("domain", "localhost"), ("domain", "a b.com"),
                          ("domain", "evil.com\n0.0.0.0 debian.org"), ("domain", "security.debian.org"),
                          ("domain", "-x.com"), ("sha256", "abc"), ("url", "http://x")):
            with self.assertRaises(ir.IRError):
                ir.check_ioc(kind, bad)

    def test_hosts_block_is_rewritten_not_appended(self):
        base = "127.0.0.1 localhost\n10.0.0.2 nas   # mine\n"
        one = ir.render_hosts(base, ["evil.example.com"])
        self.assertTrue(one.startswith(base))
        self.assertIn("0.0.0.0 evil.example.com\n:: evil.example.com\n", one)
        two = ir.render_hosts(one, ["b.example.net", "evil.example.com", "b.example.net"])
        self.assertEqual(two.count(ir.HOSTS_BEGIN), 1)
        self.assertEqual(two.count("b.example.net"), 2)
        self.assertEqual(ir.render_hosts(two, []), base)        # tolti tutti: file come prima

    def test_process_identity_and_protection(self):
        p = subprocess.Popen(["sleep", "30"])
        try:
            info = ir.proc_info(p.pid)
            self.assertEqual((info["name"], info["ppid"]), ("sleep", os.getpid()))
            self.assertEqual(ir.parse_target(f"{p.pid}:{info['starttime']}"), (p.pid, info["starttime"]))
            self.assertEqual(ir.protected_reason(info), "")
            self.assertIn("Security Center", ir.protected_reason(info, own_pids={p.pid}))
        finally:
            p.kill()
            p.wait()
        with self.assertRaises(ir.IRError):
            ir.proc_info(p.pid)
        self.assertTrue(ir.protected_reason(ir.proc_info(1)))
        self.assertTrue(ir.protected_reason({"pid": 900, "ppid": 1, "name": "sddm", "exe": "/usr/bin/sddm"}))
        self.assertTrue(ir.protected_reason({"pid": 77, "ppid": 2, "name": "kworker/0:1", "exe": ""}))
        for bad in ("123", "abc:1", "1:2:3", "", "12:-4"):
            with self.assertRaises(ir.IRError):
                ir.parse_target(bad)

    def test_sweep_finds_files_by_hash(self):
        d = tempfile.mkdtemp(dir=TMP)
        for name, data in (("a", b"one"), ("b", b"two"), ("c", b"one")):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        os.link(os.path.join(d, "a"), os.path.join(d, "a-hardlink"))
        want = ir.sha256_file(os.path.join(d, "a"))
        found = ir.sweep([want], sorted(os.path.join(d, n) for n in os.listdir(d)) + ["/nonexistent"])
        self.assertEqual(sorted(os.path.basename(p) for p, _h in found), ["a", "c"])   # lo stesso file una volta sola


class ReportTest(Base):
    def test_report_contains_the_facts_and_escapes_html(self):
        cid = ir.open_case("high", "malware", "Miner <script>alert(1)</script>", "desc")["id"]
        pb = ir.load_playbooks()[0]["malware"]
        ir.start_playbook(cid, pb)
        ir.step_set(cid, "classify", "done", pb=pb)
        ir.record("host-isolated", cid, mode="full")
        ir.record("process-terminated", cid, pid=4242, name="xmrig", sha256="ab" * 32)
        ir.add_note(cid, "Root cause: weak password")
        case = ir.load_case(cid)
        state = ir.recovery_state(case)
        html = ir_report.build(case, ir.read_chain(ir.timeline_path(cid)),
                               [{"evidence_id": "NEFI-EV-20261115-101500-ab12", "kind": "live-collection",
                                 "collected_utc": "2026-11-15T10:15:00Z", "operator": "E. G.", "size": 1234, "signed": True}],
                               pb, [(label, state[rid]) for rid, label, _a, _h in ir.RECOVERY],
                               {"categories": ir.CATEGORIES}, True, "nefi-test")
        for text in (cid, "HIGH", "Malware", "Host isolated from the network", "xmrig", "NEFI-EV-20261115-101500-ab12",
                     "Root cause: weak password", "Confirm and classify", "NOT DONE", "integrity verified"):
            self.assertIn(text, html)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("WARNING", ir_report.build(case, [], [], None, [], {}, False))
        self.assertEqual(ir_report.duration("2026-11-15T10:00:00+0100", "2026-11-16T12:30:00+0100"), "1 d 2 h")
        self.assertEqual(ir_report.duration("2026-11-15T10:00:00+0100", "2026-11-15T10:07:00+0100"), "7 min")
        self.assertEqual(ir_report.duration("x", None), "")


class IsolationScriptTest(unittest.TestCase):
    """Gli script di isolamento: sintassi e rifiuto degli argomenti non validi (senza toccare la rete)."""
    IR = os.path.join(ROOT, "opt", "nefi", "ir")

    def test_syntax(self):
        for name in ("activate.sh", "deactivate.sh", "confirm.sh", "boot-check.sh", "state.sh"):
            self.assertEqual(subprocess.run(["bash", "-n", os.path.join(self.IR, name)]).returncode, 0, name)
        self.assertEqual(subprocess.run(["bash", "-n", os.path.join(ROOT, "usr", "bin", "nefi-ir-recover")]).returncode, 0)

    def test_arguments_are_validated_before_anything_happens(self):
        with open(os.path.join(self.IR, "activate.sh"), encoding="utf-8") as f:
            script = f.read()
        head = script[:script.index('echo "[NEFI-IR] Activating')]      # solo la parte che legge gli argomenti
        self.assertNotIn("nft", head.replace("nftables", ""))
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(head.replace(". /opt/nefi/ir/state.sh", ":") + '\necho "OK allow=$ALLOW rollback=$ROLLBACK case=$CASE"\n')
        try:
            run = lambda *a: subprocess.run(["bash", f.name, *a], capture_output=True, text=True)   # noqa: E731
            self.assertEqual(run("--allow", "10.0.0.7", "--rollback", "15", "--case", "NEFI-INC-20261115-ab12").stdout.strip(),
                             "OK allow=10.0.0.7 rollback=15 case=NEFI-INC-20261115-ab12")
            self.assertIn("allow=2001:db8::1 ", run("--allow", "2001:DB8:0::1").stdout)
            for bad in (["--allow", "10.0.0.7 accept; drop"], ["--allow", "0.0.0.0"], ["--allow", "host.example"],
                        ["--rollback", "7"], ["--rollback", "15; reboot"], ["--case", "x; reboot"], ["--what"],
                        ["--allow", "$(reboot)"]):
                r = run(*bad)
                self.assertNotEqual(r.returncode, 0, bad)
                self.assertNotIn("OK allow", r.stdout, bad)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main(verbosity=1)
