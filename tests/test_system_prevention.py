#!/usr/bin/env python3
"""Test di System e Prevention: punti per controllo, storico del punteggio, priorita' delle CVE, annulla correzioni.

    python3 tests/test_system_prevention.py        (dalla cartella del repo, non serve root)
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "config", "includes.chroot")


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


collect = load("nefi_collect", "opt/nefi/system/collect.py")
fix = load("nefi_fix", "opt/nefi/prevention/fix.py")


class Gains(unittest.TestCase):
    def test_gains_add_up_to_the_missing_points(self):
        res = [{"id": "a", "status": "pass", "weight": 5}, {"id": "b", "status": "fail", "weight": 3},
               {"id": "c", "status": "warn", "weight": 2}, {"id": "d", "status": "unknown", "weight": 10}]
        collect.add_gains(res)
        self.assertNotIn("gain", res[0])
        self.assertNotIn("gain", res[3])                      # non verificabile: non conta
        self.assertEqual(res[1]["gain"], 30.0)                # 3 su 10 verificabili
        self.assertEqual(res[2]["gain"], 10.0)                # avviso = meta' del peso
        score = collect.score_of(res)["score"]
        self.assertEqual(round(score + res[1]["gain"] + res[2]["gain"]), 100)


class History(unittest.TestCase):
    def report(self, score, status):
        return {"generated": "2026-11-13T10:00:00+0000", "summary": {"score": score, "coverage": 90},
                "categories": {"kernel": {"score": score}}, "checks": [{"id": "x", "status": status}]}

    def test_only_changes_are_recorded(self):
        path = os.path.join(tempfile.mkdtemp(), "history.jsonl")
        self.assertTrue(collect.append_history(self.report(50, "fail"), path))
        self.assertFalse(collect.append_history(self.report(50, "fail"), path))     # niente di nuovo
        self.assertTrue(collect.append_history(self.report(70, "pass"), path))
        with open(path) as f:
            rows = [json.loads(l) for l in f]
        self.assertEqual([r["score"] for r in rows], [50, 70])
        self.assertEqual(rows[1]["status"], {"x": "pass"})
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o640)

    def test_history_is_capped(self):
        path = os.path.join(tempfile.mkdtemp(), "history.jsonl")
        old = collect.HISTORY_MAX
        collect.HISTORY_MAX = 5
        try:
            for i in range(12):
                collect.append_history(self.report(i, "fail"), path)
        finally:
            collect.HISTORY_MAX = old
        with open(path) as f:
            self.assertEqual([json.loads(l)["score"] for l in f], [7, 8, 9, 10, 11])


class VulnPriority(unittest.TestCase):
    def test_order(self):
        p = collect.vuln_priority
        self.assertEqual(p({"kev": True, "urgency": "low"}), 1)
        self.assertEqual(p({"remote": True, "exposed": True, "urgency": "low"}), 2)
        self.assertEqual(p({"remote": True, "urgency": "high"}), 2)
        self.assertEqual(p({"remote": True, "urgency": "low"}), 3)
        self.assertEqual(p({"urgency": "high"}), 3)
        self.assertEqual(p({"urgency": "medium"}), 4)
        self.assertEqual(p({"urgency": "low", "exposed": True}), 5)


class UndoHelpers(unittest.TestCase):
    def test_drop_keys_keeps_other_settings(self):
        path = os.path.join(tempfile.mkdtemp(), "95-nefi-fixes.conf")
        with open(path, "w") as f:
            f.write("# header\nkernel.kptr_restrict = 2\nfs.protected_fifos = 2\n")
        fix.drop_keys(path, ["kernel.kptr_restrict"])
        with open(path) as f:
            self.assertEqual(f.read(), "# header\nfs.protected_fifos = 2\n")
        fix.drop_keys(path, ["fs.protected_fifos"])
        self.assertFalse(os.path.exists(path))                 # solo commenti rimasti: file tolto

    def test_drop_keys_ssh_style(self):
        path = os.path.join(tempfile.mkdtemp(), "40-nefi-fixes.conf")
        with open(path, "w") as f:
            f.write("# h\nClientAliveInterval 300\nClientAliveCountMax 2\nX11Forwarding no\n")
        fix.drop_keys(path, ["ClientAliveInterval", "ClientAliveCountMax"])
        with open(path) as f:
            self.assertEqual(f.read(), "# h\nX11Forwarding no\n")

    def test_undo_of_something_never_applied(self):
        fix.APPLIED = os.path.join(tempfile.mkdtemp(), "applied.json")
        ok, msg = fix.undo("sysctl:kernel.kptr_restrict")
        self.assertFalse(ok)
        self.assertIn("nothing to undo", msg)


if __name__ == "__main__":
    unittest.main(verbosity=1)
