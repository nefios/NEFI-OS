#!/usr/bin/env python3
"""Test dello stato di Incident Response: parser Python (ir_state.py) e scrittura (opt/nefi/ir/state.sh).

    python3 tests/test_ir_state.py          (dalla cartella del repo, non serve root)
"""
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "config", "includes.chroot")
sys.path.insert(0, os.path.join(ROOT, "usr", "lib", "nefi", "modules"))
import ir_state  # noqa: E402

STATE_SH = os.path.join(ROOT, "opt", "nefi", "ir", "state.sh")


class ParserTest(unittest.TestCase):
    def test_missing_file(self):
        self.assertEqual(ir_state.read("/nonexistent/ir-state.conf"), {})
        self.assertFalse(ir_state.is_active(ir_state.read("/nonexistent/ir-state.conf")))

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            path = f.name
        try:
            self.assertEqual(ir_state.read(path), {})
            self.assertFalse(ir_state.is_active(ir_state.read(path)))
        finally:
            os.remove(path)

    def test_old_file_true_then_false_is_inactive(self):
        # file scritto dalle versioni vecchie: la chiave compare due volte
        old = "IR_START=2026-11-01T10:00:00Z\nNETWORK_BLOCKED=true\nIR_ACTIVE=true\nIR_ACTIVE=false\nIR_END=x\n"
        self.assertFalse(ir_state.is_active(ir_state.parse(old)))

    def test_false_then_true_is_active(self):
        self.assertTrue(ir_state.is_active(ir_state.parse("IR_ACTIVE=false\nIR_ACTIVE=true\n")))

    def test_garbage_and_comments_ignored(self):
        st = ir_state.parse("# comment\n\nnot a line\nlower=1\n IR_ACTIVE = true\nIR_ACTIVE=true\n")
        self.assertEqual(st, {"IR_ACTIVE": "true"})

    def test_values_are_case_insensitive(self):
        self.assertTrue(ir_state.is_active({"IR_ACTIVE": "TRUE"}))
        self.assertFalse(ir_state.is_active({"IR_ACTIVE": "yes"}))


class ShellWriterTest(unittest.TestCase):
    """state.sh con la cartella di stato spostata in una cartella temporanea."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.file = os.path.join(self.dir, "ir-state.conf")

    def sh(self, *commands):
        script = (f'. "{STATE_SH}"\nSTATE_DIR="{self.dir}"\nSTATE_FILE="{self.file}"\n' + "\n".join(commands))
        r = subprocess.run(["bash", "-c", "set -e\n" + script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def lines(self, key):
        with open(self.file) as f:
            return [l for l in f.read().splitlines() if l.startswith(key + "=")]

    def test_activate_then_deactivate(self):
        self.sh("ir_state_reset IR_START 2026-11-09T10:00:00Z IR_ACTIVE false",
                "ir_state_set IR_ACTIVE true NETWORK_BLOCKED true",
                "ir_state_set LOGS_PROTECTED true",
                "ir_state_set IR_ACTIVE false NETWORK_BLOCKED false IR_END 2026-11-09T11:00:00Z")
        self.assertEqual(self.lines("IR_ACTIVE"), ["IR_ACTIVE=false"])
        self.assertEqual(self.lines("NETWORK_BLOCKED"), ["NETWORK_BLOCKED=false"])
        self.assertFalse(ir_state.is_active(ir_state.read(self.file)))
        self.assertEqual(ir_state.read(self.file)["IR_START"], "2026-11-09T10:00:00Z")

    def test_reactivate(self):
        self.sh("ir_state_reset IR_ACTIVE false", "ir_state_set IR_ACTIVE true",
                "ir_state_set IR_ACTIVE false", "ir_state_set IR_ACTIVE true")
        self.assertEqual(self.lines("IR_ACTIVE"), ["IR_ACTIVE=true"])
        self.assertTrue(ir_state.is_active(ir_state.read(self.file)))

    def test_old_duplicated_file_is_cleaned(self):
        with open(self.file, "w") as f:
            f.write("IR_START=a\nIR_ACTIVE=true\nIR_ACTIVE=false\nNETWORK_BLOCKED=true\nNETWORK_BLOCKED=true\n")
        self.sh("ir_state_set IR_END b")
        self.assertEqual(self.lines("IR_ACTIVE"), ["IR_ACTIVE=false"])
        self.assertEqual(self.lines("NETWORK_BLOCKED"), ["NETWORK_BLOCKED=true"])

    def test_mode_and_no_temp_files_left(self):
        self.sh("ir_state_reset IR_ACTIVE true")
        self.assertEqual(os.stat(self.file).st_mode & 0o777, 0o640)
        self.assertEqual(sorted(os.listdir(self.dir)), ["ir-state.conf"])

    def test_invalid_key_or_value_rejected(self):
        for cmd in ("ir_state_set bad_key x", "ir_state_set IR_ACTIVE 'true; rm -rf /'", "ir_state_set IR_ACTIVE"):
            script = f'. "{STATE_SH}"\nSTATE_DIR="{self.dir}"\nSTATE_FILE="{self.file}"\n{cmd}'
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, cmd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
