#!/usr/bin/env python3
"""Test del DFIR: catena di custodia (firma, registro) e fonti della timeline.

    python3 tests/test_dfir.py        (dalla cartella del repo, non serve root; serve gpg)
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "config", "includes.chroot", "opt", "nefi", "forensics"))
import custody as cu     # noqa: E402
import timeline as tl    # noqa: E402


class Custody(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = os.path.join(self.dir, "store")
        os.makedirs(self.store)
        cu.KEYS = os.path.join(self.dir, "keys")
        cu.ENV = dict(cu.ENV, GNUPGHOME=cu.KEYS)
        cu.store_dir = lambda: self.store
        cu._chattr = lambda *a: None
        if os.geteuid() != 0:
            os.chown = lambda *a, **k: None

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_ids_and_text_validation(self):
        eid = cu.new_id("EV")
        self.assertTrue(cu.ID_RE.fullmatch(eid))
        self.assertFalse(cu.ID_RE.fullmatch("../../etc/passwd"))
        self.assertEqual(cu.clean("  Case \n 42 ", "case"), "Case 42")
        for bad in ("", "x" * 201, "a\x00b"):
            with self.assertRaises(ValueError):
                cu.clean(bad, "case")

    def test_custody_chain_detects_removed_and_changed_records(self):
        for i in range(4):
            cu.custody("note", "NEFI-EV-20260101-000000-abcd", "Op", text=f"n{i}")
        path = cu.custody_path()
        self.assertEqual(cu.verify_custody()[:2], (True, 4))
        with open(path) as f:
            lines = f.read().splitlines()
        with open(path, "w") as f:
            f.write("\n".join(lines[:1] + lines[2:]) + "\n")
        self.assertFalse(cu.verify_custody()[0])
        rec = json.loads(lines[1])
        rec["operator"] = "Someone else"
        with open(path, "w") as f:
            f.write("\n".join([lines[0], json.dumps(rec, sort_keys=True)] + lines[2:]) + "\n")
        self.assertFalse(cu.verify_custody()[0])

    @unittest.skipUnless(shutil.which("gpg"), "gpg not installed")
    def test_signed_manifest_detects_changes(self):
        eid = cu.new_id("EV")
        obj = os.path.join(self.store, eid + ".tar.gz")
        with open(obj, "wb") as f:
            f.write(b"evidence bytes")
        manifest = {"evidence_id": eid, "kind": "live-collection", "case": "C", "operator": "Op",
                    "collected_utc": cu.utc_now(), "time": {"ntp_synchronized": False},
                    "objects": [{"name": eid + ".tar.gz", "path": obj, "size": 14, "sha256": cu.sha256_file(obj)}]}
        path = cu.write_manifest(manifest)
        ok, fpr = cu.verify_signature(path)
        self.assertTrue(ok, fpr)
        self.assertEqual(fpr, cu.load_manifest(eid)["signing_key"])
        index = json.load(open(os.path.join(self.store, "index.json")))
        self.assertEqual((index[0]["evidence_id"], index[0]["signed"], index[0]["size"]), (eid, True, 14))
        with open(path) as f:
            text = f.read()
        with open(path, "w") as f:
            f.write(text.replace('"Op"', '"Other"'))
        ok, why = cu.verify_signature(path)
        self.assertFalse(ok)
        self.assertIn("changed", why)


class Timeline(unittest.TestCase):
    def test_macb_flags_like_mactime(self):
        evs = tl.macb_events("/x", {"m": 100, "a": 100, "c": 200, "b": 0}, 0, "filesystem")
        self.assertEqual(sorted(e["timestamp_desc"] for e in evs), ["..c.", "ma.."])
        self.assertEqual(tl.macb_events("/x", {"m": 100, "a": 100, "c": 100, "b": 100}, 0, "filesystem")[0]["timestamp_desc"], "macb")
        self.assertEqual(tl.macb_events("/x", {"m": 100}, 500 * 1_000_000, "filesystem"), [])      # prima della finestra

    def test_packages_and_apt(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "dpkg.log"), "w") as f:
            f.write("2026-11-10 10:00:00 startup archives unpack\n"
                    "2026-11-10 10:00:01 install nmap:amd64 <none> 7.95\n"
                    "2026-11-10 10:00:02 upgrade openssl:amd64 3.5.1 3.5.2\n"
                    "2026-11-10 10:00:03 status installed nmap:amd64 7.95\n")
        with open(os.path.join(d, "history.log"), "w") as f:
            f.write("\nStart-Date: 2026-11-10  10:00:00\nCommandline: apt install nmap\nRequested-By: anna (1000)\n"
                    "Install: nmap:amd64 (7.95)\nEnd-Date: 2026-11-10  10:00:05\n\n")
        evs = tl.packages_source(0, os.path.join(d, "dpkg.log*"), os.path.join(d, "history.log*"))
        msgs = [e["message"] for e in evs]
        self.assertIn("dpkg install nmap:amd64 7.95", msgs)
        self.assertIn("dpkg upgrade openssl:amd64 3.5.1 -> 3.5.2", msgs)
        self.assertIn("apt: apt install nmap (requested by anna (1000))", msgs)
        self.assertEqual(len(evs), 3)

    def test_shell_history_only_timestamped_lines(self):
        home = tempfile.mkdtemp()
        now = int(time.time())
        with open(os.path.join(home, ".bash_history"), "w") as f:
            f.write(f"no time\n#{now - 60}\nwget http://example.org/x\n#{now - 50}\nchmod +x x\n")
        with open(os.path.join(home, ".zsh_history"), "w") as f:
            f.write(f": {now - 40}:0;ls -la\n")
        msgs = [e["message"] for e in tl.shell_source(0, [("anna", home)])]
        self.assertEqual(msgs, ["anna$ wget http://example.org/x", "anna$ chmod +x x", "anna$ ls -la"])

    def test_firefox_history_read_from_a_copy(self):
        home = tempfile.mkdtemp()
        prof = os.path.join(home, ".mozilla", "firefox", "abc.default")
        os.makedirs(prof)
        db = os.path.join(prof, "places.sqlite")
        con = sqlite3.connect(db)
        con.executescript("CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url,title);"
                          "CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,place_id,visit_date);"
                          "CREATE TABLE moz_annos(id INTEGER PRIMARY KEY,place_id,anno_attribute_id,content,dateAdded);"
                          "CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY,name);")
        now = int(time.time() * 1e6)
        con.execute("INSERT INTO moz_places VALUES(1,'https://example.org/a','A')")
        con.execute("INSERT INTO moz_historyvisits VALUES(1,1,?)", (now,))
        con.commit()
        con.close()
        before = os.stat(db).st_mtime_ns
        evs = tl.browser_source(0, [("anna", home)])
        self.assertEqual(evs[0]["message"], "Firefox (anna): https://example.org/a A")
        self.assertEqual(os.stat(db).st_mtime_ns, before)          # l'originale non e' stato toccato

    def test_build_sorts_and_exports_timesketch_fields(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, "t.jsonl")
        tl.detection_source = lambda since: [tl.ev(3_000_000, "b", "detection", "second"), tl.ev(1_000_000, "a", "detection", "first")]
        summary = tl.build(["detection"], 0, out, log=lambda m: None)
        rows = [json.loads(l) for l in open(out)]
        self.assertEqual([r["message"] for r in rows], ["first", "second"])
        self.assertTrue(all({"message", "datetime", "timestamp_desc"} <= set(r) for r in rows))
        self.assertEqual(rows[0]["datetime"], "1970-01-01T00:00:01.000000+00:00")
        self.assertEqual(summary["by_source"], {"detection": 2})
        tl.to_csv(out, out + ".csv")
        self.assertEqual(open(out + ".csv").readline().strip(), "datetime,timestamp_desc,message,source")


if __name__ == "__main__":
    unittest.main(verbosity=1)
