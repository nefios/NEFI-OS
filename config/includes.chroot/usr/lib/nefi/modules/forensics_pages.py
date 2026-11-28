"""NEFI Security Center — DFIR: Evidence & Custody, Memory Forensics, Timeline, Disk Forensics.

Le pagine girano come utente e leggono solo l'indice e il registro di custodia (root:sudo 0640).
Ogni operazione passa da /opt/nefi/forensics/dfir.py con pkexec, che valida gli argomenti,
firma i manifest e scrive nel registro di custodia.
"""
import json
import os
import shutil
import subprocess
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QGridLayout, QMessageBox, QFileDialog,
    QTextEdit, QInputDialog, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from nefi_theme import C, Card, SectionLabel, GhostButton, PageHeader
from prevention_pages import make_table, fill, StatTile, INPUT_QSS
from system_pages import CmdWorker

CONF = "/etc/nefi/forensics.json"
DEFAULT_STORE = "/var/lib/nefi/forensics"
DFIR = ["pkexec", "/usr/bin/python3", "/opt/nefi/forensics/dfir.py"]
PREFS = os.path.expanduser("~/.config/nefi/dfir.json")
KIND = {"live-collection": "Live collection", "memory": "Memory image", "disk-image": "Disk image",
        "timeline": "Timeline", "network-capture": "Network capture"}
TL_SOURCES = [("filesystem", "File times (MACB)"), ("auth", "Logins, sudo, PAM"), ("systemd", "Services"),
              ("logins", "Sessions (wtmp)"), ("packages", "Packages"), ("shell", "Shell history"),
              ("browser", "Browser history"), ("detection", "NEFI alerts"), ("process", "Programs executed"),
              ("journal", "Whole system journal")]
VOL_PLUGINS = [("Kernel banner (works without symbols)", "banners.Banners"), ("Process list", "linux.pslist.PsList"),
               ("Process tree", "linux.pstree.PsTree"), ("Processes with arguments", "linux.psaux.PsAux"),
               ("Bash history from memory", "linux.bash.Bash"), ("Kernel modules", "linux.lsmod.Lsmod"),
               ("Hidden kernel modules", "linux.check_modules.Check_modules"),
               ("System call table hooks", "linux.check_syscall.Check_syscall"), ("Network sockets", "linux.sockstat.Sockstat"),
               ("Injected code (malfind)", "linux.malfind.Malfind"), ("Environment variables", "linux.envars.Envars"),
               ("Open files", "linux.lsof.Lsof"), ("Mounts", "linux.mountinfo.MountInfo")]
ANALYSIS = [("Partition table (mmls)", "mmls"), ("File system details (fsstat)", "fsstat"),
            ("All files, also deleted (fls)", "fls"), ("File carving (foremost)", "foremost"),
            ("Artifact extraction (bulk_extractor)", "bulk_extractor")]


def store_dir():
    try:
        with open(CONF) as f:
            return json.load(f).get("store") or DEFAULT_STORE
    except (OSError, ValueError):
        return DEFAULT_STORE


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024


def make_combo(items, width=None):
    from PyQt6.QtWidgets import QComboBox
    c = QComboBox()
    c.setStyleSheet(f"QComboBox {{ {INPUT_QSS} }}")
    for label, data in items:
        c.addItem(label, data)
    if width:
        c.setMinimumWidth(width)
    return c


class DfirPage(QWidget):
    """Base: intestazione, statistiche, campi caso/operatore/motivo, comandi root con registro a video."""
    TITLE = ""
    SUBTITLE = ""
    STATS = []
    KINDS = ()

    def __init__(self):
        super().__init__()
        self.worker = None
        self._sig = None
        self.items = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(14)
        lay.addWidget(PageHeader(self.TITLE, self.SUBTITLE))
        head = Card(padding=18)
        grid = QGridLayout()
        self.stats = {}
        for i, (key, label) in enumerate(self.STATS):
            self.stats[key] = StatTile(label)
            grid.addWidget(self.stats[key], 0, i)
        head.body.addLayout(grid)
        self.note = QLabel("")
        self.note.setWordWrap(True)
        self.note.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        head.body.addWidget(self.note)
        lay.addWidget(head)
        self.body = lay
        self.build()
        log_card = Card(padding=18)
        log_card.body.addWidget(SectionLabel("Operation log"))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(130)
        self.log.setPlaceholderText("The output of each operation appears here. Every operation is also written "
                                    "to the custody log with your account name.")
        self.log.setStyleSheet(f"background: {C['bg']}; color: {C['accent']}; border: 1px solid {C['border']}; "
                               f"border-radius: 8px; font-family: monospace; font-size: 12px;")
        log_card.body.addWidget(self.log)
        lay.addWidget(log_card)
        self.refresh(force=True)

    def build(self):
        pass

    # ── campi comuni ──
    def case_row(self, layout):
        prefs = read_json(PREFS, {})
        row = QHBoxLayout()
        self.f_case = self._edit(row, "Case name or number", 200, prefs.get("case", ""))
        self.f_operator = self._edit(row, "Operator (your full name)", 220, prefs.get("operator", ""))
        self.f_reason = self._edit(row, "Reason for this operation", 320, "")
        row.addStretch()
        layout.addLayout(row)
        return row

    def _edit(self, row, placeholder, width, text=""):
        e = QLineEdit(text)
        e.setPlaceholderText(placeholder)
        e.setStyleSheet(INPUT_QSS)
        e.setMinimumWidth(width)
        row.addWidget(e)
        return e

    def case_args(self, need_reason=True):
        case, op, why = self.f_case.text().strip(), self.f_operator.text().strip(), self.f_reason.text().strip()
        if not case or not op or (need_reason and not why):
            QMessageBox.information(self, "Chain of custody", "Fill in the case, the operator"
                                    + (" and the reason" if need_reason else "") + ": they are written in the signed "
                                    "manifest and in the custody log.")
            return None
        try:
            os.makedirs(os.path.dirname(PREFS), exist_ok=True)
            with open(PREFS, "w", encoding="utf-8") as f:
                json.dump({"case": case, "operator": op}, f)
        except OSError:
            pass
        return [case, op, why] if need_reason else [case, op]

    def btn(self, row, label, icon, tone, fn):
        b = GhostButton(label, icon, 32, tone=tone)
        b.clicked.connect(fn)
        row.addWidget(b)
        return b

    # ── comandi ──
    def run(self, cmd, title):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Busy", "Another operation is still running.")
            return
        self.log.clear()
        self.log.append(title)
        self.worker = CmdWorker(list(cmd))
        self.worker.line.connect(lambda l: self.log.append(l) if l.strip() else None)
        self.worker.finished_ok.connect(lambda ok: (self.log.append("— finished —" if ok else "— FAILED or cancelled —"),
                                                    self.refresh(force=True)))
        self.worker.start()

    def dfir(self, args, title):
        self.run(DFIR + list(args), title + " (admin password)…")

    # ── dati ──
    def selected(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Select", "Select a row in the table first.")
            return None
        eid = self.table.item(sel[0].row(), 0).text()
        return next((x for x in self.items if x.get("evidence_id") == eid), None)

    def load(self):
        store = store_dir()
        index = read_json(os.path.join(store, "index.json"), None)
        return store, index

    def refresh(self, force=False):
        store = store_dir()
        try:
            sig = (store, os.stat(os.path.join(store, "index.json")).st_mtime_ns,
                   os.path.getsize(os.path.join(store, "custody.jsonl")))
        except OSError:
            sig = (store, None)
        if not force and sig == self._sig:
            return
        self._sig = sig
        store, index = self.load()
        self.items = [x for x in (index or []) if not self.KINDS or x.get("kind") in self.KINDS]
        self.apply(store, index)

    def apply(self, store, index):
        pass


# ───────────────────────────── Evidence & Custody ─────────────────────────────

class EvidencePage(DfirPage):
    TITLE = "Evidence & Chain of Custody"
    SUBTITLE = ("Collect live evidence and keep it usable as evidence: every item has a unique ID, a manifest with "
                "the SHA-256 of each file signed with a dedicated key, the operator, the case, the state of the clock, "
                "and a tamper-evident log of every operation done on it.")
    STATS = [("count", "evidence items"), ("size", "total size"), ("custody", "custody log records"),
             ("free", "free space in the store")]

    def build(self):
        card = Card(padding=18)
        card.body.addWidget(SectionLabel("Collect live evidence"))
        info = QLabel("System and hardware information, processes, network connections, logs, hashes of critical files "
                      "and of system programs, autorun entries. Memory and disks are acquired from their own pages.")
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent;")
        card.body.addWidget(info)
        row = self.case_row(card.body)
        self.btn(row, "Collect now", "folder", "ok", self._collect)
        srow = QHBoxLayout()
        self.store_lbl = QLabel("")
        self.store_lbl.setWordWrap(True)
        self.store_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.store_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent;")
        srow.addWidget(self.store_lbl, 1)
        self.btn(srow, "Change evidence store…", "folder", "muted", self._store)
        self.btn(srow, "Export public key…", "key", "muted", self._key)
        card.body.addLayout(srow)
        self.body.addWidget(card)

        ecard = Card(padding=18)
        erow = QHBoxLayout()
        erow.addWidget(SectionLabel("Evidence"))
        erow.addStretch()
        self.btn(erow, "Verify", "check_sq", "ok", self._verify)
        self.btn(erow, "Export copy…", "download", "muted", self._export)
        self.btn(erow, "Add custody note…", "file", "muted", self._note)
        self.btn(erow, "Delete…", "x", "danger", self._delete)
        ecard.body.addLayout(erow)
        self.table = make_table(["Evidence ID", "Type", "Case", "Operator", "Collected (UTC)", "Size", "Signed",
                                 "Clock", "Description"])
        self.table.setMinimumHeight(170)
        ecard.body.addWidget(self.table, 1)
        self.body.addWidget(ecard, 2)

        ccard = Card(padding=18)
        crow = QHBoxLayout()
        crow.addWidget(SectionLabel("Custody log (append-only, hash-chained)"))
        crow.addStretch()
        self.btn(crow, "Verify log integrity", "fingerprint", "muted",
                 lambda: self.dfir(["custody-verify"], "Checking the custody log chain"))
        ccard.body.addLayout(crow)
        self.custody = make_table(["Time (UTC)", "Action", "Evidence", "Account", "Operator", "Details"])
        self.custody.setMinimumHeight(150)
        ccard.body.addWidget(self.custody, 1)
        self.body.addWidget(ccard, 2)

    def apply(self, store, index):
        if index is None:
            self.note.setText("No evidence yet, or your user is not in the 'sudo' group (needed to read the index).")
        else:
            self.note.setText("Keep a copy of the public key and of its fingerprint away from this machine: that is "
                              "what lets anyone prove later that a manifest was not rewritten.")
        self.stats["count"].set(len(self.items) if index is not None else "–")
        self.stats["size"].set(human(sum(x.get("size", 0) for x in self.items)) if index is not None else "–")
        try:
            st = os.statvfs(store)
            free = st.f_bavail * st.f_frsize
            self.stats["free"].set(human(free), C["warn"] if free < 5 * 2**30 else None)
        except OSError:
            self.stats["free"].set("–")
        default = store == DEFAULT_STORE
        self.store_lbl.setText(f"Evidence store: {store}" + (" — this is the disk of the examined system. For real cases "
                               "choose an external disk: evidence should not live only on the machine it describes." if default else ""))
        fill(self.table, [[x.get("evidence_id", ""), KIND.get(x.get("kind"), x.get("kind", "")), x.get("case", ""),
                           x.get("operator", ""), (x.get("collected_utc") or "").replace("T", " ").replace("Z", ""),
                           human(x.get("size", 0)), "yes" if x.get("signed") else "NO",
                           "NTP synchronised" if x.get("ntp_synchronized") else "local clock only",
                           x.get("description", "")] for x in self.items],
             {i: C["danger"] for i, x in enumerate(self.items) if not x.get("signed")})
        rows, n = [], 0
        try:
            with open(os.path.join(store, "custody.jsonl"), encoding="utf-8") as f:
                lines = f.readlines()
            n = len(lines)
            for line in reversed(lines[-300:]):
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                details = ", ".join(f"{k}={v}" for k, v in r.items()
                                    if k not in ("ts", "action", "evidence", "account", "operator", "prev", "host") and v not in ("", None))
                rows.append([r.get("ts", "").replace("T", " ").replace("Z", ""), r.get("action", ""), r.get("evidence", ""),
                             r.get("account", ""), r.get("operator", ""), details[:400]])
        except OSError:
            pass
        self.stats["custody"].set(n if index is not None else "–")
        fill(self.custody, rows)

    def _collect(self):
        args = self.case_args()
        if args:
            self.dfir(["collect"] + args, "Collecting live evidence")

    def _store(self):
        path = QFileDialog.getExistingDirectory(self, "Folder for the evidence (ideally on an external disk)", "/media")
        if path:
            self.dfir(["store", path], f"Setting the evidence store to {path}")

    def _key(self):
        path = QFileDialog.getExistingDirectory(self, "Where to save the public key (ideally removable media)", "/media")
        if path:
            self.dfir(["key-export", path], "Exporting the public key")

    def _verify(self):
        x = self.selected()
        if x:
            self.dfir(["verify", x["evidence_id"]], f"Verifying {x['evidence_id']}")

    def _export(self):
        x = self.selected()
        if not x:
            return
        path = QFileDialog.getExistingDirectory(self, "Destination folder (another disk)", "/media")
        if path:
            self.dfir(["export", x["evidence_id"], path], f"Exporting {x['evidence_id']} to {path}")

    def _note(self):
        x = self.selected()
        if not x:
            return
        if not self.f_operator.text().strip():
            QMessageBox.information(self, "Custody note", "Write the operator name in the form above first.")
            return
        text, ok = QInputDialog.getText(self, "Custody note", "What happened to this evidence? (handed over to…, "
                                        "moved to…, examined by…)")
        if ok and text.strip():
            self.dfir(["note", x["evidence_id"], self.f_operator.text().strip(), text.strip()], "Adding the note")

    def _delete(self):
        x = self.selected()
        if not x:
            return
        if not self.f_operator.text().strip():
            QMessageBox.information(self, "Delete", "Write the operator name in the form above first.")
            return
        why, ok = QInputDialog.getText(self, "Delete evidence", f"Delete {x['evidence_id']}?\nThe custody log keeps the "
                                       "record that it existed and that you deleted it.\n\nReason:")
        if ok and why.strip():
            self.dfir(["delete", x["evidence_id"], self.f_operator.text().strip(), why.strip()], "Deleting")


# ───────────────────────────── Memory Forensics ─────────────────────────────

class MemoryPage(DfirPage):
    TITLE = "Memory Forensics"
    SUBTITLE = ("Acquire the whole RAM with AVML as signed evidence, check that the acquisition is complete, and "
                "analyse memory images with Volatility 3. Running malware, injected code and network connections "
                "that never touch the disk are only visible here.")
    STATS = [("ram", "RAM installed"), ("free", "free space in the store"), ("images", "memory images"),
             ("lockdown", "kernel lockdown")]
    KINDS = ("memory",)

    def build(self):
        card = Card(padding=18)
        card.body.addWidget(SectionLabel("Tools and acquisition"))
        self.tools = QLabel("")
        self.tools.setWordWrap(True)
        self.tools.setStyleSheet(f"color: {C['text']}; font-size: 13px; background: transparent;")
        card.body.addWidget(self.tools)
        trow = QHBoxLayout()
        self.btn(trow, "Install AVML and Volatility 3", "download", "muted",
                 lambda: self.run(["pkexec", "/opt/nefi/forensics/install-memory-tools.sh"],
                                  "Installing the memory tools (admin password, Internet needed)…"))
        self.btn(trow, "Create kernel symbols", "cpu", "muted", self._symbols)
        trow.addStretch()
        card.body.addLayout(trow)
        row = self.case_row(card.body)
        self.b_acq = self.btn(row, "Acquire memory now", "cpu", "ok", self._acquire)
        self.body.addWidget(card)

        icard = Card(padding=18)
        irow = QHBoxLayout()
        irow.addWidget(SectionLabel("Memory images"))
        irow.addStretch()
        self.plugin = make_combo(VOL_PLUGINS, 280)
        irow.addWidget(self.plugin)
        self.btn(irow, "Analyse with Volatility", "search", "ok", self._vol)
        self.btn(irow, "Verify", "check_sq", "muted", self._verify)
        icard.body.addLayout(irow)
        self.table = make_table(["Evidence ID", "Case", "Operator", "Acquired (UTC)", "Size", "Signed", "Description"])
        self.table.setMinimumHeight(140)
        icard.body.addWidget(self.table, 1)
        self.body.addWidget(icard, 1)

    def apply(self, store, index):
        avml = shutil.which("avml") or (os.path.exists("/usr/local/bin/avml") and "/usr/local/bin/avml")
        vol = os.path.exists("/opt/nefi/forensics/vol3/bin/vol")
        try:
            with open("/sys/kernel/security/lockdown") as f:
                txt = f.read()
            lock = txt[txt.index("[") + 1:txt.index("]")] if "[" in txt else "none"
        except (OSError, ValueError):
            lock = "none"
        ram = 0
        try:
            with open("/proc/meminfo") as f:
                ram = int(f.readline().split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
        try:
            st = os.statvfs(store)
            free = st.f_bavail * st.f_frsize
        except OSError:
            free = 0
        sym = os.path.exists(f"/opt/nefi/forensics/symbols/linux/debian-{os.uname().release}.json.xz")
        self.stats["ram"].set(human(ram))
        self.stats["free"].set(human(free), C["danger"] if free < ram * 1.05 else None)
        self.stats["images"].set(len(self.items) if index is not None else "–")
        self.stats["lockdown"].set(lock, C["warn"] if lock != "none" else C["accent"])
        self.tools.setText(f"AVML: {'installed' if avml else 'not installed'}   •   Volatility 3: "
                           f"{'installed' if vol else 'not installed'}   •   symbols of this kernel: "
                           f"{'ready' if sym else 'not created (needed for process lists and most Linux plugins)'}")
        notes = []
        if lock != "none":
            notes.append(f"Kernel lockdown is '{lock}' (Secure Boot): the kernel blocks every way to read physical memory "
                         "from the running system, so this machine cannot be acquired from inside. For a virtual "
                         "machine take a snapshot from the hypervisor; otherwise boot once with Secure Boot disabled. "
                         "Images taken elsewhere can still be analysed here.")
        if free < ram * 1.05:
            notes.append(f"The image needs about {human(ram)}: choose an external disk as evidence store "
                         "(DFIR > Evidence & Chain of Custody).")
        self.note.setText(" ".join(notes))
        self.b_acq.setEnabled(bool(avml))
        fill(self.table, [[x.get("evidence_id", ""), x.get("case", ""), x.get("operator", ""),
                           (x.get("collected_utc") or "").replace("T", " ").replace("Z", ""), human(x.get("size", 0)),
                           "yes" if x.get("signed") else "NO", x.get("description", "")] for x in self.items])

    def _acquire(self):
        args = self.case_args()
        if args and QMessageBox.question(self, "Acquire memory", "Acquire the whole RAM now? It takes a few minutes and "
                                         "the image is as large as the RAM.") == QMessageBox.StandardButton.Yes:
            self.dfir(["memory"] + args, "Acquiring memory")

    def _symbols(self):
        if QMessageBox.question(self, "Kernel symbols", "Download the debug package of the running kernel (about 1 GB, "
                                "removed afterwards) and build the symbol table Volatility needs?\nIt takes several "
                                "minutes and about 4 GB of RAM.") == QMessageBox.StandardButton.Yes:
            self.run(["pkexec", "/opt/nefi/forensics/install-memory-tools.sh", "symbols"],
                     "Creating the kernel symbols (admin password, Internet needed)…")

    def _vol(self):
        x = self.selected()
        if x:
            self.dfir(["vol", x["evidence_id"], self.plugin.currentData()], f"Volatility 3: {self.plugin.currentText()}")

    def _verify(self):
        x = self.selected()
        if x:
            self.dfir(["verify", x["evidence_id"]], f"Verifying {x['evidence_id']}")


# ───────────────────────────── Timeline ─────────────────────────────

class TimelineLoader(QThread):
    done = pyqtSignal(list, int, str)

    def __init__(self, path, text, source, start, limit=5000):
        super().__init__()
        self.path, self.text, self.source, self.start_at, self.limit = path, text.lower(), source, start, limit

    def run(self):
        rows, total = [], 0
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if self.text and self.text not in line.lower():
                        continue
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if self.source and e.get("source") != self.source:
                        continue
                    if self.start_at and (e.get("datetime") or "") < self.start_at:
                        continue
                    total += 1
                    if len(rows) < self.limit:
                        rows.append(e)
        except OSError as e:
            self.done.emit([], 0, str(e))
            return
        self.done.emit(rows, total, "")


class TimelinePage(DfirPage):
    TITLE = "Timeline"
    SUBTITLE = ("One ordered list of everything that happened: file times (modified, accessed, changed, born), "
                "logins, services, packages, shell and browser history, executed programs and NEFI alerts - from "
                "the live system or from a disk image. The result is signed evidence and can be imported in Timesketch.")
    STATS = [("count", "timelines"), ("events", "events in the selected timeline"), ("shown", "events shown")]
    KINDS = ("timeline",)

    def build(self):
        self.loader = None
        card = Card(padding=18)
        card.body.addWidget(SectionLabel("Build a timeline"))
        srow = QHBoxLayout()
        self.checks = {}
        for key, label in TL_SOURCES:
            cb = QCheckBox(label)
            cb.setChecked(key != "journal")
            cb.setStyleSheet(f"color: {C['text2']}; background: transparent;")
            self.checks[key] = cb
            srow.addWidget(cb)
        srow.addStretch()
        card.body.addLayout(srow)
        row = QHBoxLayout()
        self.days = make_combo([("Last 24 hours", 1), ("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90),
                                ("Everything", 0)])
        self.days.setCurrentIndex(1)
        row.addWidget(self.days)
        self.f_case = self._edit(row, "Case name or number", 180, read_json(PREFS, {}).get("case", ""))
        self.f_operator = self._edit(row, "Operator", 180, read_json(PREFS, {}).get("operator", ""))
        self.f_reason = QLineEdit()
        self.image = self._edit(row, "Disk image to include (optional, .E01 or .dd)", 300)
        self.btn(row, "…", None, "muted", self._pick_image)
        self.btn(row, "Build", "play", "ok", self._build)
        row.addStretch()
        card.body.addLayout(row)
        self.body.addWidget(card)

        vcard = Card(padding=18)
        vrow = QHBoxLayout()
        vrow.addWidget(SectionLabel("Timelines"))
        vrow.addStretch()
        self.btn(vrow, "Plaso super-timeline of an evidence…", "search", "muted", self._plaso)
        self.btn(vrow, "Verify", "check_sq", "muted", lambda: (lambda x: x and self.dfir(["verify", x["evidence_id"]], "Verifying"))(self.selected()))
        vcard.body.addLayout(vrow)
        self.table = make_table(["Evidence ID", "Case", "Built (UTC)", "Description"])
        self.table.setMaximumHeight(150)
        self.table.itemSelectionChanged.connect(self._view)
        vcard.body.addWidget(self.table)
        frow = QHBoxLayout()
        self.q = self._edit(frow, "Filter: text contained in the event", 300)
        self.q.returnPressed.connect(self._view)
        self.src = make_combo([("All sources", "")] + [(l, k) for k, l in TL_SOURCES] + [("Disk image", "image")])
        frow.addWidget(self.src)
        self.start = self._edit(frow, "From (UTC), e.g. 2026-11-12T14:00", 240)
        self.start.returnPressed.connect(self._view)
        self.btn(frow, "Show", "search", "ok", self._view)
        frow.addStretch()
        vcard.body.addLayout(frow)
        self.events = make_table(["Time (UTC)", "Source", "Type", "Event"])
        self.events.setMinimumHeight(260)
        vcard.body.addWidget(self.events, 1)
        self.path_lbl = QLabel("")
        self.path_lbl.setWordWrap(True)
        self.path_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.path_lbl.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        vcard.body.addWidget(self.path_lbl)
        self.body.addWidget(vcard, 1)

    def apply(self, store, index):
        self.stats["count"].set(len(self.items) if index is not None else "–")
        self.note.setText("" if shutil.which("fls") else "The Sleuth Kit is not installed: timelines of disk images "
                          "are not available (it is in the 'large' software selection).")
        fill(self.table, [[x.get("evidence_id", ""), x.get("case", ""),
                           (x.get("collected_utc") or "").replace("T", " ").replace("Z", ""),
                           x.get("description", "")] for x in self.items])

    def _pick_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Disk image", "/media", "Disk images (*.E01 *.dd *.raw *.img);;All files (*)")
        if path:
            self.image.setText(path)

    def _build(self):
        args = self.case_args(need_reason=False)
        if not args:
            return
        sources = ",".join(k for k, cb in self.checks.items() if cb.isChecked())
        if not sources:
            QMessageBox.information(self, "Timeline", "Choose at least one source.")
            return
        cmd = ["timeline", str(self.days.currentData()), sources] + args
        if self.image.text().strip():
            cmd.append(self.image.text().strip())
        self.dfir(cmd, "Building the timeline")

    def _plaso(self):
        index = read_json(os.path.join(store_dir(), "index.json"), [])
        ids = [x["evidence_id"] for x in index if x.get("kind") in ("live-collection", "disk-image")]
        if not any(shutil.which(n) for n in ("plaso-log2timeline", "log2timeline.py", "log2timeline")):
            QMessageBox.information(self, "Plaso", "Plaso is not installed (sudo apt install plaso).")
            return
        if not ids:
            QMessageBox.information(self, "Plaso", "Collect live evidence or acquire a disk image first.")
            return
        eid, ok = QInputDialog.getItem(self, "Plaso super-timeline", "Evidence to process (it can take a long time):", ids, 0, False)
        if ok and eid:
            self.dfir(["plaso", eid], f"Plaso on {eid}")

    def _view(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel or (self.loader and self.loader.isRunning()):
            return
        eid = self.table.item(sel[0].row(), 0).text()
        path = os.path.join(store_dir(), "timelines", eid + ".jsonl")
        self.path_lbl.setText(f"Files for Timesketch or a spreadsheet: {path}  and  {path[:-6]}.csv")
        self.loader = TimelineLoader(path, self.q.text().strip(), self.src.currentData(), self.start.text().strip())
        self.loader.done.connect(self._loaded)
        self.loader.start()

    def _loaded(self, rows, total, err):
        if err:
            self.path_lbl.setText(f"Cannot read the timeline: {err}")
            return
        self.stats["events"].set(total)
        self.stats["shown"].set(len(rows), C["warn"] if len(rows) < total else None)
        fill(self.events, [[(e.get("datetime") or "")[:19].replace("T", " "), e.get("source", ""),
                            e.get("timestamp_desc", ""), e.get("message", "")[:500]] for e in rows])


# ───────────────────────────── Disk Forensics ─────────────────────────────

class DiskPage(DfirPage):
    TITLE = "Disk Forensics"
    SUBTITLE = ("Acquire a disk without changing it: the device is write-blocked and the block is verified before a "
                "single byte is read, the image (E01 or raw) is hashed and verified, and the result is signed "
                "evidence. Then analyse the image - never the original - with The Sleuth Kit and Foremost.")
    STATS = [("disks", "disks connected"), ("blocker", "write blocker for new disks"), ("images", "disk images")]
    KINDS = ("disk-image",)

    def build(self):
        self.disks = []
        card = Card(padding=18)
        hrow = QHBoxLayout()
        hrow.addWidget(SectionLabel("Disks"))
        hrow.addStretch()
        self.btn(hrow, "Write blocker: ON", "lock", "ok", lambda: self.dfir(["writeblock", "on"], "Enabling the write blocker"))
        self.btn(hrow, "Write blocker: OFF", "x", "muted", lambda: self.dfir(["writeblock", "off"], "Disabling the write blocker"))
        self.btn(hrow, "Refresh", "refresh", "muted", lambda: self.refresh(force=True))
        card.body.addLayout(hrow)
        hint = QLabel("Turn the write blocker ON before connecting the disk to examine: disks connected afterwards "
                      "are read-only and are not mounted automatically. A software block does not replace a hardware "
                      "write blocker when the evidence must stand in court.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        card.body.addWidget(hint)
        self.dtable = make_table(["Device", "Size", "Model", "Serial", "Bus", "Read-only", "Mounted at", "Note"])
        self.dtable.setMinimumHeight(140)
        card.body.addWidget(self.dtable, 1)
        row = self.case_row(card.body)
        row2 = QHBoxLayout()
        self.dest = self._edit(row2, "Destination folder (on another disk)", 340)
        self.btn(row2, "…", None, "muted", self._pick_dest)
        self.fmt = make_combo([("E01 (EnCase, compressed)", "e01"), ("Raw (dd)", "raw")])
        row2.addWidget(self.fmt)
        self.btn(row2, "Acquire image", "snapshot", "ok", self._acquire)
        self.btn(row2, "Open Guymager", "snapshot", "muted", lambda: self._launch("guymager"))
        row2.addStretch()
        card.body.addLayout(row2)
        self.body.addWidget(card, 1)

        icard = Card(padding=18)
        irow = QHBoxLayout()
        irow.addWidget(SectionLabel("Disk images"))
        irow.addStretch()
        # bulk_extractor non e' in Debian 13: la voce compare solo se e' installato
        self.tool = make_combo([(l, t) for l, t in ANALYSIS if t != "bulk_extractor" or shutil.which(t)], 260)
        irow.addWidget(self.tool)
        self.btn(irow, "Run on image", "play", "ok", self._analyze)
        self.btn(irow, "Verify", "check_sq", "muted", lambda: (lambda x: x and self.dfir(["verify", x["evidence_id"]], "Verifying"))(self.selected()))
        self.btn(irow, "Open Autopsy", "search", "muted", lambda: self._launch("autopsy"))
        icard.body.addLayout(irow)
        self.table = make_table(["Evidence ID", "Case", "Operator", "Acquired (UTC)", "Size", "Signed", "Description", "Location"])
        self.table.setMinimumHeight(130)
        icard.body.addWidget(self.table, 1)
        self.body.addWidget(icard, 1)

    def _lsblk(self):
        try:
            r = subprocess.run(["lsblk", "-J", "-b", "-o", "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,RO,MOUNTPOINTS"],
                               capture_output=True, text=True, timeout=10)
            return json.loads(r.stdout).get("blockdevices", [])
        except (OSError, subprocess.SubprocessError, ValueError):
            return []

    def apply(self, store, index):
        rows, colors, self.disks = [], {}, []
        for d in self._lsblk():
            if d.get("type") not in ("disk", "loop") or not int(d.get("size") or 0):
                continue

            def mounts(n):
                out = [m for m in (n.get("mountpoints") or []) if m]
                for c in n.get("children", []):
                    out += mounts(c)
                return out
            mp = mounts(d)
            system = any(m in ("/", "/boot", "/boot/efi", "/home", "/var", "[SWAP]") for m in mp)
            note = "system disk: cannot be imaged from the running system" if system else \
                ("unmount before imaging" if mp else "ready to image")
            if d.get("type") == "loop" and not mp:
                note = "loop device"
            self.disks.append(d)
            rows.append([d.get("path", ""), human(d.get("size")), (d.get("model") or "").strip(), d.get("serial") or "",
                         d.get("tran") or "", "yes" if str(d.get("ro")) in ("1", "True", "true") else "no",
                         ", ".join(mp), note])
            if system:
                colors[len(rows) - 1] = C["text3"]
        fill(self.dtable, rows, colors)
        on = os.path.exists("/etc/udev/rules.d/01-nefi-writeblock.rules")
        self.stats["disks"].set(len(rows))
        self.stats["blocker"].set("ON" if on else "off", C["accent"] if on else C["warn"])
        self.stats["images"].set(len(self.items) if index is not None else "–")
        missing = [t for t in ("ewfacquire", "fls", "foremost") if not shutil.which(t)]
        self.note.setText(("Not installed: " + ", ".join(missing) + " (packages ewf-tools, sleuthkit, foremost: "
                           "in the 'large' software selection).") if missing else "")
        fill(self.table, [[x.get("evidence_id", ""), x.get("case", ""), x.get("operator", ""),
                           (x.get("collected_utc") or "").replace("T", " ").replace("Z", ""), human(x.get("size", 0)),
                           "yes" if x.get("signed") else "NO", x.get("description", ""),
                           os.path.dirname((x.get("objects") or [{}])[0].get("path") or "")] for x in self.items])

    def _pick_dest(self):
        path = QFileDialog.getExistingDirectory(self, "Destination folder for the image (another disk)", "/media")
        if path:
            self.dest.setText(path)

    def _acquire(self):
        sel = self.dtable.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Acquire", "Select the disk to image in the table.")
            return
        dev = self.dtable.item(sel[0].row(), 0).text()
        dest = self.dest.text().strip()
        if not dest:
            QMessageBox.information(self, "Acquire", "Choose the destination folder (on another disk).")
            return
        args = self.case_args()
        if not args:
            return
        if QMessageBox.question(self, "Acquire image", f"Acquire {dev} into {dest}?\n\nThe disk is set read-only and the "
                                "block is verified first; if it cannot be verified nothing is read.") \
                == QMessageBox.StandardButton.Yes:
            self.dfir(["image", dev, dest, self.fmt.currentData()] + args, f"Acquiring {dev}")

    def _analyze(self):
        x = self.selected()
        if x:
            self.dfir(["analyze", x["evidence_id"], self.tool.currentData()], f"{self.tool.currentText()}")

    def _launch(self, prog):
        if not shutil.which(prog):
            QMessageBox.information(self, prog, f"{prog} is not installed (sudo apt install {prog}).")
            return
        try:
            subprocess.Popen([prog], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if prog == "autopsy":
                self.log.append("Autopsy started: open http://localhost:9999/autopsy in the browser.")
        except OSError as e:
            QMessageBox.warning(self, prog, str(e))
