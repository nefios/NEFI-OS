"""NEFI Security Center — Response: Incidents, Playbooks, Host Isolation, Containment, Recovery.

Le pagine girano come utente e leggono /var/lib/nefi/ir (root:sudo 0640). Ogni azione passa da
/opt/nefi/ir/irctl.py (o dagli script di isolamento) con pkexec e finisce nella cronologia
dell'incidente, che e' in sola aggiunta e concatenata con hash.
"""
import json
import os
import socket
import sys
import time

import psutil
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QTextEdit, QInputDialog, QFileDialog,
    QSplitter, QTabWidget
)
from PyQt6.QtCore import Qt

from nefi_theme import C, Card, SectionLabel, GhostButton
from prevention_pages import make_table, fill, INPUT_QSS
from system_pages import CmdWorker
from detection_pages import EnginePage, read_json, short_time, combo
import ir_report
import ir_state

for _p in ("/opt/nefi/ir", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..",
                                         "opt", "nefi", "ir")):
    if os.path.isfile(os.path.join(_p, "irlib.py")) and _p not in sys.path:
        sys.path.insert(0, _p)
        break
import irlib as ir           # noqa: E402

IRCTL = ["pkexec", "/usr/bin/python3", "/opt/nefi/ir/irctl.py"]
DFIR = ["pkexec", "/usr/bin/python3", "/opt/nefi/forensics/dfir.py"]
SCRIPT = ["pkexec", "/bin/bash"]
PREFS = os.path.expanduser("~/.config/nefi/dfir.json")
REPORTS = os.path.expanduser("~/Documents/NEFI-reports")
SEV_COLOR = {"low": C["text2"], "medium": C["warn"], "high": C["danger"], "critical": C["danger"]}
STATUS_TEXT = {"new": "New", "investigating": "Investigating", "contained": "Contained", "eradicated": "Eradicated",
               "recovering": "Recovering", "closed": "Closed"}
STEP_TEXT = {"done": "Done", "skipped": "Skipped", "failed": "FAILED", "todo": "To do"}
TABS_QSS = (f"QTabWidget::pane {{ border: none; }} QTabBar::tab {{ background: transparent; color: {C['text2']}; "
            f"padding: 8px 18px; border: 1px solid {C['border']}; border-radius: 8px; margin-right: 6px; }} "
            f"QTabBar::tab:selected {{ color: {C['accent']}; border-color: {C['accent']}; background: {C['card2']}; }}")
SHARED = {"case": ""}          # l'incidente su cui si sta lavorando, comune a tutte le pagine Response


def cases_index():
    return read_json(os.path.join(ir.CASES, "index.json"), []) or []


def load_case(cid):
    return read_json(os.path.join(ir.CASES, cid + ".json"), None) if ir.CASE_RE.fullmatch(cid or "") else None


def evidence_for(case):
    """Prove dell'archivio DFIR raccolte per questo incidente (campo 'case') o collegate a mano."""
    conf = read_json("/etc/nefi/forensics.json", {}) or {}
    index = read_json(os.path.join(conf.get("store") or "/var/lib/nefi/forensics", "index.json"), []) or []
    linked = set(case.get("links", {}).get("evidence", []))
    return [e for e in index if e.get("case") == case["id"] or e.get("evidence_id") in linked]


def set_combo(box, items, keep):
    box.blockSignals(True)
    box.clear()
    for label, data in items:
        box.addItem(label, data)
    i = box.findData(keep)
    box.setCurrentIndex(i if i >= 0 else 0)
    box.blockSignals(False)


def write_pdf(html, path, title):
    """HTML -> PDF A4 con Qt (nessun programma esterno)."""
    from PyQt6.QtGui import QTextDocument, QPdfWriter, QPageSize, QPageLayout
    from PyQt6.QtCore import QMarginsF, QSizeF
    pdf = QPdfWriter(path)
    pdf.setResolution(96)                      # 96 punti per pollice: i "px" del rapporto hanno la misura giusta
    pdf.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    pdf.setPageMargins(QMarginsF(14, 14, 14, 14), QPageLayout.Unit.Millimeter)
    pdf.setTitle(title)
    doc = QTextDocument()
    doc.setDefaultStyleSheet("td, th { font-size: 11px; } body { font-size: 12px; }")
    doc.setHtml(html)
    doc.setPageSize(QSizeF(pdf.width(), pdf.height()))
    doc.print(pdf)


def ask_operator(parent):
    prefs = read_json(PREFS, {}) or {}
    name, ok = QInputDialog.getText(parent, "Operator", "Your full name (written in the evidence manifest):",
                                    text=prefs.get("operator", ""))
    if not ok or not name.strip():
        return None
    try:
        os.makedirs(os.path.dirname(PREFS), exist_ok=True)
        with open(PREFS, "w", encoding="utf-8") as f:
            json.dump(dict(prefs, operator=name.strip()), f)
    except OSError:
        pass
    return name.strip()


class RespPage(EnginePage):
    """Base delle pagine Response: scelta dell'incidente, comandi irctl, registro a video."""
    def btn(self, row, label, icon, tone, fn):
        b = GhostButton(label, icon, 32, tone=tone)
        b.clicked.connect(fn)
        row.addWidget(b)
        return b

    def edit(self, row, placeholder, width, stretch=0):
        e = QLineEdit()
        e.setPlaceholderText(placeholder)
        e.setStyleSheet(INPUT_QSS)
        e.setMinimumWidth(width)
        row.addWidget(e, stretch)
        return e

    def case_box(self, row, optional=True):
        self.optional_case = optional
        row.addWidget(QLabel("Incident:"))
        self.cases = combo([], 380)
        self.cases.currentIndexChanged.connect(self._case_changed)
        row.addWidget(self.cases)

    def _case_changed(self, _i):
        SHARED["case"] = self.cases.currentData() or ""
        self.refresh(force=True)

    def reload_cases(self):
        items = [(f"{c['id']}  ·  {c.get('title', '')[:60]}", c["id"]) for c in cases_index()
                 if c.get("status") != "closed"]
        if self.optional_case:
            items.insert(0, ("(no incident: record in the general log only)", ""))
        elif not items:
            items = [("(no open incident: open one in Response > Incidents)", "")]
        set_combo(self.cases, items, SHARED["case"])
        return self.cases.currentData() or ""

    def need_case(self):
        cid = self.cases.currentData()
        if not cid:
            QMessageBox.information(self, "Incident", "Open an incident first (Response > Incidents) and select it here.")
        return cid

    def irctl(self, args, title, case=""):
        self.run_cmd(IRCTL + (["--case", case] if case else []) + list(args), title + " (admin password)…")

    def add_log(self, layout, placeholder, max_height=0):
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(120)
        if max_height:
            self.log.setMaximumHeight(max_height)
        self.log.setPlaceholderText(placeholder)
        self.log.setStyleSheet(f"background: {C['bg']}; color: {C['accent']}; border: 1px solid {C['border']}; "
                               f"border-radius: 8px; font-family: monospace; font-size: 12px;")
        layout.addWidget(self.log)

    def run_log(self, cmd, title):
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

    def go(self, page):
        if page and hasattr(self.window(), "open_module"):
            self.window().open_module(page)

    def stamp(self, *paths):
        sig = [SHARED["case"]]
        for p in paths:
            try:
                sig.append(os.stat(p).st_mtime_ns)
            except OSError:
                sig.append(0)
        if sig == self._sig:
            return False
        self._sig = sig
        return True


# ───────────────────────────── Incidents ─────────────────────────────
class IncidentsPage(RespPage):
    TITLE = "Incidents"
    SUBTITLE = ("One record per incident: what happened, how serious it is, everything that was done and by whom. "
                "Containment actions, playbook steps and evidence collected for an incident are added to its timeline "
                "automatically; the timeline cannot be edited afterwards.")
    STATS = [("open", "open incidents"), ("serious", "open, high or critical"), ("contained", "contained, not closed"),
             ("closed", "closed")]

    def build(self):
        self.index, self.case = [], None
        new = Card(padding=18)
        new.body.addWidget(SectionLabel("New incident"))
        row = QHBoxLayout()
        self.f_title = self.edit(row, "What happened, in a few words", 300, 2)
        self.f_sev = combo([(s.capitalize(), s) for s in ir.SEVERITIES], 110)
        self.f_sev.setCurrentIndex(1)
        self.f_sev.currentIndexChanged.connect(lambda _i: self.sev_help.setText(ir.SEVERITY_HELP[self.f_sev.currentData()]))
        row.addWidget(self.f_sev)
        self.f_cat = combo([(label, cid) for cid, label in ir.CATEGORIES.items()], 220)
        row.addWidget(self.f_cat)
        self.btn(row, "Open incident", "siren", "ok", self._open)
        new.body.addLayout(row)
        row = QHBoxLayout()
        self.f_desc = self.edit(row, "Description: what you saw, when, how you noticed (optional)", 300, 1)
        new.body.addLayout(row)
        self.sev_help = QLabel(ir.SEVERITY_HELP["medium"])
        self.sev_help.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        new.body.addWidget(self.sev_help)
        self.body.addWidget(new)

        split = QSplitter(Qt.Orientation.Vertical)
        split.setStyleSheet("QSplitter::handle { background: transparent; height: 12px; }")
        lst = Card(padding=18)
        lst.body.addWidget(SectionLabel("Incidents"))
        self.table = make_table(["Incident", "Opened", "Severity", "Category", "Status", "Title", "Handled by"])
        self.table.itemSelectionChanged.connect(self._select)
        lst.body.addWidget(self.table, 1)
        split.addWidget(lst)

        det = Card(padding=18)
        self.head = QLabel("Select an incident")
        self.head.setWordWrap(True)
        self.head.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.head.setStyleSheet("font-size: 14px; background: transparent;")
        det.body.addWidget(self.head)
        row = QHBoxLayout()
        self.d_status = combo([(STATUS_TEXT[s], s) for s in ir.STATUSES[:-1]], 140)
        self.d_sev = combo([(s.capitalize(), s) for s in ir.SEVERITIES], 110)
        self.d_cat = combo([(label, cid) for cid, label in ir.CATEGORIES.items()], 200)
        for label, box, field in (("Status", self.d_status, "status"), ("Severity", self.d_sev, "severity"),
                                  ("Category", self.d_cat, "category")):
            row.addWidget(QLabel(label))
            row.addWidget(box)
            box.activated.connect(lambda _i, b=box, f=field: self._set(f, b.currentData()))
        row.addStretch()
        det.body.addLayout(row)
        row = QHBoxLayout()
        self.btn(row, "Collect evidence", "folder", "ok", self._collect)
        self.btn(row, "Playbook", "list", "muted", lambda: self.go("playbooks"))
        self.btn(row, "Recovery", "refresh", "muted", lambda: self.go("recovery"))
        self.btn(row, "Export report", "file", "muted", self._report)
        self.btn(row, "Verify", "fingerprint", "muted", self._verify)
        row.addStretch()
        self.btn(row, "Close incident", "check_sq", "danger", self._close)
        det.body.addLayout(row)
        row = QHBoxLayout()
        self.f_note = self.edit(row, "Add a note to the timeline (finding, decision, phone call…)", 300, 1)
        self.f_note.returnPressed.connect(self._note)
        self.btn(row, "Add note", "check_sq", "muted", self._note)
        det.body.addLayout(row)
        self.timeline = make_table(["Time", "Event", "Details", "By"])
        self.timeline.setSortingEnabled(False)
        det.body.addWidget(self.timeline, 1)
        split.addWidget(det)
        split.setSizes([200, 460])
        self.body.addWidget(split, 1)

    def _open(self):
        title = self.f_title.text().strip()
        if len(title) < 4:
            QMessageBox.information(self, "New incident", "Write a short title: what happened.")
            return
        args = ["case-open", self.f_sev.currentData(), self.f_cat.currentData(), title]
        if self.f_desc.text().strip():
            args.append(self.f_desc.text().strip()[:480])
        self.f_title.clear()
        self.f_desc.clear()
        self.irctl(args, "Opening the incident")

    def _select(self):
        sel = self.table.selectionModel().selectedRows()
        if sel:
            SHARED["case"] = self.table.item(sel[0].row(), 0).text()
            self._show()

    def _current(self):
        if not self.case:
            QMessageBox.information(self, "Incident", "Select an incident in the table first.")
            return None
        return self.case

    def _editable(self):
        case = self._current()
        if case and case.get("status") == "closed":
            QMessageBox.information(self, "Incident", "This incident is closed: it can only be read and exported.")
            return None
        return case

    def _set(self, field, value):
        case = self._editable()
        if case and case.get(field) != value:
            self.irctl(["case-set", case["id"], field, value], f"Changing the {field}")

    def _note(self):
        case, text = self._editable(), self.f_note.text().strip()
        if case and text:
            self.f_note.clear()
            self.irctl(["case-note", case["id"], text[:490]], "Adding the note")

    def _collect(self):
        case = self._editable()
        operator = ask_operator(self) if case else None
        if operator:
            self.run_cmd(DFIR + ["collect", case["id"], operator, f"Incident {case['id']}: {case['title']}"[:190]],
                         "Collecting evidence for this incident (admin password, a few minutes)…")

    def _verify(self):
        case = self._current()
        if case:
            self.irctl(["case-verify", case["id"]], "Verifying the timeline")

    def _close(self):
        case = self._editable()
        if not case:
            return
        left = [label for rid, label, _a, _h in ir.RECOVERY if ir.recovery_state(case)[rid] == "todo"]
        if left:
            if QMessageBox.question(self, "Close incident", f"{len(left)} item(s) of the recovery checklist are still "
                                    "open:\n\n• " + "\n• ".join(left[:8]) + "\n\nOpen the Recovery page?") \
                    == QMessageBox.StandardButton.Yes:
                self.go("recovery")
            return
        summary, ok = QInputDialog.getMultiLineText(self, "Close incident", "Closing summary: what it was, how it was "
                                                    "resolved, what changes (max 500 characters):")
        if ok and summary.strip():
            self.irctl(["case-close", case["id"], " ".join(summary.split())[:490]], "Closing the incident")

    def _report(self):
        case = self._current()
        if not case:
            return
        tl_path = ir.timeline_path(case["id"])
        books, _ = ir.load_playbooks()
        state = ir.recovery_state(case)
        html = ir_report.build(case, ir.read_chain(tl_path), evidence_for(case),
                               books.get((case.get("playbook") or {}).get("id", "")),
                               [(label, state[rid]) for rid, label, _a, _h in ir.RECOVERY],
                               {"categories": ir.CATEGORIES}, ir.verify_chain(tl_path)[0], socket.gethostname())
        try:
            os.makedirs(REPORTS, exist_ok=True)
            base = os.path.join(REPORTS, f"{case['id']}-{time.strftime('%Y%m%d-%H%M')}")
            with open(base + ".html", "w", encoding="utf-8") as f:
                f.write(html)
            os.chmod(base + ".html", 0o600)
            saved = [base + ".html"]
            try:
                write_pdf(html, base + ".pdf", f"Incident report {case['id']}")
                os.chmod(base + ".pdf", 0o600)
                saved.append(base + ".pdf")
            except Exception as e:                       # il PDF e' un extra: l'HTML e' gia' salvato
                saved.append(f"(PDF not created: {e})")
            QMessageBox.information(self, "Incident report", "Report saved:\n\n" + "\n".join(saved))
        except OSError as e:
            QMessageBox.warning(self, "Incident report", f"Could not save the report: {e}")

    def _show(self):
        self.case = load_case(SHARED["case"])
        c = self.case
        if not c:
            self.head.setText("Select an incident" if self.index else "No incident yet. Open one above, or from an "
                              "alert in Detection > Detections and Monitoring > Network IDS.")
            fill(self.timeline, [])
            return
        ev = evidence_for(c)
        pb = c.get("playbook") or {}
        closed = f"  ·  closed {short_time(c.get('closed'))}" if c.get("closed") else ""
        self.head.setText(
            f"<b>{c['id']}</b>  ·  {c.get('title', '')}{closed}<br>"
            f"<span style='color:{C['text2']}'>{c.get('description') or 'No description.'}</span><br>"
            f"<span style='color:{C['text3']}'>Evidence: {', '.join(e['evidence_id'] for e in ev) or 'none yet'}"
            f"  ·  Playbook: {pb.get('title') or 'not started'}"
            + (f"  ·  Summary: {c['summary']}" if c.get("summary") else "") + "</span>")
        for box, field in ((self.d_status, "status"), (self.d_sev, "severity"), (self.d_cat, "category")):
            box.blockSignals(True)
            i = box.findData(c.get(field))
            box.setCurrentIndex(i if i >= 0 else 0)
            box.setEnabled(c.get("status") != "closed")
            box.blockSignals(False)
        rows = [[short_time(r.get("ts")), ir_report.DESCRIBE.get(r.get("action"), r.get("action", "")),
                 ir_report.details_text(r)[:400], r.get("account", "")]
                for r in reversed(ir.read_chain(ir.timeline_path(c["id"])))]
        fill(self.timeline, rows)
        self.timeline.setSortingEnabled(False)

    def refresh(self, force=False):
        tl = ir.timeline_path(SHARED["case"]) if ir.CASE_RE.fullmatch(SHARED["case"] or "") else ""
        if not self.stamp(os.path.join(ir.CASES, "index.json"), tl) and not force:
            return
        self.index = cases_index()
        opened = [c for c in self.index if c.get("status") != "closed"]
        serious = [c for c in opened if c.get("severity") in ("high", "critical")]
        self.stats["open"].set(len(opened), C["warn"] if opened else C["accent"])
        self.stats["serious"].set(len(serious), C["danger"] if serious else C["accent"])
        self.stats["contained"].set(sum(1 for c in opened if c.get("status") in ("contained", "eradicated", "recovering")))
        self.stats["closed"].set(len(self.index) - len(opened))
        self.note.setText("" if os.path.isdir(ir.CASES) else "No incident has been opened on this machine yet.")
        if self.index and not any(c["id"] == SHARED["case"] for c in self.index):
            SHARED["case"] = self.index[0]["id"]
        self.table.blockSignals(True)
        fill(self.table, [[c["id"], short_time(c.get("opened")), str(c.get("severity", "")).capitalize(),
                           ir.CATEGORIES.get(c.get("category"), c.get("category", "")),
                           STATUS_TEXT.get(c.get("status"), c.get("status", "")), c.get("title", ""),
                           c.get("assignee", "")] for c in self.index],
             {i: (C["text3"] if c.get("status") == "closed" else SEV_COLOR.get(c.get("severity"), C["text"]))
              for i, c in enumerate(self.index)})
        for r in range(self.table.rowCount()):
            if self.table.item(r, 0).text() == SHARED["case"]:
                self.table.selectRow(r)
        self.table.blockSignals(False)
        self._show()


# ───────────────────────────── Playbooks ─────────────────────────────
class PlaybookPage(RespPage):
    TITLE = "Playbooks"
    SUBTITLE = ("A playbook is the procedure for one kind of incident, step by step, in the order that loses the "
                "least evidence. Manual steps tell you what to do and where; automatic steps run only when you press "
                "'Run action'. Every step you complete or skip is written in the incident timeline.")
    STATS = [("done", "steps completed"), ("left", "steps left"), ("phase", "current phase"),
             ("auto", "automatic actions")]

    def build(self):
        self.books, self.case, self.pb = {}, None, None
        card = Card(padding=18)
        row = QHBoxLayout()
        self.case_box(row, optional=False)
        row.addWidget(QLabel("Playbook:"))
        self.pbs = combo([], 320)
        self.pbs.currentIndexChanged.connect(lambda _i: self._describe())
        row.addWidget(self.pbs)
        self.b_start = self.btn(row, "Start playbook", "play", "ok", self._start)
        row.addStretch()
        card.body.addLayout(row)
        self.desc = QLabel("")
        self.desc.setWordWrap(True)
        self.desc.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        card.body.addWidget(self.desc)
        self.body.addWidget(card)

        steps = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Steps"))
        row.addStretch()
        self.btn(row, "Run action", "play", "ok", self._run)
        self.btn(row, "Open page", "search", "muted", lambda: self.go((self._step() or {}).get("page")))
        self.btn(row, "Mark done", "check_sq", "ok", lambda: self._mark("done"))
        self.btn(row, "Skip…", "x", "warn", lambda: self._mark("skipped"))
        self.btn(row, "Reopen", "refresh", "muted", lambda: self._mark("todo"))
        steps.body.addLayout(row)
        self.table = make_table(["#", "Phase", "Step", "State", "Kind", "By", "When", "Note"])
        self.table.setSortingEnabled(False)
        self.table.itemSelectionChanged.connect(self._help)
        steps.body.addWidget(self.table, 2)
        self.help = QLabel("Select a step to read what to do.")
        self.help.setWordWrap(True)
        self.help.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.help.setStyleSheet(f"color: {C['text']}; font-size: 13px; background: {C['bg']}; border: 1px solid "
                                f"{C['border']}; border-radius: 8px; padding: 10px;")
        steps.body.addWidget(self.help)
        self.add_log(steps.body, "The output of automatic actions appears here.", 160)
        self.body.addWidget(steps, 1)

    def _describe(self):
        pb = self.books.get(self.pbs.currentData() or "")
        self.desc.setText(pb["description"] if pb else "")

    def _start(self):
        cid = self.need_case()
        pb = self.books.get(self.pbs.currentData() or "")
        if not cid or not pb:
            return
        if self.case and (self.case.get("playbook") or {}).get("id") and QMessageBox.question(
                self, "Start playbook", "This incident already has a playbook. Start a new one? The steps already done "
                "stay in the timeline, but the checklist starts again.") != QMessageBox.StandardButton.Yes:
            return
        self.irctl(["playbook-start", cid, pb["id"]], "Starting the playbook")

    def _step(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel or not self.pb:
            QMessageBox.information(self, "Playbook", "Start a playbook and select a step first.")
            return None
        return self.pb["steps"][sel[0].row()]

    def _help(self):
        sel = self.table.selectionModel().selectedRows()
        if sel and self.pb:
            s = self.pb["steps"][sel[0].row()]
            kind = ("<span style='color:%s'>Automatic action: press 'Run action'.</span>" % C["accent"]) if s["action"] \
                else "Manual step" + (": 'Open page' takes you there." if s["page"] else ".")
            self.help.setText(f"<b>{s['title']}</b><br>{s['help']}<br><span style='color:{C['text3']}'>{kind}</span>")

    def _mark(self, state):
        s = self._step()
        if not s:
            return
        args = ["playbook-step", self.case["id"], s["id"], state]
        if state == "skipped":
            why, ok = QInputDialog.getText(self, "Skip step", f"Why is '{s['title']}' skipped?")
            if not ok or not why.strip():
                return
            args.append(why.strip()[:400])
        self.irctl(args, "Updating the step")

    def _run(self):
        s = self._step()
        if not s:
            return
        if not s["action"]:
            QMessageBox.information(self, "Playbook", "This is a manual step: do what it says, then press 'Mark done'.")
            return
        warn = {"isolate": "This cuts EVERY network connection of this machine. The network comes back by itself after "
                           "15 minutes unless you confirm the isolation in Response > Host Isolation.",
                "memory": "Acquiring the memory writes a file as large as the RAM and can take several minutes.",
                "capture": "Records all network traffic for 10 minutes (200 MB at most)."}.get(s["action"], "")
        if QMessageBox.question(self, "Run action", f"Run '{s['title']}' now?\n\n{warn}") == QMessageBox.StandardButton.Yes:
            self.run_log(IRCTL + ["playbook-run", self.case["id"], s["id"]], f"{s['title']} (admin password)…")

    def refresh(self, force=False):
        cid_now = SHARED["case"]
        tl = ir.timeline_path(cid_now) if ir.CASE_RE.fullmatch(cid_now or "") else ""
        if not self.stamp(os.path.join(ir.CASES, "index.json"), tl) and not force:
            return
        self.books, errors = ir.load_playbooks()
        self.note.setText(("Playbooks with errors (not loaded): " + "; ".join(errors)) if errors else
                          "Your own playbooks go in /etc/nefi/ir/playbooks (format: /usr/share/nefi/ir/playbooks/README.md).")
        cid = self.reload_cases()
        self.case = load_case(cid)
        book = (self.case or {}).get("playbook") or {}
        self.pb = self.books.get(book.get("id", ""))
        cat = (self.case or {}).get("category")
        order = sorted(self.books.values(), key=lambda b: (cat not in b["categories"], b["title"]))
        set_combo(self.pbs, [(("★ " if cat in b["categories"] else "") + b["title"], b["id"]) for b in order],
                  book.get("id") or (order[0]["id"] if order else ""))
        self._describe()
        if not self.pb:
            for k in self.stats:
                self.stats[k].set("–")
            fill(self.table, [])
            self.help.setText("Choose the incident and the playbook (★ = suggested for its category), then press "
                              "'Start playbook'.")
            return
        state = book.get("steps", {})
        rows, colors, phase = [], {}, ""
        for i, s in enumerate(self.pb["steps"]):
            st = state.get(s["id"], {})
            cur = st.get("state", "todo")
            if cur in ("todo", "failed") and not phase:
                phase = s["phase"]
            colors[i] = {"done": C["accent"], "skipped": C["text3"], "failed": C["danger"]}.get(cur, C["text"])
            rows.append([i + 1, s["phase"], s["title"], STEP_TEXT[cur], "automatic" if s["action"] else "manual",
                         st.get("by", ""), short_time(st.get("ts")) if st.get("ts") else "", st.get("note", "")])
        sel = self.table.selectionModel().selectedRows()
        keep = sel[0].row() if sel else next((i for i, s in enumerate(self.pb["steps"])
                                              if state.get(s["id"], {}).get("state", "todo") in ("todo", "failed")), 0)
        fill(self.table, rows, colors)
        self.table.setSortingEnabled(False)
        self.table.selectRow(min(keep, len(rows) - 1))
        done, total = ir.playbook_progress(self.case, self.pb)
        self.stats["done"].set(done, C["accent"])
        self.stats["left"].set(total - done, C["warn"] if total - done else C["accent"])
        self.stats["phase"].set(phase or "Complete")
        self.stats["auto"].set(sum(1 for s in self.pb["steps"] if s["action"]))


# ───────────────────────────── Host Isolation ─────────────────────────────
class IsolationPage(RespPage):
    TITLE = "Host Isolation"
    SUBTITLE = ("Cuts this machine off the network so an attacker or a malicious program can neither receive commands "
                "nor reach other machines. It also protects the logs from tampering, saves the list of processes and "
                "connections, and collects evidence. Local work continues; nothing is shut down.")
    STATS = [("state", "network"), ("mode", "mode"), ("since", "isolated since"), ("net", "safety net")]

    def build(self):
        opt = Card(padding=18)
        opt.body.addWidget(SectionLabel("Isolate this machine"))
        row = QHBoxLayout()
        self.case_box(row, optional=True)
        row.addStretch()
        opt.body.addLayout(row)
        row = QHBoxLayout()
        row.addWidget(QLabel("Safety net:"))
        self.f_roll = combo([("Restore the network after 15 minutes unless I confirm", "15"),
                             ("…after 5 minutes", "5"), ("…after 30 minutes", "30"), ("…after 60 minutes", "60"),
                             ("No safety net (stay isolated until I exit)", "0")], 380)
        row.addWidget(self.f_roll)
        self.f_allow = self.edit(row, "Keep ONE address reachable (optional, e.g. your admin PC)", 340)
        row.addStretch()
        opt.body.addLayout(row)
        row = QHBoxLayout()
        self.b_on = self.btn(row, "Isolate now", "siren", "danger", self._activate)
        self.b_confirm = self.btn(row, "Confirm isolation (stop the countdown)", "lock", "warn", self._confirm)
        self.b_off = self.btn(row, "Exit: restore the network", "check_sq", "ok", self._deactivate)
        row.addStretch()
        opt.body.addLayout(row)
        tip = QLabel("If the Security Center is not available while the machine is isolated: open a terminal, or a text "
                     "console with Ctrl+Alt+F3, and run  <b>sudo nefi-ir-recover</b>. An isolation you confirmed is "
                     "applied again after a reboot; one you did not confirm is removed.")
        tip.setWordWrap(True)
        tip.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        opt.body.addWidget(tip)
        self.body.addWidget(opt)
        out = Card(padding=18)
        out.body.addWidget(SectionLabel("Output"))
        self.add_log(out.body, "What the isolation does appears here, step by step.")
        self.body.addWidget(out, 1)

    def _activate(self):
        allow, roll = self.f_allow.text().strip(), self.f_roll.currentData()
        if allow:
            try:
                ir.check_ioc("ip", allow)
            except ir.IRError:
                QMessageBox.information(self, "Host isolation", "The address to keep reachable is not a valid IP address.")
                return
        text = ("Isolate this machine from the network NOW?\n\n• every connection is cut"
                + (f", except with {allow}" if allow else "")
                + "\n• downloads, remote sessions and updates stop\n• "
                + (f"the network comes back by itself after {roll} minutes unless you press 'Confirm isolation'"
                   if roll != "0" else "there is NO automatic restore: you must exit by hand"))
        if QMessageBox.warning(self, "Host isolation", text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        cmd = SCRIPT + ["/opt/nefi/ir/activate.sh", "--rollback", roll]
        cmd += ["--allow", allow] if allow else []
        cmd += ["--case", self.cases.currentData()] if self.cases.currentData() else []
        self.run_log(cmd, "Activating the isolation (admin password)…")

    def _confirm(self):
        self.run_log(SCRIPT + ["/opt/nefi/ir/confirm.sh"], "Confirming the isolation (admin password)…")

    def _deactivate(self):
        if QMessageBox.question(self, "Host isolation", "Restore the network? Do it only when the threat is contained "
                                "(process terminated, files quarantined, indicators blocked).") \
                == QMessageBox.StandardButton.Yes:
            self.run_log(SCRIPT + ["/opt/nefi/ir/deactivate.sh"], "Restoring the network (admin password)…")

    def refresh(self, force=False):
        if self.cases.count() == 0 or force:
            self.reload_cases()
        st = ir_state.read()
        active = ir_state.is_active(st)
        busy = bool(self.worker and self.worker.isRunning())
        left = 0
        if active and st.get("CONFIRMED") == "false" and st.get("ROLLBACK_AT", "").isdigit():
            left = int(st["ROLLBACK_AT"]) - int(time.time())
        self.stats["state"].set("ISOLATED" if active else "Connected", C["danger"] if active else C["accent"])
        self.stats["mode"].set(("Only " + st.get("ALLOW_IP", "?")) if active and st.get("MODE") == "selective"
                               else "Everything blocked" if active else "–")
        self.stats["since"].set(st.get("IR_START", "")[11:16] + " UTC" if active else "–")
        if not active:
            self.stats["net"].set("–")
        elif st.get("CONFIRMED") == "false":
            self.stats["net"].set(f"restores in {max(0, left) // 60}:{max(0, left) % 60:02d}", C["warn"])
        else:
            self.stats["net"].set("off (confirmed)")
        note = ""
        if active and st.get("CONFIRMED") == "false":
            note = ("The isolation is NOT confirmed: the network comes back by itself when the countdown ends. If you "
                    "can read this and want to stay isolated, press 'Confirm isolation'.")
        elif not active and st.get("AUTO_RELEASED") == "true":
            note = (f"The last isolation was removed automatically ({st.get('IR_END', '')}) because it was not "
                    "confirmed in time.")
        elif active and st.get("EVIDENCE_COLLECTED") == "false":
            note = "Isolated, but the automatic evidence collection failed: collect it from DFIR > Evidence & Custody."
        self.note.setText(note)
        self.note.setStyleSheet(f"color: {C['warn']}; font-size: 12px; background: transparent;")
        self.b_on.setEnabled(not active and not busy)
        self.b_confirm.setEnabled(active and st.get("CONFIRMED") == "false" and not busy)
        self.b_off.setEnabled(active and not busy)
        for w in (self.f_roll, self.f_allow, self.cases):
            w.setEnabled(not active)


# ───────────────────────────── Containment ─────────────────────────────
class ContainmentPage(RespPage):
    TITLE = "Containment"
    SUBTITLE = ("Smaller tools than isolating the whole machine: stop one process, lock one file away, block one "
                "address or domain. Every action records who did it, when, and the SHA-256 of the program or file "
                "involved, so it can be used as evidence and undone if it was a mistake.")
    STATS = [("frozen", "processes suspended"), ("quar", "files in quarantine"), ("iocs", "indicators blocked"),
             ("sweep", "matches in the last sweep")]

    def build(self):
        self.procs, self.quar, self.iocs = [], [], []
        top = Card(padding=18)
        row = QHBoxLayout()
        self.case_box(row, optional=True)
        row.addStretch()
        top.body.addLayout(row)
        self.body.addWidget(top)
        card = Card(padding=18)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(TABS_QSS)
        card.body.addWidget(self.tabs, 1)
        self.body.addWidget(card, 1)

        # processi
        w, lay = self._tab("Processes")
        row = QHBoxLayout()
        self.f_filter = self.edit(row, "Filter: name, user, PID or path", 280)
        self.f_filter.textChanged.connect(lambda _t: self._fill_procs())
        self.btn(row, "Refresh list", "refresh", "muted", lambda: self._load_procs())
        row.addStretch()
        self.btn(row, "Freeze", "lock", "warn", lambda: self._proc("proc-freeze"))
        self.btn(row, "Resume", "play", "muted", lambda: self._proc("proc-resume"))
        self.btn(row, "Terminate", "x", "danger", lambda: self._proc("proc-kill"))
        lay.addLayout(row)
        hint = QLabel("Freeze first, terminate later: a suspended process cannot act, but its memory can still be "
                      "acquired (DFIR > Memory Forensics). Terminating it destroys that evidence.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        lay.addWidget(hint)
        self.ptable = make_table(["PID", "User", "Name", "State", "Started", "Program", "Command line"])
        lay.addWidget(self.ptable, 1)

        # quarantena
        w, lay = self._tab("File quarantine")
        row = QHBoxLayout()
        self.f_path = self.edit(row, "Full path of the file", 320, 2)
        self.btn(row, "Browse…", "folder", "muted", self._browse)
        self.f_qreason = self.edit(row, "Reason", 200, 1)
        self.btn(row, "Quarantine", "lock", "danger", self._quarantine)
        lay.addLayout(row)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Files in quarantine (cannot run, cannot be read by users)"))
        row.addStretch()
        self.btn(row, "Restore", "refresh", "warn", lambda: self._q("quarantine-restore", "Put the file back where it "
                 "was, with its original owner and permissions?"))
        self.btn(row, "Delete for good", "x", "danger", lambda: self._q("quarantine-delete", "Delete the quarantined "
                 "copy for good? Collect it as evidence first if the incident is not closed."))
        lay.addLayout(row)
        self.qtable = make_table(["ID", "Original path", "SHA-256", "Size", "By", "When", "Incident", "Reason"])
        lay.addWidget(self.qtable, 1)

        # indicatori
        w, lay = self._tab("Indicators (IOC)")
        row = QHBoxLayout()
        self.f_kind = combo([("IP address", "ip"), ("Domain", "domain"), ("File hash (SHA-256)", "sha256")], 170)
        row.addWidget(self.f_kind)
        self.f_value = self.edit(row, "Value", 320, 2)
        self.f_inote = self.edit(row, "Note (where it comes from)", 200, 1)
        self.btn(row, "Block", "block", "danger", self._ioc_add)
        lay.addLayout(row)
        row = QHBoxLayout()
        self.sweep_label = QLabel("")
        self.sweep_label.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        row.addWidget(self.sweep_label, 1)
        self.btn(row, "Sweep for hashes", "search", "ok", lambda: self.irctl(
            ["ioc-sweep"], "Looking for files with the blocked hashes (a few minutes)", self.cases.currentData()))
        self.btn(row, "Unblock", "x", "warn", self._ioc_del)
        lay.addLayout(row)
        self.itable = make_table(["Type", "Value", "Note", "By", "When", "Incident"])
        lay.addWidget(self.itable, 1)
        self.tabs.currentChanged.connect(lambda _i: self.refresh(force=True))

    def _tab(self, title):
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 12, 0, 0)
        lay.setSpacing(10)
        self.tabs.addTab(w, title)
        return w, lay

    # ── processi ──
    def _load_procs(self):
        procs = []
        for p in psutil.process_iter(["pid", "username", "name", "status", "create_time", "exe", "cmdline"]):
            i = p.info
            if not i.get("exe") and not i.get("cmdline"):
                continue                                   # thread del kernel
            procs.append({"pid": i["pid"], "user": i.get("username") or "?", "name": i.get("name") or "",
                          "status": "SUSPENDED" if i.get("status") == psutil.STATUS_STOPPED else i.get("status") or "",
                          "started": time.strftime("%m-%d %H:%M:%S", time.localtime(i.get("create_time") or 0)),
                          "exe": i.get("exe") or "", "cmd": " ".join(i.get("cmdline") or [])[:300]})
        self.procs = sorted(procs, key=lambda x: -x["pid"])
        self._fill_procs()

    def _fill_procs(self):
        needle = self.f_filter.text().strip().lower()
        rows = [p for p in self.procs if not needle or needle in
                f"{p['pid']} {p['user']} {p['name']} {p['exe']} {p['cmd']}".lower()]
        fill(self.ptable, [[p["pid"], p["user"], p["name"], p["status"], p["started"], p["exe"], p["cmd"]] for p in rows],
             {i: C["warn"] for i, p in enumerate(rows) if p["status"] == "SUSPENDED"})

    def _proc(self, cmd):
        sel = self.ptable.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Process", "Select a process in the table first.")
            return
        pid, name = self.ptable.item(sel[0].row(), 0).text(), self.ptable.item(sel[0].row(), 2).text()
        try:
            info = ir.proc_info(int(pid))
        except ir.IRError as e:
            QMessageBox.information(self, "Process", str(e))
            self._load_procs()
            return
        why = ir.protected_reason(info)
        if why:
            QMessageBox.information(self, "Process", f"{name} (PID {pid}): {why}.")
            return
        text = {"proc-freeze": f"Suspend {name} (PID {pid})? It stops running but stays in memory.",
                "proc-resume": f"Let {name} (PID {pid}) run again?",
                "proc-kill": f"Terminate {name} (PID {pid})?\n\nIts memory is lost: acquire it first if you need it "
                             "as evidence. Unsaved work in that program is lost."}[cmd]
        if QMessageBox.warning(self, "Process", text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.irctl([cmd, f"{pid}:{info['starttime']}"], "Working on the process", self.cases.currentData())

    # ── quarantena ──
    def _browse(self):
        path, _f = QFileDialog.getOpenFileName(self, "File to quarantine", os.path.expanduser("~"))
        if path:
            self.f_path.setText(path)

    def _quarantine(self):
        path = self.f_path.text().strip()
        if not path.startswith("/"):
            QMessageBox.information(self, "Quarantine", "Write the full path of the file (it starts with /).")
            return
        if QMessageBox.warning(self, "Quarantine", f"Move this file to quarantine?\n\n{path}\n\nIt disappears from where "
                               "it is and can no longer run. You can restore it later.",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            args = ["quarantine", path] + ([self.f_qreason.text().strip()[:190]] if self.f_qreason.text().strip() else [])
            self.f_path.clear()
            self.irctl(args, "Moving the file to quarantine", self.cases.currentData())

    def _q(self, cmd, question):
        sel = self.qtable.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Quarantine", "Select a quarantined file in the table first.")
            return
        qid = self.qtable.item(sel[0].row(), 0).text()
        if QMessageBox.warning(self, "Quarantine", question, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.irctl([cmd, qid], "Working on the quarantined file", self.cases.currentData())

    # ── indicatori ──
    def _ioc_add(self):
        kind, value = self.f_kind.currentData(), self.f_value.text().strip()
        try:
            value = ir.check_ioc(kind, value)
        except ir.IRError as e:
            QMessageBox.information(self, "Indicator", str(e).capitalize() + ".")
            return
        args = ["ioc-add", kind, value] + ([self.f_inote.text().strip()[:190]] if self.f_inote.text().strip() else [])
        self.f_value.clear()
        self.irctl(args, f"Blocking {value}", self.cases.currentData())

    def _ioc_del(self):
        sel = self.itable.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Indicator", "Select an indicator in the table first.")
            return
        value = self.itable.item(sel[0].row(), 1).text()
        item = next((i for i in self.iocs if i["value"] == value), None)
        if item:
            self.irctl(["ioc-del", item["type"], item["value"]], f"Unblocking {item['value']}", self.cases.currentData())

    def refresh(self, force=False):
        if not self.stamp(ir.FROZEN, ir.QINDEX, ir.IOCS, ir.SWEEP, os.path.join(ir.CASES, "index.json")) and not force:
            return
        self.reload_cases()
        frozen = read_json(ir.FROZEN, []) or []
        self.quar = read_json(ir.QINDEX, []) or []
        self.iocs = read_json(ir.IOCS, []) or []
        known = {i["value"] for i in self.iocs if i.get("type") == "ip"}
        for b in read_json("/etc/nefi/detection/blocked.json", []) or []:      # blocchi fatti dalle pagine Detection
            if b.get("ip") and b["ip"] not in known:
                self.iocs.append({"type": "ip", "value": b["ip"], "note": "blocked from Detection", "by": b.get("by", ""),
                                  "ts": b.get("created", ""), "case": ""})
        sweep = read_json(ir.SWEEP, None)
        self.stats["frozen"].set(len(frozen), C["warn"] if frozen else None)
        self.stats["quar"].set(len(self.quar))
        self.stats["iocs"].set(len(self.iocs))
        matches = (sweep or {}).get("matches", [])
        self.stats["sweep"].set(len(matches) if sweep else "–", C["danger"] if matches else None)
        self.note.setText(("Suspended now: " + ", ".join(f"{f['name']} (PID {f['pid']})" for f in frozen[:6])
                           + ". Terminate or resume them before closing the incident.") if frozen else "")
        self.note.setStyleSheet(f"color: {C['warn']}; font-size: 12px; background: transparent;")
        if force:
            self._load_procs()
        fill(self.qtable, [[q["id"], q["path"], q["sha256"], q.get("size", 0), q.get("by", ""), short_time(q.get("ts")),
                            q.get("case", ""), q.get("reason", "")] for q in self.quar])
        kinds = {"ip": "IP address", "domain": "Domain", "sha256": "SHA-256"}
        fill(self.itable, [[kinds.get(i["type"], i["type"]), i["value"], i.get("note", ""), i.get("by", ""),
                            short_time(i.get("ts")), i.get("case", "")] for i in self.iocs])
        if sweep:
            text = f"Last sweep {short_time(sweep.get('ts'))}: {sweep.get('checked', 0)} files checked, {len(matches)} match(es)."
            if matches:
                text += "  " + "; ".join(m["path"] + (f" (running, PID {m['pid']})" if m.get("running") else "")
                                         for m in matches[:4])
            self.sweep_label.setText(text)
            self.sweep_label.setStyleSheet(f"color: {C['danger'] if matches else C['text3']}; font-size: 12px; "
                                           f"background: transparent;")
        else:
            self.sweep_label.setText("IP addresses are blocked in the firewall, domains in /etc/hosts; hashes are "
                                     "looked for with 'Sweep for hashes'.")


# ───────────────────────────── Recovery ─────────────────────────────
class RecoveryPage(RespPage):
    TITLE = "Recovery"
    SUBTITLE = ("Before an incident is closed, the machine must be back to a state you can trust. NEFI verifies what "
                "it can measure (system files, isolation, logs, monitoring, evidence); the rest is for you to do and "
                "tick. An incident can be closed only when every item is done or marked not applicable.")
    STATS = [("done", "items complete"), ("open", "items open"), ("auto", "verified by NEFI"), ("checked", "last check")]

    def build(self):
        self.case = None
        card = Card(padding=18)
        row = QHBoxLayout()
        self.case_box(row, optional=False)
        row.addStretch()
        self.btn(row, "Run checks", "refresh", "ok", self._check)
        self.btn(row, "Mark done", "check_sq", "ok", lambda: self._set("done"))
        self.btn(row, "Not applicable", "x", "muted", lambda: self._set("na"))
        self.btn(row, "Reopen", "refresh", "muted", lambda: self._set("todo"))
        self.btn(row, "Close incident", "check_sq", "danger", lambda: self.go("cases"))
        card.body.addLayout(row)
        self.table = make_table(["Item", "State", "Verified", "How"])
        self.table.setSortingEnabled(False)
        card.body.addWidget(self.table, 2)
        self.add_log(card.body, "'Run checks' verifies the automatic items; the result appears here.", 170)
        self.body.addWidget(card, 1)

    def _check(self):
        cid = self.need_case()
        if cid:
            self.run_log(IRCTL + ["recovery-check", cid], "Running the recovery checks (admin password, about a minute)…")

    def _set(self, state):
        cid = self.need_case()
        sel = self.table.selectionModel().selectedRows()
        if not cid or not sel:
            if cid:
                QMessageBox.information(self, "Recovery", "Select an item in the table first.")
            return
        rid, label, auto, _h = ir.RECOVERY[sel[0].row()]
        if auto and state == "done":
            QMessageBox.information(self, "Recovery", f"'{label}' is verified by NEFI: press 'Run checks'. If it does "
                                    "not apply to this incident, mark it 'Not applicable'.")
            return
        self.irctl(["recovery-set", cid, rid, state], "Updating the checklist")

    def refresh(self, force=False):
        cid_now = SHARED["case"]
        path = os.path.join(ir.CASES, cid_now + ".json") if cid_now else ""
        if not self.stamp(os.path.join(ir.CASES, "index.json"), path) and not force:
            return
        self.case = load_case(self.reload_cases())
        if not self.case:
            for k in self.stats:
                self.stats[k].set("–")
            fill(self.table, [[label, "", "by NEFI" if auto else "by you", how] for _r, label, auto, how in ir.RECOVERY])
            self.table.setSortingEnabled(False)
            return
        state = ir.recovery_state(self.case)
        text = {"done": "Done", "na": "Not applicable", "todo": "To do"}
        sel = self.table.selectionModel().selectedRows()
        keep = sel[0].row() if sel else 0
        fill(self.table, [[label, text[state[rid]], "by NEFI" if auto else "by you", how]
                          for rid, label, auto, how in ir.RECOVERY],
             {i: (C["accent"] if state[r[0]] == "done" else C["text3"] if state[r[0]] == "na" else C["warn"])
              for i, r in enumerate(ir.RECOVERY)})
        self.table.setSortingEnabled(False)
        self.table.selectRow(keep)
        left = sum(1 for v in state.values() if v == "todo")
        self.stats["done"].set(len(state) - left, C["accent"])
        self.stats["open"].set(left, C["warn"] if left else C["accent"])
        self.stats["auto"].set(len(ir.RECOVERY_AUTO))
        checked = self.case.get("auto", {}).get("checked")
        self.stats["checked"].set(short_time(checked)[5:16] if checked else "never", None if checked else C["warn"])
        changed = self.case.get("auto", {}).get("changed_files") or []
        self.note.setText(("Program files that differ from their Debian package: " + ", ".join(changed[:6])
                           + (" …" if len(changed) > 6 else "") + ". Reinstall the packages they belong to "
                           "(dpkg -S FILE tells which one).") if changed else
                          ("Every item is complete: close the incident from Response > Incidents." if not left else ""))
        self.note.setStyleSheet(f"color: {C['warn'] if changed else C['accent']}; font-size: 12px; background: transparent;")
