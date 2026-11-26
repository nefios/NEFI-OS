"""NEFI Security Center — Detection: Detections, Integrity & Persistence, Detection Rules.

Le pagine NON rilevano niente da sole: mostrano il lavoro del servizio root nefi-detectd
(/opt/nefi/detection/detectd.py) e chiedono le modifiche all'helper ctl.py tramite pkexec.
  /var/log/nefi/detection/alerts.jsonl    avvisi (registro a sola aggiunta con catena di hash)
  /var/lib/nefi/detection/status.json     stato del motore, regole, soppressioni
  /var/lib/nefi/detection/pending.json    modifiche in attesa di approvazione
  /var/lib/nefi/detection/audit.jsonl     chi ha approvato / soppresso cosa
  /var/lib/nefi/detection/processes.jsonl programmi eseguiti (albero dei processi)
Lo stato "visto / riaperto" di un avviso e' personale: ~/.local/share/nefi/detection-triage.json
"""
import html
import json
import os
import time
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QLineEdit, QGridLayout, QDialog,
    QDialogButtonBox, QFormLayout, QMessageBox, QFileDialog, QTextBrowser, QSplitter
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices

from nefi_theme import C, Card, SectionLabel, GhostButton, Pill, PageHeader
from prevention_pages import make_table, fill, StatTile, INPUT_QSS
from system_pages import CmdWorker

STATE = "/var/lib/nefi/detection"
ALERTS = "/var/log/nefi/detection/alerts.jsonl"
STATUS = STATE + "/status.json"
PENDING = STATE + "/pending.json"
AUDIT = STATE + "/audit.jsonl"
PROCESSES = STATE + "/processes.jsonl"
CTL = ["pkexec", "/usr/bin/python3", "/opt/nefi/detection/ctl.py"]
TRIAGE = os.path.expanduser("~/.local/share/nefi/detection-triage.json")

LEVELS = ["informational", "low", "medium", "high", "critical"]
LEVEL_COLOR = {"critical": C["danger"], "high": "#ff8a4c", "medium": C["warn"], "low": C["info"],
               "informational": C["text3"]}
TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Collection", "Command and Control", "Exfiltration", "Impact"]
SUPPRESS_FIELDS = ["Image", "ParentImage", "CommandLine", "TargetFilename", "User", "Item", "DestinationIp",
                   "DestinationPort", "QueryName", "FalcoRule", "Signature", "Unit"]
KIND_TEXT = {"new": "New", "modified": "Modified", "removed": "Removed"}


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def read_jsonl_tail(path, max_bytes=3 * 1024 * 1024):
    """Ultime righe di un file JSONL (senza caricarlo tutto)."""
    out = []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return None
    lines = data.split(b"\n")
    if size > max_bytes:
        lines = lines[1:]                     # la prima riga puo' essere tagliata
    for raw in lines:
        if raw.strip():
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
    return out


def short_time(iso):
    try:
        return datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return str(iso or "")


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def combo(items, width=None):
    c = QComboBox()
    c.setStyleSheet(f"QComboBox {{ {INPUT_QSS} }}")
    for label, data in items:
        c.addItem(label, data)
    if width:
        c.setMinimumWidth(width)
    return c


class EnginePage(QWidget):
    """Base: intestazione, riga di statistiche, comandi root con una riga di esito."""
    TITLE = ""
    SUBTITLE = ""
    STATS = []

    def __init__(self):
        super().__init__()
        self.worker = None
        self._sig = None
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
        self.pills = QHBoxLayout()
        self.pills.setSpacing(8)
        head.body.addLayout(self.pills)
        self.note = QLabel("")
        self.note.setWordWrap(True)
        self.note.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        head.body.addWidget(self.note)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.result.setStyleSheet(f"color: {C['accent']}; font-family: monospace; font-size: 12px; background: transparent;")
        self.result.hide()
        head.body.addWidget(self.result)
        lay.addWidget(head)
        self.body = lay
        self.build()
        self.refresh(force=True)

    def build(self):
        pass

    def ctl(self, args, title):
        self.run_cmd(CTL + list(args), title)

    def run_cmd(self, cmd, title):
        if self.worker and self.worker.isRunning():
            return
        self._out = []
        self.result.show()
        self.result.setText(title)
        self.worker = CmdWorker(list(cmd))
        self.worker.line.connect(lambda l: self._out.append(l.replace("[NEFI] ", "")) if l.strip() else None)
        self.worker.finished_ok.connect(self._done)
        self.worker.start()

    def _done(self, ok):
        text = "\n".join(self._out[-6:]) or ("Done." if ok else "Cancelled or failed (administrator password not given?).")
        self.result.setText(text)
        self.result.setStyleSheet(f"color: {C['accent'] if ok else C['danger']}; font-family: monospace; "
                                  f"font-size: 12px; background: transparent;")
        self.refresh(force=True)

    def engine_note(self, status):
        """Testo sullo stato del motore: (testo, in funzione?)."""
        if status is None:
            return ("The detection engine has not produced any data yet. It starts at boot (service "
                    "nefi-detectd); your user must be in the 'sudo' group to read its results.", False)
        try:
            age = time.time() - datetime.strptime(status["generated"][:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        except (KeyError, ValueError):
            age = 1e9
        if age > 120:
            return (f"The detection engine is NOT running (last sign of life: {short_time(status.get('generated'))}). "
                    f"Start it from System > Security Services or with: sudo systemctl start nefi-detectd", False)
        return ("", True)

    def refresh(self, force=False):
        pass


# ───────────────────────────── Detections ─────────────────────────────

class FalsePositiveDialog(QDialog):
    """Sceglie cosa non deve piu' far scattare la regola (una condizione sola, la piu' stretta possibile)."""
    def __init__(self, parent, alert):
        super().__init__(parent)
        self.setWindowTitle("Mark as false positive")
        self.setMinimumWidth(620)
        self.setStyleSheet(f"QDialog {{ background: {C['card']}; }} QLabel {{ color: {C['text']}; background: transparent; }}")
        lay = QVBoxLayout(self)
        info = QLabel(f"<b>{html.escape(alert.get('title', ''))}</b><br>"
                      f"Rule: {html.escape(alert.get('rule_id', ''))}<br><br>"
                      "Choose the condition that identifies the legitimate activity. From now on this rule will "
                      "stay silent when the condition is true. Keep it as narrow as possible: a broad exception "
                      "is a blind spot an attacker can use. You can use * as a wildcard in the value.")
        info.setWordWrap(True)
        lay.addWidget(info)
        form = QFormLayout()
        ev = alert.get("event", {})
        choices = [(f"{f} = {str(ev[f])[:80]}", f) for f in SUPPRESS_FIELDS if ev.get(f) not in (None, "")]
        choices.append(("The whole rule (never alert again)", "-"))
        self.field = combo(choices, 420)
        self.value = QLineEdit()
        self.value.setStyleSheet(INPUT_QSS)
        self.comment = QLineEdit()
        self.comment.setStyleSheet(INPUT_QSS)
        self.comment.setPlaceholderText("Why is this legitimate? (kept in the audit log)")
        form.addRow("Condition", self.field)
        form.addRow("Value", self.value)
        form.addRow("Reason", self.comment)
        lay.addLayout(form)
        self.ev = ev
        self.field.currentIndexChanged.connect(self._fill)
        self._fill()
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _fill(self):
        f = self.field.currentData()
        self.value.setEnabled(f != "-")
        self.value.setText("" if f == "-" else str(self.ev.get(f, "")))

    def result_args(self):
        f = self.field.currentData()
        return [f, self.value.text().strip() or "-", self.comment.text().strip()]


class DetectionsPage(EnginePage):
    TITLE = "Detections"
    SUBTITLE = ("Everything the detection engine found: suspicious process behaviour, privilege escalation, "
                "credential access, persistence, rootkit indicators, network and DNS anomalies, plus Falco and "
                "Suricata alerts - each mapped to MITRE ATT&CK. Select an alert to investigate it.")
    STATS = [("critical", "critical (24 h)"), ("high", "high (24 h)"), ("medium", "medium (24 h)"),
             ("low", "low (24 h)"), ("suppressed", "suppressed as false positives"),
             ("pending", "changes waiting for approval")]

    def build(self):
        self.alerts, self.triage, self.current = [], read_json(TRIAGE, {}), None
        self.src_pills = {}
        for key, label in (("engine", "Engine"), ("auditd", "Kernel audit"), ("falco", "Falco"),
                           ("suricata", "Suricata / DNS"), ("osquery", "osquery"), ("yara", "YARA"),
                           ("chain", "Log integrity")):
            p = Pill(label, "muted", 100)
            p.setFixedHeight(28)
            self.pills.addWidget(p)
            self.src_pills[key] = (p, label)
        self.pills.addStretch()

        split = QSplitter(Qt.Orientation.Vertical)
        split.setChildrenCollapsible(False)
        top = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Alerts"))
        row.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search title, program, file, technique…")
        self.search.setStyleSheet(INPUT_QSS)
        self.search.setFixedWidth(260)
        self.search.textChanged.connect(lambda _t: self.redraw())
        row.addWidget(self.search)
        self.f_level = combo([("Medium and above", 2), ("High and above", 3), ("Critical only", 4), ("All levels", 0)])
        self.f_tactic = combo([("All tactics", "")] + [(t, t) for t in TACTICS])
        self.f_state = combo([("Open", "open"), ("Acknowledged", "ack"), ("All", "all")])
        for c in (self.f_level, self.f_tactic, self.f_state):
            c.currentIndexChanged.connect(lambda _i: self.redraw())
            row.addWidget(c)
        top.body.addLayout(row)
        self.table = make_table(["Time", "Level", "Alert", "Technique", "Program / item", "Source"])
        self.table.itemSelectionChanged.connect(self._select)
        top.body.addWidget(self.table, 1)
        split.addWidget(top)

        det = Card(padding=18)
        bar = QHBoxLayout()
        bar.addWidget(SectionLabel("Investigation"))
        bar.addStretch()
        self.b_ack = GhostButton("Acknowledge", "check_sq", 32, tone="ok")
        self.b_ack.clicked.connect(self._ack)
        self.b_fp = GhostButton("False positive…", "eye_off", 32)
        self.b_fp.clicked.connect(self._false_positive)
        self.b_base = GhostButton("Review changes", "fingerprint", 32)
        self.b_base.clicked.connect(lambda: self.window().open_module("baseline") if hasattr(self.window(), "open_module") else None)
        self.b_report = GhostButton("Export report", "file", 32)
        self.b_report.clicked.connect(self._report)
        for b in (self.b_ack, self.b_fp, self.b_base, self.b_report):
            bar.addWidget(b)
        det.body.addLayout(bar)
        rbar = QHBoxLayout()
        rl = QLabel("Respond (you decide, every action asks for confirmation and is recorded):")
        rl.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        rbar.addWidget(rl)
        rbar.addStretch()
        self.b_kill = GhostButton("Terminate process", "x", 32, tone="danger")
        self.b_kill.clicked.connect(self._kill)
        self.b_block = GhostButton("Block address", "block", 32, tone="danger")
        self.b_block.clicked.connect(self._block)
        self.b_iso = GhostButton("Isolate this machine…", "siren", 32, tone="danger")
        self.b_iso.clicked.connect(lambda: self.window().open_module("ir") if hasattr(self.window(), "open_module") else None)
        self.b_case = GhostButton("Open incident", "siren", 32, tone="ok")
        self.b_case.clicked.connect(self._incident)
        for b in (self.b_case, self.b_kill, self.b_block, self.b_iso):
            rbar.addWidget(b)
        det.body.addLayout(rbar)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        self.detail.setMinimumHeight(230)
        self.detail.setStyleSheet(f"QTextBrowser {{ background: {C['bg']}; color: {C['text']}; border: 1px solid "
                                  f"{C['border']}; border-radius: 8px; padding: 10px; font-size: 13px; }}")
        det.body.addWidget(self.detail, 1)
        split.addWidget(det)
        split.setSizes([420, 330])
        self.body.addWidget(split, 1)
        self._show(None)

    # ── dati ──
    def refresh(self, force=False):
        try:
            sig = (os.stat(ALERTS).st_size, os.stat(STATUS).st_mtime_ns)
        except OSError:
            sig = None
        if not force and sig == self._sig and sig is not None:
            return
        self._sig = sig
        status = read_json(STATUS, None)
        alerts = read_jsonl_tail(ALERTS)
        self.alerts = list(reversed(alerts or []))[:3000]
        note, running = self.engine_note(status)
        st = status or {}
        src = st.get("sources", {})
        self._pill("engine", "ok" if running else "danger", "running" if running else "stopped")
        self._pill("auditd", "ok" if src.get("auditd", {}).get("available") else "danger",
                   f"{src.get('auditd', {}).get('events', 0)} events" if src.get("auditd", {}).get("available") else "no log")
        self._pill("falco", "ok" if src.get("falco", {}).get("available") else "muted",
                   "connected" if src.get("falco", {}).get("available") else "not installed")
        self._pill("suricata", "ok" if src.get("suricata", {}).get("available") else "muted",
                   "connected" if src.get("suricata", {}).get("available") else "not active")
        self._pill("osquery", "ok" if src.get("osquery", {}).get("available") else "muted",
                   "connected" if src.get("osquery", {}).get("available") else "not installed")
        yara = st.get("yara", {})
        self._pill("yara", "ok" if yara.get("available") and yara.get("rules") else "muted",
                   f"{yara.get('rules', 0)} rule files" if yara.get("available") else "not installed")
        chain = st.get("log_chain", {})
        self._pill("chain", "ok" if chain.get("ok", True) else "danger", "intact" if chain.get("ok", True) else "TAMPERED")
        extra = []
        if running and not src.get("falco", {}).get("available"):
            extra.append("Falco is not installed: install it from Detection > Runtime Alerts for deeper runtime detection.")
        if running and not src.get("suricata", {}).get("available"):
            extra.append("DNS detection needs Suricata (eve.json): it is not active on this machine.")
        if st.get("baseline", {}).get("learning_network"):
            extra.append("Learning period (first 24 h): programs that use the network are being learned, not reported.")
        self.note.setText(" ".join([note] + extra).strip())
        day = time.time() - 86400
        counts = {l: 0 for l in LEVELS}
        for a in self.alerts:
            try:
                if datetime.strptime(a["ts"][:19], "%Y-%m-%dT%H:%M:%S").timestamp() >= day:
                    counts[a.get("level", "low")] = counts.get(a.get("level", "low"), 0) + 1
            except (KeyError, ValueError):
                continue
        self.stats["critical"].set(counts["critical"], C["danger"] if counts["critical"] else None)
        self.stats["high"].set(counts["high"], "#ff8a4c" if counts["high"] else None)
        self.stats["medium"].set(counts["medium"], C["warn"] if counts["medium"] else None)
        self.stats["low"].set(counts["low"])
        self.stats["suppressed"].set(st.get("suppressed_events", "–"))
        pend = st.get("baseline", {}).get("pending", "–")
        self.stats["pending"].set(pend, C["warn"] if isinstance(pend, int) and pend else None)
        self.redraw()

    def _pill(self, key, tone, text):
        p, label = self.src_pills[key]
        p.setText(f"{label}: {text}")
        p.set_tone(tone)

    def _visible(self):
        q = self.search.text().strip().lower()
        min_level, tactic, state = self.f_level.currentData(), self.f_tactic.currentData(), self.f_state.currentData()
        out = []
        for a in self.alerts:
            if LEVELS.index(a.get("level", "low")) < min_level:
                continue
            acked = self.triage.get(a.get("id")) == "ack"
            if (state == "open" and acked) or (state == "ack" and not acked):
                continue
            if tactic and tactic not in [t["name"] for t in a.get("mitre", {}).get("tactics", [])]:
                continue
            if q and q not in json.dumps(a, ensure_ascii=False).lower():
                continue
            out.append(a)
        return out[:800]

    def redraw(self):
        keep = self.current.get("id") if self.current else None
        self.rows = self._visible()
        colors = {i: LEVEL_COLOR.get(a.get("level"), C["text"]) for i, a in enumerate(self.rows)
                  if a.get("level") in ("critical", "high")}
        table_rows = []
        for a in self.rows:
            ev = a.get("event", {})
            what = ev.get("Image") or ev.get("Item") or ev.get("TargetFilename") or ev.get("QueryName") or \
                ev.get("DestinationIp") or ""
            tech = ", ".join(t["id"] for t in a.get("mitre", {}).get("techniques", [])[:3])
            table_rows.append([short_time(a.get("ts")), a.get("level", ""), a.get("title", ""), tech, str(what)[:70],
                               a.get("source", "")])
        self.table.blockSignals(True)
        fill(self.table, table_rows, colors)
        if keep:
            for i, a in enumerate(self.rows):
                if a.get("id") == keep:
                    self.table.selectRow(i)
                    break
        self.table.blockSignals(False)

    def _select(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return
        t = self.table.item(sel[0].row(), 0).text()
        title = self.table.item(sel[0].row(), 2).text()
        for a in self.rows:
            if short_time(a.get("ts")) == t and a.get("title") == title:
                self._show(a)
                return

    # ── dettaglio e albero dei processi ──
    def _descendants(self, alert, limit=40):
        ev = alert.get("event", {})
        root = str(ev.get("pid", "") or "")
        if not root or alert.get("category") not in ("process", "file", "network"):
            return []
        try:
            t0 = datetime.strptime(alert["ts"][:19], "%Y-%m-%dT%H:%M:%S").timestamp() - 5
        except (KeyError, ValueError):
            return []
        recs = read_jsonl_tail(PROCESSES, 6 * 1024 * 1024) or []
        family, out = {root: 0}, []
        for r in recs:
            if r.get("ts", 0) < t0:
                continue
            if r.get("ppid") in family and r.get("pid") not in family:
                family[r["pid"]] = family[r["ppid"]] + 1
                out.append((family[r["pid"]], r))
                if len(out) >= limit:
                    break
        return out

    def _show(self, a):
        self.current = a
        for b in (self.b_ack, self.b_fp, self.b_report):
            b.setEnabled(a is not None)
        ev0 = (a or {}).get("event", {})
        self.b_kill.setEnabled(bool(a) and str(ev0.get("pid", "")).isdigit() and bool(ev0.get("Image"))
                               and a.get("source") in ("auditd", "nefi", "falco"))
        self.b_block.setEnabled(bool(self._alert_ip(a)))
        self.b_base.setVisible(bool(a and a.get("category") == "state"))
        if a is None:
            self.detail.setHtml(f"<span style='color:{C['text3']}'>Select an alert in the table to see what happened, "
                                f"the MITRE ATT&amp;CK technique, the process tree and the possible false positives.</span>")
            return
        self.b_ack.setText("  Reopen" if self.triage.get(a.get("id")) == "ack" else "  Acknowledge")
        e = html.escape
        col = LEVEL_COLOR.get(a.get("level"), C["text"])
        h = [f"<div style='font-size:16px;font-weight:bold'>{e(a.get('title', ''))}</div>",
             f"<div><span style='color:{col};font-weight:bold'>{e(a.get('level', '').upper())}</span>"
             f" &nbsp;•&nbsp; {e(short_time(a.get('ts')))} &nbsp;•&nbsp; rule <code>{e(a.get('rule_id', ''))}</code>"
             f" ({e(a.get('origin', ''))}) &nbsp;•&nbsp; source {e(a.get('source', ''))}</div>",
             f"<p>{e(a.get('description', ''))}</p>"]
        if a.get("correlation"):
            h.append(f"<p><b>Correlation:</b> {e(str(a['correlation']))}</p>")
        m = a.get("mitre", {})
        if m.get("tactics") or m.get("techniques"):
            tac = ", ".join(e(t["name"]) for t in m.get("tactics", []))
            tech = ", ".join(f"<a style='color:{C['accent']}' href='{technique_url(t['id'])}'>{e(t['id'])}"
                             f"{' ' + e(t['name']) if t.get('name') else ''}</a>" for t in m.get("techniques", []))
            h.append(f"<p><b>MITRE ATT&amp;CK</b> — tactic: {tac or 'n/a'} — technique: {tech or 'n/a'}</p>")
        tree = list(reversed(a.get("process_tree", [])))
        kids = self._descendants(a)
        if tree or kids:
            h.append("<p><b>Process tree</b> (oldest ancestor first; ▶ = the process of this alert)</p><pre "
                     f"style='font-family:monospace;font-size:12px;color:{C['text2']}'>")
            ev = a.get("event", {})
            depth = 0
            for p in tree:
                h.append(e(f"{'  ' * depth}└ [{p.get('pid')}] {p.get('User') or '?'}  {p.get('Image')}  "
                           f"{p.get('CommandLine', '')[:160]}") + "\n")
                depth += 1
            if a.get("category") == "process":
                h.append(f"<span style='color:{col}'>" + e(f"{'  ' * depth}▶ [{ev.get('pid')}] {ev.get('User', '?')}  "
                         f"{ev.get('Image', '')}  {str(ev.get('CommandLine', ''))[:200]}") + "</span>\n")
                depth += 1
            for d, r in kids:
                h.append(e(f"{'  ' * (depth + d - 1)}└ [{r.get('pid')}] {r.get('User') or '?'}  {r.get('Image')}  "
                           f"{r.get('CommandLine', '')[:160]}") + "\n")
            h.append("</pre>")
        h.append("<p><b>Event details</b></p><table cellspacing='0' cellpadding='3'>")
        for k, v in sorted(a.get("event", {}).items()):
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            h.append(f"<tr><td style='color:{C['text3']}'>{e(str(k))}</td><td style='font-family:monospace'>"
                     f"{e(str(v))[:1200]}</td></tr>")
        h.append("</table>")
        if a.get("falsepositives"):
            h.append("<p><b>Known legitimate causes:</b> " + e("; ".join(a["falsepositives"])) + "</p>")
        self.detail.setHtml("".join(h))

    # ── azioni ──
    def _ack(self):
        if not self.current:
            return
        aid = self.current.get("id")
        if self.triage.get(aid) == "ack":
            self.triage.pop(aid, None)
        else:
            self.triage[aid] = "ack"
        try:
            os.makedirs(os.path.dirname(TRIAGE), exist_ok=True)
            with open(TRIAGE, "w", encoding="utf-8") as f:
                json.dump(dict(list(self.triage.items())[-5000:]), f)
        except OSError:
            pass
        self.redraw()
        self._show(None if self.f_state.currentData() != "all" else self.current)

    @staticmethod
    def _alert_ip(a):
        """L'indirizzo ESTERNO coinvolto nell'avviso (quello che ha senso bloccare)."""
        import ipaddress
        ev = (a or {}).get("event", {})
        for key in ("DestinationIp", "SourceIp"):
            try:
                ip = ipaddress.ip_address(str(ev.get(key, "")))
            except ValueError:
                continue
            if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast):
                return str(ip)
        return ""

    def _kill(self):
        a = self.current
        if not a:
            return
        ev = a.get("event", {})
        if QMessageBox.warning(self, "Terminate process",
                               f"Terminate process {ev.get('pid')}?\n\n{ev.get('Image', '')}\n"
                               f"{str(ev.get('CommandLine', ''))[:200]}\n\nIt is terminated only if it is still the "
                               f"same program. Unsaved work in that program is lost.",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.ctl(["kill", a.get("id", "")], "Terminating the process (admin password)…")

    def _incident(self):
        """Apre un incidente (Response > Incidents) a partire dall'avviso selezionato."""
        a = self.current
        if not a:
            QMessageBox.information(self, "Open incident", "Select an alert first.")
            return
        sev = {"critical": "critical", "high": "high", "medium": "medium"}.get(a.get("level"), "low")
        ev = a.get("event", {})
        title = " ".join(str(a.get("title", "Detection alert")).split())[:150]
        desc = " ".join(f"Detection alert {a.get('id', '')} (rule {a.get('rule_id', '')}) at {str(a.get('ts', ''))[:19]}. "
                        f"{ev.get('Image', '')} {str(ev.get('CommandLine', ''))[:200]}".split())[:480]
        if QMessageBox.question(self, "Open incident", f"Open a {sev}-severity incident for this alert?\n\n{title}\n\n"
                                "You then work on it in Response > Incidents (playbook, containment, report).") \
                == QMessageBox.StandardButton.Yes:
            self.run_cmd(["pkexec", "/usr/bin/python3", "/opt/nefi/ir/irctl.py", "case-open", sev, "other", title, desc,
                          str(a.get("id", ""))], "Opening the incident (admin password)…")

    def _block(self):
        a = self.current
        ip = self._alert_ip(a)
        if not ip:
            return
        if QMessageBox.warning(self, "Block address",
                               f"Block every connection from and to {ip}?\n\nThe block stays until you remove it "
                               f"in Detection > Detection Settings.",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.ctl(["block-ip", ip, a.get("id", "")], f"Blocking {ip} (admin password)…")

    def _report(self):
        a = self.current
        if not a:
            return
        folder = os.path.expanduser("~/Documents/NEFI-reports")
        try:
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, f"incident-{a.get('ts', '')[:19].replace(':', '').replace('-', '')}-{a.get('id', 'x')}.html")
            related = [x for x in self.alerts if x is not a and abs(_epoch(x.get("ts")) - _epoch(a.get("ts"))) <= 900][:60]
            with open(path, "w", encoding="utf-8") as f:
                f.write(incident_report(a, list(reversed(a.get("process_tree", []))), self._descendants(a), related))
            os.chmod(path, 0o600)
        except OSError as e:
            QMessageBox.warning(self, "Export report", f"Could not write the report: {e}")
            return
        if QMessageBox.question(self, "Export report", f"Report saved:\n{path}\n\nOpen it now?") == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _false_positive(self):
        if not self.current:
            return
        dlg = FalsePositiveDialog(self, self.current)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            field, value, comment = dlg.result_args()
            self.triage[self.current.get("id")] = "ack"
            self.ctl(["suppress-add", self.current.get("rule_id", ""), field, value, comment],
                     "Adding the false-positive exception (admin password)…")


# ───────────────────────────── Integrity & Persistence ─────────────────────────────

class BaselinePage(EnginePage):
    TITLE = "Integrity & Persistence"
    SUBTITLE = ("Critical files, autorun entries (systemd, cron, autostart, shell startup, SSH keys), SUID "
                "programs, accounts, administrators and listening ports are compared with an approved baseline. "
                "The baseline never updates itself: a change stays here until an administrator approves it, and "
                "every approval is recorded.")
    STATS = [("pending", "changes waiting"), ("items", "items in the baseline"),
             ("verified", "program files matching their package"), ("created", "baseline created")]

    def build(self):
        self.pending = []
        card = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Changes waiting for approval"))
        row.addStretch()
        for label, icon, tone, fn in (
            ("Approve selected", "check_sq", "ok", self._approve_selected),
            ("Approve all", "check_sq", "muted", self._approve_all),
            ("Scan now", "refresh", "muted", lambda: self.ctl(["scan"], "Asking the engine to scan now (admin password)…")),
            ("Rebuild baseline", "fingerprint", "danger", self._rebuild),
        ):
            b = GhostButton(label, icon, 32, tone=tone)
            b.clicked.connect(fn)
            row.addWidget(b)
        card.body.addLayout(row)
        hint = QLabel("Approve only what you recognise (an update you installed, a service you enabled, a password you "
                      "changed). If you do not recognise a change, do not approve it: investigate it in Detections. "
                      "Hold Ctrl or Shift to select several rows.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        card.body.addWidget(hint)
        self.table = make_table(["Change", "Type", "Item", "Package check", "First seen", "ATT&CK"])
        self.table.setSelectionMode(self.table.SelectionMode.ExtendedSelection)
        card.body.addWidget(self.table, 1)
        self.body.addWidget(card, 2)

        acard = Card(padding=18)
        acard.body.addWidget(SectionLabel("Audit trail (who approved or changed what)"))
        self.audit = make_table(["Time", "Action", "By", "Details"])
        acard.body.addWidget(self.audit, 1)
        self.body.addWidget(acard, 1)

    def refresh(self, force=False):
        sig = []
        for p in (PENDING, STATUS, AUDIT):
            try:
                sig.append(os.stat(p).st_mtime_ns)
            except OSError:
                sig.append(0)
        if not force and sig == self._sig:
            return
        self._sig = sig
        status = read_json(STATUS, None)
        note, _running = self.engine_note(status)
        base = (status or {}).get("baseline", {})
        chain = (status or {}).get("log_chain", {})
        if status and not chain.get("ok", True):
            note = f"WARNING: the detection logs were tampered with ({chain.get('message', '')}). " + note
        self.note.setText(note)
        self.pending = read_json(PENDING, [])
        self.stats["pending"].set(len(self.pending), C["warn"] if self.pending else C["accent"])
        self.stats["items"].set(base.get("items", "–"))
        self.stats["verified"].set(base.get("verification", {}).get("package_verified", "–"))
        self.stats["created"].set(short_time(base.get("created"))[:10] or "–")
        pk = {True: "matches the Debian package", False: "DIFFERENT from the package", None: "not from a package"}
        colors = {i: (C["danger"] if p.get("package_verified") is False or p.get("class", "").startswith(
            ("persistence.preload", "suid", "admin")) else C["warn"]) for i, p in enumerate(self.pending)
            if p.get("kind") != "removed"}
        fill(self.table, [[KIND_TEXT.get(p.get("kind"), p.get("kind")), p.get("label", p.get("class", "")),
                           p.get("item", ""), pk.get(p.get("package_verified"), ""), short_time(p.get("first_seen")),
                           p.get("technique", "")] for p in self.pending], colors)
        rows = []
        for r in reversed((read_jsonl_tail(AUDIT, 512 * 1024) or [])[-200:]):
            details = ", ".join(f"{k}={v}" for k, v in r.items()
                                if k not in ("ts", "action", "actor", "prev", "old", "new") and v not in ("", None))
            rows.append([short_time(r.get("ts")), r.get("action", ""), r.get("actor", ""), details[:300]])
        fill(self.audit, rows)

    def _approve_selected(self):
        ids = []
        for idx in self.table.selectionModel().selectedRows():
            item, kind = self.table.item(idx.row(), 2).text(), self.table.item(idx.row(), 0).text()
            for p in self.pending:
                if p.get("item") == item and KIND_TEXT.get(p.get("kind")) == kind and p["id"] not in ids:
                    ids.append(p["id"])
        if not ids:
            QMessageBox.information(self, "Approve", "Select one or more changes in the table first.")
            return
        if QMessageBox.question(self, "Approve changes", f"Approve {len(ids)} change(s)? They become part of the trusted "
                                f"baseline and the approval is recorded with your name.") == QMessageBox.StandardButton.Yes:
            self.ctl(["approve"] + ids, "Approving (admin password)…")

    def _approve_all(self):
        if not self.pending:
            return
        if QMessageBox.question(self, "Approve all", f"Approve ALL {len(self.pending)} pending changes without reviewing "
                                f"them one by one?") == QMessageBox.StandardButton.Yes:
            self.ctl(["approve-all"], "Approving all changes (admin password)…")

    def _rebuild(self):
        if QMessageBox.warning(self, "Rebuild baseline",
                               "This replaces the trusted baseline with the CURRENT state of the system, including "
                               "anything an intruder may have changed. Do it only on a system you trust (for example "
                               "right after a clean installation).\n\nRebuild the baseline?",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.ctl(["baseline-rebuild"], "Rebuilding the baseline (admin password, about a minute)…")


# ───────────────────────────── Detection Rules ─────────────────────────────

class RulesPage(EnginePage):
    TITLE = "Detection Rules"
    SUBTITLE = ("The rules the engine applies, in Sigma format, with their MITRE ATT&CK mapping. Disable a noisy "
                "rule, import your own Sigma rules for Linux, and manage the false-positive exceptions.")
    STATS = [("enabled", "rules enabled"), ("custom", "custom rules"), ("correlation", "correlation rules"),
             ("techniques", "ATT&CK techniques covered"), ("suppressions", "false-positive exceptions")]

    def build(self):
        self.rules, self.sups = [], []
        cov = Card(padding=18)
        cov.body.addWidget(SectionLabel("MITRE ATT&CK coverage (enabled rules per tactic)"))
        grid = QGridLayout()
        grid.setSpacing(6)
        self.cov = {}
        for i, t in enumerate(TACTICS):
            p = Pill(t, "muted", 150)
            p.setFixedHeight(30)
            self.cov[t] = p
            grid.addWidget(p, i // 5, i % 5)
        cov.body.addLayout(grid)
        self.body.addWidget(cov)

        card = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Rules"))
        row.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search rules…")
        self.search.setStyleSheet(INPUT_QSS)
        self.search.setFixedWidth(220)
        self.search.textChanged.connect(lambda _t: self._draw())
        row.addWidget(self.search)
        for label, icon, tone, fn in (
            ("Enable", "check_sq", "ok", lambda: self._toggle(True)),
            ("Disable", "x", "muted", lambda: self._toggle(False)),
            ("Import Sigma rule…", "download", "muted", self._import),
            ("Delete custom rule", "x", "danger", self._delete),
        ):
            b = GhostButton(label, icon, 32, tone=tone)
            b.clicked.connect(fn)
            row.addWidget(b)
        card.body.addLayout(row)
        self.table = make_table(["State", "Level", "Rule", "Type", "Applies to", "ATT&CK", "Origin", "Hits"])
        self.table.itemSelectionChanged.connect(self._describe)
        card.body.addWidget(self.table, 1)
        self.desc = QLabel("")
        self.desc.setWordWrap(True)
        self.desc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.desc.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent;")
        card.body.addWidget(self.desc)
        self.body.addWidget(card, 3)

        scard = Card(padding=18)
        srow = QHBoxLayout()
        srow.addWidget(SectionLabel("False-positive exceptions"))
        srow.addStretch()
        b = GhostButton("Remove exception", "x", 32, tone="danger")
        b.clicked.connect(self._remove_sup)
        srow.addWidget(b)
        scard.body.addLayout(srow)
        self.sup_table = make_table(["Id", "Rule", "Condition", "Reason", "Added", "By"])
        scard.body.addWidget(self.sup_table, 1)
        self.body.addWidget(scard, 1)

    def refresh(self, force=False):
        try:
            sig = os.stat(STATUS).st_mtime_ns
        except OSError:
            sig = None
        status = read_json(STATUS, None)
        key = json.dumps([(r.get("id"), r.get("enabled"), r.get("hits")) for r in (status or {}).get("rules", [])]
                         + [(status or {}).get("suppressions")], sort_keys=True, default=str) if status else None
        if not force and key == self._sig and sig is not None:
            return
        self._sig = key
        note, _running = self.engine_note(status)
        st = status or {}
        errs = st.get("rule_errors", [])
        if errs:
            note += f" {len(errs)} rule(s) not loaded: " + "; ".join(
                f"{os.path.basename(x['file'])}: {x['error']}" for x in errs[:3])
        self.note.setText(note.strip())
        self.rules, self.sups = st.get("rules", []), st.get("suppressions", [])
        enabled = [r for r in self.rules if r.get("enabled")]
        techs = {t["id"] for r in enabled for t in r.get("mitre", {}).get("techniques", [])}
        self.stats["enabled"].set(f"{len(enabled)}/{len(self.rules)}" if self.rules else "–")
        self.stats["custom"].set(sum(1 for r in self.rules if r.get("origin") == "custom") if status else "–")
        self.stats["correlation"].set(sum(1 for r in enabled if r.get("kind") == "correlation") if status else "–")
        self.stats["techniques"].set(len(techs) if status else "–")
        self.stats["suppressions"].set(len(self.sups) if status else "–")
        for t, pill in self.cov.items():
            n = sum(1 for r in enabled if t in [x["name"] for x in r.get("mitre", {}).get("tactics", [])])
            pill.setText(f"{t}: {n}")
            pill.set_tone("ok" if n else "muted")
        fill(self.sup_table, [[s.get("id", ""), s.get("rule_id", ""),
                               f"{s.get('field')} = {s.get('value')}" if s.get("field") else "whole rule",
                               s.get("comment", ""), short_time(s.get("created")), s.get("by", "")] for s in self.sups])
        self._draw()

    def _draw(self):
        q = self.search.text().strip().lower()
        self.shown = [r for r in self.rules if not q or q in json.dumps(r).lower()]
        self.shown.sort(key=lambda r: (-LEVELS.index(r.get("level", "low")) if r.get("level") in LEVELS else 0,
                                       r.get("title", "")))
        rows = []
        for r in self.shown:
            ls = r.get("logsource", {})
            scope = ls.get("category") or ls.get("service") or ("other rules" if r.get("kind") == "correlation" else "")
            m = r.get("mitre", {})
            att = ", ".join([t["id"] for t in m.get("techniques", [])][:3]) or ", ".join(t["name"] for t in m.get("tactics", [])[:2])
            state = "on" if r.get("enabled") else "OFF"
            if r.get("silent"):
                state += " (silent)"
            rows.append([state, r.get("level", ""), r.get("title", ""), r.get("kind", ""), scope, att,
                         "NEFI" if r.get("origin") == "builtin" else "custom", r.get("hits", 0)])
        fill(self.table, rows, {i: C["text3"] for i, r in enumerate(self.shown) if not r.get("enabled")})

    def _selected(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return None
        title = self.table.item(sel[0].row(), 2).text()
        return next((r for r in self.shown if r.get("title") == title), None)

    def _describe(self):
        r = self._selected()
        if not r:
            return
        fps = "  Known legitimate causes: " + "; ".join(r["falsepositives"]) + "." if r.get("falsepositives") else ""
        silent = "  Silent rule: it only feeds correlation rules." if r.get("silent") else ""
        self.desc.setText(f"{r.get('id')}: {r.get('description', '')}{fps}{silent}")

    def _toggle(self, on):
        r = self._selected()
        if r:
            self.ctl(["rule-enable" if on else "rule-disable", r["id"]],
                     f"{'Enabling' if on else 'Disabling'} {r['id']} (admin password)…")

    def _import(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import a Sigma rule for Linux", os.path.expanduser("~"),
                                              "Sigma rules (*.yml *.yaml *.json)")
        if path:
            self.ctl(["rule-import", path], "Checking and importing the rule (admin password)…")

    def _delete(self):
        r = self._selected()
        if not r:
            return
        if r.get("origin") != "custom":
            QMessageBox.information(self, "Delete rule", "Built-in rules cannot be deleted: disable them instead.")
            return
        if QMessageBox.question(self, "Delete rule", f"Delete the custom rule '{r.get('title')}'?") == QMessageBox.StandardButton.Yes:
            self.ctl(["rule-delete", r["id"]], "Deleting the rule (admin password)…")

    def _remove_sup(self):
        sel = self.sup_table.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Remove exception", "Select an exception in the table first.")
            return
        sid = self.sup_table.item(sel[0].row(), 0).text()
        self.ctl(["suppress-del", sid], "Removing the exception (admin password)…")




# ───────────────────────────── Incident report ─────────────────────────────

import hashlib      # noqa: E402
import shutil       # noqa: E402
import subprocess   # noqa: E402

from PyQt6.QtCore import QThread, pyqtSignal   # noqa: E402


def _epoch(iso):
    try:
        return datetime.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    except ValueError:
        return 0.0


def incident_report(a, ancestors, descendants, related):
    """Un avviso come documento HTML autonomo (stampabile, senza risorse esterne)."""
    e = html.escape
    ev = a.get("event", {})
    m = a.get("mitre", {})
    digest = hashlib.sha256(json.dumps(a, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    col = {"critical": "#b3261e", "high": "#c4500c", "medium": "#9a6700", "low": "#0b57d0"}.get(a.get("level"), "#444")
    out = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>NEFI incident report {e(a.get('id', ''))}</title>
<style>
body{{font-family:system-ui,sans-serif;color:#1b1f23;max-width:960px;margin:32px auto;padding:0 16px;line-height:1.45}}
h1{{font-size:22px;margin-bottom:4px}} h2{{font-size:16px;margin-top:28px;border-bottom:1px solid #d0d7de;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border:1px solid #d0d7de;padding:5px 8px;text-align:left;vertical-align:top}}
th{{background:#f3f5f7}} pre,code,.mono{{font-family:ui-monospace,monospace;font-size:12.5px}} pre{{background:#f6f8fa;padding:10px;overflow-x:auto}}
.lvl{{color:{col};font-weight:700}} .muted{{color:#57606a;font-size:13px}} .hit{{color:{col};font-weight:700}}
td.k{{width:190px;color:#57606a}} td.v{{word-break:break-all}}
</style></head><body>
<h1>{e(a.get('title', ''))}</h1>
<div><span class="lvl">{e(str(a.get('level', '')).upper())}</span> &nbsp;·&nbsp; {e(short_time(a.get('ts')))}
 &nbsp;·&nbsp; host <b>{e(os.uname().nodename)}</b> &nbsp;·&nbsp; alert id <code>{e(a.get('id', ''))}</code></div>
<p>{e(a.get('description', ''))}</p>
<h2>Summary</h2><table>
<tr><td class="k">Detection rule</td><td>{e(a.get('rule_id', ''))} ({e(a.get('origin', ''))})</td></tr>
<tr><td class="k">Telemetry source</td><td>{e(a.get('source', ''))}</td></tr>"""]
    if a.get("correlation"):
        out.append(f"<tr><td class='k'>Correlation</td><td>{e(str(a['correlation']))}</td></tr>")
    tac = ", ".join(f"{e(t['name'])} ({e(t['id'])})" for t in m.get("tactics", [])) or "n/a"
    tech = ", ".join(f"<a href='{technique_url(t['id'])}'>{e(t['id'])}</a> {e(t.get('name', ''))}"
                     for t in m.get("techniques", [])) or "n/a"
    out.append(f"<tr><td class='k'>MITRE ATT&amp;CK tactic</td><td>{tac}</td></tr>"
               f"<tr><td class='k'>MITRE ATT&amp;CK technique</td><td>{tech}</td></tr></table>")
    if ancestors or descendants or a.get("category") == "process":
        out.append("<h2>Process tree</h2><pre>")
        depth = 0
        for p in ancestors:
            out.append(e(f"{'  ' * depth}└ [{p.get('pid')}] {p.get('User') or '?'}  {p.get('Image')}  {p.get('CommandLine', '')}") + "\n")
            depth += 1
        if a.get("category") == "process":
            out.append("<span class='hit'>" + e(f"{'  ' * depth}▶ [{ev.get('pid')}] {ev.get('User', '?')}  {ev.get('Image', '')}  "
                                                 f"{ev.get('CommandLine', '')}") + "</span>\n")
            depth += 1
        for d, r in descendants:
            out.append(e(f"{'  ' * (depth + d - 1)}└ [{r.get('pid')}] {r.get('User') or '?'}  {r.get('Image')}  {r.get('CommandLine', '')}") + "\n")
        out.append("</pre>")
    out.append("<h2>Evidence (event fields)</h2><table>")
    for k, v in sorted(ev.items()):
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        out.append(f"<tr><td class='k'>{e(str(k))}</td><td class='v mono'>{e(str(v))}</td></tr>")
    out.append("</table>")
    if related:
        out.append("<h2>Other alerts within 15 minutes</h2><table><tr><th>Time</th><th>Level</th><th>Alert</th>"
                   "<th>Technique</th></tr>")
        for r in sorted(related, key=lambda x: x.get("ts", "")):
            t = ", ".join(x["id"] for x in r.get("mitre", {}).get("techniques", []))
            out.append(f"<tr><td>{e(short_time(r.get('ts')))}</td><td>{e(r.get('level', ''))}</td>"
                       f"<td>{e(r.get('title', ''))}</td><td>{e(t)}</td></tr>")
        out.append("</table>")
    if a.get("falsepositives"):
        out.append("<h2>Known legitimate causes</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in a["falsepositives"]) + "</ul>")
    out.append(f"""<h2>Record integrity</h2>
<p class="muted">SHA-256 of this alert record: <code>{digest}</code><br>
Previous record in the hash-chained alert log: <code>{e(str(a.get('prev', '')))}</code><br>
Verify the whole log on the machine with: <code>sudo python3 /opt/nefi/detection/ctl.py verify</code></p>
<p class="muted">Generated by NEFI Security Center on {e(time.strftime('%Y-%m-%d %H:%M:%S %z'))} by user {e(os.environ.get('USER', '?'))}.</p>
</body></html>""")
    return "".join(out)


# ───────────────────────────── Threat Hunting ─────────────────────────────

class HuntWorker(QThread):
    done = pyqtSignal(list, int, str)

    def __init__(self, text, user, hours):
        super().__init__()
        self.text, self.user, self.hours = text.lower(), user.lower(), hours

    def run(self):
        since = time.time() - self.hours * 3600 if self.hours else 0
        hits, scanned, err = [], 0, ""
        for path in (PROCESSES + ".1", PROCESSES):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        scanned += 1
                        if self.text and self.text not in line.lower():
                            continue
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        if r.get("ts", 0) < since or (self.user and self.user != str(r.get("User", "")).lower()):
                            continue
                        hits.append(r)
            except FileNotFoundError:
                continue
            except OSError as e:
                err = str(e)
        self.done.emit(hits[-3000:], scanned, err)


class QueryWorker(QThread):
    done = pyqtSignal(list, str)

    def __init__(self, sql):
        super().__init__()
        self.sql = sql

    def run(self):
        try:
            r = subprocess.run(["osqueryi", "--json", self.sql], capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                self.done.emit([], (r.stderr or r.stdout).strip()[:400] or "query failed")
                return
            rows = json.loads(r.stdout or "[]")
            self.done.emit(rows[:2000] if isinstance(rows, list) else [], "")
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            self.done.emit([], str(e)[:400])


OSQUERY_PRESETS = [
    ("Processes listening on the network", "SELECT p.name, p.path, l.port, l.protocol, l.address FROM listening_ports l JOIN processes p USING (pid) WHERE l.port != 0;"),
    ("Processes whose program file was deleted", "SELECT pid, name, path, cmdline FROM processes WHERE on_disk = 0 AND path != '';"),
    ("Open network connections by process", "SELECT p.name, p.path, s.remote_address, s.remote_port FROM process_open_sockets s JOIN processes p USING (pid) WHERE s.remote_port != 0;"),
    ("Users with a login shell", "SELECT username, uid, gid, directory, shell FROM users WHERE shell NOT LIKE '%nologin' AND shell NOT LIKE '%false';"),
    ("Logged-in sessions", "SELECT user, host, tty, type, time FROM logged_in_users;"),
    ("Scheduled jobs (cron)", "SELECT command, path, minute, hour FROM crontab;"),
    ("SUID programs", "SELECT path, username, permissions FROM suid_bin;"),
    ("Loaded kernel modules", "SELECT name, size, used_by, status FROM kernel_modules;"),
    ("Recently installed packages (largest first)", "SELECT name, version, size FROM deb_packages ORDER BY size DESC LIMIT 50;"),
    ("USB devices", "SELECT vendor, model, serial, class FROM usb_devices;"),
    ("SSH authorized keys", "SELECT u.username, k.key_file, k.algorithm, k.comment FROM users u JOIN authorized_keys k USING (uid);"),
]


class HuntingPage(EnginePage):
    TITLE = "Threat Hunting"
    SUBTITLE = ("Search the history of every program executed on this machine (kernel audit telemetry kept by the "
                "detection engine), rebuild who started what, and ask the system live questions with osquery.")
    STATS = [("tracked", "programs in the engine's memory"), ("found", "results of the last search"),
             ("scanned", "records searched")]

    def build(self):
        self.hw = self.qw = None
        self.records = []
        card = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Program execution history"))
        row.addStretch()
        self.q = QLineEdit()
        self.q.setPlaceholderText("Program, argument, path… (empty = everything)")
        self.q.setStyleSheet(INPUT_QSS)
        self.q.setMinimumWidth(320)
        self.q.returnPressed.connect(self._search)
        self.user = QLineEdit()
        self.user.setPlaceholderText("User")
        self.user.setStyleSheet(INPUT_QSS)
        self.user.setFixedWidth(110)
        self.span = combo([("Last hour", 1), ("Last 24 hours", 24), ("Last 7 days", 168), ("Everything kept", 0)])
        b = GhostButton("Search", "search", 32, tone="ok")
        b.clicked.connect(self._search)
        for w in (self.q, self.user, self.span, b):
            row.addWidget(w)
        card.body.addLayout(row)
        self.table = make_table(["Time", "User", "PID", "Parent PID", "Program", "Command line", "Parent program"])
        self.table.itemSelectionChanged.connect(self._tree)
        card.body.addWidget(self.table, 2)
        self.tree = QTextBrowser()
        self.tree.setMinimumHeight(120)
        self.tree.setStyleSheet(f"QTextBrowser {{ background: {C['bg']}; color: {C['text2']}; border: 1px solid "
                                f"{C['border']}; border-radius: 8px; padding: 8px; font-family: monospace; font-size: 12px; }}")
        self.tree.setPlainText("Select a row to see who started that program and what it started in turn.")
        card.body.addWidget(self.tree, 1)
        self.body.addWidget(card, 3)

        oc = Card(padding=18)
        orow = QHBoxLayout()
        orow.addWidget(SectionLabel("Live query (osquery)"))
        orow.addStretch()
        self.preset = combo([("Choose a ready-made question…", "")] + OSQUERY_PRESETS, 320)
        self.preset.currentIndexChanged.connect(lambda _i: self.sql.setText(self.preset.currentData() or self.sql.text()))
        orow.addWidget(self.preset)
        self.b_run = GhostButton("Run query", "play", 32, tone="ok")
        self.b_run.clicked.connect(self._query)
        orow.addWidget(self.b_run)
        oc.body.addLayout(orow)
        self.sql = QLineEdit()
        self.sql.setPlaceholderText("SELECT … FROM … (read-only SQL over the state of the system)")
        self.sql.setStyleSheet(INPUT_QSS + " font-family: monospace;")
        self.sql.returnPressed.connect(self._query)
        oc.body.addWidget(self.sql)
        self.qnote = QLabel("")
        self.qnote.setWordWrap(True)
        self.qnote.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        oc.body.addWidget(self.qnote)
        self.qtable = make_table(["Result"])
        oc.body.addWidget(self.qtable, 1)
        self.body.addWidget(oc, 2)

    def refresh(self, force=False):
        status = read_json(STATUS, None)
        note, _running = self.engine_note(status)
        self.note.setText(note)
        self.stats["tracked"].set((status or {}).get("processes_tracked", "–"))
        have = shutil.which("osqueryi") is not None
        self.b_run.setEnabled(have)
        if not have:
            self.qnote.setText("osquery is not installed: install it from Detection > Detection Settings.")
        elif not self.qnote.text() or self.qnote.text().startswith("osquery is not"):
            self.qnote.setText("Runs as your user: a few tables show more when queried by root.")

    def _search(self):
        if self.hw and self.hw.isRunning():
            return
        self.tree.setPlainText("Searching…")
        self.hw = HuntWorker(self.q.text().strip(), self.user.text().strip(), self.span.currentData())
        self.hw.done.connect(self._found)
        self.hw.start()

    def _found(self, hits, scanned, err):
        self.records = list(reversed(hits))
        self.stats["found"].set(len(hits))
        self.stats["scanned"].set(scanned)
        fill(self.table, [[datetime.fromtimestamp(r.get("ts", 0)).strftime("%Y-%m-%d %H:%M:%S"), r.get("User", ""),
                           r.get("pid", ""), r.get("ppid", ""), r.get("Image", ""), str(r.get("CommandLine", ""))[:300],
                           r.get("ParentImage", "")] for r in self.records])
        if err:
            self.tree.setPlainText(f"Could not read the history: {err}. Your user must be in the 'sudo' group.")
        elif not hits:
            self.tree.setPlainText("No program matches. The history starts when the detection engine was installed "
                                   "and keeps about 60 MB of records.")
        else:
            self.tree.setPlainText(f"{len(hits)} programs found (newest first). Select a row to see its process tree.")

    def _tree(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel or not self.records:
            return
        key = (self.table.item(sel[0].row(), 0).text(), self.table.item(sel[0].row(), 2).text())
        rec = next((r for r in self.records if (datetime.fromtimestamp(r.get("ts", 0)).strftime("%Y-%m-%d %H:%M:%S"),
                                                str(r.get("pid", ""))) == key), None)
        if rec is None:
            return
        # tutta la storia serve per risalire ai genitori, anche se non corrispondono alla ricerca
        every = read_jsonl_tail(PROCESSES, 12 * 1024 * 1024) or []
        by_pid = {}
        for r in every:
            by_pid.setdefault(r.get("pid"), []).append(r)
        chain, cur, seen = [], rec, set()
        while cur and len(chain) < 15:
            parents = [p for p in by_pid.get(cur.get("ppid"), []) if p.get("ts", 0) <= cur.get("ts", 0)]
            if not parents or cur.get("ppid") in seen:
                break
            seen.add(cur.get("ppid"))
            cur = parents[-1]
            chain.append(cur)
        lines, depth = [], 0
        for p in reversed(chain):
            lines.append(f"{'  ' * depth}└ [{p.get('pid')}] {p.get('User') or '?'}  {p.get('Image')}  {str(p.get('CommandLine', ''))[:200]}")
            depth += 1
        lines.append(f"{'  ' * depth}▶ [{rec.get('pid')}] {rec.get('User') or '?'}  {rec.get('Image')}  {str(rec.get('CommandLine', ''))[:300]}")
        family = {rec.get("pid"): depth}
        for r in every:
            if r.get("ts", 0) >= rec.get("ts", 0) and r.get("ppid") in family and r.get("pid") not in family and len(family) < 60:
                family[r["pid"]] = family[r["ppid"]] + 1
                lines.append(f"{'  ' * family[r['pid']]}└ [{r.get('pid')}] {r.get('User') or '?'}  {r.get('Image')}  {str(r.get('CommandLine', ''))[:200]}")
        self.tree.setPlainText("\n".join(lines))

    def _query(self):
        sql = self.sql.text().strip()
        if not sql or (self.qw and self.qw.isRunning()):
            return
        self.qnote.setText("Running…")
        self.qw = QueryWorker(sql)
        self.qw.done.connect(self._answered)
        self.qw.start()

    def _answered(self, rows, err):
        if err:
            self.qnote.setText(f"Query error: {err}")
            return
        cols = list(rows[0].keys()) if rows else ["Result"]
        self.qtable.setColumnCount(len(cols))
        self.qtable.setHorizontalHeaderLabels(cols)
        fill(self.qtable, [[r.get(c, "") for c in cols] for r in rows] if rows else [])
        self.qnote.setText(f"{len(rows)} row(s).")


# ───────────────────────────── Detection Settings ─────────────────────────────

class SettingsPage(EnginePage):
    TITLE = "Detection Settings"
    SUBTITLE = ("Extra sources and protections for the detection engine: decoy files, a copy of the alerts on "
                "another machine, the public SigmaHQ rules, YARA, osquery, a Wazuh server, and the addresses you blocked.")
    STATS = [("canaries", "canary files watched"), ("blocked", "addresses blocked"), ("sigma", "SigmaHQ rules"),
             ("yara", "YARA rule files"), ("forwarded", "records sent to the log server")]

    def _section(self, title, text):
        card = Card(padding=18)
        card.body.addWidget(SectionLabel(title))
        info = QLabel(text)
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent;")
        card.body.addWidget(info)
        state = QLabel("")
        state.setWordWrap(True)
        state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        state.setStyleSheet(f"color: {C['text']}; font-size: 13px; background: transparent;")
        card.body.addWidget(state)
        row = QHBoxLayout()
        card.body.addLayout(row)
        return card, state, row

    def _btn(self, row, label, icon, tone, fn):
        b = GhostButton(label, icon, 32, tone=tone)
        b.clicked.connect(fn)
        row.addWidget(b)
        return b

    def _edit(self, row, placeholder, width):
        e = QLineEdit()
        e.setPlaceholderText(placeholder)
        e.setStyleSheet(INPUT_QSS)
        e.setFixedWidth(width)
        row.addWidget(e)
        return e

    def build(self):
        grid = QGridLayout()
        grid.setSpacing(14)
        # canary
        c, self.s_canary, r = self._section("Canary files", (
            "Decoy files with fake passwords and keys, placed where an intruder looks first. Nobody has a reason to "
            "open them, so any access raises a critical alert with almost no false positives. Do not open them yourself."))
        self._btn(r, "Create / refresh", "check_sq", "ok", lambda: self.ctl(["canary-setup"], "Creating the canary files (admin password)…"))
        self._btn(r, "Remove", "x", "danger", lambda: self.ctl(["canary-remove"], "Removing the canary files (admin password)…"))
        r.addStretch()
        grid.addWidget(c, 0, 0)
        # forward
        c, self.s_fwd, r = self._section("Copy alerts to another machine", (
            "Sends every alert and the audit trail to a syslog server (RFC 5424 over TCP, TLS recommended) as soon as "
            "they are written. An intruder who becomes root here cannot delete what has already left. "
            "Works with rsyslog, syslog-ng, Graylog, Wazuh, Splunk and similar."))
        self.f_host = self._edit(r, "log server (name or IP)", 190)
        self.f_port = self._edit(r, "port", 70)
        self.f_port.setText("6514")
        self.f_mode = combo([("TLS (encrypted)", "tls"), ("Plain TCP", "tcp")])
        r.addWidget(self.f_mode)
        self.f_ca = self._edit(r, "CA certificate file (optional)", 210)
        self._btn(r, "Apply", "check_sq", "ok", self._forward)
        self._btn(r, "Disable", "x", "muted", lambda: self.ctl(["forward-off"], "Disabling log forwarding (admin password)…"))
        r.addStretch()
        grid.addWidget(c, 1, 0)
        # sigma
        c, self.s_sigma, r = self._section("SigmaHQ rules", (
            "Downloads the official public Sigma rules (github.com/SigmaHQ/sigma, 'core' set) and keeps the Linux "
            "rules the engine can apply (process, file and network rules of level medium or higher). "
            "They appear in Detection Rules with origin 'sigma' and can be disabled one by one."))
        self._btn(r, "Update now", "download", "ok", lambda: self.ctl(["sigma-update"], "Downloading the SigmaHQ rules (admin password, Internet needed)…"))
        self._btn(r, "Weekly: on", "refresh", "muted", lambda: self.ctl(["sigma-auto", "on"], "Enabling the weekly update (admin password)…"))
        self._btn(r, "Weekly: off", "x", "muted", lambda: self.ctl(["sigma-auto", "off"], "Disabling the weekly update (admin password)…"))
        self._btn(r, "Remove", "x", "danger", lambda: self.ctl(["sigma-clear"], "Removing the SigmaHQ rules (admin password)…"))
        r.addStretch()
        grid.addWidget(c, 2, 0)
        # yara
        c, self.s_yara, r = self._section("YARA scanning", (
            "Programs started from a temporary directory, new autorun entries and new SUID programs are checked "
            "against the YARA malware signatures downloaded by Detection > Threat Intelligence. A match is a critical alert."))
        self._btn(r, "Open Threat Intelligence", "globe", "muted",
                  lambda: self.window().open_module("threatintel") if hasattr(self.window(), "open_module") else None)
        r.addStretch()
        grid.addWidget(c, 3, 0)
        # osquery
        c, self.s_osq, r = self._section("osquery", (
            "Turns the system into a database you can question with SQL (Detection > Threat Hunting) and adds "
            "scheduled checks to the engine: processes whose file was deleted, preloaded libraries, new USB devices, "
            "remote logins, /etc/hosts and APT source changes. Installed from the official osquery repository."))
        self._btn(r, "Install osquery", "download", "ok",
                  lambda: self.run_cmd(["pkexec", "/opt/nefi/detection/install-osquery.sh"],
                                       "Installing osquery (admin password, Internet needed, about a minute)…"))
        r.addStretch()
        grid.addWidget(c, 4, 0)
        # wazuh
        c, self.s_wazuh, r = self._section("Wazuh server", (
            "Connects this machine to a Wazuh manager you ALREADY run (the agent alone is useless). The official "
            "agent is installed and NEFI's alerts are sent to the manager. The agent cannot be newer than the "
            "manager: if yours is older, write its version (for example 4.9.2)."))
        self.w_host = self._edit(r, "Wazuh manager (name or IP)", 210)
        self.w_ver = self._edit(r, "agent version (optional)", 160)
        self._btn(r, "Connect", "network", "ok", self._wazuh)
        r.addStretch()
        grid.addWidget(c, 5, 0)
        self.body.addLayout(grid)
        # blocked
        bc = Card(padding=18)
        brow = QHBoxLayout()
        brow.addWidget(SectionLabel("Blocked addresses (from Detections > Block address)"))
        brow.addStretch()
        self.b_ip = self._edit(brow, "IP address to block", 180)
        self._btn(brow, "Block", "block", "danger", self._block)
        self._btn(brow, "Unblock selected", "x", "muted", self._unblock)
        bc.body.addLayout(brow)
        self.btable = make_table(["Address", "Blocked on", "By", "Alert"])
        self.btable.setMinimumHeight(110)
        bc.body.addWidget(self.btable, 1)
        self.body.addWidget(bc, 1)

    def refresh(self, force=False):
        try:
            sig = os.stat(STATUS).st_mtime_ns
        except OSError:
            sig = None
        if not force and sig == self._sig and sig is not None:
            return
        self._sig = sig
        status = read_json(STATUS, None)
        note, _running = self.engine_note(status)
        self.note.setText(note)
        st = status or {}
        can, blk, sg, ya, fw = (st.get("canaries", []), st.get("blocked", []), st.get("sigma", {}), st.get("yara", {}),
                                st.get("forward", {}))
        self.stats["canaries"].set(len(can) if status else "–", C["accent"] if can else None)
        self.stats["blocked"].set(len(blk) if status else "–")
        self.stats["sigma"].set(sg.get("rules", 0) if status else "–")
        self.stats["yara"].set(ya.get("rules", 0) if status else "–")
        self.stats["forwarded"].set(fw.get("sent", 0) if status else "–")
        self.s_canary.setText(("Active: " + ", ".join(can)) if can else "Not set up.")
        if fw.get("enabled"):
            state = "connected" if fw.get("connected") else f"NOT connected ({fw.get('error') or 'connecting…'})"
            self.s_fwd.setText(f"Sending to {fw.get('target')}: {state}; {fw.get('sent', 0)} records sent since the engine started.")
        else:
            self.s_fwd.setText("Disabled: alerts are kept only on this machine.")
        if sg.get("rules"):
            skipped = sum(sg.get("skipped", {}).values())
            self.s_sigma.setText(f"{sg['rules']} rules installed on {short_time(sg.get('updated'))} "
                                 f"({str(sg.get('version', '')).splitlines()[0] if sg.get('version') else 'version unknown'}); "
                                 f"{skipped} skipped.")
        else:
            self.s_sigma.setText("Not installed.")
        if not ya.get("available"):
            self.s_yara.setText("The 'yara' program is not installed (it is part of the 'default' software selection).")
        elif not ya.get("rules"):
            self.s_yara.setText("No YARA rules yet: update the feeds in Threat Intelligence.")
        else:
            self.s_yara.setText(f"{ya['rules']} rule files loaded; {ya.get('scanned', 0)} files scanned, "
                                f"{ya.get('matched', 0)} matches since the engine started.")
        osq = st.get("sources", {}).get("osquery", {})
        self.s_osq.setText(f"Installed and connected ({osq.get('events', 0)} changes received)." if osq.get("available")
                           else ("Installed, waiting for the first results." if shutil.which("osqueryi") else "Not installed."))
        try:
            w = subprocess.run(["systemctl", "is-active", "wazuh-agent.service"], capture_output=True, text=True,
                               timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            w = "unknown"
        self.s_wazuh.setText("Agent running." if w == "active" else
                             ("Agent installed but not running." if os.path.isdir("/var/ossec") else "Not connected."))
        fill(self.btable, [[b.get("ip", ""), short_time(b.get("created")), b.get("by", ""), b.get("alert", "")] for b in blk])

    def _forward(self):
        host, port = self.f_host.text().strip(), self.f_port.text().strip()
        if not host or not port.isdigit():
            QMessageBox.information(self, "Log server", "Write the name or address of the log server and its port.")
            return
        mode = self.f_mode.currentData()
        if mode == "tcp" and QMessageBox.warning(
                self, "Plain TCP", "Without TLS the alerts travel unencrypted and the server is not verified. "
                "Use it only on a trusted network.\n\nContinue?", QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        args = ["forward-set", host, port, mode] + ([self.f_ca.text().strip()] if self.f_ca.text().strip() else [])
        self.ctl(args, "Setting the log server (admin password)…")

    def _wazuh(self):
        host, ver = self.w_host.text().strip(), self.w_ver.text().strip()
        if not host:
            QMessageBox.information(self, "Wazuh", "Write the name or address of your Wazuh manager.")
            return
        if QMessageBox.question(self, "Wazuh", f"Install the official Wazuh agent and connect it to {host}?\n\n"
                                "The manager must already exist and be reachable on ports 1514 and 1515.") \
                != QMessageBox.StandardButton.Yes:
            return
        self.run_cmd(["pkexec", "/opt/nefi/detection/install-wazuh.sh", host] + ([ver] if ver else []),
                     "Installing the Wazuh agent (admin password, Internet needed, a few minutes)…")

    def _block(self):
        ip = self.b_ip.text().strip()
        if ip:
            self.ctl(["block-ip", ip], f"Blocking {ip} (admin password)…")

    def _unblock(self):
        sel = self.btable.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Unblock", "Select an address in the table first.")
            return
        self.ctl(["unblock-ip", self.btable.item(sel[0].row(), 0).text()], "Removing the block (admin password)…")
