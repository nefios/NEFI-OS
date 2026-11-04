"""NEFI Security Center — Detection › Runtime Alerts (Falco)

Mostra gli avvisi di Falco letti da /var/log/falco/events.json (JSON, una riga per evento).
Il file e' leggibile dal gruppo sudo: niente password per consultarlo.
Se Falco non e' installato, offre l'installazione (pkexec /opt/nefi/falco/install.sh).
"""
import json
import os
from datetime import datetime
import subprocess
from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

from nefi_theme import C, Card, SectionLabel, PrimaryButton, GhostButton, Pill, PageHeader

EVENTS = "/var/log/falco/events.json"
SERVICE = "falco-modern-bpf.service"
INSTALLER = "/opt/nefi/falco/install.sh"
MAX_EVENTS = 500
# priorita' di Falco, dalla piu' grave
PRIORITIES = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
PRIO_TONE = {"Emergency": "danger", "Alert": "danger", "Critical": "danger", "Error": "danger",
             "Warning": "warn", "Notice": "info", "Informational": "muted", "Debug": "muted"}


def local_time(text):
    """Orario UTC di Falco -> ora locale del PC (es. 2026-10-26 12:17:43)."""
    t = str(text or "")
    try:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
        return (dt.astimezone() if dt.tzinfo else dt).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return t[:19].replace("T", " ")


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(cmd, 1, "", "")


def falco_state():
    """'missing' se non installato, altrimenti lo stato del servizio (active, inactive, failed...)."""
    if not os.path.exists("/usr/bin/falco"):
        return "missing"
    return _run(["systemctl", "is-active", SERVICE]).stdout.strip() or "unknown"


def read_events(path=EVENTS, limit=MAX_EVENTS):
    """Ultimi `limit` eventi validi del file JSON di Falco (dal piu' recente)."""
    lines = deque(maxlen=limit)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                lines.append(line)
    except OSError:
        return None          # file assente o non leggibile
    events = []
    for line in reversed(lines):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict):
            events.append(ev)
    return events


class LoadWorker(QThread):
    done = pyqtSignal(str, object)

    def run(self):
        self.done.emit(falco_state(), read_events())


class InstallWorker(QThread):
    line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def run(self):
        try:
            p = subprocess.Popen(["pkexec", "/bin/bash", INSTALLER], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1)
            for l in p.stdout:
                self.line.emit(l.rstrip())
            p.wait()
            self.finished_ok.emit(p.returncode == 0)
        except OSError as e:
            self.line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class RuntimeAlertsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.events = []
        self.selected_key = None    # avviso che l'utente sta guardando
        self.shown_sig = None       # dati attualmente mostrati in tabella
        self.loader = None
        self.installer = None
        self._build_ui()
        self.refresh()

    # ── UI ──
    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(14)
        lay.addWidget(PageHeader("Runtime Alerts",
                                 "Real-time threat detection by Falco (CNCF): suspicious process, file "
                                 "and network activity on this system."))

        # stato
        status = Card(padding=18)
        row = QHBoxLayout()
        self.state_pill = Pill("…", "muted", 110)
        row.addWidget(self.state_pill)
        self.state_lbl = QLabel("Checking Falco…")
        self.state_lbl.setWordWrap(True)
        self.state_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 14px; background: transparent;")
        row.addWidget(self.state_lbl, 1)
        self.install_btn = PrimaryButton("Install Falco", "download", 42)
        self.install_btn.clicked.connect(self._install)
        self.install_btn.hide()
        row.addWidget(self.install_btn)
        self.refresh_btn = GhostButton("Refresh", "refresh", 40)
        self.refresh_btn.clicked.connect(self.refresh)
        row.addWidget(self.refresh_btn)
        status.body.addLayout(row)
        self.counts_lbl = QLabel("")
        self.counts_lbl.setStyleSheet(f"color: {C['text3']}; font-size: 13px; background: transparent;")
        status.body.addWidget(self.counts_lbl)
        lay.addWidget(status)

        # avvisi
        card = Card(padding=18)
        head = QHBoxLayout()
        head.addWidget(SectionLabel("Latest alerts"))
        head.addStretch()
        head.addWidget(QLabel("Minimum priority:"))
        self.prio_box = QComboBox()
        self.prio_box.addItems(["Warning", "Error", "Critical", "Notice", "Informational"])
        self.prio_box.setStyleSheet(f"""
            QComboBox {{ background: {C['bg']}; color: {C['text']}; border: 1px solid {C['border2']};
                         border-radius: 6px; padding: 5px 10px; min-width: 130px; }}
            QComboBox QAbstractItemView {{ background: {C['card']}; color: {C['text']};
                                           selection-background-color: {C['accent_bg']}; }}
        """)
        self.prio_box.currentIndexChanged.connect(lambda _i: self._fill_table(force=True))
        head.addWidget(self.prio_box)
        card.body.addLayout(head)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Priority", "Rule", "Details"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(2, 280)
        self.table.setMinimumHeight(220)
        self.table.setStyleSheet(f"""
            QTableWidget {{ background: {C['bg']}; border: 1px solid {C['border']}; border-radius: 8px;
                            gridline-color: {C['border']}; }}
            QHeaderView::section {{ background: {C['card2']}; color: {C['text2']}; border: none; padding: 6px; }}
            QTableWidget::item:selected {{ background: {C['accent_bg']}; color: {C['text']}; }}
        """)
        self.table.itemSelectionChanged.connect(self._show_detail)
        card.body.addWidget(self.table, 1)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMinimumHeight(220)
        self.detail.setPlaceholderText("Select an alert to see all its fields.")
        self.detail.setStyleSheet(f"background: {C['bg']}; color: {C['text2']}; border: 1px solid "
                                  f"{C['border']}; border-radius: 8px; font-family: monospace; font-size: 12px;")
        card.body.addWidget(self.detail)
        lay.addWidget(card, 1)

    # ── dati ──
    def refresh(self):
        if self.loader and self.loader.isRunning():
            return
        self.loader = LoadWorker()
        self.loader.done.connect(self._apply)
        self.loader.start()

    def _apply(self, state, events):
        self.install_btn.setVisible(state == "missing")
        if state == "missing":
            self.state_pill.setText("Not installed")
            self.state_pill.set_tone("warn")
            self.state_lbl.setText("Falco is not installed. Install it from the official Falco "
                                   "repository (about 100 MB, needs Internet and the admin password).")
        elif state == "active":
            self.state_pill.setText("Active")
            self.state_pill.set_tone("ok")
            self.state_lbl.setText(f"Falco is monitoring the system ({SERVICE}).")
        else:
            self.state_pill.setText(state.capitalize())
            self.state_pill.set_tone("danger")
            self.state_lbl.setText(f"Falco is installed but not running. Check: journalctl -u {SERVICE}")

        if events is None:
            self.events = []
            if state != "missing":
                self.counts_lbl.setText(f"Cannot read {EVENTS} (your user must be in the 'sudo' group).")
        else:
            self.events = events
            n = {p: 0 for p in PRIORITIES}
            for ev in events:
                n[ev.get("priority", "Debug")] = n.get(ev.get("priority", "Debug"), 0) + 1
            high = n["Emergency"] + n["Alert"] + n["Critical"] + n["Error"]
            self.counts_lbl.setText(f"Last {len(events)} events  •  {high} high  •  "
                                    f"{n['Warning']} warning  •  {n['Notice']} notice")
        self._fill_table()

    @staticmethod
    def _key(ev):
        """Identifica un evento (stesso istante, regola e testo = stesso evento)."""
        return (ev.get("time"), ev.get("rule"), ev.get("output"))

    def _fill_table(self, force=False):
        minimum = self.prio_box.currentText()
        keep = PRIORITIES[:PRIORITIES.index(minimum) + 1]
        rows = [ev for ev in self.events if ev.get("priority") in keep]
        sig = (minimum, tuple(self._key(ev) for ev in rows))
        if not force and sig == self.shown_sig:
            return                  # niente di nuovo: la tabella e i dettagli restano come sono
        self.shown_sig = sig

        self.table.blockSignals(True)       # durante il ridisegno non cambiare i dettagli
        self.table.clearSelection()
        self.table.setRowCount(len(rows))
        reselect = -1
        for r, ev in enumerate(rows):
            if self._key(ev) == self.selected_key:
                reselect = r
            t = local_time(ev.get("time"))
            prio = str(ev.get("priority", ""))
            fg = {"danger": C["danger"], "warn": C["warn"], "info": C["info"]}.get(PRIO_TONE.get(prio), C["text2"])
            cells = [t, prio, str(ev.get("rule", "")), str(ev.get("output", ""))]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if c == 1:
                    item.setForeground(QColor(fg))
                item.setData(Qt.ItemDataRole.UserRole, ev)
                self.table.setItem(r, c, item)
        if reselect >= 0:
            self.table.selectRow(reselect)  # l'avviso che stavi guardando resta selezionato
        self.table.blockSignals(False)
        if reselect < 0 and self.selected_key is not None:
            # l'avviso non c'e' piu' (es. filtro cambiato): svuoto i dettagli
            self.selected_key = None
            self.detail.clear()

    def _show_detail(self):
        items = self.table.selectedItems()
        if items:
            ev = items[0].data(Qt.ItemDataRole.UserRole)
            self.selected_key = self._key(ev)
            self.detail.setPlainText(json.dumps(ev, indent=2, ensure_ascii=False))

    # ── installazione ──
    def _install(self):
        if self.installer and self.installer.isRunning():
            return
        self.install_btn.setEnabled(False)
        self.detail.clear()
        self.detail.append("Installing Falco… (the admin password will be requested)")
        self.installer = InstallWorker()
        self.installer.line.connect(self.detail.append)
        self.installer.finished_ok.connect(self._installed)
        self.installer.start()

    def _installed(self, ok):
        self.install_btn.setEnabled(True)
        self.detail.append("\nDone." if ok else "\nInstallation failed: see the messages above.")
        self.refresh()
