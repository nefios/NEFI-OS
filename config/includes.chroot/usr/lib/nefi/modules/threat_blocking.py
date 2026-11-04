"""NEFI Security Center — Response › Threat Blocking (CrowdSec)

Mostra gli indirizzi bloccati da CrowdSec e gli avvisi recenti, letti da
/var/lib/nefi/crowdsec/state.json (aggiornato ogni 30 s, leggibile dal gruppo sudo).
L'utente decide: sblocca, consenti sempre, oppure blocca a mano un indirizzo.
Le azioni passano da /opt/nefi/crowdsec/helper.py via pkexec (password di amministratore).
"""
import ipaddress
import json
from datetime import datetime
import os
import subprocess

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QLineEdit, QSpinBox, QTextEdit, QListWidget, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from nefi_theme import C, Card, SectionLabel, PrimaryButton, GhostButton, Pill, PageHeader

STATE = "/var/lib/nefi/crowdsec/state.json"
HELPER = "/opt/nefi/crowdsec/helper.py"
INSTALLER = "/opt/nefi/crowdsec/install.sh"

TABLE_QSS = f"""
    QTableWidget, QListWidget {{ background: {C['bg']}; border: 1px solid {C['border']}; border-radius: 8px;
                                 gridline-color: {C['border']}; }}
    QHeaderView::section {{ background: {C['card2']}; color: {C['text2']}; border: none; padding: 6px; }}
    QTableWidget::item:selected, QListWidget::item:selected {{ background: {C['accent_bg']}; color: {C['text']}; }}
"""
INPUT_QSS = f"""
    QLineEdit, QSpinBox {{ background: {C['bg']}; color: {C['text']}; border: 1px solid {C['border2']};
                           border-radius: 6px; padding: 6px 10px; }}
    QLineEdit:focus, QSpinBox:focus {{ border-color: {C['accent']}; }}
"""


def local_time(text):
    """'2026-10-27T15:37:17Z' (UTC) -> '2026-10-27 16:37:17' nell'ora locale del PC."""
    t = str(text or "")
    try:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return t[:19].replace("T", " ")


def installed():
    return os.path.exists("/usr/bin/cscli")


def read_state():
    try:
        with open(STATE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


class Worker(QThread):
    line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1)
            for l in p.stdout:
                self.line.emit(l.rstrip())
            p.wait()
            self.finished_ok.emit(p.returncode == 0)
        except OSError as e:
            self.line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


def table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    hh = t.horizontalHeader()
    for i in range(len(headers) - 1):
        hh.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
    hh.setSectionResizeMode(len(headers) - 1, QHeaderView.ResizeMode.Stretch)
    t.setStyleSheet(TABLE_QSS)
    return t


class ThreatBlockingWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self._sig = None
        self._build_ui()
        self.refresh()

    # ── UI ──
    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(14)
        lay.addWidget(PageHeader(
            "Threat Blocking",
            "CrowdSec detects hostile behaviour in the system and network logs (brute force, scans, "
            "exploitation attempts) and blocks the source address in the firewall. You decide: unblock it, "
            "always allow it, or block an address yourself."))

        # stato
        st = Card(padding=18)
        row = QHBoxLayout()
        self.state_pill = Pill("…", "muted", 120)
        row.addWidget(self.state_pill)
        self.state_lbl = QLabel("")
        self.state_lbl.setWordWrap(True)
        self.state_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 14px; background: transparent;")
        row.addWidget(self.state_lbl, 1)
        self.install_btn = PrimaryButton("Install CrowdSec", "download", 42)
        self.install_btn.clicked.connect(self._install)
        self.install_btn.hide()
        row.addWidget(self.install_btn)
        st.body.addLayout(row)
        lay.addWidget(st)

        # blocchi attivi
        bc = Card(padding=18)
        h = QHBoxLayout()
        h.addWidget(SectionLabel("Blocked now"))
        h.addStretch()
        self.unblock_btn = GhostButton("Unblock", "lock", 36)
        self.unblock_btn.setToolTip("Remove the block: the address can connect again (it may be blocked again "
                                    "if the hostile behaviour continues).")
        self.unblock_btn.clicked.connect(lambda: self._act_selected("unblock"))
        h.addWidget(self.unblock_btn)
        self.allow_btn = GhostButton("Always allow", "check_sq", 36, tone="ok")
        self.allow_btn.setToolTip("Remove the block and never block this address again (false positive).")
        self.allow_btn.clicked.connect(lambda: self._act_selected("allow"))
        h.addWidget(self.allow_btn)
        bc.body.addLayout(h)
        self.blocks = table(["Address", "Country", "Reason", "Origin", "Time left", "Events"])
        self.blocks.setMinimumHeight(170)
        self.blocks.itemSelectionChanged.connect(self._update_buttons)
        bc.body.addWidget(self.blocks)

        # blocco manuale
        m = QHBoxLayout()
        for_lbl = QLabel("Block an address:")
        for_lbl.setStyleSheet("background: transparent;")
        m.addWidget(for_lbl)
        self.ip_in = QLineEdit()
        self.ip_in.setPlaceholderText("e.g. 203.0.113.7")
        self.ip_in.setStyleSheet(INPUT_QSS)
        m.addWidget(self.ip_in, 1)
        f2 = QLabel("for")
        f2.setStyleSheet("background: transparent;")
        m.addWidget(f2)
        self.hours = QSpinBox()
        self.hours.setRange(1, 720)
        self.hours.setValue(24)
        self.hours.setSuffix(" h")
        self.hours.setStyleSheet(INPUT_QSS)
        m.addWidget(self.hours)
        self.block_btn = GhostButton("Block", "block", 36, tone="danger")
        self.block_btn.clicked.connect(self._block_manual)
        m.addWidget(self.block_btn)
        bc.body.addLayout(m)
        lay.addWidget(bc)

        # sotto: avvisi + lista "sempre consentiti"
        bottom = QHBoxLayout()
        ac = Card(padding=18)
        ac.body.addWidget(SectionLabel("Recent detections"))
        self.alerts = table(["Time", "Address", "Scenario", "Events"])
        self.alerts.setMinimumHeight(170)
        ac.body.addWidget(self.alerts)
        bottom.addWidget(ac, 3)

        wc = Card(padding=18)
        wh = QHBoxLayout()
        wh.addWidget(SectionLabel("Always allowed"))
        wh.addStretch()
        self.disallow_btn = GhostButton("Remove", "x", 32)
        self.disallow_btn.clicked.connect(self._disallow)
        wh.addWidget(self.disallow_btn)
        wc.body.addLayout(wh)
        self.allow_list = QListWidget()
        self.allow_list.setStyleSheet(TABLE_QSS)
        self.allow_list.itemSelectionChanged.connect(self._update_buttons)
        wc.body.addWidget(self.allow_list)
        bottom.addWidget(wc, 1)
        lay.addLayout(bottom)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(90)
        self.log.setPlaceholderText("Action results will appear here.")
        self.log.setStyleSheet(f"background: {C['bg']}; color: {C['accent']}; border: 1px solid {C['border']}; "
                               f"border-radius: 8px; font-family: monospace; font-size: 12px;")
        lay.addWidget(self.log)
        self._update_buttons()

    # ── dati ──
    def refresh(self):
        ok_install = installed()
        state = read_state() if ok_install else None
        self.install_btn.setVisible(not ok_install)
        if not ok_install:
            self.state_pill.setText("Not installed")
            self.state_pill.set_tone("warn")
            self.state_lbl.setText("CrowdSec is not installed. Install it from the official CrowdSec repository "
                                   "(needs Internet and the admin password).")
        elif state is None:
            self.state_pill.setText("Waiting")
            self.state_pill.set_tone("muted")
            self.state_lbl.setText(f"No data yet in {STATE} (your user must be in the 'sudo' group; "
                                   "it is updated every 30 seconds).")
        else:
            engine, bouncer = state.get("crowdsec"), state.get("bouncer")
            good = engine == "active" and bouncer == "active"
            self.state_pill.setText("Protecting" if good else "Problem")
            self.state_pill.set_tone("ok" if good else "danger")
            self.state_lbl.setText(f"Detection engine: {engine}  •  firewall blocking: {bouncer}  •  "
                                   f"{len(state.get('decisions') or [])} address(es) blocked  •  "
                                   f"updated {str(state.get('updated', ''))[11:19]}")
        self._fill(state or {})

    def _fill(self, state):
        decisions = state.get("decisions") or []
        alerts = state.get("alerts") or []
        allow = state.get("allowlist") or []
        sig = json.dumps([decisions, alerts, allow], sort_keys=True)
        if sig == self._sig:
            return                       # niente di nuovo: non tocco tabelle e selezioni
        self._sig = sig
        keep_ip = self._selected_ip()

        self.blocks.setRowCount(len(decisions))
        for r, d in enumerate(decisions):
            vals = [d.get("ip"), d.get("country"), d.get("reason"), d.get("origin"),
                    str(d.get("duration") or "").split(".")[0], d.get("events")]
            for c, v in enumerate(vals):
                it = QTableWidgetItem("" if v is None else str(v))
                it.setToolTip(it.text())
                self.blocks.setItem(r, c, it)
            if d.get("ip") == keep_ip:
                self.blocks.selectRow(r)

        self.alerts.setRowCount(len(alerts))
        for r, a in enumerate(alerts):
            vals = [local_time(a.get("time")), a.get("ip"), a.get("scenario"), a.get("events")]
            for c, v in enumerate(vals):
                it = QTableWidgetItem("" if v is None else str(v))
                it.setToolTip(it.text())
                self.alerts.setItem(r, c, it)

        self.allow_list.clear()
        self.allow_list.addItems([str(x) for x in allow])
        self._update_buttons()

    def _selected_ip(self):
        rows = self.blocks.selectionModel().selectedRows() if self.blocks.selectionModel() else []
        if rows:
            it = self.blocks.item(rows[0].row(), 0)
            return it.text() if it else None
        return None

    def _update_buttons(self):
        busy = bool(self.worker and self.worker.isRunning())
        has = installed() and not busy
        sel = self._selected_ip() is not None
        self.unblock_btn.setEnabled(has and sel)
        self.allow_btn.setEnabled(has and sel)
        self.block_btn.setEnabled(has)
        self.disallow_btn.setEnabled(has and bool(self.allow_list.selectedItems()))

    # ── azioni ──
    def _run(self, cmd, title):
        if self.worker and self.worker.isRunning():
            return
        self.log.clear()
        self.log.append(title)
        self.worker = Worker(cmd)
        self.worker.line.connect(self.log.append)
        self.worker.finished_ok.connect(self._done)
        self.worker.start()
        self._update_buttons()

    def _done(self, ok):
        self.log.append("Done." if ok else "The action failed: see the message above.")
        self._sig = None
        self.refresh()

    def _helper(self, *args):
        self._run(["pkexec", "/usr/bin/python3", HELPER, *args],
                  f"{args[0].capitalize()} {' '.join(args[1:])} (the admin password will be requested)…")

    def _act_selected(self, action):
        ip = self._selected_ip()
        if not ip:
            return
        if action == "allow":
            q = QMessageBox.question(
                self, "Always allow",
                f"{ip} will be unblocked and NEVER blocked again, even if it attacks.\n"
                "Use this only for addresses you trust (a false positive).\n\nContinue?")
            if q != QMessageBox.StandardButton.Yes:
                return
        self._helper(action, ip)

    def _block_manual(self):
        text = self.ip_in.text().strip()
        try:
            ip = str(ipaddress.ip_address(text))
        except ValueError:
            self.log.setPlainText(f"'{text}' is not a valid IPv4/IPv6 address.")
            return
        self._helper("block", ip, str(self.hours.value()))
        self.ip_in.clear()

    def _disallow(self):
        items = self.allow_list.selectedItems()
        if items:
            self._helper("disallow", items[0].text())

    def _install(self):
        self._run(["pkexec", "/bin/bash", INSTALLER],
                  "Installing CrowdSec… (the admin password will be requested)")
