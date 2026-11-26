"""NEFI Security Center — Monitoring: Network IDS, DNS Monitoring, Traffic & Flows, Packet Capture.

Le pagine girano come utente. I dati arrivano da /var/lib/nefi/netmon (root:sudo 0640), scritti ogni
due minuti dal servizio nefi-netmon a partire dagli eventi di Suricata (eve.json): avvisi IDS,
richieste DNS, flussi, TLS. Le catture di pacchetti e le modifiche a Suricata passano da
/opt/nefi/netmon/netmon.py con pkexec. Una cattura si apre con Wireshark come utente normale.
"""
import os
import shutil
import subprocess
import sys
import time

import psutil
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QTextEdit, QInputDialog, QSpinBox, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen

from nefi_theme import C, Card, SectionLabel, GhostButton
from prevention_pages import make_table, fill, INPUT_QSS
from detection_pages import EnginePage, read_json, read_jsonl_tail, short_time, combo

for _p in ("/opt/nefi/netmon", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..",
                                             "opt", "nefi", "netmon")):
    if os.path.isfile(os.path.join(_p, "netlib.py")) and _p not in sys.path:
        sys.path.insert(0, _p)
        break
import netlib as nl          # noqa: E402
import pcap_summary          # noqa: E402

NETMON = ["pkexec", "/usr/bin/python3", "/opt/nefi/netmon/netmon.py"]
IRCTL = ["pkexec", "/usr/bin/python3", "/opt/nefi/ir/irctl.py"]
DETCTL = ["pkexec", "/usr/bin/python3", "/opt/nefi/detection/ctl.py"]
RANGES = [("Last hour", 1), ("Last 24 hours", 24), ("Last 7 days", 168), ("Last 30 days", 720)]
SEV = {1: ("High", C["danger"]), 2: ("Medium", C["warn"]), 3: ("Low", C["text2"])}


def human(n):
    n = float(n or 0)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000


def where(ip):
    return "Local network" if nl.is_local(ip) else "Internet"


def suricata_note(st):
    """Stato della fonte dei dati: (testo, problema?, azione consigliata)."""
    if st is None:
        return ("No data yet. The network summary is written every two minutes by the service nefi-netmon "
                "(sudo systemctl start nefi-netmon.timer); your user must be in the 'sudo' group to read it.", True, "")
    if time.time() - st.get("generated", 0) > 600:
        return ("The network summary is not being updated (last update: "
                f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(st.get('generated', 0)))}). "
                "Start it with: sudo systemctl start nefi-netmon.timer", True, "")
    if not st.get("suricata_installed"):
        return ("Suricata is not installed: there is no source for IDS alerts, DNS and flows "
                "(sudo apt install suricata suricata-update).", True, "")
    if not st.get("suricata_active"):
        return "Suricata is installed but NOT running: nothing is being recorded.", True, "enable"
    conf, dflt = st.get("configured_iface", ""), st.get("default_iface", "")
    if not st.get("iface_ok"):
        return (f"Suricata is configured for the interface '{conf or '?'}', which does not exist on this machine: "
                f"it sees no traffic." + (f" The network goes through {dflt}." if dflt else ""), True, "iface")
    if dflt and conf != dflt:
        return (f"Suricata listens on {conf}, but the network goes through {dflt}: most traffic is not inspected.",
                True, "iface")
    age = (time.time() - st["rules_updated"]) / 86400 if st.get("rules_updated") else None
    if age is None:
        return (f"Suricata is running on {conf}. The IDS rules were never updated: press 'Update IDS rules'.",
                True, "rules")
    if age > 14:
        return f"Suricata is running on {conf}. The IDS rules are {age:.0f} days old: update them.", True, "rules"
    return f"Suricata is running on {conf}; IDS rules updated {age:.0f} day(s) ago.", False, ""


class MonPage(EnginePage):
    """Base: come le pagine Detection, piu' la scelta del periodo e lo stato di Suricata."""
    def range_combo(self, row):
        self.range = combo(RANGES, 150)
        self.range.setCurrentIndex(1)
        self.range.currentIndexChanged.connect(lambda _i: self.refresh(force=True))
        row.addWidget(self.range)

    def btn(self, row, label, icon, tone, fn):
        b = GhostButton(label, icon, 32, tone=tone)
        b.clicked.connect(fn)
        row.addWidget(b)
        return b

    def changed(self):
        """True se i dati su disco sono cambiati dall'ultimo disegno."""
        sig = []
        for p in (nl.STATUS, nl.CAPTURES, nl.ALERTS):
            try:
                sig.append(os.stat(p).st_mtime_ns)
            except OSError:
                sig.append(0)
        if sig == self._sig:
            return False
        self._sig = sig
        return True

    def status(self):
        st = read_json(nl.STATUS, None)
        text, bad, _action = suricata_note(st)
        self.note.setText(text)
        self.note.setStyleSheet(f"color: {C['warn'] if bad else C['text3']}; font-size: 12px; background: transparent;")
        return st

    def data(self):
        return nl.load_range(self.range.currentData())

    def selected_text(self, table, col, what):
        sel = table.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Select", f"Select {what} in the table first.")
            return None
        return table.item(sel[0].row(), col).text()

    def block_ip(self, ip):
        if not ip:
            return
        if nl.is_local(ip):
            QMessageBox.information(self, "Block address", f"{ip} is an address of your local network. Blocking it here "
                                    "is rarely what you want: use Response > Containment if you are sure.")
            return
        if QMessageBox.warning(self, "Block address", f"Block every connection from and to {ip}?\n\nThe block stays "
                               "until you remove it in Response > Containment.",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.run_cmd(IRCTL + ["ioc-add", "ip", ip, "Blocked from Monitoring"], f"Blocking {ip} (admin password)…")


# ───────────────────────────── Network IDS ─────────────────────────────
class NetworkIDSPage(MonPage):
    TITLE = "Network IDS"
    SUBTITLE = ("Suricata inspects the traffic of this machine and raises an alert when it matches a known attack, "
                "malware or policy signature. Alerts also reach Detection > Detections, where they are correlated with "
                "what the programs on this machine are doing.")
    STATS = [("alerts", "alerts in the period"), ("high", "high severity"), ("sigs", "different signatures"),
             ("sources", "remote addresses involved")]

    def build(self):
        self.alerts = []
        top = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Alerts by signature"))
        row.addStretch()
        self.range_combo(row)
        self.b_iface = self.btn(row, "Fix interface", "network", "warn", lambda: self.run_cmd(
            NETMON + ["suricata-iface", "auto"], "Pointing Suricata at the active interface (admin password)…"))
        self.b_enable = self.btn(row, "Start Suricata", "play", "warn", lambda: self.run_cmd(
            NETMON + ["suricata-enable"], "Starting Suricata (admin password)…"))
        self.btn(row, "Update IDS rules", "download", "muted", lambda: self.run_cmd(
            NETMON + ["suricata-update"], "Downloading the IDS rules (admin password, about a minute)…"))
        top.body.addLayout(row)
        self.sig_table = make_table(["Alerts", "Severity", "Signature", "Category", "SID"])
        top.body.addWidget(self.sig_table, 1)
        self.body.addWidget(top, 1)

        card = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Latest alerts"))
        row.addStretch()
        self.btn(row, "Open incident", "siren", "ok", self._incident)
        self.btn(row, "Record its traffic", "activity", "muted", self._capture)
        self.btn(row, "Block address", "block", "danger",
                 lambda: self.block_ip((self._alert() or {}).get("remote", "")))
        card.body.addLayout(row)
        self.table = make_table(["Time", "Severity", "Signature", "From", "To", "Protocol", "Action"])
        card.body.addWidget(self.table, 1)
        self.body.addWidget(card, 1)

    def _alert(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Select", "Select an alert in the 'Latest alerts' table first.")
            return None
        key = (self.table.item(sel[0].row(), 0).data(Qt.ItemDataRole.UserRole))
        return next((a for a in self.alerts if id(a) == key), None)

    def _incident(self):
        a = self._alert()
        if not a:
            return
        sev = {1: "high", 2: "medium", 3: "low"}.get(a.get("severity"), "medium")
        title = f"IDS: {a.get('signature', 'alert')}"[:150]
        desc = (f"Suricata alert SID {a.get('sid')} at {a.get('ts', '')[:19]}: {a.get('src')}:{a.get('sport')} -> "
                f"{a.get('dst')}:{a.get('dport')} {a.get('proto')}. Category: {a.get('category', '')}")[:480]
        if QMessageBox.question(self, "Open incident", f"Open a {sev}-severity incident for this alert?\n\n{title}") \
                == QMessageBox.StandardButton.Yes:
            self.run_cmd(IRCTL + ["case-open", sev, "network-intrusion", title, desc], "Opening the incident (admin password)…")

    def _capture(self):
        a = self._alert()
        st = read_json(nl.STATUS, {}) or {}
        if not a:
            return
        if not st.get("default_iface"):
            QMessageBox.information(self, "Capture", "No active network interface was found.")
            return
        host = a.get("remote") or a.get("src")
        if QMessageBox.question(self, "Record traffic", f"Record every packet exchanged with {host} for 10 minutes "
                                f"(200 MB at most)?\n\nThe capture appears in Monitoring > Packet Capture.") \
                == QMessageBox.StandardButton.Yes:
            self.run_cmd(NETMON + ["capture-start", st["default_iface"], "10", "200", host, "-", "-", "-",
                                   f"IDS alert: {a.get('signature', '')}"[:190]], "Starting the capture (admin password)…")

    def refresh(self, force=False):
        if not self.changed() and not force:
            return
        st = self.status()
        _t, _bad, action = suricata_note(st)
        self.b_iface.setVisible(action == "iface")
        self.b_enable.setVisible(action == "enable")
        d = self.data()
        import json
        sigs = [(json.loads(k), n) for k, n in nl.top(d["alerts"], 200)]
        self.stats["alerts"].set(d["alert_total"], C["warn"] if d["alert_total"] else C["accent"])
        self.stats["high"].set(d["alert_high"], C["danger"] if d["alert_high"] else C["accent"])
        self.stats["sigs"].set(len(sigs))
        self.stats["sources"].set(len(d["alert_src"]))
        fill(self.sig_table, [[n, SEV.get(k[2], SEV[3])[0], k[1], k[3], k[0]] for k, n in sigs],
             {i: SEV.get(k[2], SEV[3])[1] for i, (k, n) in enumerate(sigs)})
        self.alerts = list(reversed((read_jsonl_tail(nl.ALERTS, 1024 * 1024) or [])[-300:]))
        fill(self.table, [[short_time(a.get("ts")), SEV.get(a.get("severity"), SEV[3])[0], a.get("signature", ""),
                           f"{a.get('src')}:{a.get('sport')}", f"{a.get('dst')}:{a.get('dport')}",
                           f"{a.get('proto', '')} {a.get('app') or ''}".strip(), a.get("action", "")]
                          for a in self.alerts],
             {i: SEV.get(a.get("severity"), SEV[3])[1] for i, a in enumerate(self.alerts)})
        for i, a in enumerate(self.alerts):
            self.table.item(i, 0).setData(Qt.ItemDataRole.UserRole, id(a))


# ───────────────────────────── DNS ─────────────────────────────
class DnsPage(MonPage):
    TITLE = "DNS Monitoring"
    SUBTITLE = ("Every name this machine asks the DNS for, as seen on the network. Almost every connection starts "
                "with a DNS request: an unknown or random-looking name, or one domain with hundreds of different "
                "subdomains, is often the first visible sign of malware. Encrypted DNS (DoH/DoT) is not visible here.")
    STATS = [("total", "DNS requests"), ("unique", "different names"), ("nx", "names that do not exist"),
             ("flags", "names worth a look")]

    def build(self):
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setStyleSheet("QSplitter::handle { background: transparent; width: 12px; }")
        left = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Most requested names"))
        row.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter (part of a name)")
        self.search.setStyleSheet(INPUT_QSS)
        self.search.setMaximumWidth(220)
        self.search.textChanged.connect(lambda _t: self.refresh(force=True))
        row.addWidget(self.search)
        self.range_combo(row)
        left.body.addLayout(row)
        self.table = make_table(["Requests", "Name", "Domain"])
        left.body.addWidget(self.table, 1)
        split.addWidget(left)

        right = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Names worth a look"))
        row.addStretch()
        self.btn(row, "Block domain", "block", "danger", self._block)
        right.body.addLayout(row)
        hint = QLabel("Indicators, not proof: content networks and telemetry also use long random names. Check which "
                      "program asked (Detection > Threat Hunting) before blocking.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        right.body.addWidget(hint)
        self.flags = make_table(["Name", "Why", "When", "Asked by"])
        right.body.addWidget(self.flags, 1)
        split.addWidget(right)
        self.body.addWidget(split, 1)

    def _block(self):
        name = None
        for table, col in ((self.flags, 0), (self.table, 1)):
            sel = table.selectionModel().selectedRows()
            if sel:
                name = table.item(sel[0].row(), col).text().lstrip("*.")
                break
        if not name:
            QMessageBox.information(self, "Select", "Select a name in one of the two tables first.")
            return
        if QMessageBox.warning(self, "Block domain", f"Make {name} unreachable from this machine?\n\nOnly this exact "
                               "name is blocked (not its subdomains). Remove the block in Response > Containment.",
                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                               QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.run_cmd(IRCTL + ["ioc-add", "domain", name, "Blocked from DNS Monitoring"],
                         f"Blocking {name} (admin password)…")

    def refresh(self, force=False):
        if not self.changed() and not force:
            return
        self.status()
        d = self.data()
        total = d["dns_total"]
        self.stats["total"].set(total)
        self.stats["unique"].set(len(d["dns"]))
        pct = 100 * d["nxdomain"] / total if total else 0
        self.stats["nx"].set(f"{d['nxdomain']} ({pct:.0f}%)", C["warn"] if pct > 20 and total > 50 else None)
        self.stats["flags"].set(len(d["dns_flags"]), C["warn"] if d["dns_flags"] else C["accent"])
        needle = self.search.text().strip().lower()
        rows = [[n, name, nl.base_domain(name)] for name, n in nl.top(d["dns"], 600) if needle in name]
        fill(self.table, rows)
        fill(self.flags, [[f.get("name", ""), f.get("why", ""), short_time(f.get("ts")) or f.get("ts", ""),
                           f.get("src", "")] for f in d["dns_flags"] if needle in f.get("name", "")])


# ───────────────────────────── Traffic & Flows ─────────────────────────────
class TrafficChart(QWidget):
    """Byte inviati e ricevuti per ora (barre affiancate)."""
    def __init__(self):
        super().__init__()
        self.hours = []
        self.setMinimumHeight(170)
        self.setStyleSheet("background: transparent;")

    def set_hours(self, hours):
        self.hours = hours
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        left, right, top, bottom = 64, 8, 22, 22
        area = QRectF(left, top, max(1, self.width() - left - right), max(1, self.height() - top - bottom))
        p.setPen(QColor(C["text3"]))
        if not self.hours:
            p.drawText(area, Qt.AlignmentFlag.AlignCenter, "No traffic recorded in this period.")
            return
        peak = max(max(h["out"], h["in"]) for h in self.hours) or 1
        for frac in (0, 0.5, 1):
            y = area.bottom() - area.height() * frac
            p.setPen(QPen(QColor(C["border"]), 1))
            p.drawLine(int(area.left()), int(y), int(area.right()), int(y))
            p.setPen(QColor(C["text3"]))
            p.drawText(QRectF(0, y - 8, left - 6, 16), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       human(peak * frac))
        slot = area.width() / len(self.hours)
        bar = max(1.0, min(14.0, slot / 2 - 1))
        for i, h in enumerate(self.hours):
            x = area.left() + slot * i + (slot - 2 * bar) / 2
            for j, (key, col) in enumerate((("out", C["info"]), ("in", C["accent"]))):
                hgt = area.height() * h[key] / peak
                p.fillRect(QRectF(x + j * bar, area.bottom() - hgt, max(1.0, bar - 1), hgt), QColor(col))
        p.setPen(QColor(C["text3"]))
        first, last = self.hours[0]["hour"], self.hours[-1]["hour"]
        p.drawText(QRectF(area.left(), area.bottom() + 4, 160, 16), Qt.AlignmentFlag.AlignLeft, first.replace("T", " ") + ":00")
        p.drawText(QRectF(area.right() - 160, area.bottom() + 4, 160, 16), Qt.AlignmentFlag.AlignRight,
                   last.replace("T", " ") + ":00")
        p.fillRect(QRectF(area.left(), 4, 10, 10), QColor(C["info"]))
        p.drawText(QRectF(area.left() + 16, 0, 80, 18), Qt.AlignmentFlag.AlignVCenter, "sent")
        p.fillRect(QRectF(area.left() + 80, 4, 10, 10), QColor(C["accent"]))
        p.drawText(QRectF(area.left() + 96, 0, 100, 18), Qt.AlignmentFlag.AlignVCenter, "received")


class FlowsPage(MonPage):
    TITLE = "Traffic & Flows"
    SUBTITLE = ("Who this machine talked to, on which service and how much, hour by hour for the last 30 days. "
                "A flow is one connection: NEFI keeps its endpoints and size, not its content. Look for remote "
                "hosts you do not recognise and for large amounts of data SENT.")
    STATS = [("out", "sent"), ("in", "received"), ("flows", "connections"), ("hosts", "remote hosts")]

    def build(self):
        chart = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Traffic per hour"))
        row.addStretch()
        self.range_combo(row)
        chart.body.addLayout(row)
        self.chart = TrafficChart()
        chart.body.addWidget(self.chart)
        self.body.addWidget(chart)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setStyleSheet("QSplitter::handle { background: transparent; width: 12px; }")
        left = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Remote hosts"))
        row.addStretch()
        self.btn(row, "Block address", "block", "danger",
                 lambda: self.block_ip(self.selected_text(self.hosts, 0, "a remote host")))
        left.body.addLayout(row)
        self.hosts = make_table(["Address", "Where", "Data", "Connections"])
        left.body.addWidget(self.hosts, 1)
        split.addWidget(left)
        mid = Card(padding=18)
        mid.body.addWidget(SectionLabel("Services and protocols"))
        self.ports = make_table(["Service", "Data", "Connections"])
        mid.body.addWidget(self.ports, 1)
        split.addWidget(mid)
        right = Card(padding=18)
        right.body.addWidget(SectionLabel("Encrypted sites (TLS server names)"))
        self.tls = make_table(["Connections", "Server name"])
        right.body.addWidget(self.tls, 1)
        split.addWidget(right)
        self.body.addWidget(split, 1)

    def refresh(self, force=False):
        if not self.changed() and not force:
            return
        self.status()
        d = self.data()
        self.stats["out"].set(human(d["bytes_out"]))
        self.stats["in"].set(human(d["bytes_in"]))
        self.stats["flows"].set(d["flows"])
        self.stats["hosts"].set(len(d["talkers"]))
        self.chart.set_hours(d.get("hours", [])[-72:] if self.range.currentData() > 72 else d.get("hours", []))
        hosts = nl.top(d["talkers"], 300)
        fill(self.hosts, [[ip, where(ip), human(v[0]), v[1]] for ip, v in hosts])
        rows = [[k, human(v[0]), v[1]] for k, v in nl.top(d["ports"], 100)]
        rows += [[f"protocol {k}", human(v[0]), v[1]] for k, v in nl.top(d["app"], 30) if k not in ("unknown", "failed")]
        fill(self.ports, rows)
        fill(self.tls, [[n, name] for name, n in nl.top(d["tls"], 300)])


# ───────────────────────────── Packet Capture ─────────────────────────────
class SummaryWorker(QThread):
    done = pyqtSignal(str)

    def __init__(self, path):
        super().__init__()
        self.path = path

    def run(self):
        try:
            self.done.emit(pcap_summary.as_text(pcap_summary.summarize(self.path)))
        except Exception as e:                       # un file rovinato non deve chiudere la finestra
            self.done.emit(f"Could not read the capture: {e}")


class PcapPage(MonPage):
    TITLE = "Packet Capture"
    SUBTITLE = ("Record the packets themselves (PCAP) when you need to see exactly what was exchanged. Every capture "
                "has a time and size limit, a reason and the name of who started it. Captures are stored readable "
                "by administrators only and open in Wireshark without root. Captured traffic can contain "
                "passwords and personal data: record only what the investigation needs.")
    STATS = [("running", "running now"), ("stored", "captures stored"), ("size", "disk used"),
             ("tool", "capture tool")]

    def build(self):
        self.items, self.sw = [], None
        form = Card(padding=18)
        form.body.addWidget(SectionLabel("New capture"))
        row = QHBoxLayout()
        ifaces = [(n, n) for n, s in psutil.net_if_stats().items() if n != "lo" and s.isup] or \
                 [(n, n) for n in psutil.net_if_stats() if n != "lo"] or [("(no interface)", "")]
        self.f_iface = combo(ifaces, 120)
        row.addWidget(self.f_iface)
        self.f_host = self._edit(row, "Only this IP address (empty = all)", 230)
        self.f_port = self._edit(row, "Port", 70)
        self.f_proto = combo([("Any protocol", "-"), ("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp")], 120)
        row.addWidget(self.f_proto)
        self.f_min = self._spin(row, 1, 240, 10, " min")
        self.f_mb = self._spin(row, 10, 4096, 200, " MB max")
        row.addStretch()
        form.body.addLayout(row)
        row = QHBoxLayout()
        self.f_case = self._edit(row, "Incident or case (optional)", 230)
        self.f_reason = self._edit(row, "Reason for this capture (required)", 420)
        self.btn(row, "Start capture", "play", "ok", self._start)
        row.addStretch()
        form.body.addLayout(row)
        self.body.addWidget(form)

        card = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Captures"))
        row.addStretch()
        self.btn(row, "Stop", "x", "warn", lambda: self._cmd("capture-stop", "Stopping the capture"))
        self.btn(row, "Summary", "list", "muted", self._summary)
        self.btn(row, "Open in Wireshark", "search", "muted", self._wireshark)
        self.btn(row, "Preserve as evidence", "folder", "ok", self._preserve)
        self.btn(row, "Delete", "x", "danger", self._delete)
        card.body.addLayout(row)
        self.table = make_table(["Capture", "State", "Started", "Interface", "Filter", "Size", "By", "Case", "Reason"])
        card.body.addWidget(self.table, 1)
        self.summary = QTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setMinimumHeight(170)
        self.summary.setPlaceholderText("Select a finished capture and press 'Summary': conversations, services, DNS "
                                        "names, TLS server names and HTTP hosts found in the file.")
        self.summary.setStyleSheet(f"background: {C['bg']}; color: {C['text']}; border: 1px solid {C['border']}; "
                                   f"border-radius: 8px; font-family: monospace; font-size: 12px;")
        card.body.addWidget(self.summary, 1)
        self.body.addWidget(card, 1)

    def _edit(self, row, placeholder, width):
        e = QLineEdit()
        e.setPlaceholderText(placeholder)
        e.setStyleSheet(INPUT_QSS)
        e.setFixedWidth(width)
        row.addWidget(e)
        return e

    def _spin(self, row, lo, hi, val, suffix):
        s = QSpinBox()
        s.setRange(lo, hi)
        s.setValue(val)
        s.setSuffix(suffix)
        s.setStyleSheet(f"QSpinBox {{ {INPUT_QSS} }}")
        s.setFixedWidth(120)
        row.addWidget(s)
        return s

    def _start(self):
        iface, reason = self.f_iface.currentData(), self.f_reason.text().strip()
        host, port = self.f_host.text().strip(), self.f_port.text().strip()
        if not iface or not reason:
            QMessageBox.information(self, "New capture", "Choose the interface and write the reason for the capture: "
                                    "it is recorded with your account name.")
            return
        try:
            nl.capture_filter(host, port, "" if self.f_proto.currentData() == "-" else self.f_proto.currentData())
        except ValueError as e:
            QMessageBox.information(self, "New capture", f"Check the filter: {e}")
            return
        self.run_cmd(NETMON + ["capture-start", iface, str(self.f_min.value()), str(self.f_mb.value()), host or "-",
                               port or "-", self.f_proto.currentData(), self.f_case.text().strip() or "-", reason],
                     "Starting the capture (admin password)…")

    def _selected(self, finished=False):
        cid = self.selected_text(self.table, 0, "a capture")
        item = next((c for c in self.items if c.get("id") == cid), None)
        if item and finished and item.get("status") != "stopped":
            QMessageBox.information(self, "Capture", "This capture is still running: stop it first.")
            return None
        return item

    def _cmd(self, cmd, title):
        item = self._selected()
        if item:
            self.run_cmd(NETMON + [cmd, item["id"]], f"{title} (admin password)…")

    def _delete(self):
        item = self._selected(finished=True)
        if item and QMessageBox.warning(self, "Delete capture", f"Delete {item['id']} for good?\n\nA copy preserved as "
                                        "evidence is not affected.", QMessageBox.StandardButton.Yes |
                                        QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) \
                == QMessageBox.StandardButton.Yes:
            self.run_cmd(NETMON + ["capture-delete", item["id"]], "Deleting (admin password)…")

    def _summary(self):
        item = self._selected(finished=True)
        if not item or (self.sw and self.sw.isRunning()):
            return
        self.summary.setPlainText(f"Reading {item['id']}…")
        self.sw = SummaryWorker(item["file"])
        self.sw.done.connect(self.summary.setPlainText)
        self.sw.start()

    def _wireshark(self):
        item = self._selected(finished=True)
        if not item:
            return
        if not shutil.which("wireshark"):
            QMessageBox.information(self, "Wireshark", "Wireshark is not installed (sudo apt install wireshark).\n\n"
                                    f"The capture file is:\n{item['file']}")
            return
        if not os.access(item["file"], os.R_OK):
            QMessageBox.information(self, "Wireshark", "Your user cannot read the capture: it must be in the 'sudo' group.")
            return
        subprocess.Popen(["wireshark", "-r", item["file"]], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _preserve(self):
        item = self._selected(finished=True)
        if not item:
            return
        case, ok = QInputDialog.getText(self, "Preserve as evidence", "Case or incident:", text=item.get("case", ""))
        if not ok or not case.strip():
            return
        operator, ok = QInputDialog.getText(self, "Preserve as evidence", "Operator (your full name):")
        if not ok or not operator.strip():
            return
        self.run_cmd(NETMON + ["capture-preserve", item["id"], case.strip(), operator.strip(),
                               item.get("reason") or "Network capture"],
                     "Copying to the evidence store and signing (admin password)…")

    def refresh(self, force=False):
        if not self.changed() and not force:
            return
        st = self.status() or {}
        self.items = read_json(nl.CAPTURES, [])
        running = [c for c in self.items if c.get("status") == "running"]
        self.stats["running"].set(len(running), C["warn"] if running else None)
        self.stats["stored"].set(len(self.items) - len(running))
        self.stats["size"].set(human(sum(c.get("size", 0) for c in self.items)))
        tools = st.get("tools", {})
        self.stats["tool"].set("dumpcap" if tools.get("dumpcap") else "tcpdump" if tools.get("tcpdump") else "none",
                               None if tools.get("dumpcap") or tools.get("tcpdump") else C["danger"])
        fill(self.table, [[c.get("id", ""), "RECORDING" if c.get("status") == "running" else
                           ("empty" if not c.get("size") else "finished"), short_time(c.get("started")),
                           c.get("iface", ""), c.get("filter") or "all traffic", human(c.get("size", 0)),
                           c.get("by", ""), c.get("case", ""), c.get("reason", "")] for c in self.items],
             {i: C["warn"] for i, c in enumerate(self.items) if c.get("status") == "running"})
