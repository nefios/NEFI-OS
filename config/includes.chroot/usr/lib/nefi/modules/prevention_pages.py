"""NEFI Security Center — Prevention: Vulnerability Management, Attack Surface, Kernel Hardening, SSH Security.

I dati arrivano da /opt/nefi/system/collect.py (root):
  /var/lib/nefi/system/vulns.json    CVE dei pacchetti installati (debsecan, Debian Security Tracker)
  /var/lib/nefi/system/surface.json  inventario della superficie d'attacco
  /var/lib/nefi/system/report.json   controlli kernel/SSH con le correzioni proposte
"""
import json
import time
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QLineEdit, QTabWidget, QAbstractItemView, QGridLayout, QMessageBox
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices, QColor

from nefi_theme import C, Card, SectionLabel, GhostButton, Pill, PageHeader
from assessment import CategoryPage
from system_pages import CmdWorker

VULNS = "/var/lib/nefi/system/vulns.json"
SURFACE = "/var/lib/nefi/system/surface.json"
COLLECTOR = "/opt/nefi/system/collect.py"
TRACKER = "https://security-tracker.debian.org/tracker/"

TABLE_QSS = f"""
    QTableWidget {{ background: {C['bg']}; color: {C['text']}; border: 1px solid {C['border']};
                    border-radius: 8px; gridline-color: {C['border']}; font-size: 12px; }}
    QTableWidget::item:selected {{ background: {C['accent_bg']}; color: {C['text']}; }}
    QHeaderView::section {{ background: {C['card2']}; color: {C['text2']}; border: none;
                            border-bottom: 1px solid {C['border']}; padding: 6px; font-weight: bold; }}
"""
INPUT_QSS = (f"background: {C['bg']}; color: {C['text']}; border: 1px solid {C['border2']}; "
             f"border-radius: 6px; padding: 6px 10px;")
URGENCY_ORDER = {"high": 0, "medium": 1, "low": 2, "unimportant": 3, "not yet assigned": 4, "": 5}


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def age(generated):
    try:
        dt = datetime.strptime((generated or "")[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return "never"
    mins = int((time.time() - dt.timestamp()) // 60)
    ago = "just now" if mins < 1 else f"{mins} min ago" if mins < 120 else f"{mins // 60} h ago"
    return f"{dt.strftime('%Y-%m-%d %H:%M')} ({ago})"


def make_table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(False)
    t.setSortingEnabled(True)
    t.setStyleSheet(TABLE_QSS)
    h = t.horizontalHeader()
    h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    h.setStretchLastSection(True)
    h.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
    h.sectionClicked.connect(lambda _i: setattr(t, "_user_sorted", True))
    return t


def fill(table, rows, colors=None):
    """rows: liste di stringhe. colors: {indice_riga: colore} per evidenziare."""
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            it = QTableWidgetItem(str(val))
            if colors and r in colors:
                it.setForeground(QColor(colors[r]))
            table.setItem(r, c, it)
    if table.horizontalHeader().sortIndicatorSection() == 0 and not getattr(table, "_user_sorted", False):
        table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)   # tengo l'ordine NEFI
    table.setSortingEnabled(True)


class StatTile(QWidget):
    def __init__(self, label):
        super().__init__()
        self.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.val = QLabel("–")
        self.val.setStyleSheet("font-size: 26px; font-weight: bold; background: transparent;")
        cap = QLabel(label)
        cap.setWordWrap(True)
        cap.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        lay.addWidget(self.val)
        lay.addWidget(cap)

    def set(self, value, color=None):
        self.val.setText(str(value))
        self.val.setStyleSheet(f"font-size: 26px; font-weight: bold; background: transparent; "
                               f"color: {color or C['text']};")


class DataPage(QWidget):
    """Base: intestazione, riga di statistiche, barra azioni con log, ricarica senza sfarfallio."""
    TITLE = ""
    SUBTITLE = ""
    PATH = ""
    STATS = []          # [(chiave, etichetta)]

    def __init__(self):
        super().__init__()
        self.data = None
        self.cmd_worker = None
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
        bar = QHBoxLayout()
        self.when_lbl = QLabel("")
        self.when_lbl.setWordWrap(True)
        self.when_lbl.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        bar.addWidget(self.when_lbl, 1)
        self.actions = bar
        head.body.addLayout(bar)
        self.log = QLabel("")
        self.log.setWordWrap(True)
        self.log.setStyleSheet(f"color: {C['accent']}; font-family: monospace; font-size: 12px; background: transparent;")
        self.log.hide()
        head.body.addWidget(self.log)
        lay.addWidget(head)
        self.body = lay
        self.build()
        self.refresh(force=True)

    def build(self):
        pass

    def button(self, label, icon, tone, cmd, title):
        b = GhostButton(label, icon, 34, tone=tone)
        b.clicked.connect(lambda: self._cmd(cmd, title))
        self.actions.addWidget(b)
        return b

    def _cmd(self, cmd, title):
        if self.cmd_worker and self.cmd_worker.isRunning():
            return
        self.log.show()
        self.log.setText(title)
        self.cmd_worker = CmdWorker(cmd)
        self.cmd_worker.line.connect(lambda l: self.log.setText(l[-200:]) if l.strip() else None)
        self.cmd_worker.finished_ok.connect(self._cmd_done)
        self.cmd_worker.start()

    def _cmd_done(self, ok):
        self.log.setText(self.log.text() + ("\nDone." if ok else "\nFailed or cancelled."))
        self.refresh(force=True)

    def refresh(self, force=False):
        data = load_json(self.PATH)
        if force or data != self.data:
            self.data = data
            self.when_lbl.setText(self.status_text(data))
            self.apply(data)

    def status_text(self, data):
        if data is None:
            return ("No data yet: it is produced by the system assessment (3 minutes after boot and every 30 "
                    "minutes) or by 'Rescan'. Your user must be in the 'sudo' group to read it.")
        return f"Last update: {age(data.get('generated'))}"

    def apply(self, data):
        pass


# ───────────────────────────── Vulnerability Management ─────────────────────────────

class VulnerabilityPage(DataPage):
    TITLE = "Vulnerability Management"
    SUBTITLE = ("Known vulnerabilities (CVE) in the packages installed on this machine, from the Debian Security "
                "Tracker via debsecan. Not a configuration audit: these are real flaws in real software versions. "
                "Double-click a row to open the CVE in the Debian tracker.")
    PATH = VULNS
    STATS = [("kev", "actively exploited (CISA KEV)"), ("exposed", "in services reachable from the network"),
             ("fix", "fix available now"), ("remote", "remotely exploitable"), ("high", "high urgency"),
             ("total", "known vulnerabilities")]

    def build(self):
        self.button("Rescan", "refresh", "muted", ["pkexec", "/usr/bin/python3", COLLECTOR, "--only", "vulns"],
                    "Updating the vulnerability list from the Debian Security Tracker (admin password)…")
        self.button("Install security fixes", "download", "ok", ["pkexec", "/usr/bin/unattended-upgrade", "-v"],
                    "Installing available security updates with unattended-upgrade (admin password)…")
        card = Card(padding=18)
        row = QHBoxLayout()
        row.addWidget(SectionLabel("Vulnerabilities"))
        row.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search CVE or package…")
        self.search.setStyleSheet(INPUT_QSS)
        self.search.setFixedWidth(240)
        self.search.textChanged.connect(lambda _t: self.apply(self.data))
        row.addWidget(self.search)
        self.flt = QComboBox()
        self.flt.setStyleSheet(f"QComboBox {{ {INPUT_QSS} }}")
        for key, label in (("top", "Fix first (priority 1-2)"), ("kev", "Actively exploited"),
                           ("exposed", "In exposed services"), ("fix", "Fix available"),
                           ("remote", "Remotely exploitable"), ("high", "High urgency"), ("all", "All")):
            self.flt.addItem(label, key)
        self.flt.currentIndexChanged.connect(lambda _i: self.apply(self.data))
        row.addWidget(self.flt)
        card.body.addLayout(row)
        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        card.body.addWidget(self.hint)
        self.table = make_table(["Priority", "CVE", "Package", "Exploited", "Exposed", "Urgency", "Remote",
                                 "Fix available", "Notes"])
        self.table.cellDoubleClicked.connect(self._open)
        card.body.addWidget(self.table, 1)
        self.body.addWidget(card, 1)

    def _open(self, row, _col):
        it = self.table.item(row, 1)
        if it:
            QDesktopServices.openUrl(QUrl(TRACKER + it.text()))

    def status_text(self, data):
        if data and not data.get("available", True):
            return "debsecan is not installed: sudo apt install debsecan, then click Rescan."
        if data and data.get("error"):
            return f"Last update: {age(data.get('generated'))}  •  problem: {data['error']}"
        txt = super().status_text(data)
        if not data:
            return txt
        kev = data.get("kev") or {}
        ktxt = (f"CISA KEV catalogue: {kev.get('count', 0)} CVEs" if kev.get("available")
                else f"CISA KEV catalogue not available ({kev.get('error') or 'run Rescan with Internet'})")
        return txt + f"  •  Debian suite: {data.get('suite')}  •  {ktxt}"

    def apply(self, data):
        items = (data or {}).get("items") or []
        high = [v for v in items if (v.get("urgency") or "").startswith("high")]
        fix = [v for v in items if v.get("fix_available")]
        remote = [v for v in items if v.get("remote")]
        kev = [v for v in items if v.get("kev")]
        exposed = [v for v in items if v.get("exposed")]
        top = [v for v in items if v.get("priority", 5) <= 2]
        self.stats["kev"].set(len(kev) if data else "–", C["danger"] if kev else C["accent"])
        self.stats["exposed"].set(len(exposed) if data else "–", C["warn"] if exposed else None)
        self.stats["total"].set(len(items) if data else "–")
        self.stats["fix"].set(len(fix) if data else "–", C["warn"] if fix else C["accent"])
        self.stats["remote"].set(len(remote) if data else "–", C["danger"] if remote else C["text"])
        self.stats["high"].set(len(high) if data else "–", C["danger"] if high else C["text"])
        key = self.flt.currentData()
        sel = {"fix": fix, "remote": remote, "high": high, "kev": kev, "exposed": exposed, "top": top}.get(key, items)
        if key == "top" and not top:
            sel = items                      # niente di urgente: mostro comunque l'elenco
        q = self.search.text().strip().lower()
        if q:
            sel = [v for v in sel if q in v.get("id", "").lower() or q in v.get("package", "").lower()]
        sel = sorted(sel, key=lambda v: (v.get("priority", 5), not v.get("fix_available"), not v.get("remote"),
                                         URGENCY_ORDER.get((v.get("urgency") or "").replace("*", ""), 5), v.get("id")))
        colors = {i: (C["danger"] if v.get("priority", 5) == 1 else C["warn"]) for i, v in enumerate(sel)
                  if v.get("priority", 5) <= 2}
        fill(self.table, [[v.get("priority", ""), v.get("id", ""), v.get("package", ""),
                           "YES" if v.get("kev") else "", "yes" if v.get("exposed") else "",
                           v.get("urgency") or "not assigned",
                           "yes" if v.get("remote") else "", "yes" if v.get("fix_available") else "no",
                           v.get("flags", "")] for v in sel], colors)
        if kev:
            self.hint.setText(f"{len(kev)} vulnerabilit{'y' if len(kev) == 1 else 'ies'} on this machine "
                              f"{'is' if len(kev) == 1 else 'are'} being exploited in real attacks "
                              f"(CISA KEV catalogue). Install their fixes first"
                              + (": click 'Install security fixes'." if any(v.get("fix_available") for v in kev)
                                 else "; where no fix exists yet, stop or firewall the affected service."))
        elif top:
            self.hint.setText(f"{len(top)} vulnerabilities have priority 1-2: remotely exploitable and either high "
                              f"urgency or in a service reachable from the network. "
                              + (f"{len(fix)} fixes are available: click 'Install security fixes'." if fix else ""))
        elif fix:
            self.hint.setText(f"{len(fix)} vulnerabilities already have a fixed version in Debian: click "
                              f"'Install security fixes'.")
        elif items:
            self.hint.setText("No fix is available yet for the remaining vulnerabilities. Many are low urgency or "
                              "'unimportant' for Debian; check the tracker for details.")
        else:
            self.hint.setText("")


# ───────────────────────────── Attack Surface ─────────────────────────────

class AttackSurfacePage(DataPage):
    TITLE = "Attack Surface"
    SUBTITLE = ("Everything on this machine an attacker could try to use: open network ports (and whether the "
                "firewall really exposes them), enabled services, accounts that can log in, SUID programs and "
                "scheduled jobs. Fewer entries = smaller attack surface.")
    PATH = SURFACE
    STATS = [("network_reachable", "ports reachable from the network"), ("local_only", "local-only ports"),
             ("enabled_services", "enabled services"), ("login_accounts", "login accounts"),
             ("suid", "SUID programs"), ("cron_entries", "scheduled jobs")]

    def build(self):
        self.button("Rescan", "refresh", "muted", ["pkexec", "/usr/bin/python3", COLLECTOR, "--only", "surface"],
                    "Updating the attack surface inventory (admin password)…")
        card = Card(padding=18)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: none; }}
            QTabBar::tab {{ background: transparent; color: {C['text2']}; padding: 8px 14px; border: none;
                            border-bottom: 2px solid transparent; }}
            QTabBar::tab:selected {{ color: {C['accent']}; border-bottom: 2px solid {C['accent']}; }}
        """)
        self.t = {}
        for key, label, headers in (
            ("listening", "Network ports", ["Exposure", "Protocol", "Address", "Port", "Process", "User", "Package", "Program"]),
            ("services", "Services", ["Service", "Enabled at boot", "Running"]),
            ("accounts", "Login accounts", ["User", "UID", "Administrator", "Shell"]),
            ("suid", "SUID programs", ["Program"]),
            ("cron", "Scheduled jobs", ["File", "Entry"]),
            ("other", "Other", ["Item", "Value"]),
        ):
            self.t[key] = make_table(headers)
            self.tabs.addTab(self.t[key], label)
        card.body.addWidget(self.tabs, 1)
        self.body.addWidget(card, 1)

    def apply(self, data):
        d = data or {}
        s = d.get("summary", {})
        for key, tile in self.stats.items():
            v = s.get(key, "–") if data else "–"
            color = C["danger"] if key == "network_reachable" and isinstance(v, int) and v else None
            tile.set(v, color)
        tone = {"reachable from the network": C["danger"], "blocked by firewall": C["warn"]}
        lst = sorted(d.get("listening", []), key=lambda x: (x.get("exposure") != "reachable from the network",
                                                             x.get("exposure") != "blocked by firewall", x.get("port", 0)))
        fill(self.t["listening"], [[x.get("exposure", ""), x.get("proto", ""), x.get("address", ""), x.get("port", ""),
                                    x.get("process", ""), x.get("user", ""), x.get("package") or "not from a package",
                                    x.get("exe", "")] for x in lst],
             {i: tone[x["exposure"]] for i, x in enumerate(lst) if x.get("exposure") in tone})
        enabled, running = set(d.get("enabled_services", [])), set(d.get("running_services", []))
        fill(self.t["services"], [[u, "yes" if u in enabled else "", "yes" if u in running else ""]
                                  for u in sorted(enabled | running)])
        acc = d.get("login_accounts", [])
        fill(self.t["accounts"], [[a.get("user"), a.get("uid"), "yes" if a.get("admin") else "", a.get("shell")]
                                  for a in acc], {i: C["warn"] for i, a in enumerate(acc) if a.get("admin")})
        fill(self.t["suid"], [[p] for p in d.get("suid", [])])
        fill(self.t["cron"], [[c.get("file"), c.get("entry")] for c in d.get("cron", [])])
        other = [["Installed packages", d.get("packages_installed", "")],
                 ["Loaded kernel modules", d.get("kernel_modules", "")],
                 ["Active timers", len(d.get("timers", []))]]
        for i in d.get("interfaces", []):
            if isinstance(i, list) and i:
                other.append([f"Network interface {i[0]}", "  ".join(i[1:])])
        fill(self.t["other"], other)


# ───────────────────────────── Kernel Hardening / SSH ─────────────────────────────

class FixAllPage(CategoryPage):
    """CategoryPage con 'applica tutte le correzioni consigliate' (whitelist di fix.py)."""
    EXCLUDE = set()
    BULK_LABEL = "Apply all recommended settings"
    BULK_INFO = ""

    def build_extra(self):
        card = Card(padding=18)
        card.body.addWidget(SectionLabel("Fix"))
        row = QHBoxLayout()
        self.bulk_info = QLabel(self.BULK_INFO)
        self.bulk_info.setWordWrap(True)
        self.bulk_info.setStyleSheet(f"color: {C['text2']}; background: transparent;")
        row.addWidget(self.bulk_info, 1)
        self.bulk_btn = GhostButton(self.BULK_LABEL, "check_sq", 34, tone="ok")
        self.bulk_btn.clicked.connect(self._bulk)
        row.addWidget(self.bulk_btn)
        card.body.addLayout(row)
        arow = QHBoxLayout()
        arow.addWidget(SectionLabel("Fixes applied by NEFI"))
        arow.addStretch()
        ub = GhostButton("Undo selected", "x", 32, tone="danger")
        ub.clicked.connect(self._undo_selected)
        arow.addWidget(ub)
        card.body.addLayout(arow)
        self.applied_table = make_table(["Fix", "Setting", "Applied", "By", "Value before"])
        self.applied_table.setSelectionMode(self.applied_table.SelectionMode.ExtendedSelection)
        self.applied_table.setFixedHeight(150)
        card.body.addWidget(self.applied_table)
        self.extra.addWidget(card)
        self._applied_sig = None

    def _applied(self):
        """Correzioni applicate da NEFI che riguardano questa pagina (sysctl/modules per kernel, ssh per SSH)."""
        data = load_json("/var/lib/nefi/prevention/applied.json") or {}
        kinds = ("ssh:",) if self.CATEGORY == "ssh" else ("sysctl:", "modules")
        return {k: v for k, v in data.items() if k.startswith(kinds)}

    def _undo_selected(self):
        ids = sorted({self.applied_table.item(i.row(), 0).text() for i in self.applied_table.selectionModel().selectedRows()})
        if not ids:
            QMessageBox.information(self, "Undo fix", "Select one or more applied fixes in the table first.")
            return
        self.undo_fix(ids)

    def _fixes(self):
        checks = (self.report or {}).get("checks", [])
        out = []
        for c in checks:
            f = c.get("fix")
            if c.get("category") == self.CATEGORY and f and f not in self.EXCLUDE and f not in out:
                out.append(f)
        return out

    def _bulk(self):
        fx = self._fixes()
        if fx:
            self.apply_fix(fx, "\n".join(fx))

    def apply(self, rep):
        super().apply(rep)
        if hasattr(self, "bulk_btn"):
            n = len(self._fixes())
            self.bulk_btn.setEnabled(n > 0)
            self.bulk_btn.setText(f"  {self.BULK_LABEL} ({n})" if n else "  Nothing to fix")
            applied = self._applied()
            if applied != self._applied_sig:
                self._applied_sig = applied
                fill(self.applied_table, [[k, v.get("summary", ""), str(v.get("at", ""))[:19].replace("T", " "),
                                           v.get("by", ""),
                                           ", ".join(v["previous"]) if isinstance(v.get("previous"), list)
                                           else ("" if v.get("previous") is None else str(v["previous"]))]
                                          for k, v in sorted(applied.items())])


class KernelHardeningPage(FixAllPage):
    CATEGORY = "kernel"
    TITLE = "Kernel Hardening Assessment"
    SUBTITLE = ("Kernel parameters (sysctl), boot command line, AppArmor, audit, blocked modules and kernel taint, "
                "compared with the NEFI / KSPP recommendations. Fixable items can be corrected one by one (open a "
                "check) or all together.")
    BULK_LABEL = "Apply all recommended kernel settings"
    BULK_INFO = ("Values are written to /etc/sysctl.d/95-nefi-fixes.conf and /etc/modprobe.d/nefi-blacklist.conf "
                 "and applied immediately. Each applied fix is listed below and can be undone.")


class SSHPage(FixAllPage):
    CATEGORY = "ssh"
    TITLE = "SSH Security Assessment"
    SUBTITLE = ("The effective configuration of the SSH server (sshd -T), not just the config file: root login, "
                "passwords, brute-force limits, forwarding, idle sessions, cryptography, keys and brute-force "
                "protection. If the SSH server is not installed, these checks are not verifiable.")
    EXCLUDE = {"ssh:PasswordAuthentication"}
    BULK_LABEL = "Apply all recommended SSH settings"
    BULK_INFO = ("Settings go to /etc/ssh/sshd_config.d/40-nefi-fixes.conf and are tested with 'sshd -t' before "
                 "reloading (an invalid change is undone); applied fixes are listed below and can be undone. Turning off password login is never done in bulk: open "
                 "that check, and NEFI refuses it until an administrator has an SSH key, so you cannot lock "
                 "yourself out.")
