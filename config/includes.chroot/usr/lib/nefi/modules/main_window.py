"""NEFI Security Center — finestra principale con navigazione a 6 sezioni."""
import importlib
import os
import traceback

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QStackedWidget, QTextEdit, QSizePolicy, QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QPoint
from PyQt6.QtGui import QPixmap, QIcon

from nefi_theme import C, icon_pixmap, glow, SectionLabel, Card, compact

# ── Registro moduli: sezione → (id, titolo, icona, descrizione, modulo, classe) ──
SECTIONS = [
    ("system", "System", "monitor", [
        ("score",      "Security Score",  "target",   "Overall security posture",        "security_score",     "SecurityScoreWidget"),
        ("overview",   "System Overview", "cpu",      "CPU, memory, disk and uptime",    "system_status",      "SystemStatusWidget"),
        ("secureboot", "Secure Boot",     "power",    "Secure Boot, TPM and lockdown",   "secureboot_monitor", "SecureBootMonitorWidget"),
        ("snapshots",  "Snapshots",       "snapshot", "Btrfs snapshots and rollback",    "snapshot_manager",   "SnapshotManagerWidget"),
    ]),
    ("prevention", "Prevention", "shield", [
        ("profiles",   "Hardening Profiles", "sliders",  "Home, Professional, Paranoid",  "hardening_profiles", "HardeningProfilesWidget"),
        ("hardcheck",  "Hardening Check",    "check_sq", "Verify applied configurations", "hardening_check",    "HardeningCheckWidget"),
        ("zerotrust",  "Zero Trust",         "zero",     "Least privilege and segmentation", "zero_trust",      "ZeroTrustWidget"),
        ("usb",        "USB Guardian",       "usb",      "Control USB devices",           "usb_guardian",       "USBGuardianWidget"),
        ("privacy",    "Privacy",            "eye_off",  "Camera, mic, Bluetooth, DNS",   "privacy_control",    "PrivacyControlWidget"),
        ("sandbox",    "Sandbox",            "cube",     "Run apps in isolation",         "sandbox",            "SandboxWidget"),
    ]),
    ("detection", "Detection", "search", [
        ("edr",        "EDR",                   "radar", "Endpoint detection and response", "edr",          "EDRWidget"),
        ("threatintel","Threat Intelligence",   "globe", "IOC, feeds and VirusTotal",       "threat_intel", "ThreatIntelWidget"),
        ("vuln",       "Vulnerability Scanner", "bug",   "Lynis security audit",            "vuln_scanner", "VulnScannerWidget"),
        ("honeypot",   "Honeypot",              "honey", "Decoy SSH and HTTP services",     "honeypot",     "HoneypotWidget"),
    ]),
    ("dfir", "DFIR", "file", [
        ("evidence",   "Evidence Collection", "folder",      "One-click forensic acquisition", "forensics",         "ForensicsWidget"),
        ("integrity",  "Integrity Control",   "fingerprint", "AIDE file integrity",            "integrity_control", "IntegrityControlWidget"),
        ("logs",       "Log Viewer",          "terminal",    "System and security logs",       "log_viewer",        "LogViewerWidget"),
    ]),
    ("monitoring", "Monitoring", "chart", [
        ("services",   "Security Services", "services", "Status of security daemons",   "security_status", "SecurityStatusWidget"),
        ("network",    "Network Monitor",   "network",  "Interfaces and connections",   "network_monitor", "NetworkMonitorWidget"),
        ("processes",  "Processes",         "activity", "Process tree and control",     "process_monitor", "ProcessMonitorWidget"),
    ]),
    ("response", "Response", "gear", [
        ("ir",         "Incident Response", "siren", "Isolate host and collect evidence", "incident_response", "IncidentResponseWidget"),
        ("guardian",   "NEFI Guardian",     "bot",   "AI security assistant",             "guardian",          "GuardianWidget"),
    ]),
]

EAGER = {"edr"}   # moduli avviati subito (monitoraggio continuo)
NATIVE = {"score"}  # moduli già ridisegnati: gestiscono da soli lo spazio


# ── Barra di navigazione ────────────────────────────────
class NavButton(QFrame):
    hovered = pyqtSignal(object)
    left = pyqtSignal()
    clicked = pyqtSignal(object)

    def __init__(self, key, label, icon_name):
        super().__init__()
        self.key, self.icon_name = key, icon_name
        self.active = self.hover = False
        self.setObjectName("navBtn")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(46 if compact() else 58)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 0, 18, 0)
        lay.setSpacing(12)
        lay.addStretch()
        self.icon_lbl = QLabel()
        lay.addWidget(self.icon_lbl)
        self.text_lbl = QLabel(label)
        lay.addWidget(self.text_lbl)
        lay.addSpacing(6)
        self.chev = QLabel()
        lay.addWidget(self.chev)
        lay.addStretch()
        self._restyle()

    def set_active(self, on):
        self.active = on
        self._restyle()

    def _restyle(self):
        hi = self.active or self.hover
        col = C["accent"] if self.active else (C["text"] if hi else C["text"])
        self.icon_lbl.setPixmap(icon_pixmap(self.icon_name, C["accent"] if self.active else C["text2"], 24))
        self.chev.setPixmap(icon_pixmap("chev_down", C["accent"] if self.active else C["text3"], 14))
        self.text_lbl.setStyleSheet(f"color: {col}; font-size: 16px; background: transparent;")
        if self.active:
            bg = (f"background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 {C['accent_bg']}, stop:1 #0b2b27);"
                  f"border: 1px solid {C['accent']}44; border-bottom: 3px solid {C['accent']};")
        elif self.hover:
            bg = f"background: {C['card2']}; border: 1px solid {C['border']};"
        else:
            bg = "background: transparent; border: 1px solid transparent;"
        self.setStyleSheet(f"QFrame#navBtn {{ {bg} border-radius: 12px; }}")

    def enterEvent(self, e):
        self.hover = True
        self._restyle()
        self.hovered.emit(self)

    def leaveEvent(self, e):
        self.hover = False
        self._restyle()
        self.left.emit()

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self)


class DropdownItem(QFrame):
    clicked = pyqtSignal(str)

    def __init__(self, mod_id, title, icon_name, desc):
        super().__init__()
        self.mod_id = mod_id
        self.setObjectName("ddItem")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 10, 14, 10)
        lay.setSpacing(14)
        tile = QLabel()
        tile.setFixedSize(38, 38)
        tile.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tile.setPixmap(icon_pixmap(icon_name, C["accent"], 20))
        tile.setStyleSheet(f"background: {C['accent_bg']}; border-radius: 10px;")
        lay.addWidget(tile)
        txt = QVBoxLayout()
        txt.setSpacing(1)
        t = QLabel(title)
        t.setStyleSheet("font-size: 14px; font-weight: bold; background: transparent;")
        d = QLabel(desc)
        d.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        txt.addWidget(t)
        txt.addWidget(d)
        lay.addLayout(txt, 1)
        self.set_current(False)

    def set_current(self, on):
        border = f"border-left: 3px solid {C['accent']};" if on else "border-left: 3px solid transparent;"
        self.setStyleSheet(f"""
            QFrame#ddItem {{ background: {C['card2'] if on else 'transparent'}; {border} border-radius: 10px; }}
            QFrame#ddItem:hover {{ background: {C['card2']}; }}
        """)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.mod_id)


class Dropdown(QFrame):
    """Menu a tendina interno alla finestra (compatibile Wayland)."""
    entered = pyqtSignal()
    left = pyqtSignal()
    picked = pyqtSignal(str)

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("dropdown")
        self.setStyleSheet(f"""
            QFrame#dropdown {{
                background-color: {C['card']};
                border: 1px solid {C['border2']};
                border-radius: 14px;
            }}
        """)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(8, 8, 8, 8)
        self.lay.setSpacing(2)
        self.items = {}          # sezione → voci (create una volta sola)
        self.hide()

    def populate(self, key, modules, current_id):
        if key not in self.items:
            lst = []
            for mod_id, title, icon_name, desc, *_ in modules:
                item = DropdownItem(mod_id, title, icon_name, desc)
                item.clicked.connect(self.picked.emit)
                self.lay.addWidget(item)
                lst.append(item)
            self.items[key] = lst
        for k, lst in self.items.items():
            for it in lst:
                it.setVisible(k == key)
                it.set_current(it.mod_id == current_id)
        h = 16 + sum(it.sizeHint().height() for it in self.items[key]) + 2 * (len(self.items[key]) - 1)
        self.setFixedHeight(h)

    def enterEvent(self, e):
        self.entered.emit()

    def leaveEvent(self, e):
        self.left.emit()


# ── Finestra principale ─────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NEFI Security Center")
        self.setWindowIcon(QIcon.fromTheme("nefi-security-center",
                           QIcon("/usr/share/nefi/logo-color.png")))
        self.setMinimumSize(1100, 660)
        scr = self.screen().availableGeometry() if self.screen() else None
        if scr:
            self.resize(min(1600, scr.width() - 40), min(960, scr.height() - 40))
        else:
            self.resize(1600, 960)
        self.containers = {}   # id → widget mostrato nello stack

        self.modules = {}      # id → (sezione, dati modulo)
        self.pages = {}        # id → widget
        self.current = None
        for key, label, ic, mods in SECTIONS:
            for m in mods:
                self.modules[m[0]] = (key, label, m)

        self._build_ui()
        for mod_id in EAGER:
            self._page(mod_id)
        self.open_module("score")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh)
        self.timer.start(5000)

    # ── UI ──
    def _build_ui(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        self.root = root
        outer = QVBoxLayout(root)
        cm = compact()
        outer.setContentsMargins(22, 10, 22, 6) if cm else outer.setContentsMargins(28, 18, 28, 10)
        outer.setSpacing(10 if cm else 16)

        outer.addLayout(self._header())

        # barra di navigazione
        nav = QFrame()
        nav.setObjectName("navBar")
        nav.setStyleSheet(f"""
            QFrame#navBar {{
                background: {C['bg2']};
                border: 1px solid {C['border']};
                border-radius: 16px;
            }}
        """)
        nl = QHBoxLayout(nav)
        nl.setContentsMargins(6, 6, 6, 6)
        nl.setSpacing(4)
        self.nav_buttons = {}
        for i, (key, label, ic, mods) in enumerate(SECTIONS):
            if i:
                sep = QFrame()
                sep.setFixedSize(1, 28)
                sep.setStyleSheet(f"background: {C['border2']};")
                nl.addWidget(sep)
            b = NavButton(key, label, ic)
            b.hovered.connect(self._show_dropdown)
            b.left.connect(self._schedule_hide)
            b.clicked.connect(lambda btn: self.open_module(self._first_of(btn.key)))
            nl.addWidget(b)
            self.nav_buttons[key] = b
        outer.addWidget(nav)

        # percorso
        self.crumb = QLabel()
        self.crumb.setStyleSheet(f"color: {C['text3']}; font-size: 13px; padding-left: 6px;")
        outer.addWidget(self.crumb)

        # contenuti
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("QStackedWidget { background: transparent; }")
        outer.addWidget(self.stack, 1)

        # menu a tendina
        self.dropdown = Dropdown(root)
        self.dropdown.entered.connect(self._cancel_hide)
        self.dropdown.left.connect(self._schedule_hide)
        self.dropdown.picked.connect(self._pick)
        self.hide_timer = QTimer(self)
        self.hide_timer.setSingleShot(True)
        self.hide_timer.setInterval(250)
        self.hide_timer.timeout.connect(self.dropdown.hide)

        # barra di stato
        dot = QLabel()
        dot.setPixmap(icon_pixmap("dot", C["accent"], 12))
        self.status_lbl = QLabel("NEFI OS  •  System ready  •  Blue Team Mode")
        self.status_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 12px;")
        self.statusBar().addWidget(dot)
        self.statusBar().addWidget(self.status_lbl)
        self.statusBar().setSizeGripEnabled(False)

    def _header(self):
        h = QHBoxLayout()
        h.setSpacing(18)
        logo = QLabel()
        pm = QPixmap("/usr/share/nefi/logo-white.png")
        if pm.isNull():
            pm = icon_pixmap("shield", C["accent"], 30)
        else:
            s = 44 if compact() else 62
            pm = pm.scaled(s, s, Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
        logo.setPixmap(pm)
        glow(logo, radius=26, alpha=120)
        h.addWidget(logo)

        tb = QVBoxLayout()
        tb.setSpacing(0)
        title = QLabel(f'<span style="color:{C["text"]}">NEFI</span> '
                       f'<span style="color:{C["accent"]}">Security Center</span>')
        title.setStyleSheet(f"font-size: {24 if compact() else 30}px; font-weight: bold; background: transparent;")
        sub = QLabel("Network Event Forensics Intelligence")
        sub.setStyleSheet(f"color: {C['text2']}; font-size: {12 if compact() else 14}px; letter-spacing: 2px; background: transparent;")
        tb.addWidget(title)
        tb.addWidget(sub)
        h.addLayout(tb)
        h.addStretch()

        pill = QFrame()
        pill.setObjectName("verPill")
        pill.setStyleSheet(f"""
            QFrame#verPill {{
                background: {C['bg2']}; border: 1px solid {C['accent']}88; border-radius: 22px;
            }}
        """)
        pl = QHBoxLayout(pill)
        pl.setContentsMargins(18, 6, 20, 6) if compact() else pl.setContentsMargins(20, 10, 22, 10)
        pl.setSpacing(10)
        d = QLabel()
        d.setPixmap(icon_pixmap("dot", C["accent"], 12))
        pl.addWidget(d)
        v = QLabel("v0.1  •  Blue Team Edition")
        v.setStyleSheet("font-size: 14px; background: transparent;")
        pl.addWidget(v)
        h.addWidget(pill)
        return h

    # ── Menu a tendina ──
    def _show_dropdown(self, btn):
        self._cancel_hide()
        key = btn.key
        mods = next(m for k, _, _, m in SECTIONS if k == key)
        w = max(320, btn.width())
        self.dropdown.setFixedWidth(w)
        self.dropdown.populate(key, mods, self.current)
        pos = btn.mapTo(self.root, QPoint(0, btn.height() + 8))
        x = min(pos.x(), self.root.width() - w - 12)
        self.dropdown.move(max(12, x), pos.y())
        self.dropdown.show()
        self.dropdown.raise_()

    def _schedule_hide(self):
        self.hide_timer.start()

    def _cancel_hide(self):
        self.hide_timer.stop()

    def _pick(self, mod_id):
        self.dropdown.hide()
        self.open_module(mod_id)

    def _first_of(self, section_key):
        return next(m for k, _, _, m in SECTIONS if k == section_key)[0][0]

    # ── Pagine ──
    def _page(self, mod_id):
        if mod_id in self.pages:
            return self.pages[mod_id]
        _, _, (mid, title, _, _, module, cls) = self.modules[mod_id]
        try:
            widget = getattr(importlib.import_module(module), cls)()
        except Exception:
            widget = self._error_page(title, traceback.format_exc())
        self.pages[mod_id] = widget
        container = widget
        if mod_id not in NATIVE:
            container = QScrollArea()
            container.setWidgetResizable(True)
            container.setFrameShape(QFrame.Shape.NoFrame)
            container.viewport().setStyleSheet("background: transparent;")
            container.setWidget(widget)
        self.containers[mod_id] = container
        self.stack.addWidget(container)
        return widget

    def _error_page(self, title, tb):
        page = QWidget()
        lay = QVBoxLayout(page)
        card = Card()
        head = QLabel(f"⚠  The module “{title}” could not be loaded")
        head.setStyleSheet(f"color: {C['danger']}; font-size: 18px; font-weight: bold; background: transparent;")
        card.body.addWidget(head)
        hint = QLabel("The rest of NEFI Security Center keeps working. Technical details:")
        hint.setStyleSheet(f"color: {C['text2']}; background: transparent;")
        card.body.addWidget(hint)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlainText(tb)
        box.setStyleSheet(f"background: {C['bg']}; color: {C['text2']}; border: 1px solid {C['border']}; "
                          f"border-radius: 8px; font-family: monospace; font-size: 12px;")
        card.body.addWidget(box)
        lay.addWidget(card)
        return page

    def open_module(self, mod_id):
        if mod_id not in self.modules:
            return
        section_key, section_label, (mid, title, *_rest) = self.modules[mod_id]
        self._page(mod_id)
        self.stack.setCurrentWidget(self.containers[mod_id])
        self.current = mod_id
        for k, b in self.nav_buttons.items():
            b.set_active(k == section_key)
        self.crumb.setText(f'<span style="color:{C["text3"]}">{section_label}</span>'
                           f'<span style="color:{C["text3"]}">&nbsp;&nbsp;›&nbsp;&nbsp;</span>'
                           f'<span style="color:{C["text"]}">{title}</span>')

    def _refresh(self):
        page = self.pages.get(self.current)
        if hasattr(page, "refresh"):
            try:
                page.refresh()
            except Exception:
                pass

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.dropdown.hide()

    def closeEvent(self, e):
        for page in self.pages.values():
            page.close()
        super().closeEvent(e)
