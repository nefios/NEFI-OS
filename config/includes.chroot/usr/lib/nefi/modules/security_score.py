"""NEFI Security Center — System › Security Score"""
import subprocess
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from nefi_theme import (
    C, TONES, HeroCard, ScoreRing, SectionLabel, PrimaryButton, GhostButton,
    CheckRow, Card, icon_pixmap, compact
)

# id, icona, titolo, descrizione, punti, suggerimento se fallisce
CHECKS = [
    ("firewall",   "wall",     "Firewall active",      "nftables or ufw running",            20, "Start nftables or ufw"),
    ("apparmor",   "box",      "AppArmor enforcing",   "Mandatory Access Control active",    20, "Start AppArmor via systemctl"),
    ("auditd",     "file",     "Kernel audit",         "auditd tracks system events",        15, "Start auditd"),
    ("secureboot", "power",    "Secure Boot",          "Bootloader signature verified",      15, "Enable Secure Boot in BIOS/UEFI"),
    ("encryption", "lock",     "Disk encryption",      "LUKS/dm-crypt on filesystem",        15, "Configure LUKS during installation"),
    ("updates",    "download", "System up to date",    "No pending security updates",        10, "Run apt update && apt upgrade"),
    ("rootlogin",  "user_x",   "Root login disabled",  "SSH root login not permitted",        5, "Set PermitRootLogin no in sshd_config"),
]


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                              text=True, timeout=timeout).stdout
    except Exception:
        return ""


class ScoreWorker(QThread):
    done = pyqtSignal(dict)

    def run(self):
        active = lambda s: _run(["systemctl", "is-active", s]).strip() == "active"
        res = {
            "firewall":   active("nftables") or active("ufw"),
            "apparmor":   active("apparmor"),
            "auditd":     active("auditd"),
            "secureboot": "enabled" in _run("mokutil --sb-state 2>/dev/null").lower(),
            "encryption": "crypt" in _run("lsblk -o TYPE 2>/dev/null"),
            "updates":    _run("apt list --upgradable 2>/dev/null | grep -ci security", 20).strip() in ("", "0"),
            "rootlogin":  "yes" not in _run("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null").lower(),
        }
        self.done.emit(res)


class SecurityScoreWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.last_run = 0
        self.issues_only = False
        self.results = {}
        self._build_ui()
        self.recalculate()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(18)

        # ── Hero ──
        hero = HeroCard()
        self.ring = ScoreRing(180 if compact() else 240)
        hero.body.addWidget(self.ring)

        info = QVBoxLayout()
        info.setSpacing(14)
        info.addStretch()
        info.addWidget(SectionLabel("Security Score"))
        self.title = QLabel()
        self.title.setStyleSheet("font-size: 34px; font-weight: bold; background: transparent;")
        info.addWidget(self.title)

        self.level_box = QFrame()
        self.level_box.setObjectName("levelBox")
        self.level_box.setStyleSheet(f"""
            QFrame#levelBox {{ background: {C['bg2']}AA; border: 1px solid {C['border2']}; border-radius: 12px; }}
        """)
        lb = QHBoxLayout(self.level_box)
        lb.setContentsMargins(18, 12, 22, 12)
        lb.setSpacing(14)
        self.level_icon = QLabel()
        lb.addWidget(self.level_icon)
        self.level_lbl = QLabel("Calculating…")
        self.level_lbl.setWordWrap(True)
        self.level_lbl.setStyleSheet("font-size: 15px; background: transparent;")
        lb.addWidget(self.level_lbl, 1)
        self.level_box.setMaximumWidth(460)
        info.addWidget(self.level_box)

        info.addSpacing(6)
        self.recalc_btn = PrimaryButton("Recalculate", "refresh", 46 if compact() else 54)
        self.recalc_btn.setFixedWidth(260)
        self.recalc_btn.clicked.connect(self.recalculate)
        info.addWidget(self.recalc_btn)
        info.addStretch()
        hero.body.addLayout(info)
        hero.body.addStretch()
        lay.addWidget(hero)

        # ── Controlli ──
        card = Card(padding=26)
        head = QHBoxLayout()
        head.addWidget(SectionLabel("Checks performed"))
        head.addStretch()
        self.view_btn = GhostButton("View issues only", "list", 42)
        self.view_btn.clicked.connect(self._toggle_view)
        head.addWidget(self.view_btn)
        card.body.addLayout(head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setStyleSheet("background: transparent;")
        self.rows_lay = QVBoxLayout(inner)
        self.rows_lay.setContentsMargins(0, 0, 8, 0)
        self.rows_lay.setSpacing(10)
        self.rows = {}
        for cid, ic, title, desc, pts, _ in CHECKS:
            row = CheckRow(ic, title, desc, f"+{pts}", True)
            row.set_state(True, desc, f"+{pts}", tone="muted")
            self.rows[cid] = row
            self.rows_lay.addWidget(row)
        self.rows_lay.addStretch()
        scroll.setWidget(inner)
        card.body.addWidget(scroll, 1)
        lay.addWidget(card, 1)

    # ── Logica ──
    def recalculate(self):
        if self.worker and self.worker.isRunning():
            return
        self.recalc_btn.setEnabled(False)
        self.recalc_btn.setText("  Checking…")
        self.worker = ScoreWorker()
        self.worker.done.connect(self._apply)
        self.worker.start()

    def _apply(self, res):
        self.results = res
        self.last_run = time.time()
        self.recalc_btn.setEnabled(True)
        self.recalc_btn.setText("  Recalculate")

        total = max_total = 0
        failed = 0
        for cid, ic, title, desc, pts, hint in CHECKS:
            ok = res.get(cid, False)
            max_total += pts
            total += pts if ok else 0
            failed += 0 if ok else 1
            self.rows[cid].set_state(ok, desc if ok else hint, f"+{pts}" if ok else "+0")
        score = round(100 * total / max_total)
        self.ring.set_score(score)

        if score >= 80:
            level, tone = "Good", "ok"
        elif score >= 50:
            level, tone = "Needs improvement", "warn"
        else:
            level, tone = "Critical", "danger"
        fg = TONES[tone][0]
        self.title.setText(f'NEFI Score: <span style="color:{C["accent"]}">{score}/100</span>')
        self.level_icon.setPixmap(icon_pixmap("alert" if failed else "check_sq", fg, 26))
        issues = f"{failed} checks need improvement" if failed else "all checks passed"
        self.level_lbl.setText(f'Level: <b style="color:{fg}">{level}</b> — {issues}')
        self._apply_filter()

    def _toggle_view(self):
        self.issues_only = not self.issues_only
        self.view_btn.setText("  View all checks" if self.issues_only else "  View issues only")
        self._apply_filter()

    def _apply_filter(self):
        for cid, row in self.rows.items():
            row.setVisible(not self.issues_only or not self.results.get(cid, False))

    def refresh(self):
        # ricalcola al massimo ogni 60 secondi, senza bloccare l'interfaccia
        if time.time() - self.last_run > 60:
            self.recalculate()
