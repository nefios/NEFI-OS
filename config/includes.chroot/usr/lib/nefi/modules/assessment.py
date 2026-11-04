"""NEFI Security Center — System assessment: dati e componenti comuni.

Legge /var/lib/nefi/system/report.json (scritto da /opt/nefi/system/collect.py come root,
leggibile dal gruppo sudo) e fornisce:
  - load_report()           il report (o None)
  - RunWorker               esegue subito i controlli (pkexec)
  - CheckList               elenco dei controlli con stato, peso, prova e metodo
  - CategoryPage            pagina generica per una categoria (Hardware, Boot, Kernel, ...)
"""
import json
import subprocess
import time
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea, QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from nefi_theme import C, Card, SectionLabel, GhostButton, PrimaryButton, Pill, PageHeader, icon_pixmap

REPORT = "/var/lib/nefi/system/report.json"
COLLECTOR = "/opt/nefi/system/collect.py"

STATUS = {   # stato -> (testo, tono, icona)
    "pass":    ("Passed", "ok", "check_sq"),
    "warn":    ("Warning", "warn", "alert"),
    "fail":    ("Failed", "danger", "x"),
    "unknown": ("Not verifiable", "muted", "search"),
}
ORDER = {"fail": 0, "warn": 1, "unknown": 2, "pass": 3}


def load_report():
    try:
        with open(REPORT) as f:
            data = json.load(f)
        return data if isinstance(data, dict) and "checks" in data else None
    except (OSError, ValueError):
        return None


def when(report):
    """'oggi 14:32' / data, piu' quanti minuti fa."""
    g = (report or {}).get("generated", "")
    try:
        dt = datetime.strptime(g[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return "never"
    mins = int((time.time() - dt.timestamp()) // 60)
    ago = "just now" if mins < 1 else f"{mins} min ago" if mins < 120 else f"{mins // 60} h ago"
    return f"{dt.strftime('%Y-%m-%d %H:%M')} ({ago})"


class RunWorker(QThread):
    line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, full=False):
        super().__init__()
        self.full = full

    def run(self):
        cmd = ["pkexec", "/usr/bin/python3", COLLECTOR] + (["--full"] if self.full else [])
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            for l in (p.stdout + p.stderr).splitlines():
                self.line.emit(l)
            self.finished_ok.emit(p.returncode == 0)
        except (OSError, subprocess.SubprocessError) as e:
            self.line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class CheckRow(QFrame):
    """Una riga: stato, titolo, prova in breve, peso. Clic = dettagli (perche', prova completa, metodo)."""
    def __init__(self, chk):
        super().__init__()
        self.chk = chk
        self.open = False
        self.setObjectName("chkRow")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        txt, tone, ic = STATUS.get(chk.get("status"), STATUS["unknown"])
        fg = {"ok": C["accent"], "warn": C["warn"], "danger": C["danger"], "muted": C["text3"]}[tone]
        self.setStyleSheet(f"""
            QFrame#chkRow {{ background: {C['card2']}; border: 1px solid {C['border']};
                             border-left: 3px solid {fg}; border-radius: 10px; }}
            QFrame#chkRow:hover {{ border-color: {C['border2']}; border-left: 3px solid {fg}; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(6)
        top = QHBoxLayout()
        top.setSpacing(12)
        icl = QLabel()
        icl.setPixmap(icon_pixmap(ic, fg, 20))
        icl.setStyleSheet("background: transparent;")
        top.addWidget(icl)
        text = QVBoxLayout()
        text.setSpacing(2)
        t = QLabel(chk.get("title", ""))
        t.setStyleSheet("font-size: 14px; font-weight: bold; background: transparent;")
        first = (chk.get("evidence") or "").splitlines()[0] if chk.get("evidence") else ""
        e = QLabel(first[:160])
        e.setWordWrap(True)
        e.setStyleSheet(f"color: {fg if tone != 'ok' else C['text2']}; font-size: 12px; background: transparent;")
        text.addWidget(t)
        text.addWidget(e)
        top.addLayout(text, 1)
        w = QLabel(f"weight {chk.get('weight', 0)}")
        w.setToolTip("Weight of this check in the Security Score (1 = minor, 10 = core protection)")
        w.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        top.addWidget(w)
        p = Pill(txt, tone, 110)
        p.setFixedHeight(28)
        top.addWidget(p)
        lay.addLayout(top)

        self.details = QLabel()
        self.details.setWordWrap(True)
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.details.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: {C['bg']}; "
                                   f"border: 1px solid {C['border']}; border-radius: 8px; padding: 10px;")
        cached = chk.get("cached_at")
        cache_txt = (f"<br><i>Slow check: result from {datetime.fromtimestamp(cached).strftime('%Y-%m-%d %H:%M')}"
                     f" (refreshed periodically)</i>") if cached else ""
        ev = (chk.get("evidence") or "").replace("&", "&amp;").replace("<", "&lt;").replace("\n", "<br>")
        self.details.setText(
            f"<b>Why it matters:</b> {chk.get('why', '')}<br><br>"
            f"<b>Evidence:</b><br><span style='font-family:monospace'>{ev}</span><br><br>"
            f"<b>How it was verified:</b> <span style='font-family:monospace'>{chk.get('method', '')}</span>"
            f"&nbsp;&nbsp;•&nbsp;&nbsp;<b>ID:</b> {chk.get('id', '')}{cache_txt}")
        self.details.hide()
        lay.addWidget(self.details)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.open = not self.open
            self.details.setVisible(self.open)


class CheckList(QWidget):
    """Elenco dei controlli, ordinati: falliti, avvisi, non verificabili, superati."""
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background: transparent;")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(8)
        self._sig = None
        self.filter = "all"

    def set_checks(self, checks, flt=None):
        if flt:
            self.filter = flt
        sel = [c for c in checks if self.filter == "all"
               or (self.filter == "issues" and c.get("status") in ("fail", "warn"))
               or (self.filter == "unknown" and c.get("status") == "unknown")]
        sel.sort(key=lambda c: (ORDER.get(c.get("status"), 9), -c.get("weight", 0)))
        sig = json.dumps(sel, sort_keys=True)
        if sig == self._sig:
            return                      # niente di nuovo: non ridisegno (le righe aperte restano aperte)
        self._sig = sig
        while self.lay.count():
            w = self.lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        if not sel:
            l = QLabel("Nothing to show with this filter.")
            l.setStyleSheet(f"color: {C['text3']}; background: transparent;")
            self.lay.addWidget(l)
        for c in sel:
            self.lay.addWidget(CheckRow(c))
        self.lay.addStretch()


def stat_line(s):
    return (f"{s.get('passed', 0)} passed  •  {s.get('warnings', 0)} warnings  •  {s.get('failed', 0)} failed  •  "
            f"{s.get('unknown', 0)} not verifiable")


def tone_for(score):
    if score is None:
        return "muted"
    return "ok" if score >= 80 else "warn" if score >= 50 else "danger"


class AssessmentBase(QWidget):
    """Base comune: barra di stato con 'Run checks now', log, aggiornamento senza sfarfallio."""
    def __init__(self):
        super().__init__()
        self.worker = None
        self.report = None

    def _run_bar(self):
        bar = QHBoxLayout()
        self.when_lbl = QLabel("")
        self.when_lbl.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        bar.addWidget(self.when_lbl, 1)
        self.run_btn = GhostButton("Run checks now", "refresh", 36)
        self.run_btn.setToolTip("Checks also run automatically at boot and every 30 minutes")
        self.run_btn.clicked.connect(self.run_now)
        bar.addWidget(self.run_btn)
        return bar

    def run_now(self):
        if self.worker and self.worker.isRunning():
            return
        self.run_btn.setEnabled(False)
        self.run_btn.setText("  Checking… (admin password)")
        self.worker = RunWorker()
        self.worker.line.connect(lambda l: None)
        self.worker.finished_ok.connect(self._ran)
        self.worker.start()

    def _ran(self, ok):
        self.run_btn.setEnabled(True)
        self.run_btn.setText("  Run checks now")
        self.refresh(force=True)

    def refresh(self, force=False):
        rep = load_report()
        if rep is None:
            self.when_lbl.setText("No assessment yet: it runs 3 minutes after boot, or click 'Run checks now'. "
                                  "(Your user must be in the 'sudo' group to read the results.)")
        else:
            self.when_lbl.setText(f"Last assessment: {when(rep)}  •  host {rep.get('hostname', '?')}")
        if force or rep != self.report:
            self.report = rep
            self.apply(rep)

    def apply(self, rep):   # da implementare nelle sottoclassi
        pass


class CategoryPage(AssessmentBase):
    """Pagina di una categoria: punteggio della categoria, copertura, controlli con le prove."""
    CATEGORY = ""
    TITLE = ""
    SUBTITLE = ""

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(14)
        lay.addWidget(PageHeader(self.TITLE, self.SUBTITLE))
        head = Card(padding=18)
        row = QHBoxLayout()
        self.score_pill = Pill("…", "muted", 120)
        row.addWidget(self.score_pill)
        self.sum_lbl = QLabel("")
        self.sum_lbl.setWordWrap(True)
        self.sum_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 14px; background: transparent;")
        row.addWidget(self.sum_lbl, 1)
        head.body.addLayout(row)
        head.body.addLayout(self._run_bar())
        lay.addWidget(head)
        self.extra = QVBoxLayout()          # spazio per azioni specifiche della pagina
        lay.addLayout(self.extra)
        card = Card(padding=18)
        card.body.addWidget(SectionLabel("Checks (click a check for evidence and method)"))
        self.list = CheckList()
        card.body.addWidget(self.list)
        lay.addWidget(card, 1)
        self.build_extra()
        self.refresh(force=True)

    def build_extra(self):
        pass

    def apply(self, rep):
        if rep is None:
            self.score_pill.setText("No data")
            self.score_pill.set_tone("muted")
            self.sum_lbl.setText("")
            self.list.set_checks([])
            return
        cat = rep.get("categories", {}).get(self.CATEGORY, {})
        sc = cat.get("score")
        self.score_pill.setText(f"{sc}/100" if sc is not None else "n/a")
        self.score_pill.set_tone(tone_for(sc))
        self.sum_lbl.setText(f"{stat_line(cat)}  •  coverage {cat.get('coverage', 0)}%")
        self.list.set_checks([c for c in rep.get("checks", []) if c.get("category") == self.CATEGORY])
