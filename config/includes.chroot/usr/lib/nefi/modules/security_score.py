"""NEFI Security Center — System › Security Score

Il punteggio NON viene calcolato qui: viene da /opt/nefi/system/collect.py (root), che esegue
controlli verificabili e salva per ognuno stato, prova, metodo e peso.
Score    = (pesi superati + meta' dei pesi in avviso) / pesi verificabili x 100
Coverage = pesi verificabili / pesi totali  (i controlli non verificabili sono esclusi e mostrati a parte)
"""
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGridLayout
from PyQt6.QtCore import Qt

from nefi_theme import (C, TONES, HeroCard, ScoreRing, SectionLabel, GhostButton, Card, Pill,
                        icon_pixmap, compact)
from assessment import AssessmentBase, CheckList, stat_line, tone_for

CAT_PAGE = {   # categoria -> id della pagina nel menu
    "hardware": "hardware", "boot": "boot", "kernel": "kernelsec", "integrity": "sysintegrity",
    "services": "secservices", "packages": "packages", "config": "configaudit",
    "backup": "backup", "updates": "updates",
}


class CategoryTile(QFrame):
    def __init__(self, key, on_open):
        super().__init__()
        self.key, self.on_open = key, on_open
        self.setObjectName("catTile")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        t = QVBoxLayout()
        t.setSpacing(2)
        self.name = QLabel("")
        self.name.setStyleSheet("font-size: 14px; font-weight: bold; background: transparent;")
        self.sub = QLabel("")
        self.sub.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        t.addWidget(self.name)
        t.addWidget(self.sub)
        lay.addLayout(t, 1)
        self.pill = Pill("…", "muted", 80)
        self.pill.setFixedHeight(30)
        lay.addWidget(self.pill)
        self.setStyleSheet(f"QFrame#catTile {{ background: {C['card2']}; border: 1px solid {C['border']}; "
                           f"border-radius: 10px; }} QFrame#catTile:hover {{ border-color: {C['accent']}; }}")

    def set_data(self, cat):
        sc = cat.get("score")
        self.name.setText(cat.get("name", self.key))
        self.sub.setText(f"{cat.get('failed', 0)} failed • {cat.get('warnings', 0)} warn • "
                         f"{cat.get('unknown', 0)} n/v • coverage {cat.get('coverage', 0)}%")
        self.pill.setText(f"{sc}" if sc is not None else "n/a")
        self.pill.set_tone(tone_for(sc))

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.on_open(self.key)


class SecurityScoreWidget(AssessmentBase):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)

        # ── punteggio ──
        hero = HeroCard(decoration=False)   # niente esagoni: il testo qui e' lungo
        self.ring = ScoreRing(170 if compact() else 220)
        hero.body.addWidget(self.ring)
        info = QVBoxLayout()
        info.setSpacing(10)
        info.addStretch()
        info.addWidget(SectionLabel("Security Score"))
        self.title = QLabel("Security Score")
        self.title.setStyleSheet("font-size: 30px; font-weight: bold; background: transparent;")
        info.addWidget(self.title)
        self.level = QLabel("")
        self.level.setWordWrap(True)
        self.level.setStyleSheet("font-size: 15px; background: transparent;")
        info.addWidget(self.level)
        self.coverage = QLabel("")
        self.coverage.setWordWrap(True)
        self.coverage.setStyleSheet(f"color: {C['text2']}; font-size: 13px; background: transparent;")
        info.addWidget(self.coverage)
        info.addLayout(self._run_bar())
        info.addStretch()
        hero.body.addLayout(info, 1)
        lay.addWidget(hero)

        # ── categorie ──
        cats = Card(padding=18)
        cats.body.addWidget(SectionLabel("By area (click to open)"))
        grid = QGridLayout()
        grid.setSpacing(8)
        self.tiles = {}
        for i, key in enumerate(CAT_PAGE):
            tile = CategoryTile(key, self._open)
            self.tiles[key] = tile
            grid.addWidget(tile, i // 3, i % 3)
        cats.body.addLayout(grid)
        lay.addWidget(cats)

        # ── controlli ──
        card = Card(padding=18)
        head = QHBoxLayout()
        head.addWidget(SectionLabel("All checks"))
        head.addStretch()
        self.filter_btns = {}
        for key, label in (("issues", "Issues"), ("unknown", "Not verifiable"), ("all", "All")):
            b = GhostButton(label, None, 32)
            b.clicked.connect(lambda _c, k=key: self._filter(k))
            head.addWidget(b)
            self.filter_btns[key] = b
        card.body.addLayout(head)
        self.method = QLabel("")
        self.method.setWordWrap(True)
        self.method.setStyleSheet(f"color: {C['text3']}; font-size: 12px; background: transparent;")
        card.body.addWidget(self.method)
        self.list = CheckList()
        self.list.filter = "issues"
        card.body.addWidget(self.list)
        lay.addWidget(card, 1)
        self.refresh(force=True)

    def _open(self, key):
        win = self.window()
        if hasattr(win, "open_module"):
            win.open_module(CAT_PAGE[key])

    def _filter(self, key):
        if self.report:
            self.list.set_checks(self.report.get("checks", []), key)

    def apply(self, rep):
        if rep is None:
            self.ring.set_score(0)
            self.title.setText("Security Score: not calculated yet")
            self.level.setText("")
            self.coverage.setText("")
            self.list.set_checks([])
            return
        s = rep.get("summary", {})
        sc = s.get("score")
        self.ring.set_score(sc or 0)
        tone = tone_for(sc)
        fg = TONES[tone][0]
        level = {"ok": "Good", "warn": "Needs improvement", "danger": "Critical", "muted": "Unknown"}[tone]
        self.title.setText(f'NEFI Score: <span style="color:{fg}">{sc if sc is not None else "n/a"}/100</span>')
        self.level.setText(f'Level: <b style="color:{fg}">{level}</b>  —  {stat_line(s)}')
        self.coverage.setText(
            f"Coverage: <b>{s.get('coverage', 0)}%</b> of the checks (by weight) could be verified on this machine. "
            f"Checks that could not be verified are not counted as passed: see the 'Not verifiable' filter.")
        doc = rep.get("weights_doc", {})
        self.method.setText(f"How the score is calculated: {doc.get('formula', '')} {doc.get('scale', '')}")
        for key, tile in self.tiles.items():
            tile.set_data(rep.get("categories", {}).get(key, {"name": key}))
        self.list.set_checks(rep.get("checks", []))
