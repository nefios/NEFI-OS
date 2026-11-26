"""NEFI Security Center — System › Security Score

Il punteggio NON viene calcolato qui: viene da /opt/nefi/system/collect.py (root), che esegue
controlli verificabili e salva per ognuno stato, prova, metodo e peso.
Score    = (pesi superati + meta' dei pesi in avviso) / pesi verificabili x 100
Coverage = pesi verificabili / pesi totali  (i controlli non verificabili sono esclusi e mostrati a parte)
"""
import html
import json
import os
import time
from datetime import datetime

from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGridLayout, QWidget, QMessageBox
from PyQt6.QtCore import Qt, QPointF, QRectF, QUrl
from PyQt6.QtGui import QPainter, QPen, QColor, QPolygonF, QDesktopServices

from nefi_theme import (C, TONES, HeroCard, ScoreRing, SectionLabel, GhostButton, Card, Pill,
                        icon_pixmap, compact)
from assessment import AssessmentBase, CheckList, stat_line, tone_for

CAT_PAGE = {   # categoria -> id della pagina nel menu
    "hardware": "hardware", "boot": "boot", "kernel": "kernelsec", "integrity": "sysintegrity",
    "services": "secservices", "packages": "packages", "config": "configaudit",
    "backup": "backup", "updates": "updates", "ssh": "sshsec",
}


HISTORY = "/var/lib/nefi/system/history.jsonl"
STATUS_WORD = {"pass": "passed", "warn": "warning", "fail": "failed", "unknown": "not verifiable"}
RANK = {"pass": 3, "warn": 2, "unknown": 1, "fail": 0}


def load_history(path=HISTORY, limit=1500):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f.read().splitlines()[-limit:]:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and "t" in e:
                    out.append(e)
    except OSError:
        pass
    return out


def history_changes(history, titles, limit=40):
    """Controlli che hanno cambiato stato tra una valutazione e la successiva (i piu' recenti per primi)."""
    out = []
    for prev, cur in zip(history, history[1:]):
        a, b = prev.get("status", {}), cur.get("status", {})
        for cid in b:
            if cid in a and a[cid] != b[cid]:
                out.append({"t": cur["t"], "id": cid, "title": titles.get(cid, cid), "from": a[cid], "to": b[cid],
                            "better": RANK.get(b[cid], 1) > RANK.get(a[cid], 1)})
    return list(reversed(out))[:limit]


class TrendChart(QWidget):
    """Andamento del Security Score nel tempo (una linea, scala 0-100)."""
    def __init__(self):
        super().__init__()
        self.points = []
        self.setMinimumHeight(150)
        self.setStyleSheet("background: transparent;")

    def set_history(self, history):
        self.points = [(e["t"], e["score"]) for e in history if isinstance(e.get("score"), (int, float))]
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        left, right, top, bottom = 34, 10, 10, 22
        area = QRectF(left, top, max(1, w - left - right), max(1, h - top - bottom))
        p.setFont(self.font())
        for val in (0, 50, 80, 100):
            y = area.bottom() - area.height() * val / 100
            p.setPen(QPen(QColor(C["border"]), 1, Qt.PenStyle.DashLine if val in (50, 80) else Qt.PenStyle.SolidLine))
            p.drawLine(QPointF(area.left(), y), QPointF(area.right(), y))
            p.setPen(QColor(C["text3"]))
            p.drawText(QRectF(0, y - 8, left - 6, 16), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(val))
        if not self.points:
            p.setPen(QColor(C["text3"]))
            p.drawText(area, Qt.AlignmentFlag.AlignCenter, "The trend appears after the first assessments.")
            return
        t0, t1 = self.points[0][0], self.points[-1][0]
        span = max(1, t1 - t0)

        def xy(t, sc):
            x = area.left() + (area.width() * (t - t0) / span if len(self.points) > 1 else area.width())
            return QPointF(x, area.bottom() - area.height() * max(0, min(100, sc)) / 100)
        pts = []
        for i, (t, sc) in enumerate(self.points):       # a gradini: il punteggio resta quello fino al cambio
            if i:
                pts.append(xy(t, self.points[i - 1][1]))
            pts.append(xy(t, sc))
        last = self.points[-1][1]
        col = QColor(C["accent"] if last >= 80 else C["warn"] if last >= 50 else C["danger"])
        if len(pts) > 1:
            fill_col = QColor(col)
            fill_col.setAlpha(36)
            poly = QPolygonF(pts + [QPointF(pts[-1].x(), area.bottom()), QPointF(pts[0].x(), area.bottom())])
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(fill_col)
            p.drawPolygon(poly)
            p.setPen(QPen(col, 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPolyline(QPolygonF(pts))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(col)
        p.drawEllipse(pts[-1], 4, 4)
        p.setPen(QColor(C["text3"]))
        fmt = "%Y-%m-%d" if span > 2 * 86400 else "%m-%d %H:%M"
        p.drawText(QRectF(area.left(), area.bottom() + 4, 160, 16), Qt.AlignmentFlag.AlignLeft,
                   datetime.fromtimestamp(t0).strftime(fmt))
        p.drawText(QRectF(area.right() - 160, area.bottom() + 4, 160, 16), Qt.AlignmentFlag.AlignRight,
                   datetime.fromtimestamp(t1).strftime(fmt))


def security_report(rep, changes):
    """Rapporto completo in un file HTML autonomo (stampabile)."""
    e = html.escape
    s = rep.get("summary", {})
    col = {"pass": "#1a7f37", "warn": "#9a6700", "fail": "#b3261e", "unknown": "#57606a"}
    out = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>NEFI security report - {e(rep.get('hostname', ''))}</title>
<style>body{{font-family:system-ui,sans-serif;color:#1b1f23;max-width:1000px;margin:32px auto;padding:0 16px;line-height:1.45}}
h1{{font-size:22px;margin-bottom:4px}} h2{{font-size:16px;margin-top:28px;border-bottom:1px solid #d0d7de;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border:1px solid #d0d7de;padding:5px 8px;text-align:left;vertical-align:top}}
th{{background:#f3f5f7}} .muted{{color:#57606a;font-size:13px}} .mono{{font-family:ui-monospace,monospace;font-size:12px;word-break:break-word}}
.score{{font-size:40px;font-weight:700}}</style></head><body>
<h1>NEFI OS security report</h1>
<div class="muted">Host <b>{e(rep.get('hostname', '?'))}</b> · assessment of {e(str(rep.get('generated', ''))[:19].replace('T', ' '))}
 · generated {e(time.strftime('%Y-%m-%d %H:%M'))}</div>
<p><span class="score">{e(str(s.get('score')))}/100</span> &nbsp; coverage {s.get('coverage', 0)}% ·
 {s.get('passed', 0)} passed · {s.get('warnings', 0)} warnings · {s.get('failed', 0)} failed · {s.get('unknown', 0)} not verifiable</p>
<p class="muted">{e(rep.get('weights_doc', {}).get('formula', ''))} {e(rep.get('weights_doc', {}).get('scale', ''))}</p>
<h2>By area</h2><table><tr><th>Area</th><th>Score</th><th>Coverage</th><th>Failed</th><th>Warnings</th><th>Not verifiable</th></tr>"""]
    for c in rep.get("categories", {}).values():
        out.append(f"<tr><td>{e(str(c.get('name')))}</td><td>{e(str(c.get('score')))}</td><td>{c.get('coverage', 0)}%</td>"
                   f"<td>{c.get('failed', 0)}</td><td>{c.get('warnings', 0)}</td><td>{c.get('unknown', 0)}</td></tr>")
    out.append("</table><h2>What to fix first</h2><table><tr><th>Gain</th><th>Check</th><th>Status</th><th>Evidence</th></tr>")
    todo = sorted((c for c in rep.get("checks", []) if c.get("gain")), key=lambda c: -c["gain"])
    for c in todo:
        out.append(f"<tr><td>+{c['gain']:g}</td><td>{e(c.get('title', ''))}</td>"
                   f"<td style='color:{col[c['status']]}'>{STATUS_WORD[c['status']]}</td>"
                   f"<td class='mono'>{e((c.get('evidence') or '')[:400])}</td></tr>")
    if not todo:
        out.append("<tr><td colspan='4'>Nothing to fix.</td></tr>")
    out.append("</table>")
    if changes:
        out.append("<h2>Recent changes</h2><table><tr><th>When</th><th>Check</th><th>Change</th></tr>")
        for c in changes:
            out.append(f"<tr><td>{datetime.fromtimestamp(c['t']).strftime('%Y-%m-%d %H:%M')}</td><td>{e(c['title'])}</td>"
                       f"<td>{STATUS_WORD.get(c['from'], c['from'])} → {STATUS_WORD.get(c['to'], c['to'])}</td></tr>")
        out.append("</table>")
    out.append("<h2>All checks</h2><table><tr><th>Area</th><th>Check</th><th>Status</th><th>Weight</th><th>Evidence</th><th>Method</th></tr>")
    names = {k: v.get("name", k) for k, v in rep.get("categories", {}).items()}
    for c in sorted(rep.get("checks", []), key=lambda c: (c.get("category", ""), -RANK.get(c.get("status"), 1) * -1, c.get("title", ""))):
        out.append(f"<tr><td>{e(str(names.get(c.get('category'), c.get('category'))))}</td><td>{e(c.get('title', ''))}<br>"
                   f"<span class='muted'>{e(c.get('id', ''))}</span></td>"
                   f"<td style='color:{col.get(c.get('status'), '#444')}'>{STATUS_WORD.get(c.get('status'), '')}</td>"
                   f"<td>{c.get('weight', '')}</td><td class='mono'>{e((c.get('evidence') or '')[:600])}</td>"
                   f"<td class='mono'>{e((c.get('method') or '')[:200])}</td></tr>")
    out.append("</table></body></html>")
    return "".join(out)


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
        self.advice = QLabel("")
        self.advice.setWordWrap(True)
        self.advice.setStyleSheet(f"color: {C['text2']}; font-size: 13px; background: transparent;")
        info.addWidget(self.advice)
        bar = self._run_bar()
        exp = GhostButton("Export report", "file", 34)
        exp.clicked.connect(self._export)
        bar.addWidget(exp)
        info.addLayout(bar)
        info.addStretch()
        hero.body.addLayout(info, 1)
        lay.addWidget(hero)

        # ── andamento e cambiamenti ──
        trend = Card(padding=18)
        trow = QHBoxLayout()
        trow.setSpacing(18)
        left = QVBoxLayout()
        left.addWidget(SectionLabel("Score over time"))
        self.chart = TrendChart()
        left.addWidget(self.chart, 1)
        trow.addLayout(left, 3)
        right = QVBoxLayout()
        right.addWidget(SectionLabel("What changed"))
        self.changes = QLabel("")
        self.changes.setWordWrap(True)
        self.changes.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.changes.setTextFormat(Qt.TextFormat.RichText)
        self.changes.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent;")
        right.addWidget(self.changes, 1)
        trow.addLayout(right, 2)
        trend.body.addLayout(trow)
        lay.addWidget(trend)
        self._hist_sig = None
        self._changes = []

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
        self.list.on_fix = self.apply_fix
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
            self.advice.setText("")
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
        todo = sorted((c for c in rep.get("checks", []) if c.get("gain")), key=lambda c: -c["gain"])
        if todo:
            best = todo[:5]
            self.advice.setText(f"Fixing the {len(best)} most valuable issue{'s' if len(best) != 1 else ''} adds about "
                                f"<b>+{round(sum(c['gain'] for c in best))} points</b>. Start with: "
                                f"<b>{html.escape(best[0].get('title', ''))}</b> (+{best[0]['gain']:g}).")
        else:
            self.advice.setText("Nothing to fix: every verifiable check passes.")
        self._history(rep)

    def _history(self, rep):
        try:
            sig = os.stat(HISTORY).st_mtime_ns
        except OSError:
            sig = None
        if sig == self._hist_sig and sig is not None:
            return
        self._hist_sig = sig
        hist = load_history()
        self.chart.set_history(hist)
        titles = {c["id"]: c.get("title", c["id"]) for c in rep.get("checks", [])}
        self._changes = history_changes(hist, titles)
        if not hist:
            self.changes.setText("No history yet. It is recorded at every assessment, from this version on.")
        elif not self._changes:
            self.changes.setText(f"No check has changed state since {datetime.fromtimestamp(hist[0]['t']).strftime('%Y-%m-%d %H:%M')}.")
        else:
            rows = []
            for c in self._changes[:9]:
                col = C["accent"] if c["better"] else C["danger"]
                rows.append(f"<span style='color:{C['text3']}'>{datetime.fromtimestamp(c['t']).strftime('%m-%d %H:%M')}</span> "
                            f"<span style='color:{col}'>{'▲' if c['better'] else '▼'}</span> {html.escape(c['title'])}: "
                            f"{STATUS_WORD.get(c['from'], c['from'])} → <b style='color:{col}'>{STATUS_WORD.get(c['to'], c['to'])}</b>")
            self.changes.setText("<br>".join(rows))

    def _export(self):
        if not self.report:
            QMessageBox.information(self, "Export report", "Run the checks first.")
            return
        folder = os.path.expanduser("~/Documents/NEFI-reports")
        try:
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, f"security-report-{time.strftime('%Y%m%d-%H%M')}.html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(security_report(self.report, self._changes))
            os.chmod(path, 0o600)
        except OSError as e:
            QMessageBox.warning(self, "Export report", f"Could not write the report: {e}")
            return
        if QMessageBox.question(self, "Export report", f"Report saved:\n{path}\n\nOpen it now?") == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
