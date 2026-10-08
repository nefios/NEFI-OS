"""NEFI Security Center — design system: colori, stili, icone e componenti condivisi."""
from PyQt6.QtWidgets import (
    QWidget, QFrame, QLabel, QPushButton, QHBoxLayout, QVBoxLayout,
    QGraphicsDropShadowEffect, QSizePolicy
)
from PyQt6.QtCore import Qt, QRectF, QPointF, QByteArray, QSize
from PyQt6.QtGui import (
    QColor, QPainter, QPen, QBrush, QLinearGradient, QRadialGradient,
    QPainterPath, QPixmap, QIcon, QFont, QConicalGradient, QPolygonF
)
import math

try:
    from PyQt6.QtSvg import QSvgRenderer
    HAS_SVG = True
except ImportError:
    HAS_SVG = False

# ── Palette ─────────────────────────────────────────────
C = {
    "bg":        "#071417",   # finestra
    "bg2":       "#0a1b1f",   # area contenuti
    "card":      "#0d2226",   # card
    "card2":     "#10292e",   # card evidenziata / hover
    "border":    "#1a3a3f",
    "border2":   "#23525a",
    "accent":    "#1ed98a",   # smeraldo
    "accent2":   "#14b874",
    "accent_bg": "#0f3a30",
    "text":      "#eaf3f3",
    "text2":     "#a3b9bb",
    "text3":     "#6b8a8d",
    "danger":    "#ff5a5f",
    "danger_bg": "#3a171c",
    "warn":      "#ffb547",
    "warn_bg":   "#3a2c14",
    "info":      "#5ab4ff",
}

TONES = {
    "ok":     (C["accent"], C["accent_bg"]),
    "danger": (C["danger"], C["danger_bg"]),
    "warn":   (C["warn"], C["warn_bg"]),
    "info":   (C["info"], "#132c40"),
    "muted":  (C["text3"], "#12292d"),
}

GLOBAL_QSS = f"""
QWidget {{
    color: {C['text']};
    font-family: 'Noto Sans', 'DejaVu Sans', sans-serif;
    font-size: 13px;
}}
QMainWindow, QWidget#root {{ background-color: {C['bg']}; }}
QToolTip {{
    background-color: {C['card2']}; color: {C['text']};
    border: 1px solid {C['border2']}; border-radius: 6px; padding: 6px;
}}
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 4px 2px;
}}
QScrollBar::handle:vertical {{
    background: {C['border2']}; border-radius: 3px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {C['accent2']}; }}
QScrollBar:horizontal {{
    background: transparent; height: 10px; margin: 2px 4px;
}}
QScrollBar::handle:horizontal {{
    background: {C['border2']}; border-radius: 3px; min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QStatusBar {{
    background-color: {C['bg']}; color: {C['text3']};
    border-top: 1px solid {C['border']}; font-size: 12px;
}}
QMessageBox {{ background-color: {C['card']}; }}
QMenu {{
    background-color: {C['card']}; border: 1px solid {C['border2']};
    border-radius: 8px; padding: 4px;
}}
QMenu::item {{ padding: 6px 16px; border-radius: 4px; }}
QMenu::item:selected {{ background-color: {C['accent_bg']}; color: {C['accent']}; }}
"""

# ── Icone SVG (stile a linee) ───────────────────────────
_ICONS = {
    "monitor":   '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "shield":    '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/>',
    "search":    '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l5 5"/>',
    "file":      '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
    "chart":     '<path d="M4 20h16"/><path d="M7 20v-6M11 20V9M15 20v-8M19 20V5"/>',
    "gear":      '<circle cx="12" cy="12" r="3.2"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1"/>',
    "chev_down": '<path d="M7 10l5 5 5-5"/>',
    "chev_right":'<path d="M10 7l5 5-5 5"/>',
    "alert":     '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17.2v.3"/>',
    "refresh":   '<path d="M20 11a8 8 0 0 0-14.7-3.5M4 13a8 8 0 0 0 14.7 3.5"/><path d="M5 4v4h4M19 20v-4h-4"/>',
    "list":      '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r=".6"/><circle cx="4.5" cy="12" r=".6"/><circle cx="4.5" cy="18" r=".6"/>',
    "wall":      '<rect x="3" y="5" width="18" height="14" rx="1.5"/><path d="M3 10h18M3 14.5h18M9 5v5M15 5v5M6 10v4.5M12 10v4.5M18 10v4.5M9 14.5V19M15 14.5V19"/>',
    "box":       '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>',
    "power":     '<path d="M12 3v8"/><path d="M7 6.5a7 7 0 1 0 10 0"/>',
    "lock":      '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    "download":  '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
    "user_x":    '<circle cx="10" cy="8" r="4"/><path d="M3 20c0-3.5 3-6 7-6s7 2.5 7 6M17 7l4 4M21 7l-4 4"/>',
    "cpu":       '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "camera":    '<path d="M4 8h3l2-3h6l2 3h3v11H4z"/><circle cx="12" cy="13" r="3.5"/>',
    "sliders":   '<path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/>',
    "check_sq":  '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 12l3 3 5-6"/>',
    "target":    '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r=".8"/>',
    "usb":       '<path d="M12 3v14M12 3l-2 3h4z"/><circle cx="12" cy="19" r="2"/><path d="M12 13l-4-2V8M12 11l4-2V7"/><rect x="15" y="5" width="2" height="2"/><circle cx="8" cy="7.5" r="1"/>',
    "eye_off":   '<path d="M3 3l18 18"/><path d="M10.5 6.2A10 10 0 0 1 12 6c5 0 9 6 9 6a17 17 0 0 1-3.2 3.7M6.5 7.6C4.2 9.2 3 12 3 12s4 6 9 6a9 9 0 0 0 4-1"/><path d="M9.9 10a3 3 0 0 0 4.1 4.1"/>',
    "cube":      '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M8 5.3l8 4.5v4"/>',
    "radar":     '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/>',
    "globe":     '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    "bug":       '<rect x="8" y="7" width="8" height="12" rx="4"/><path d="M12 7V4M9 4l1.5 3M15 4l-1.5 3M4 11h4M16 11h4M4 16h4M16 16h4"/>',
    "honey":     '<path d="M12 3l7 4v8l-7 4-7-4V7z"/><path d="M12 7l3.5 2v4L12 15l-3.5-2V9z"/>',
    "folder":    '<path d="M3 6h6l2 2h10v11H3z"/>',
    "fingerprint":'<path d="M6 17c1-2 1-4 1-6a5 5 0 0 1 10 0c0 3-.5 6-2 8"/><path d="M9.5 19c1-2 1.5-5 1.5-8a1 1 0 0 1 2 0c0 3-.3 5.5-1 7.5"/>',
    "terminal":  '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M12 15h5"/>',
    "services":  '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.1M7 17h.1"/>',
    "network":   '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
    "activity":  '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "siren":     '<path d="M6 18v-6a6 6 0 0 1 12 0v6"/><path d="M4 18h16v3H4zM12 2v2M4.2 5.2l1.4 1.4M19.8 5.2l-1.4 1.4"/>',
    "bot":       '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 4v4"/><circle cx="12" cy="3.5" r="1"/><circle cx="9" cy="14" r="1.2"/><circle cx="15" cy="14" r="1.2"/>',
    "zero":      '<circle cx="12" cy="12" r="9"/><path d="M5.6 18.4L18.4 5.6"/>',
    "snapshot":  '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "dot":       '<circle cx="12" cy="12" r="4" fill="COLOR"/>',
}


def compact():
    """True su schermi bassi (es. 1280x800 delle VM): interfaccia più compatta."""
    from PyQt6.QtGui import QGuiApplication
    scr = QGuiApplication.primaryScreen()
    return bool(scr) and scr.availableGeometry().height() < 950


def icon_pixmap(name, color=None, size=20, stroke=1.8):
    color = color or C["text"]
    body = _ICONS.get(name, _ICONS["dot"]).replace("COLOR", color)
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
           f'stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" '
           f'stroke-linejoin="round">{body}</svg>')
    pm = QPixmap(size * 2, size * 2)
    pm.fill(Qt.GlobalColor.transparent)
    if HAS_SVG:
        r = QSvgRenderer(QByteArray(svg.encode()))
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r.render(p)
        p.end()
    pm.setDevicePixelRatio(2)
    return pm


def icon(name, color=None, size=20):
    return QIcon(icon_pixmap(name, color, size))


def glow(widget, color=None, radius=24, alpha=110):
    eff = QGraphicsDropShadowEffect(widget)
    col = QColor(color or C["accent"])
    col.setAlpha(alpha)
    eff.setColor(col)
    eff.setBlurRadius(radius)
    eff.setOffset(0, 0)
    widget.setGraphicsEffect(eff)


# ── Componenti ──────────────────────────────────────────
class SectionLabel(QLabel):
    """Etichetta di sezione in maiuscolo spaziato."""
    def __init__(self, text):
        super().__init__(text.upper())
        self.setStyleSheet(f"color: {C['text2']}; font-size: 12px; "
                           f"letter-spacing: 3px; background: transparent;")


class Card(QFrame):
    """Contenitore con bordo sottile e angoli arrotondati."""
    def __init__(self, padding=20):
        super().__init__()
        self.setObjectName("nefiCard")
        self.setStyleSheet(f"""
            QFrame#nefiCard {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 16px;
            }}
        """)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(12)


class Pill(QLabel):
    """Badge a pillola (punti, stato)."""
    def __init__(self, text, tone="ok", min_width=64):
        super().__init__(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumWidth(min_width)
        self.setFixedHeight(34)
        self.set_tone(tone)

    def set_tone(self, tone):
        fg, bg = TONES.get(tone, TONES["muted"])
        self.setStyleSheet(f"""
            color: {fg}; background-color: {bg};
            border: 1px solid {fg}55; border-radius: 9px;
            padding: 0 12px; font-size: 15px; font-weight: bold;
        """)


class IconTile(QLabel):
    """Riquadro colorato con icona (verde se ok, rosso se problema)."""
    def __init__(self, icon_name, tone="ok", size=64):
        super().__init__()
        self.icon_name = icon_name
        self.tile = size
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_tone(tone)

    def set_tone(self, tone):
        fg, bg = TONES.get(tone, TONES["muted"])
        self.setPixmap(icon_pixmap(self.icon_name, fg, int(self.tile * 0.42)))
        self.setStyleSheet(f"background-color: {bg}; border: 1px solid {fg}33; "
                           f"border-radius: 12px;")


class PrimaryButton(QPushButton):
    """Pulsante pieno smeraldo con bagliore."""
    def __init__(self, text, icon_name=None, height=48):
        super().__init__(f"  {text}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(height)
        if icon_name:
            self.setIcon(icon(icon_name, "#ffffff", 20))
            self.setIconSize(QSize(20, 20))
        self.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {C['accent']}, stop:1 {C['accent2']});
                color: #ffffff; border: none; border-radius: 12px;
                padding: 0 28px; font-size: 15px; font-weight: bold;
            }}
            QPushButton:hover {{ background: {C['accent']}; }}
            QPushButton:pressed {{ background: {C['accent2']}; }}
            QPushButton:disabled {{ background: {C['border']}; color: {C['text3']}; }}
        """)
        glow(self, radius=28, alpha=90)


class GhostButton(QPushButton):
    """Pulsante secondario con bordo."""
    def __init__(self, text, icon_name=None, height=40, tone="muted"):
        super().__init__(f"  {text}" if icon_name else text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(height)
        fg = C["text"] if tone == "muted" else TONES[tone][0]
        if icon_name:
            self.setIcon(icon(icon_name, fg, 18))
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent; color: {fg};
                border: 1px solid {C['border2']}; border-radius: 12px;
                padding: 0 18px; font-size: 13px;
            }}
            QPushButton:hover {{ border-color: {C['accent']}; background-color: {C['card2']}; }}
            QPushButton:disabled {{ color: {C['text3']}; border-color: {C['border']}; }}
        """)


class CheckRow(QFrame):
    """Riga di controllo: icona, titolo, descrizione, badge e freccia."""
    def __init__(self, icon_name, title, description, badge="", ok=True):
        super().__init__()
        self.setObjectName("checkRow")
        self.setMinimumHeight(76)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 18, 0)
        lay.setSpacing(22)

        self.tile = IconTile(icon_name, "ok", 76)
        lay.addWidget(self.tile)

        text = QVBoxLayout()
        text.setSpacing(4)
        text.setContentsMargins(0, 12, 0, 12)
        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("font-size: 16px; font-weight: bold; background: transparent;")
        self.desc_lbl = QLabel(description)
        self.desc_lbl.setWordWrap(True)
        text.addWidget(self.title_lbl)
        text.addWidget(self.desc_lbl)
        lay.addLayout(text, 1)

        self.badge = Pill(badge, "ok")
        lay.addWidget(self.badge)
        chev = QLabel()
        chev.setPixmap(icon_pixmap("chev_right", C["text2"], 18))
        chev.setStyleSheet("background: transparent;")
        lay.addWidget(chev)
        self.set_state(ok, description, badge)

    def set_state(self, ok, description=None, badge=None, tone=None):
        tone = tone or ("ok" if ok else "danger")
        fg, _ = TONES[tone]
        self.tile.set_tone(tone)
        if badge is not None:
            self.badge.setText(badge)
        self.badge.set_tone(tone)
        if description is not None:
            if tone == "ok":
                self.desc_lbl.setText(description)
                self.desc_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 14px; background: transparent;")
            else:
                self.desc_lbl.setText(f"⚠  {description}")
                self.desc_lbl.setStyleSheet(f"color: {fg}; font-size: 14px; background: transparent;")
        self.setStyleSheet(f"""
            QFrame#checkRow {{
                background-color: {C['card2']};
                border: 1px solid {C['border']};
                border-radius: 12px;
            }}
            QFrame#checkRow:hover {{ border-color: {C['border2']}; }}
        """)


class ScoreRing(QWidget):
    """Anello di punteggio con arco sfumato e bagliore."""
    def __init__(self, size=240):
        super().__init__()
        self.score = 0
        self.setFixedSize(size, size)

    def set_score(self, score):
        self.score = max(0, min(100, int(score)))
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = self.width()
        m = s * 0.09
        rect = QRectF(m, m, s - 2 * m, s - 2 * m)
        w = s * 0.075

        # alone esterno
        halo = QRadialGradient(QPointF(s / 2, s / 2), s / 2)
        halo.setColorAt(0.70, QColor(0, 0, 0, 0))
        halo.setColorAt(0.85, QColor(C["accent"]).darker(300))
        halo.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.setBrush(QBrush(halo))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(0, 0, s, s))

        # binario
        p.setPen(QPen(QColor(C["border"]), w, cap=Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(rect, 0, 360 * 16)

        # arco sfumato
        span = int(-360 * 16 * self.score / 100)
        if span:
            grad = QConicalGradient(QPointF(s / 2, s / 2), 90)
            grad.setColorAt(0.0, QColor(C["accent"]))
            grad.setColorAt(1.0, QColor(C["accent2"]).darker(130))
            p.setPen(QPen(QBrush(grad), w, cap=Qt.PenCapStyle.RoundCap))
            p.drawArc(rect, 90 * 16, span)

        # testo
        p.setPen(QColor(C["text"]))
        f = QFont("Noto Sans", int(s * 0.19), QFont.Weight.Bold)
        p.setFont(f)
        p.drawText(QRectF(0, s * 0.26, s, s * 0.3), Qt.AlignmentFlag.AlignCenter, str(self.score))
        p.setPen(QColor(C["text2"]))
        p.setFont(QFont("Noto Sans", int(s * 0.075)))
        p.drawText(QRectF(0, s * 0.56, s, s * 0.14), Qt.AlignmentFlag.AlignCenter, "/ 100")
        p.end()


class HeroCard(QFrame):
    """Card principale con sfumatura, fascio di luce e grafica a esagoni con scudo."""
    def __init__(self, decoration=True):
        super().__init__()
        self.decoration = decoration
        self.setMinimumHeight(220 if compact() else 290)
        self.body = QHBoxLayout(self)
        self.body.setContentsMargins(32, 18, 32, 18) if compact() else self.body.setContentsMargins(40, 28, 40, 28)
        self.body.setSpacing(48)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(r, 18, 18)
        p.setClipPath(path)

        bg = QLinearGradient(0, 0, r.width(), r.height())
        bg.setColorAt(0, QColor("#0b2327"))
        bg.setColorAt(1, QColor("#0c2e2a"))
        p.fillPath(path, QBrush(bg))

        # fascio di luce diagonale
        beam = QPainterPath()
        w, h = r.width(), r.height()
        beam.moveTo(w * 0.55, h)
        beam.cubicTo(w * 0.70, h * 0.55, w * 0.78, h * 0.20, w, -h * 0.05)
        beam.lineTo(w, h)
        beam.closeSubpath()
        lg = QLinearGradient(w * 0.55, h, w, 0)
        lg.setColorAt(0, QColor(30, 217, 138, 10))
        lg.setColorAt(1, QColor(30, 217, 138, 38))
        p.fillPath(beam, QBrush(lg))

        if self.decoration and w > 900:
            cx, cy, R = w - 200, h / 2, min(h * 0.40, 120)

            def hexagon(x, y, rad):
                return QPolygonF([QPointF(x + rad * math.cos(math.radians(60 * i - 30)),
                                          y + rad * math.sin(math.radians(60 * i - 30)))
                                  for i in range(6)])
            for dx, dy, k, a in ((-95, 20, 0.80, 60), (75, 30, 0.80, 60), (0, 0, 1.0, 110)):
                poly = hexagon(cx + dx, cy + dy, R * k)
                g = QLinearGradient(cx + dx, cy + dy - R, cx + dx, cy + dy + R)
                g.setColorAt(0, QColor(30, 217, 138, a // 3))
                g.setColorAt(1, QColor(10, 40, 40, a))
                p.setBrush(QBrush(g))
                p.setPen(QPen(QColor(30, 217, 138, a), 1.2))
                p.drawPolygon(poly)

            # scudo al centro
            sh = QPainterPath()
            sw, shh = R * 0.55, R * 0.68
            sx, sy = cx, cy - shh * 0.5
            sh.moveTo(sx, sy)
            sh.lineTo(sx + sw / 2, sy + shh * 0.18)
            sh.lineTo(sx + sw / 2, sy + shh * 0.50)
            sh.cubicTo(sx + sw / 2, sy + shh * 0.80, sx + sw * 0.2, sy + shh * 0.95, sx, sy + shh)
            sh.cubicTo(sx - sw * 0.2, sy + shh * 0.95, sx - sw / 2, sy + shh * 0.80, sx - sw / 2, sy + shh * 0.50)
            sh.lineTo(sx - sw / 2, sy + shh * 0.18)
            sh.closeSubpath()
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(QColor(C["accent"]), 4, join=Qt.PenJoinStyle.RoundJoin))
            p.drawPath(sh)

        p.setClipping(False)
        p.setPen(QPen(QColor(C["border2"]), 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(r, 18, 18)
        p.end()


class PageHeader(QWidget):
    """Titolo pagina con sottotitolo, usato dai moduli."""
    def __init__(self, title, subtitle=""):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        t = QLabel(title)
        t.setStyleSheet("font-size: 22px; font-weight: bold; background: transparent;")
        lay.addWidget(t)
        if subtitle:
            s = QLabel(subtitle)
            s.setWordWrap(True)
            s.setStyleSheet(f"color: {C['text2']}; font-size: 13px; background: transparent;")
            lay.addWidget(s)
