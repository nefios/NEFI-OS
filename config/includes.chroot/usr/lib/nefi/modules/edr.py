import os
import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QScrollArea, QFrame, QPushButton,
    QComboBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt
from edr_engine import EDREngine, EDREvent, SEVERITY_COLORS

EVENTS_FILE = os.path.expanduser("~/.local/share/nefi/edr-events.jsonl")
MAX_STORED = 5000
MAX_SHOWN = 200
def event_to_dict(e):
    return {
        "timestamp": e.timestamp,
        "category": e.category,
        "severity": e.severity,
        "title": e.title,
        "description": e.description,
    }


def dict_to_event(d):
    return EDREvent(
        d.get("category", "info"), d.get("severity", "info"),
        d.get("title", ""), d.get("description", ""),
        d.get("timestamp", "")
    )


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Storage ──────────────────────────────────────────────
def load_events():
    events = []
    if not os.path.exists(EVENTS_FILE):
        return events
    try:
        with open(EVENTS_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return events


def append_event(event_dict):
    try:
        os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps(event_dict) + "\n")
    except Exception:
        pass


def rotate_events():
    events = load_events()
    if len(events) > MAX_STORED:
        try:
            with open(EVENTS_FILE, "w") as f:
                for e in events[-MAX_STORED:]:
                    f.write(json.dumps(e) + "\n")
        except Exception:
            pass


# ── Widgets ──────────────────────────────────────────────
class StatCard(QWidget):
    def __init__(self, label, color="#1ed98a"):
        super().__init__()
        self.setMinimumHeight(75)
        self.setStyleSheet("""
            QWidget {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)
        lbl = QLabel(label.upper())
        lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; letter-spacing: 1px; border: none;")
        layout.addWidget(lbl)
        self.value_lbl = QLabel("--")
        self.value_lbl.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: bold; border: none;")
        layout.addWidget(self.value_lbl)

    def set_value(self, value):
        self.value_lbl.setText(str(value))


class EventCard(QFrame):
    def __init__(self, event, historical=False):
        super().__init__()
        color = SEVERITY_COLORS.get(event.severity, "#8fb0b2")
        bg = "#081a1d" if historical else "#0d2226"
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg};
                border-left: 3px solid {color};
                border-radius: 6px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        header = QHBoxLayout()
        cat_lbl = QLabel(f"[{event.category.upper()}]")
        cat_lbl.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: bold; border: none;")
        header.addWidget(cat_lbl)
        sev_lbl = QLabel(event.severity.upper())
        sev_lbl.setStyleSheet(f"""
            color: {color}; background-color: {color}22; border: 1px solid {color};
            border-radius: 8px; padding: 1px 8px; font-size: 9px; font-weight: bold;
        """)
        header.addWidget(sev_lbl)
        header.addStretch()
        time_lbl = QLabel(event.timestamp)
        time_lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; border: none;")
        header.addWidget(time_lbl)
        layout.addLayout(header)

        title_lbl = QLabel(event.title)
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet(
            f"color: {'#a3b9bb' if historical else '#e0e0e0'}; font-size: 13px; font-weight: bold; border: none;"
        )
        layout.addWidget(title_lbl)
        desc_lbl = QLabel(event.description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet(
            f"color: {'#6b8a8d' if historical else '#d5e4e5'}; font-size: 11px; border: none;"
        )
        layout.addWidget(desc_lbl)


class SessionDivider(QLabel):
    def __init__(self, text):
        super().__init__(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("""
            color: #8fb0b2; font-size: 10px; letter-spacing: 2px;
            border-top: 1px solid #1a3a3f; padding-top: 6px; margin: 6px 0;
        """)


class EDRWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.engine = None
        rotate_events()
        self.history = load_events()
        self.session = []
        self._build_ui()
        self._render()
        self._start_engine()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel("NEFI EDR")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        header.addWidget(title)
        header.addStretch()

        self.status_dot = QLabel("● Starting...")
        self.status_dot.setStyleSheet("color: #ffaa00; font-size: 11px;")
        header.addWidget(self.status_dot)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All events", "Medium and above", "High and above"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d2226; color: #e0e0e0; border: 1px solid #1a3a3f;
                border-radius: 6px; padding: 4px 10px; font-size: 11px; margin-left: 8px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #0d2226; color: #e0e0e0; border: 1px solid #1a3a3f;
            }
        """)
        self.filter_combo.currentIndexChanged.connect(self._render)
        header.addWidget(self.filter_combo)

        btn_style = """
            QPushButton {
                background-color: #0d2226; color: #8fb0b2; border: 1px solid #1a3a3f;
                border-radius: 6px; padding: 4px 12px; font-size: 11px; margin-left: 8px;
            }
            QPushButton:hover { border-color: #1ed98a; color: #1ed98a; }
        """
        export_btn = QPushButton("Export JSON")
        export_btn.setStyleSheet(btn_style)
        export_btn.clicked.connect(self._export)
        header.addWidget(export_btn)

        clear_btn = QPushButton("Clear history")
        clear_btn.setStyleSheet(btn_style)
        clear_btn.clicked.connect(self._clear_history)
        header.addWidget(clear_btn)
        layout.addLayout(header)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.proc_card = StatCard("Active processes")
        self.conn_card = StatCard("Connections")
        self.files_card = StatCard("Files monitored")
        self.session_card = StatCard("Session events", "#ffaa00")
        self.total_card = StatCard("Total stored", "#8fb0b2")
        for c in (self.proc_card, self.conn_card, self.files_card,
                  self.session_card, self.total_card):
            stats_row.addWidget(c)
        layout.addLayout(stats_row)

        events_title = QLabel("EVENTS")
        events_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px; margin-top: 8px;")
        layout.addWidget(events_title)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid #1a3a3f; border-radius: 10px; background-color: #051012;
            }
        """)
        self.events_content = QWidget()
        self.events_content.setStyleSheet("background-color: #051012;")
        self.events_layout = QVBoxLayout(self.events_content)
        self.events_layout.setContentsMargins(12, 12, 12, 12)
        self.events_layout.setSpacing(8)
        self.events_layout.addStretch()
        self.scroll.setWidget(self.events_content)
        layout.addWidget(self.scroll)

    # ── Rendering ────────────────────────────────────────
    def _min_rank(self):
        return {0: 0, 1: 2, 2: 3}.get(self.filter_combo.currentIndex(), 0)

    def _passes(self, ev_dict):
        return SEVERITY_RANK.get(ev_dict.get("severity", "info"), 0) >= self._min_rank()

    def _render(self):
        while self.events_layout.count() > 1:
            item = self.events_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        shown = 0
        session = [e for e in reversed(self.session) if self._passes(e)]
        for e in session[:MAX_SHOWN]:
            self.events_layout.insertWidget(self.events_layout.count() - 1,
                                            EventCard(dict_to_event(e)))
            shown += 1

        history = [e for e in reversed(self.history) if self._passes(e)]
        if history and shown < MAX_SHOWN:
            self.events_layout.insertWidget(self.events_layout.count() - 1,
                                            SessionDivider("PREVIOUS SESSIONS"))
            for e in history[:MAX_SHOWN - shown]:
                self.events_layout.insertWidget(self.events_layout.count() - 1,
                                                EventCard(dict_to_event(e), historical=True))

        self.session_card.set_value(len(self.session))
        self.total_card.set_value(len(self.history) + len(self.session))

    # ── Engine ───────────────────────────────────────────
    def _start_engine(self):
        self.engine = EDREngine()
        self.engine.new_event.connect(self._on_event)
        self.engine.stats_update.connect(self._on_stats)
        self.engine.start()
        self.status_dot.setText("● Monitoring active")
        self.status_dot.setStyleSheet("color: #1ed98a; font-size: 11px;")

    def _on_event(self, event):
        d = event_to_dict(event)
        append_event(d)
        self.session.append(d)
        if self._passes(d):
            self.events_layout.insertWidget(0, EventCard(event))
            # Limita i widget a schermo
            while self.events_layout.count() > MAX_SHOWN + 2:
                item = self.events_layout.takeAt(self.events_layout.count() - 2)
                if item.widget():
                    item.widget().deleteLater()
        self.session_card.set_value(len(self.session))
        self.total_card.set_value(len(self.history) + len(self.session))

    def _on_stats(self, stats):
        self.proc_card.set_value(stats.get("processes", 0))
        self.conn_card.set_value(stats.get("connections", 0))
        self.files_card.set_value(stats.get("files_monitored", 0))

    # ── Actions ──────────────────────────────────────────
    def _export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export EDR events",
            os.path.expanduser("~/nefi-edr-events.json"),
            "JSON files (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(self.history + self.session, f, indent=2)
            QMessageBox.information(self, "Export completed",
                                    f"{len(self.history) + len(self.session)} events exported to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export failed", str(e))

    def _clear_history(self):
        reply = QMessageBox.question(
            self, "Clear EDR history",
            "Delete all stored EDR events (previous sessions and current)?\n"
            "Consider exporting them first if they are needed for an investigation.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            if os.path.exists(EVENTS_FILE):
                os.remove(EVENTS_FILE)
        except Exception:
            pass
        self.history = []
        self.session = []
        self._render()

    def refresh(self):
        pass

    def closeEvent(self, event):
        if self.engine:
            self.engine.stop()
        super().closeEvent(event)
