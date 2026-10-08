import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QComboBox, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter
import re

class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        self.rules = [
            (re.compile(r'\b(error|err|failed|failure|critical|crit)\b', re.IGNORECASE),
             self._fmt("#ff6b6b", bold=True)),
            (re.compile(r'\b(warning|warn)\b', re.IGNORECASE),
             self._fmt("#ffaa00")),
            (re.compile(r'\b(notice|info|started|activated|active)\b', re.IGNORECASE),
             self._fmt("#1ed98a")),
            (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
             self._fmt("#8fb0b2")),
            (re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b'),
             self._fmt("#a78bfa")),
        ]

    def _fmt(self, color, bold=False):
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        if bold:
            fmt.setFontWeight(700)
        return fmt

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class LogViewerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("LOG VIEWER")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        controls = QHBoxLayout()
        controls.setSpacing(12)

        source_lbl = QLabel("SOURCE")
        source_lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; letter-spacing: 1px;")
        controls.addWidget(source_lbl)

        self.source_combo = QComboBox()
        self.source_combo.addItems([
            "System (journald)",
            "Kernel (dmesg)",
            "Authentication",
            "Audit (auditd)",
            "Suricata IDS",
            "ClamAV",
            "Firewall (nftables)",
        ])
        self.source_combo.setStyleSheet("""
            QComboBox {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 12px;
                min-width: 200px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                selection-background-color: #0f3a30;
            }
        """)
        self.source_combo.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.source_combo)

        controls.addStretch()

        self.line_count = QLabel("0 lines")
        self.line_count.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        controls.addWidget(self.line_count)

        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.clicked.connect(self.refresh)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 6px;
                padding: 6px 16px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #1ed98a;
                color: #061013;
            }
        """)
        controls.addWidget(refresh_btn)
        layout.addLayout(controls)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1a3a3f;")
        layout.addWidget(sep)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Monospace", 11))
        self.log_area.setStyleSheet("""
            QTextEdit {
                background-color: #051012;
                color: #d5e4e5;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        self.highlighter = LogHighlighter(self.log_area.document())
        layout.addWidget(self.log_area)

    def refresh(self):
        source = self.source_combo.currentText()
        lines = self._get_logs(source)
        self.log_area.setPlainText(lines)
        count = len(lines.splitlines())
        self.line_count.setText(f"{count} lines")
        sb = self.log_area.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _get_logs(self, source):
        try:
            if "journald" in source:
                cmd = ["journalctl", "-n", "200", "--no-pager", "-o", "short-iso"]
            elif "dmesg" in source:
                cmd = ["dmesg", "-T", "--level=err,warn,notice"]
            elif "Authentication" in source:
                cmd = ["journalctl", "-u", "ssh", "-u", "sudo", "-n", "200", "--no-pager"]
            elif "auditd" in source:
                cmd = ["journalctl", "-u", "auditd", "-n", "200", "--no-pager"]
            elif "Suricata" in source:
                cmd = ["journalctl", "-u", "suricata", "-n", "200", "--no-pager"]
            elif "ClamAV" in source:
                cmd = ["journalctl", "-u", "clamav-daemon", "-n", "200", "--no-pager"]
            elif "nftables" in source:
                cmd = ["journalctl", "-u", "nftables", "-n", "200", "--no-pager"]
            else:
                return "Source not available"

            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout or "No logs available for this source."
        except Exception as e:
            return f"Error reading logs: {e}"
