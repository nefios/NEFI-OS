import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit,
    QFrame, QScrollArea, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPainter, QColor, QPen
from PyQt6.QtCore import QRectF


class ScoreRing(QWidget):
    def __init__(self):
        super().__init__()
        self.score = 0
        self.setFixedSize(140, 140)

    def set_score(self, score):
        self.score = score
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(10, 10, 120, 120)

        pen_bg = QPen(QColor("#1a3a3f"), 10)
        pen_bg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_bg)
        painter.drawArc(rect, 0, 360 * 16)

        if self.score >= 80:
            color = "#1ed98a"
        elif self.score >= 60:
            color = "#ffaa00"
        else:
            color = "#ff6b6b"

        pen_fg = QPen(QColor(color), 10)
        pen_fg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_fg)
        angle = int(360 * (self.score / 100) * 16)
        painter.drawArc(rect, 90 * 16, -angle)

        painter.setPen(QColor(color))
        font = QFont("Sans", 26, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, str(self.score))


class VulnScanWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool, int)

    def run(self):
        try:
            process = subprocess.Popen(
                ["pkexec", "bash", "/opt/nefi/vuln-scanner/scan.sh"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            score = 0
            for line in process.stdout:
                line = line.rstrip()
                self.output_line.emit(line)
                if line.startswith("SCAN_SCORE="):
                    try:
                        score = int(line.split("=")[1])
                    except Exception:
                        pass
            process.wait()
            self.finished_ok.emit(process.returncode == 0, score)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False, 0)


class FindingCard(QFrame):
    def __init__(self, text, severity="warning"):
        super().__init__()
        colors = {
            "warning": "#ff6b6b",
            "suggestion": "#ffaa00",
            "info": "#8fb0b2",
        }
        color = colors.get(severity, "#8fb0b2")
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0d2226;
                border-left: 3px solid {color};
                border-radius: 6px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        icon = QLabel("⚠" if severity == "warning" else "💡")
        icon.setFixedWidth(20)
        icon.setStyleSheet("font-size: 14px; border: none;")
        layout.addWidget(icon)

        text_lbl = QLabel(text)
        text_lbl.setStyleSheet(f"color: {color}; font-size: 11px; border: none;")
        text_lbl.setWordWrap(True)
        layout.addWidget(text_lbl)


class VulnScannerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()
        self._load_last_scan()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("VULNERABILITY SCANNER")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        # Top row — score + info
        top_row = QHBoxLayout()
        top_row.setSpacing(24)

        self.ring = ScoreRing()
        top_row.addWidget(self.ring)

        info_block = QVBoxLayout()
        info_block.setSpacing(8)

        self.score_label = QLabel("Run a scan to get your Hardening Index")
        self.score_label.setStyleSheet("color: #e0e0e0; font-size: 15px; font-weight: bold;")
        self.score_label.setWordWrap(True)
        info_block.addWidget(self.score_label)

        self.score_sub = QLabel(
            "Lynis audits hundreds of security parameters:\n"
            "kernel config, services, file permissions, password policies, and more."
        )
        self.score_sub.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        self.score_sub.setWordWrap(True)
        info_block.addWidget(self.score_sub)

        self.scan_btn = QPushButton("▶  Run Vulnerability Scan")
        self.scan_btn.setFixedHeight(40)
        self.scan_btn.setFixedWidth(240)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 8px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
        """)
        self.scan_btn.clicked.connect(self._start_scan)
        info_block.addWidget(self.scan_btn)
        info_block.addStretch()

        top_row.addLayout(info_block)
        top_row.addStretch()
        layout.addLayout(top_row)

        # Findings
        findings_title = QLabel("FINDINGS")
        findings_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(findings_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.findings_content = QWidget()
        self.findings_content.setStyleSheet("background: transparent;")
        self.findings_layout = QVBoxLayout(self.findings_content)
        self.findings_layout.setSpacing(6)
        self.findings_layout.addStretch()
        scroll.setWidget(self.findings_content)
        layout.addWidget(scroll)

        # Output log
        log_title = QLabel("SCAN OUTPUT")
        log_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(log_title)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setFixedHeight(150)
        self.output_log.setStyleSheet("""
            QTextEdit {
                background-color: #051012;
                color: #1ed98a;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                font-family: monospace;
                font-size: 11px;
                padding: 10px;
            }
        """)
        self.output_log.setPlaceholderText(
            "Scan output will appear here...\n"
            "Administrator password required to run the scan."
        )
        layout.addWidget(self.output_log)

    def _start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        self.output_log.clear()
        self.output_log.append("Starting vulnerability scan...")
        self.output_log.append("This may take 2-5 minutes.\n")
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("⟳  Scanning...")

        while self.findings_layout.count() > 1:
            item = self.findings_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.worker = VulnScanWorker()
        self.worker.output_line.connect(self._on_line)
        self.worker.finished_ok.connect(self._on_done)
        self.worker.start()

    def _on_line(self, line):
        self.output_log.append(line)
        if "[NEFI-VULN] WARNINGS:" in line or "[NEFI-VULN] SUGGESTIONS:" in line:
            return
        if line.startswith("[NEFI-VULN]") or line.startswith("SCAN_SCORE"):
            return
        if "warning" in line.lower() and "[]=" not in line:
            card = FindingCard(line.strip(), "warning")
            self.findings_layout.insertWidget(
                self.findings_layout.count() - 1, card
            )
        elif "suggestion" in line.lower() and "[]=" not in line:
            card = FindingCard(line.strip(), "suggestion")
            self.findings_layout.insertWidget(
                self.findings_layout.count() - 1, card
            )

    def _on_done(self, success, score):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("▶  Run Vulnerability Scan")
        if success and score > 0:
            self.ring.set_score(score)
            if score >= 80:
                level = "Good"
                color = "#1ed98a"
            elif score >= 60:
                level = "Needs improvement"
                color = "#ffaa00"
            else:
                level = "Critical"
                color = "#ff6b6b"
            self.score_label.setText(f"Hardening Index: {score}/100 — {level}")
            self.score_label.setStyleSheet(
                f"color: {color}; font-size: 15px; font-weight: bold;"
            )
            self._load_findings()
        elif not success:
            self.output_log.append("\n✗ Scan failed.")

    def _load_findings(self):
        while self.findings_layout.count() > 1:
            item = self.findings_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        report = "/var/lib/nefi/vuln-scan/lynis-report.dat"
        if not os.path.exists(report):
            return

        try:
            with open(report) as f:
                lines = f.readlines()

            warnings = []
            suggestions = []

            for line in lines:
                line = line.strip()
                if line.startswith("warning[]="):
                    raw = line.replace("warning[]=", "")
                    parts = raw.split("|")
                    code = parts[0] if parts else ""
                    text = parts[1] if len(parts) > 1 else raw
                    if text:
                        warnings.append(f"[{code}] {text}")
                elif line.startswith("suggestion[]="):
                    raw = line.replace("suggestion[]=", "")
                    parts = raw.split("|")
                    code = parts[0] if parts else ""
                    text = parts[1] if len(parts) > 1 else raw
                    if text:
                        suggestions.append(f"[{code}] {text}")

            # Header warnings
            if warnings:
                hdr = QLabel(f"⚠  WARNINGS ({len(warnings)})")
                hdr.setStyleSheet("color: #ff6b6b; font-size: 11px; font-weight: bold; margin-top: 8px;")
                self.findings_layout.insertWidget(self.findings_layout.count() - 1, hdr)
                for w in warnings[:20]:
                    card = FindingCard(w, "warning")
                    self.findings_layout.insertWidget(self.findings_layout.count() - 1, card)

            # Header suggestions
            if suggestions:
                hdr2 = QLabel(f"💡  SUGGESTIONS ({len(suggestions)})")
                hdr2.setStyleSheet("color: #ffaa00; font-size: 11px; font-weight: bold; margin-top: 8px;")
                self.findings_layout.insertWidget(self.findings_layout.count() - 1, hdr2)
                for s in suggestions[:20]:
                    card = FindingCard(s, "suggestion")
                    self.findings_layout.insertWidget(self.findings_layout.count() - 1, card)

            if not warnings and not suggestions:
                ok = QLabel("✓ No warnings or suggestions found.")
                ok.setStyleSheet("color: #1ed98a; font-size: 12px;")
                self.findings_layout.insertWidget(self.findings_layout.count() - 1, ok)

        except Exception as e:
            err = QLabel(f"Error reading report: {e}")
            err.setStyleSheet("color: #ff6b6b; font-size: 11px;")
            self.findings_layout.insertWidget(self.findings_layout.count() - 1, err)

    def _load_last_scan(self):
        report = "/var/lib/nefi/vuln-scan/lynis-report.dat"
        if os.path.exists(report):
            try:
                with open(report) as f:
                    content = f.read()
                score_line = [l for l in content.splitlines()
                             if "hardening_index" in l]
                if score_line:
                    score = int(score_line[0].split("=")[1])
                    self.ring.set_score(score)
                    self.score_label.setText(
                        f"Last scan: Hardening Index {score}/100"
                    )
                    self._load_findings()
            except Exception:
                pass

    def refresh(self):
        pass
