import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer


class AIDEWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool, str)

    def __init__(self, script_path):
        super().__init__()
        self.script_path = script_path

    def run(self):
        try:
            process = subprocess.Popen(
                ["pkexec", "bash", self.script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            output = []
            for line in process.stdout:
                line = line.rstrip()
                output.append(line)
                self.output_line.emit(line)
            process.wait()
            self.finished_ok.emit(process.returncode == 0, "\n".join(output))
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False, str(e))


class IntegrityControlWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()
        self._check_baseline_exists()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("INTEGRITY CONTROL")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        info = QLabel(
            "AIDE verifies the integrity of system files by comparing them against a "
            "reference database. If a binary is modified (e.g. by a rootkit), you'll detect it here."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        status_row = QHBoxLayout()
        self.status_card = QWidget()
        self.status_card.setStyleSheet("""
            QWidget {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        status_layout = QHBoxLayout(self.status_card)
        status_layout.setContentsMargins(16, 12, 16, 12)
        self.status_label = QLabel("Checking...")
        self.status_label.setStyleSheet("color: #ffaa00; font-size: 14px; font-weight: bold; border: none;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()

        self.refresh_status_btn = QPushButton("↻ Refresh status")
        self.refresh_status_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #8fb0b2;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 4px 10px;
                font-size: 11px;
            }
            QPushButton:hover { border-color: #1ed98a; color: #1ed98a; }
        """)
        self.refresh_status_btn.clicked.connect(self._check_baseline_exists)
        status_layout.addWidget(self.refresh_status_btn)
        status_row.addWidget(self.status_card)
        layout.addLayout(status_row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.init_btn = QPushButton("Create Baseline Database")
        self.init_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
        """)
        self.init_btn.clicked.connect(self._init_baseline)
        btn_row.addWidget(self.init_btn)

        self.check_btn = QPushButton("Check Integrity Now")
        self.check_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; border-color: #1a3a3f; }
        """)
        self.check_btn.clicked.connect(self._run_check)
        self.check_btn.setEnabled(False)
        btn_row.addWidget(self.check_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        log_title = QLabel("OUTPUT")
        log_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px; margin-top: 8px;")
        layout.addWidget(log_title)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
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
            "Create a baseline database first, then you can check system integrity at any time.\n\n"
            "Note: baseline creation takes 10-15 minutes on first run.\n"
            "After completion, press '↻ Refresh status' to update the status."
        )
        layout.addWidget(self.output_log)

    def _check_baseline_exists(self):
        # Controlla sia aide.db che aide.db.new
        db_exists = (
            os.path.exists("/var/lib/aide/aide.db") or
            os.path.exists("/var/lib/aide/aide.db.new")
        )
        if db_exists:
            path = "/var/lib/aide/aide.db" if os.path.exists("/var/lib/aide/aide.db") \
                   else "/var/lib/aide/aide.db.new"
            size = os.path.getsize(path)
            self.status_label.setText(f"● Baseline present ({size//1024} KB)")
            self.status_label.setStyleSheet(
                "color: #1ed98a; font-size: 14px; font-weight: bold; border: none;"
            )
            self.check_btn.setEnabled(True)
            self.init_btn.setText("Recreate Baseline Database")
        else:
            self.status_label.setText("● No baseline — create the database to get started")
            self.status_label.setStyleSheet(
                "color: #ffaa00; font-size: 14px; font-weight: bold; border: none;"
            )
            self.check_btn.setEnabled(False)
            self.init_btn.setText("Create Baseline Database")

    def _init_baseline(self):
        if self.worker and self.worker.isRunning():
            return
        self.output_log.clear()
        self.output_log.append("Creating baseline database...")
        self.output_log.append("This process takes 10-15 minutes. Please wait...\n")
        self.output_log.append("When done, press '↻ Refresh status' to update the status.\n")
        self.init_btn.setEnabled(False)
        self.check_btn.setEnabled(False)

        self.worker = AIDEWorker("/opt/nefi/integrity/init-baseline.sh")
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(self._on_init_done)
        self.worker.start()

    def _on_init_done(self, success, output):
        self.init_btn.setEnabled(True)
        if success:
            self.output_log.append("\n✓ Baseline database created successfully.")
            self.output_log.append("Press '↻ Refresh status' to update the status indicator.")
            # Prova automaticamente dopo 3 secondi
            QTimer.singleShot(3000, self._check_baseline_exists)
        else:
            self.output_log.append("\n✗ Error creating database.")
        self.check_btn.setEnabled(os.path.exists("/var/lib/aide/aide.db") or
                                   os.path.exists("/var/lib/aide/aide.db.new"))

    def _run_check(self):
        if self.worker and self.worker.isRunning():
            return
        self.output_log.clear()
        self.output_log.append("Checking integrity...\n")
        self.init_btn.setEnabled(False)
        self.check_btn.setEnabled(False)

        self.worker = AIDEWorker("/opt/nefi/integrity/check.sh")
        self.worker.output_line.connect(self._on_check_line)
        self.worker.finished_ok.connect(self._on_check_done)
        self.worker.start()

    def _on_check_line(self, line):
        if "NO_CHANGES" in line:
            self.output_log.append("✓ No changes detected. System integrity intact.")
        elif "NO_BASELINE" in line:
            self.output_log.append("✗ No baseline database found.")
        elif line.startswith("changed:"):
            self.output_log.append(f"⚠ CHANGED: {line[8:].strip()}")
        elif line.startswith("added:"):
            self.output_log.append(f"+ ADDED: {line[6:].strip()}")
        elif line.startswith("removed:"):
            self.output_log.append(f"− REMOVED: {line[8:].strip()}")
        else:
            self.output_log.append(line)

    def _on_check_done(self, success, output):
        self.init_btn.setEnabled(True)
        self.check_btn.setEnabled(True)
        self.output_log.append("\n✓ Check completed.")

    def refresh(self):
        pass
