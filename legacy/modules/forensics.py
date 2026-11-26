import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit,
    QFrame, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import time


class ForensicsWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool, str)

    def run(self):
        try:
            process = subprocess.Popen(
                ["pkexec", "bash", "/opt/nefi/forensics/collect.sh"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            output_dir = ""
            archive = ""
            for line in process.stdout:
                line = line.rstrip()
                self.output_line.emit(line)
                if "Output directory:" in line:
                    output_dir = line.split("Output directory:")[-1].strip()
                if "Archive:" in line and "SHA256" not in line:
                    archive = line.split("Archive:")[-1].strip()
            process.wait()
            result = f"{output_dir}|{archive}"
            self.finished_ok.emit(process.returncode == 0, result)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False, "")


class EvidenceCard(QFrame):
    def __init__(self, timestamp, path, archive, sha256):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon = QLabel("🗂")
        icon.setStyleSheet("font-size: 20px; border: none;")
        layout.addWidget(icon)

        text = QVBoxLayout()
        ts_lbl = QLabel(f"Evidence — {timestamp}")
        ts_lbl.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold; border: none;")
        path_lbl = QLabel(path)
        path_lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; border: none;")
        sha_lbl = QLabel(f"SHA256: {sha256[:32]}..." if sha256 else "")
        sha_lbl.setStyleSheet("color: #4a676a; font-size: 10px; border: none;")
        text.addWidget(ts_lbl)
        text.addWidget(path_lbl)
        if sha256:
            text.addWidget(sha_lbl)
        layout.addLayout(text)
        layout.addStretch()


class ForensicsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()
        self._load_evidence_list()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("FORENSICS ONE-CLICK")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        info = QLabel(
            "One click to collect all forensic evidence: RAM dump, process snapshot, "
            "network state, logs, file hashes, persistence check, and timeline. "
            "All evidence is archived and hashed for chain of custody."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Pulsante principale
        collect_frame = QFrame()
        collect_frame.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1ed98a44;
                border-radius: 12px;
            }
        """)
        collect_layout = QVBoxLayout(collect_frame)
        collect_layout.setContentsMargins(24, 20, 24, 20)
        collect_layout.setSpacing(12)

        collect_title = QLabel("Evidence Collection")
        collect_title.setStyleSheet("color: #1ed98a; font-size: 15px; font-weight: bold;")
        collect_layout.addWidget(collect_title)

        steps_lbl = QLabel(
            "Collects:  System info  •  Process snapshot  •  Network state  •  "
            "Logs  •  File hashes  •  RAM dump  •  Timeline  •  Signed manifest"
        )
        steps_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        steps_lbl.setWordWrap(True)
        collect_layout.addWidget(steps_lbl)

        btn_row = QHBoxLayout()
        self.collect_btn = QPushButton("⬡  Collect Evidence")
        self.collect_btn.setFixedHeight(48)
        self.collect_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                padding: 0 32px;
            }
            QPushButton:hover { background-color: #14b874; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
        """)
        self.collect_btn.clicked.connect(self._start_collection)
        btn_row.addWidget(self.collect_btn)

        self.status_lbl = QLabel("Ready")
        self.status_lbl.setStyleSheet("color: #8fb0b2; font-size: 12px; margin-left: 16px;")
        btn_row.addWidget(self.status_lbl)
        btn_row.addStretch()
        collect_layout.addLayout(btn_row)

        layout.addWidget(collect_frame)

        # Output log
        log_title = QLabel("OUTPUT")
        log_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
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
            "Press 'Collect Evidence' to start forensic acquisition.\n"
            "Administrator password will be required.\n"
            "Evidence will be saved to /var/lib/nefi/forensics/"
        )
        self.output_log.setFixedHeight(200)
        layout.addWidget(self.output_log)

        # Lista evidenze precedenti
        evidence_title = QLabel("COLLECTED EVIDENCE")
        evidence_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(evidence_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.evidence_content = QWidget()
        self.evidence_content.setStyleSheet("background: transparent;")
        self.evidence_layout = QVBoxLayout(self.evidence_content)
        self.evidence_layout.setSpacing(8)
        self.evidence_layout.addStretch()
        scroll.setWidget(self.evidence_content)
        layout.addWidget(scroll)

    def _start_collection(self):
        if self.worker and self.worker.isRunning():
            return
        self.output_log.clear()
        self.output_log.append("Starting evidence collection...")
        self.output_log.append("Administrator password required.\n")
        self.collect_btn.setEnabled(False)
        self.status_lbl.setText("⟳ Collection in progress...")
        self.status_lbl.setStyleSheet("color: #ffaa00; font-size: 12px; margin-left: 16px;")

        self.worker = ForensicsWorker()
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(self._on_finished)
        self.worker.start()

    def _on_finished(self, success, result):
        self.collect_btn.setEnabled(True)
        if success:
            self.status_lbl.setText("✓ Collection completed")
            self.status_lbl.setStyleSheet("color: #1ed98a; font-size: 12px; margin-left: 16px;")
            self.output_log.append("\n✓ Evidence collection completed successfully.")
            self._load_evidence_list()
        else:
            self.status_lbl.setText("✗ Collection failed")
            self.status_lbl.setStyleSheet("color: #ff6b6b; font-size: 12px; margin-left: 16px;")
            self.output_log.append("\n✗ Evidence collection failed.")

    def _load_evidence_list(self):
        while self.evidence_layout.count() > 1:
            item = self.evidence_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        base_dir = "/var/lib/nefi/forensics"
        if not os.path.exists(base_dir):
            empty = QLabel("No evidence collected yet.")
            empty.setStyleSheet("color: #8fb0b2; font-size: 12px;")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.evidence_layout.insertWidget(0, empty)
            return

        archives = sorted(
            [f for f in os.listdir(base_dir) if f.endswith(".tar.gz")],
            reverse=True
        )

        if not archives:
            empty = QLabel("No evidence archives found.")
            empty.setStyleSheet("color: #8fb0b2; font-size: 12px;")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.evidence_layout.insertWidget(0, empty)
            return

        for archive in archives[:10]:
            ts = archive.replace("evidence-", "").replace(".tar.gz", "")
            path = os.path.join(base_dir, archive)
            sha256 = ""
            sha_file = path + ".sha256"
            if os.path.exists(sha_file):
                try:
                    with open(sha_file) as f:
                        sha256 = f.read().split()[0]
                except Exception:
                    pass
            card = EvidenceCard(ts, path, archive, sha256)
            self.evidence_layout.insertWidget(
                self.evidence_layout.count() - 1, card
            )

    def refresh(self):
        self._load_evidence_list()
