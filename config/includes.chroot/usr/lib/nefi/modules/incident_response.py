import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer


class IRWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, script):
        super().__init__()
        self.script = script

    def run(self):
        try:
            process = subprocess.Popen(
                ["pkexec", "bash", self.script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                self.output_line.emit(line.rstrip())
            process.wait()
            self.finished_ok.emit(process.returncode == 0)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class IncidentResponseWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self.ir_active = False
        self._build_ui()
        self._check_ir_state()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("INCIDENT RESPONSE MODE")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        # Banner stato IR
        self.ir_banner = QFrame()
        self.ir_banner.setFixedHeight(80)
        self.ir_banner_layout = QHBoxLayout(self.ir_banner)
        self.ir_banner_layout.setContentsMargins(24, 0, 24, 0)

        self.ir_status_icon = QLabel("⬡")
        self.ir_status_icon.setStyleSheet("font-size: 28px;")
        self.ir_banner_layout.addWidget(self.ir_status_icon)

        ir_text = QVBoxLayout()
        self.ir_status_label = QLabel("SYSTEM NORMAL")
        self.ir_status_label.setStyleSheet(
            "color: #1ed98a; font-size: 18px; font-weight: bold;"
        )
        self.ir_status_sub = QLabel(
            "No active incident response session"
        )
        self.ir_status_sub.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        ir_text.addWidget(self.ir_status_label)
        ir_text.addWidget(self.ir_status_sub)
        self.ir_banner_layout.addLayout(ir_text)
        self.ir_banner_layout.addStretch()
        layout.addWidget(self.ir_banner)
        self._set_banner_normal()

        # Info
        info = QLabel(
            "Incident Response Mode isolates the host from the network, protects logs "
            "from tampering, captures a process/network snapshot, and automatically "
            "collects forensic evidence."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Checklist azioni
        actions_title = QLabel("ACTIONS ON ACTIVATION")
        actions_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(actions_title)

        actions_grid = QHBoxLayout()
        actions_grid.setSpacing(12)

        for icon, label, desc in [
            ("🔒", "Network Isolation", "Block all external connections"),
            ("📋", "Log Protection", "Make logs immutable (chattr +i)"),
            ("📸", "Process Snapshot", "Capture running processes and ports"),
            ("🗂", "Evidence Collection", "Automatic forensic acquisition"),
        ]:
            card = QWidget()
            card.setStyleSheet("""
                QWidget {
                    background-color: #0d2226;
                    border: 1px solid #1a3a3f;
                    border-radius: 8px;
                }
            """)
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 12, 14, 12)
            cl.setSpacing(4)
            icon_lbl = QLabel(icon)
            icon_lbl.setStyleSheet("font-size: 22px; border: none;")
            name_lbl = QLabel(label)
            name_lbl.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold; border: none;")
            desc_lbl = QLabel(desc)
            desc_lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; border: none;")
            desc_lbl.setWordWrap(True)
            cl.addWidget(icon_lbl)
            cl.addWidget(name_lbl)
            cl.addWidget(desc_lbl)
            actions_grid.addWidget(card)
        layout.addLayout(actions_grid)

        # Pulsanti
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.activate_btn = QPushButton("🚨  Activate IR Mode")
        self.activate_btn.setFixedHeight(48)
        self.activate_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff4444;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                padding: 0 32px;
            }
            QPushButton:hover { background-color: #cc2222; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
        """)
        self.activate_btn.clicked.connect(self._activate_ir)
        btn_row.addWidget(self.activate_btn)

        self.deactivate_btn = QPushButton("✓  Exit IR Mode")
        self.deactivate_btn.setFixedHeight(48)
        self.deactivate_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #1ed98a;
                border: 2px solid #1ed98a;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                padding: 0 32px;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; border-color: #1a3a3f; }
        """)
        self.deactivate_btn.clicked.connect(self._deactivate_ir)
        self.deactivate_btn.setEnabled(False)
        btn_row.addWidget(self.deactivate_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Output
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
            "Press 'Activate IR Mode' to start incident response.\n"
            "WARNING: This will block all network connections."
        )
        layout.addWidget(self.output_log)

    def _set_banner_normal(self):
        self.ir_banner.setStyleSheet("""
            QFrame {
                background-color: #0b2a26;
                border: 1px solid #1ed98a44;
                border-radius: 10px;
            }
        """)
        self.ir_status_icon.setStyleSheet("font-size: 28px; color: #1ed98a;")
        self.ir_status_label.setText("SYSTEM NORMAL")
        self.ir_status_label.setStyleSheet("color: #1ed98a; font-size: 18px; font-weight: bold;")
        self.ir_status_sub.setText("No active incident response session")

    def _set_banner_active(self):
        self.ir_banner.setStyleSheet("""
            QFrame {
                background-color: #200505;
                border: 2px solid #ff4444;
                border-radius: 10px;
            }
        """)
        self.ir_status_icon.setStyleSheet("font-size: 28px; color: #ff4444;")
        self.ir_status_label.setText("⚠  IR MODE ACTIVE — NETWORK ISOLATED")
        self.ir_status_label.setStyleSheet("color: #ff4444; font-size: 18px; font-weight: bold;")
        self.ir_status_sub.setText("Host is isolated. Evidence collection in progress.")

    def _check_ir_state(self):
        state_file = "/var/lib/nefi/ir/ir-state.conf"
        if os.path.exists(state_file):
            try:
                with open(state_file) as f:
                    content = f.read()
                if "IR_ACTIVE=true" in content:
                    self.ir_active = True
                    self._set_banner_active()
                    self.activate_btn.setEnabled(False)
                    self.deactivate_btn.setEnabled(True)
            except Exception:
                pass

    def _activate_ir(self):
        if self.worker and self.worker.isRunning():
            return
        self.output_log.clear()
        self.output_log.append("Activating Incident Response Mode...")
        self.output_log.append("WARNING: Network will be blocked.\n")
        self.activate_btn.setEnabled(False)
        self.deactivate_btn.setEnabled(False)

        self.worker = IRWorker("/opt/nefi/ir/activate.sh")
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(self._on_activated)
        self.worker.start()

    def _on_activated(self, success):
        if success:
            self.ir_active = True
            self._set_banner_active()
            self.deactivate_btn.setEnabled(True)
            self.output_log.append("\n✓ IR Mode activated successfully.")
        else:
            self.activate_btn.setEnabled(True)
            self.output_log.append("\n✗ Failed to activate IR Mode.")

    def _deactivate_ir(self):
        if self.worker and self.worker.isRunning():
            return
        self.output_log.clear()
        self.output_log.append("Deactivating Incident Response Mode...")
        self.activate_btn.setEnabled(False)
        self.deactivate_btn.setEnabled(False)

        self.worker = IRWorker("/opt/nefi/ir/deactivate.sh")
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(self._on_deactivated)
        self.worker.start()

    def _on_deactivated(self, success):
        self.ir_active = False
        self._set_banner_normal()
        self.activate_btn.setEnabled(True)
        self.deactivate_btn.setEnabled(False)
        if success:
            self.output_log.append("\n✓ IR Mode deactivated. System restored.")
        else:
            self.output_log.append("\n✗ Error during deactivation.")

    def refresh(self):
        pass
