import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QScrollArea, QButtonGroup, QRadioButton
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class PrivacyWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, action):
        super().__init__()
        self.action = action

    def run(self):
        try:
            result = subprocess.run(
                ["pkexec", "bash", "/opt/nefi/privacy/control.sh", self.action],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                self.output_line.emit(line)
            self.finished_ok.emit(result.returncode == 0)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class StatusWorker(QThread):
    status_ready = pyqtSignal(dict)

    def run(self):
        try:
            result = subprocess.run(
                ["bash", "/opt/nefi/privacy/control.sh", "status"],
                capture_output=True, text=True, timeout=5
            )
            status = {}
            for line in result.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    status[k] = v
            self.status_ready.emit(status)
        except Exception:
            self.status_ready.emit({})


class PrivacyToggleCard(QFrame):
    def __init__(self, title, description, icon, enable_action, disable_action, on_toggle):
        super().__init__()
        self.enable_action = enable_action
        self.disable_action = disable_action
        self.on_toggle = on_toggle
        self.enabled = True

        self.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 10px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(16)

        self.icon_lbl = QLabel(icon)
        self.icon_lbl.setFixedSize(40, 40)
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_lbl.setStyleSheet("""
            background-color: #1a3a3f;
            border-radius: 10px;
            font-size: 20px;
            border: none;
        """)
        layout.addWidget(self.icon_lbl)

        text_block = QVBoxLayout()
        text_block.setSpacing(2)
        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;")
        self.desc_lbl = QLabel(description)
        self.desc_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        text_block.addWidget(self.title_lbl)
        text_block.addWidget(self.desc_lbl)
        layout.addLayout(text_block)
        layout.addStretch()

        self.status_lbl = QLabel("ENABLED")
        self.status_lbl.setStyleSheet("""
            color: #1ed98a;
            font-size: 10px;
            font-weight: bold;
            border: none;
        """)
        layout.addWidget(self.status_lbl)

        self.toggle_btn = QPushButton("Disable")
        self.toggle_btn.setFixedWidth(90)
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff6b6b22;
                color: #ff6b6b;
                border: 1px solid #ff6b6b;
                border-radius: 6px;
                padding: 6px;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #ff6b6b44; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; border-color: #1a3a3f; }
        """)
        self.toggle_btn.clicked.connect(self._on_click)
        layout.addWidget(self.toggle_btn)

    def _on_click(self):
        action = self.disable_action if self.enabled else self.enable_action
        self.toggle_btn.setEnabled(False)
        self.on_toggle(action, self)

    def set_state(self, enabled):
        self.enabled = enabled
        self.toggle_btn.setEnabled(True)
        if enabled:
            self.status_lbl.setText("ENABLED")
            self.status_lbl.setStyleSheet("color: #1ed98a; font-size: 10px; font-weight: bold; border: none;")
            self.toggle_btn.setText("Disable")
            self.toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: #ff6b6b22;
                    color: #ff6b6b;
                    border: 1px solid #ff6b6b;
                    border-radius: 6px;
                    padding: 6px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #ff6b6b44; }
            """)
            self.setStyleSheet("""
                QFrame {
                    background-color: #0d2226;
                    border: 1px solid #1a3a3f;
                    border-radius: 10px;
                }
            """)
        else:
            self.status_lbl.setText("DISABLED")
            self.status_lbl.setStyleSheet("color: #ff6b6b; font-size: 10px; font-weight: bold; border: none;")
            self.toggle_btn.setText("Enable")
            self.toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: #1ed98a22;
                    color: #1ed98a;
                    border: 1px solid #1ed98a;
                    border-radius: 6px;
                    padding: 6px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #1ed98a44; }
            """)
            self.setStyleSheet("""
                QFrame {
                    background-color: #0d2226;
                    border: 1px solid #ff6b6b44;
                    border-radius: 10px;
                }
            """)


class PrivacyControlWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()
        self._load_status()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel("PRIVACY CONTROL")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        header.addWidget(title)
        header.addStretch()
        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #8fb0b2;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 4px 12px;
                font-size: 11px;
            }
            QPushButton:hover { border-color: #1ed98a; color: #1ed98a; }
        """)
        refresh_btn.clicked.connect(self._load_status)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        # Toggle cards
        devices_title = QLabel("DEVICE PRIVACY")
        devices_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(devices_title)

        self.bt_card = PrivacyToggleCard(
            "Bluetooth", "Wireless device communication",
            "📡", "enable_bluetooth", "disable_bluetooth", self._run_action
        )
        self.webcam_card = PrivacyToggleCard(
            "Webcam", "Camera device (uvcvideo module)",
            "📷", "enable_webcam", "disable_webcam", self._run_action
        )
        self.mic_card = PrivacyToggleCard(
            "Microphone", "Audio input device",
            "🎤", "enable_microphone", "disable_microphone", self._run_action
        )

        layout.addWidget(self.bt_card)
        layout.addWidget(self.webcam_card)
        layout.addWidget(self.mic_card)

        # DNS section
        dns_title = QLabel("DNS PRIVACY")
        dns_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px; margin-top: 8px;")
        layout.addWidget(dns_title)

        dns_frame = QFrame()
        dns_frame.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 10px;
            }
        """)
        dns_layout = QVBoxLayout(dns_frame)
        dns_layout.setContentsMargins(20, 16, 20, 16)
        dns_layout.setSpacing(12)

        dns_header = QHBoxLayout()
        dns_icon = QLabel("🌐")
        dns_icon.setStyleSheet("font-size: 20px; border: none;")
        dns_header.addWidget(dns_icon)

        dns_text = QVBoxLayout()
        dns_name = QLabel("DNS over TLS")
        dns_name.setStyleSheet("color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;")
        self.dns_status = QLabel("Current: default")
        self.dns_status.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        dns_text.addWidget(dns_name)
        dns_text.addWidget(self.dns_status)
        dns_header.addLayout(dns_text)
        dns_header.addStretch()
        dns_layout.addLayout(dns_header)

        dns_btns = QHBoxLayout()
        dns_btns.setSpacing(8)
        for label, action, color in [
            ("Cloudflare (1.1.1.1)", "set_dns_cloudflare", "#1ed98a"),
            ("Quad9 (9.9.9.9)",      "set_dns_quad9",      "#ffaa00"),
            ("Default",              "set_dns_default",    "#8fb0b2"),
        ]:
            btn = QPushButton(label)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color}22;
                    color: {color};
                    border: 1px solid {color};
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-size: 11px;
                }}
                QPushButton:hover {{ background-color: {color}44; }}
            """)
            btn.clicked.connect(lambda checked, a=action: self._run_action(a, None))
            dns_btns.addWidget(btn)
        dns_layout.addLayout(dns_btns)
        layout.addWidget(dns_frame)
        layout.addStretch()

    def _run_action(self, action, card):
        self.worker = PrivacyWorker(action)
        self.worker.finished_ok.connect(lambda ok: self._load_status())
        self.worker.start()

    def _load_status(self):
        status_worker = StatusWorker()
        status_worker.status_ready.connect(self._apply_status)
        status_worker.start()
        self._sw = status_worker

    def _apply_status(self, status):
        self.bt_card.set_state(status.get("BLUETOOTH", "enabled") == "enabled")
        self.webcam_card.set_state(status.get("WEBCAM", "enabled") == "enabled")
        self.mic_card.set_state(status.get("MICROPHONE", "enabled") == "enabled")

        dns = status.get("DNS", "default")
        if "1.1.1.1" in dns:
            self.dns_status.setText("Current: Cloudflare DoT (1.1.1.1)")
            self.dns_status.setStyleSheet("color: #1ed98a; font-size: 11px; border: none;")
        elif "9.9.9.9" in dns:
            self.dns_status.setText("Current: Quad9 DoT (9.9.9.9)")
            self.dns_status.setStyleSheet("color: #ffaa00; font-size: 11px; border: none;")
        else:
            self.dns_status.setText("Current: System default")
            self.dns_status.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")

    def refresh(self):
        self._load_status()
