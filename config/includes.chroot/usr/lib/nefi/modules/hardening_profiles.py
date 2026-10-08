import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class ProfileWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

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
            for line in process.stdout:
                self.output_line.emit(line.rstrip())
            process.wait()
            self.finished_ok.emit(process.returncode == 0)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class ProfileCard(QWidget):
    def __init__(self, name, level, description, features, color, script):
        super().__init__()
        self.script = script
        self.setMinimumWidth(260)
        self.setStyleSheet(f"""
            QWidget {{
                background-color: #0d2226;
                border: 1px solid {color}44;
                border-radius: 12px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        level_lbl = QLabel(level.upper())
        level_lbl.setStyleSheet(f"color: {color}; font-size: 10px; letter-spacing: 2px; border: none;")
        layout.addWidget(level_lbl)

        name_lbl = QLabel(name)
        name_lbl.setStyleSheet("color: #e0e0e0; font-size: 20px; font-weight: bold; border: none;")
        layout.addWidget(name_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setStyleSheet("color: #8fb0b2; font-size: 12px; border: none;")
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {color}33; border: none;")
        layout.addWidget(sep)

        for feat in features:
            f_lbl = QLabel(f"✓ {feat}")
            f_lbl.setStyleSheet("color: #d5e4e5; font-size: 11px; border: none;")
            f_lbl.setWordWrap(True)
            layout.addWidget(f_lbl)

        layout.addStretch()

        self.apply_btn = QPushButton(f"Apply {name}")
        self.apply_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: #061013;
                border: none;
                border-radius: 8px;
                padding: 10px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: {color}cc; }}
        """)
        layout.addWidget(self.apply_btn)


class HardeningProfilesWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("HARDENING PROFILES")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        info = QLabel(
            "Select a predefined security profile. Each profile automatically applies "
            "the corresponding configurations to your system."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(16)

        self.home_card = ProfileCard(
            "Home", "Basic",
            "Essential protection for everyday use, without sacrificing convenience.",
            ["Basic firewall active", "Standard AppArmor", "Automatic updates"],
            "#1ed98a",
            "/opt/nefi/hardening/profile-home.sh"
        )
        self.pro_card = ProfileCard(
            "Professional", "Advanced",
            "Enhanced security for handling sensitive data or working in critical environments.",
            ["Advanced AppArmor enforcing", "USB device restrictions",
             "Secure DNS (DoT)", "Extended kernel auditing"],
            "#ffaa00",
            "/opt/nefi/hardening/profile-professional.sh"
        )
        self.paranoid_card = ProfileCard(
            "Paranoid", "Maximum",
            "Maximum possible security. Some features may be less convenient.",
            ["Secure Boot recommended", "USB blocked (except HID)",
             "Root login disabled", "Strict MAC", "Non-essential services disabled"],
            "#ff6b6b",
            "/opt/nefi/hardening/profile-paranoid.sh"
        )

        for card in [self.home_card, self.pro_card, self.paranoid_card]:
            cards_row.addWidget(card)
        cards_row.addStretch()
        layout.addLayout(cards_row)

        log_title = QLabel("APPLICATION OUTPUT")
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
                font-size: 12px;
                padding: 10px;
            }
        """)
        self.output_log.setPlaceholderText("Select a profile to see application logs here...")
        layout.addWidget(self.output_log)

        self.home_card.apply_btn.clicked.connect(lambda: self._apply(self.home_card.script))
        self.pro_card.apply_btn.clicked.connect(lambda: self._apply(self.pro_card.script))
        self.paranoid_card.apply_btn.clicked.connect(lambda: self._apply(self.paranoid_card.script))

    def _apply(self, script):
        if self.worker and self.worker.isRunning():
            return

        self.output_log.clear()
        self.output_log.append(f"Starting profile application: {script}")
        self.output_log.append("Administrator password may be required...\n")

        for card in [self.home_card, self.pro_card, self.paranoid_card]:
            card.apply_btn.setEnabled(False)

        self.worker = ProfileWorker(script)
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(self._on_finished)
        self.worker.start()

    def _on_finished(self, success):
        for card in [self.home_card, self.pro_card, self.paranoid_card]:
            card.apply_btn.setEnabled(True)
        if success:
            self.output_log.append("\n✓ Profile applied successfully.")
        else:
            self.output_log.append("\n✗ Error applying profile.")

    def refresh(self):
        pass
