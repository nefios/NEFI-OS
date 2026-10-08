import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QLineEdit, QTextEdit, QComboBox,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class SandboxWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            process = subprocess.Popen(
                self.cmd,
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


class SandboxProfileCard(QFrame):
    def __init__(self, name, description, icon, profile, on_launch):
        super().__init__()
        self.profile = profile
        self.on_launch = on_launch

        self.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 10px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        icon_lbl = QLabel(icon)
        icon_lbl.setFixedSize(40, 40)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet("""
            background-color: #1a3a3f;
            border-radius: 10px;
            font-size: 20px;
            border: none;
        """)
        layout.addWidget(icon_lbl)

        text_block = QVBoxLayout()
        text_block.setSpacing(2)
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet(
            "color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;"
        )
        desc_lbl = QLabel(description)
        desc_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        text_block.addWidget(name_lbl)
        text_block.addWidget(desc_lbl)
        layout.addLayout(text_block)
        layout.addStretch()

        launch_btn = QPushButton("Launch")
        launch_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a22;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 6px;
                padding: 6px 16px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
        """)
        launch_btn.clicked.connect(lambda: self.on_launch(profile, name))
        layout.addWidget(launch_btn)


class SandboxWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("SANDBOX")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        info = QLabel(
            "Run applications in an isolated sandbox using Firejail. "
            "Sandboxed apps cannot access your files, network, or system resources "
            "beyond what their profile allows."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Quick launch
        quick_title = QLabel("QUICK LAUNCH")
        quick_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(quick_title)

        profiles = [
            ("Firefox", "Isolated web browser", "🌐",
             ["firejail", "--profile=/etc/firejail/firefox.profile", "firefox-esr"]),
            ("File Manager", "Isolated file manager", "📁",
             ["firejail", "dolphin"]),
            ("Text Editor", "Isolated text editor", "📝",
             ["firejail", "kate"]),
            ("Terminal", "Isolated terminal", "⌨",
             ["firejail", "konsole"]),
        ]

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        content.setStyleSheet("background: transparent;")
        cards_layout = QVBoxLayout(content)
        cards_layout.setSpacing(8)

        for name, desc, icon, profile in profiles:
            card = SandboxProfileCard(name, desc, icon, profile, self._launch)
            cards_layout.addWidget(card)

        cards_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        # Custom command
        custom_title = QLabel("CUSTOM COMMAND")
        custom_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(custom_title)

        custom_frame = QFrame()
        custom_frame.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        custom_layout = QVBoxLayout(custom_frame)
        custom_layout.setContentsMargins(16, 12, 16, 12)
        custom_layout.setSpacing(8)

        cmd_row = QHBoxLayout()
        self.custom_input = QLineEdit()
        self.custom_input.setPlaceholderText("Command to run in sandbox (e.g. gedit, vlc, python3 script.py)")
        self.custom_input.setStyleSheet("""
            QLineEdit {
                background-color: #061013;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
            }
            QLineEdit:focus { border-color: #1ed98a; }
        """)
        self.custom_input.returnPressed.connect(self._launch_custom)
        cmd_row.addWidget(self.custom_input)

        self.security_level = QComboBox()
        self.security_level.addItems(["Standard", "Strict (no net)", "Paranoid"])
        self.security_level.setStyleSheet("""
            QComboBox {
                background-color: #061013;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
                min-width: 140px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
            }
        """)
        cmd_row.addWidget(self.security_level)

        launch_btn = QPushButton("Launch in Sandbox")
        launch_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
        """)
        launch_btn.clicked.connect(self._launch_custom)
        cmd_row.addWidget(launch_btn)
        custom_layout.addLayout(cmd_row)
        layout.addWidget(custom_frame)

        # Output
        log_title = QLabel("OUTPUT")
        log_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(log_title)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setFixedHeight(120)
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
        self.output_log.setPlaceholderText("Sandbox output will appear here...")
        layout.addWidget(self.output_log)

    def _launch(self, cmd, name):
        self.output_log.clear()
        self.output_log.append(f"Launching {name} in sandbox...")
        self.output_log.append(f"Command: {' '.join(cmd)}\n")
        self.worker = SandboxWorker(cmd)
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(
            lambda ok: self.output_log.append(
                f"\n✓ {name} closed." if ok else f"\n✗ Error launching {name}."
            )
        )
        self.worker.start()

    def _launch_custom(self):
        cmd_text = self.custom_input.text().strip()
        if not cmd_text:
            return

        level = self.security_level.currentText()
        base_cmd = ["firejail"]

        if "Strict" in level:
            base_cmd += ["--net=none", "--no3d"]
        elif "Paranoid" in level:
            base_cmd += [
                "--net=none", "--no3d",
                "--nosound", "--nodvd",
                "--private", "--private-tmp"
            ]

        full_cmd = base_cmd + cmd_text.split()
        self._launch(full_cmd, cmd_text)

    def refresh(self):
        pass
