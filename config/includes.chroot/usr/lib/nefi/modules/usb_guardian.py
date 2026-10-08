import json
import os
import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt

WHITELIST_FILE = "/var/lib/nefi/usb-whitelist.json"

ACTION_LABELS = {
    "allow": ("Allowed", "#1ed98a"),
    "readonly": ("Read-only", "#ffaa00"),
    "block": ("Blocked", "#ff6b6b"),
}


class USBDeviceCard(QFrame):
    def __init__(self, serial, action, on_change):
        super().__init__()
        self.serial = serial
        self.on_change = on_change
        label, color = ACTION_LABELS.get(action, ("Unknown", "#8fb0b2"))

        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0d2226;
                border-left: 3px solid {color};
                border-radius: 6px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)

        text_block = QVBoxLayout()
        serial_lbl = QLabel(f"Serial: {serial}")
        serial_lbl.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold; border: none;")
        status_lbl = QLabel(label)
        status_lbl.setStyleSheet(f"color: {color}; font-size: 11px; border: none;")
        text_block.addWidget(serial_lbl)
        text_block.addWidget(status_lbl)
        layout.addLayout(text_block)
        layout.addStretch()

        for act_key, (act_label, act_color) in ACTION_LABELS.items():
            btn = QPushButton(act_label)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {act_color};
                    border: 1px solid {act_color};
                    border-radius: 6px;
                    padding: 4px 10px;
                    font-size: 10px;
                }}
                QPushButton:hover {{ background-color: {act_color}22; }}
            """)
            btn.clicked.connect(lambda checked, a=act_key: self.on_change(self.serial, a))
            layout.addWidget(btn)

        remove_btn = QPushButton("✕")
        remove_btn.setFixedWidth(28)
        remove_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #8fb0b2;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 4px;
            }
            QPushButton:hover { border-color: #ff6b6b; color: #ff6b6b; }
        """)
        remove_btn.clicked.connect(lambda: self.on_change(self.serial, None))
        layout.addWidget(remove_btn)


class USBGuardianWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("USB GUARDIAN")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        info = QLabel(
            "When you plug in a new USB device, NEFI will ask you how to handle it. "
            "Your choices are saved below and can be changed at any time."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        devices_title = QLabel("KNOWN DEVICES")
        devices_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px; margin-top: 8px;")
        layout.addWidget(devices_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.content = QWidget()
        self.content.setStyleSheet("background: transparent;")
        self.list_layout = QVBoxLayout(self.content)
        self.list_layout.setSpacing(8)
        self.list_layout.addStretch()
        scroll.setWidget(self.content)
        layout.addWidget(scroll)

        self.empty_label = QLabel("No USB devices detected yet.")
        self.empty_label.setStyleSheet("color: #8fb0b2; font-size: 12px;")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def _load_whitelist(self):
        try:
            with open(WHITELIST_FILE) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_whitelist(self, data):
        # La whitelist e' di root: si salva via pkexec con uno script che valida i dati
        import subprocess
        from PyQt6.QtWidgets import QMessageBox
        r = subprocess.run(["pkexec", "/opt/nefi/usb-guardian/whitelist-save.py"],
                           input=json.dumps(data), capture_output=True, text=True)
        if r.returncode != 0:
            QMessageBox.warning(self, "USB Guardian",
                                "Whitelist not saved: administrator authorization is required.")

    def _on_change(self, serial, new_action):
        whitelist = self._load_whitelist()
        if new_action is None:
            whitelist.pop(serial, None)
        else:
            whitelist[serial] = new_action
        self._save_whitelist(whitelist)
        self.refresh()

    def refresh(self):
        while self.list_layout.count() > 1:
            item = self.list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        whitelist = self._load_whitelist()

        if not whitelist:
            self.list_layout.insertWidget(0, self.empty_label)
            return

        for serial, action in whitelist.items():
            card = USBDeviceCard(serial, action, self._on_change)
            self.list_layout.insertWidget(self.list_layout.count() - 1, card)
