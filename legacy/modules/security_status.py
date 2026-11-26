import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QScrollArea, QGridLayout
)
from PyQt6.QtCore import Qt

class ServiceCard(QWidget):
    def __init__(self, name, description, icon, parent=None):
        super().__init__(parent)
        self.setFixedHeight(72)
        self.setStyleSheet("""
            QWidget {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 10px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)
        layout.setSpacing(14)

        self.icon_lbl = QLabel(icon)
        self.icon_lbl.setFixedSize(36, 36)
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_lbl.setStyleSheet("""
            background-color: #1a3a3f;
            border-radius: 8px;
            font-size: 16px;
            border: none;
        """)
        layout.addWidget(self.icon_lbl)

        text = QVBoxLayout()
        text.setSpacing(2)
        self.name_lbl = QLabel(name)
        self.name_lbl.setStyleSheet("color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;")
        self.desc_lbl = QLabel(description)
        self.desc_lbl.setStyleSheet("color: #6b8a8d; font-size: 11px; border: none;")
        text.addWidget(self.name_lbl)
        text.addWidget(self.desc_lbl)
        layout.addLayout(text)
        layout.addStretch()

        self.badge = QLabel("CHECKING...")
        self.badge.setFixedWidth(96)
        self.badge.setFixedHeight(28)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setStyleSheet("""
            color: #8fb0b2;
            background-color: #061013;
            border: 1px solid #1a3a3f;
            border-radius: 14px;
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
        """)
        layout.addWidget(self.badge)

    def set_status(self, active):
        if active:
            self.setStyleSheet("""
                QWidget {
                    background-color: #0b2a26;
                    border: 1px solid #1ed98a55;
                    border-radius: 10px;
                }
            """)
            self.icon_lbl.setStyleSheet("""
                background-color: #1ed98a22;
                border-radius: 8px;
                font-size: 16px;
                border: none;
            """)
            self.badge.setText("● ACTIVE")
            self.badge.setStyleSheet("""
                color: #1ed98a;
                background-color: #1ed98a11;
                border: 1px solid #1ed98a;
                border-radius: 14px;
                font-size: 10px;
                font-weight: bold;
                letter-spacing: 1px;
            """)
        else:
            self.setStyleSheet("""
                QWidget {
                    background-color: #150707;
                    border: 1px solid #ff6b6b33;
                    border-radius: 10px;
                }
            """)
            self.icon_lbl.setStyleSheet("""
                background-color: #ff6b6b11;
                border-radius: 8px;
                font-size: 16px;
                border: none;
            """)
            self.badge.setText("● INACTIVE")
            self.badge.setStyleSheet("""
                color: #ff6b6b;
                background-color: #ff6b6b11;
                border: 1px solid #ff6b6b;
                border-radius: 14px;
                font-size: 10px;
                font-weight: bold;
                letter-spacing: 1px;
            """)


class SecurityStatusWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel("SECURITY SERVICES")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        header.addWidget(title)
        header.addStretch()
        self.summary_lbl = QLabel("")
        self.summary_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        header.addWidget(self.summary_lbl)
        layout.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        content.setStyleSheet("background-color: transparent;")
        grid = QGridLayout(content)
        grid.setSpacing(10)
        grid.setContentsMargins(0, 0, 8, 0)

        self.services = [
            ("AppArmor",   "apparmor",      "Mandatory Access Control",          "🛡"),
            ("auditd",     "auditd",        "System event auditing",              "📋"),
            ("nftables",   "nftables",      "Firewall — packet filtering",        "🔥"),
            ("Suricata",   "suricata",      "IDS/IPS — intrusion detection",      "🔍"),
            ("ClamAV",     "clamav-daemon", "Antivirus — malware scanning",       "🧬"),
            ("osquery",    "osqueryd",      "Endpoint visibility — SQL queries",  "🔎"),
            ("Zeek",       "zeek",          "Network analysis — traffic inspection", "🌐"),
            ("UFW",        "ufw",           "Simplified firewall",                "🚧"),
        ]

        self.cards = {}
        for i, (name, svc, desc, icon) in enumerate(self.services):
            card = ServiceCard(name, desc, icon)
            grid.addWidget(card, i // 2, i % 2)
            self.cards[svc] = card

        scroll.setWidget(content)
        layout.addWidget(scroll)

    def _check_service(self, service):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True
            )
            return result.stdout.strip() == "active"
        except Exception:
            return False

    def refresh(self):
        active_count = 0
        for name, svc, desc, icon in self.services:
            active = self._check_service(svc)
            self.cards[svc].set_status(active)
            if active:
                active_count += 1
        total = len(self.services)
        self.summary_lbl.setText(f"{active_count}/{total} active")
        color = "#1ed98a" if active_count >= total // 2 else "#ff6b6b"
        self.summary_lbl.setStyleSheet(f"color: {color}; font-size: 11px;")
