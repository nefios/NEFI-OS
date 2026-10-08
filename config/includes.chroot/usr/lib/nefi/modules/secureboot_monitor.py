import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QScrollArea, QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class SecureBootWorker(QThread):
    status_ready = pyqtSignal(dict)

    def run(self):
        status = {}

        # Secure Boot
        try:
            r = subprocess.run(
                ["mokutil", "--sb-state"],
                capture_output=True, text=True, timeout=5
            )
            output = r.stdout.strip().lower()
            if "secureboot enabled" in output:
                status["secureboot"] = ("enabled", "#1ed98a")
            elif "secureboot disabled" in output:
                status["secureboot"] = ("disabled", "#ff6b6b")
            else:
                status["secureboot"] = ("not supported", "#8fb0b2")
        except Exception:
            # Prova via efivarfs
            try:
                sb_path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
                if os.path.exists(sb_path):
                    with open(sb_path, "rb") as f:
                        data = f.read()
                    if len(data) >= 5 and data[4] == 1:
                        status["secureboot"] = ("enabled", "#1ed98a")
                    else:
                        status["secureboot"] = ("disabled", "#ff6b6b")
                else:
                    status["secureboot"] = ("not available", "#8fb0b2")
            except Exception:
                status["secureboot"] = ("unknown", "#8fb0b2")

        # TPM
        try:
            tpm_paths = [
                "/sys/class/tpm/tpm0",
                "/dev/tpm0",
                "/dev/tpmrm0",
            ]
            tpm_found = any(os.path.exists(p) for p in tpm_paths)
            if tpm_found:
                # Controlla versione TPM
                try:
                    r = subprocess.run(
                        ["cat", "/sys/class/tpm/tpm0/tpm_version_major"],
                        capture_output=True, text=True, timeout=3
                    )
                    version = r.stdout.strip()
                    status["tpm"] = (f"TPM {version} detected", "#1ed98a")
                except Exception:
                    status["tpm"] = ("detected", "#1ed98a")
            else:
                status["tpm"] = ("not detected", "#ff6b6b")
        except Exception:
            status["tpm"] = ("unknown", "#8fb0b2")

        # Kernel Lockdown
        try:
            r = subprocess.run(
                ["cat", "/sys/kernel/security/lockdown"],
                capture_output=True, text=True, timeout=3
            )
            output = r.stdout.strip()
            if "confidentiality" in output:
                status["lockdown"] = ("confidentiality mode", "#1ed98a")
            elif "integrity" in output:
                status["lockdown"] = ("integrity mode", "#ffaa00")
            elif "none" in output:
                status["lockdown"] = ("disabled", "#ff6b6b")
            else:
                status["lockdown"] = (output or "not available", "#8fb0b2")
        except Exception:
            status["lockdown"] = ("not available", "#8fb0b2")

        # UEFI Boot mode
        try:
            efi_exists = os.path.exists("/sys/firmware/efi")
            status["boot_mode"] = ("UEFI" if efi_exists else "Legacy BIOS",
                                   "#1ed98a" if efi_exists else "#ffaa00")
        except Exception:
            status["boot_mode"] = ("unknown", "#8fb0b2")

        # MOK keys
        try:
            r = subprocess.run(
                ["mokutil", "--list-enrolled"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0 and r.stdout.strip():
                lines = r.stdout.strip().splitlines()
                key_count = sum(1 for l in lines if "SHA1 Fingerprint" in l)
                status["mok"] = (f"{key_count} key(s) enrolled", "#1ed98a")
            else:
                status["mok"] = ("no keys enrolled", "#8fb0b2")
        except Exception:
            status["mok"] = ("not available", "#8fb0b2")

        # Kernel integrity (IMA)
        try:
            ima_path = "/sys/kernel/security/ima/policy"
            if os.path.exists(ima_path):
                status["ima"] = ("IMA active", "#1ed98a")
            else:
                status["ima"] = ("not active", "#8fb0b2")
        except Exception:
            status["ima"] = ("unknown", "#8fb0b2")

        self.status_ready.emit(status)


class StatusCard(QFrame):
    def __init__(self, title, icon, description):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 10px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(14)

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
        self.title_lbl.setStyleSheet(
            "color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;"
        )
        self.desc_lbl = QLabel(description)
        self.desc_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        text_block.addWidget(self.title_lbl)
        text_block.addWidget(self.desc_lbl)
        layout.addLayout(text_block)
        layout.addStretch()

        self.status_lbl = QLabel("--")
        self.status_lbl.setStyleSheet("""
            color: #8fb0b2;
            background-color: #061013;
            border: 1px solid #1a3a3f;
            border-radius: 10px;
            padding: 4px 12px;
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
        """)
        layout.addWidget(self.status_lbl)

    def set_status(self, text, color):
        self.status_lbl.setText(text.upper())
        self.status_lbl.setStyleSheet(f"""
            color: {color};
            background-color: {color}11;
            border: 1px solid {color};
            border-radius: 10px;
            padding: 4px 12px;
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
        """)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0d2226;
                border: 1px solid {color}44;
                border-radius: 10px;
            }}
        """)


class SecureBootMonitorWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel("SECURE BOOT MONITOR")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        header.addWidget(title)
        header.addStretch()

        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 6px;
                padding: 4px 12px;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
        """)
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        info = QLabel(
            "Monitors hardware and firmware security features. "
            "Some features require UEFI firmware and physical hardware to be available."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        checks_title = QLabel("FIRMWARE SECURITY STATUS")
        checks_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(checks_title)

        self.cards = {
            "secureboot": StatusCard(
                "Secure Boot", "🔐",
                "UEFI Secure Boot — verifies bootloader signature"
            ),
            "tpm": StatusCard(
                "TPM", "🔑",
                "Trusted Platform Module — hardware security chip"
            ),
            "boot_mode": StatusCard(
                "Boot Mode", "💾",
                "UEFI vs Legacy BIOS boot mode"
            ),
            "lockdown": StatusCard(
                "Kernel Lockdown", "🛡",
                "Restricts kernel features to protect integrity"
            ),
            "mok": StatusCard(
                "MOK Keys", "🗝",
                "Machine Owner Keys for custom Secure Boot"
            ),
            "ima": StatusCard(
                "IMA", "📋",
                "Integrity Measurement Architecture — file integrity"
            ),
        }

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        content.setStyleSheet("background: transparent;")
        cards_layout = QVBoxLayout(content)
        cards_layout.setSpacing(10)

        for card in self.cards.values():
            cards_layout.addWidget(card)
        cards_layout.addStretch()

        scroll.setWidget(content)
        layout.addWidget(scroll)

        # Raccomandazioni
        rec_title = QLabel("RECOMMENDATIONS")
        rec_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(rec_title)

        self.rec_label = QLabel("Run a check to see recommendations.")
        self.rec_label.setStyleSheet("color: #8fb0b2; font-size: 12px;")
        self.rec_label.setWordWrap(True)
        layout.addWidget(self.rec_label)

    def refresh(self):
        self.worker = SecureBootWorker()
        self.worker.status_ready.connect(self._apply_status)
        self.worker.start()

    def _apply_status(self, status):
        for key, card in self.cards.items():
            if key in status:
                text, color = status[key]
                card.set_status(text, color)

        # Raccomandazioni
        recs = []
        if status.get("secureboot", ("", ""))[1] == "#ff6b6b":
            recs.append("⚠ Enable Secure Boot in BIOS/UEFI settings")
        if status.get("tpm", ("", ""))[1] == "#ff6b6b":
            recs.append("⚠ TPM not detected — consider hardware with TPM 2.0")
        if status.get("lockdown", ("", ""))[0] in ("disabled", "not available"):
            recs.append("⚠ Enable kernel lockdown for additional protection")
        if status.get("boot_mode", ("", ""))[0] == "Legacy BIOS":
            recs.append("⚠ Switch to UEFI boot mode to enable Secure Boot")
        if not recs:
            recs.append("✓ All available security features are properly configured")

        self.rec_label.setText("\n".join(recs))
        color = "#1ed98a" if not any("⚠" in r for r in recs) else "#ffaa00"
        self.rec_label.setStyleSheet(f"color: {color}; font-size: 12px;")
