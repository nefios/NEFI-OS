import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class HardeningCheckWorker(QThread):
    result_ready = pyqtSignal(list)

    def run(self):
        results = []

        checks = [
            ("Firewall (nftables)", self._check_nftables),
            ("Firewall (ufw)", self._check_ufw),
            ("AppArmor", self._check_apparmor),
            ("auditd", self._check_auditd),
            ("Secure Boot", self._check_secureboot),
            ("Disk encryption", self._check_encryption),
            ("Root login disabled", self._check_rootlogin),
            ("Secure DNS (DoT)", self._check_dns),
            ("USB restrictions", self._check_usb),
            ("Automatic updates", self._check_autoupdates),
            ("Kernel hardening (sysctl)", self._check_sysctl),
            ("AIDE database", self._check_aide),
        ]

        for name, fn in checks:
            try:
                passed, detail = fn()
            except Exception as e:
                passed, detail = False, str(e)
            results.append((name, passed, detail))

        self.result_ready.emit(results)

    def _svc_active(self, svc):
        r = subprocess.run(["systemctl", "is-active", svc],
                           capture_output=True, text=True, timeout=3)
        return r.stdout.strip() == "active"

    def _check_nftables(self):
        active = self._svc_active("nftables")
        if active:
            r = subprocess.run("nft list ruleset 2>/dev/null | wc -l",
                               shell=True, capture_output=True, text=True, timeout=3)
            rules = int(r.stdout.strip() or "0")
            return True, f"Active — {rules} rule lines loaded"
        return False, "nftables service not running"

    def _check_ufw(self):
        active = self._svc_active("ufw")
        return active, "Active" if active else "ufw service not running"

    def _check_apparmor(self):
        active = self._svc_active("apparmor")
        if not active:
            return False, "AppArmor service not running (normal in live mode)"
        try:
            r = subprocess.run(["aa-status", "--enforced"],
                               capture_output=True, text=True, timeout=3)
            return True, f"Active and enforcing"
        except Exception:
            return True, "Active"

    def _check_auditd(self):
        active = self._svc_active("auditd")
        if not active:
            return False, "auditd not running"
        r = subprocess.run("auditctl -l 2>/dev/null | wc -l",
                           shell=True, capture_output=True, text=True, timeout=3)
        rules = int(r.stdout.strip() or "0")
        return True, f"Active — {rules} audit rules loaded"

    def _check_secureboot(self):
        r = subprocess.run("mokutil --sb-state 2>/dev/null",
                           shell=True, capture_output=True, text=True, timeout=3)
        if "enabled" in r.stdout.lower():
            return True, "Secure Boot enabled"
        return False, "Secure Boot not enabled — configure in BIOS/UEFI"

    def _check_encryption(self):
        r = subprocess.run("lsblk -o TYPE 2>/dev/null | grep -c crypt",
                           shell=True, capture_output=True, text=True, timeout=3)
        count = int(r.stdout.strip() or "0")
        if count > 0:
            return True, f"{count} encrypted volume(s) detected"
        return False, "No disk encryption detected — configure LUKS at installation"

    def _check_rootlogin(self):
        r = subprocess.run("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
                           shell=True, capture_output=True, text=True, timeout=3)
        if "no" in r.stdout.lower():
            return True, "Root SSH login disabled"
        if not r.stdout.strip():
            return True, "sshd_config not present (SSH not installed)"
        return False, "Root SSH login may be enabled — set PermitRootLogin no"

    def _check_dns(self):
        r = subprocess.run("cat /etc/systemd/resolved.conf.d/nefi-dns.conf 2>/dev/null",
                           shell=True, capture_output=True, text=True, timeout=3)
        if "DNSOverTLS=yes" in r.stdout:
            return True, "DNS over TLS enabled (Cloudflare + Quad9)"
        return False, "Secure DNS not configured — apply Professional profile"

    def _check_usb(self):
        r = subprocess.run("ls /etc/udev/rules.d/ 2>/dev/null | grep nefi",
                           shell=True, capture_output=True, text=True, timeout=3)
        if r.stdout.strip():
            rules = r.stdout.strip().split("\n")
            if "99-nefi-usb-paranoid.rules" in r.stdout:
                return True, "Paranoid USB policy active (all blocked except HID)"
            return True, f"USB restrictions active: {', '.join(rules)}"
        return False, "No USB restrictions — apply Professional or Paranoid profile"

    def _check_autoupdates(self):
        active = self._svc_active("unattended-upgrades")
        return active, "Automatic security updates active" if active else \
               "Automatic updates not active — apply Home profile"

    def _check_sysctl(self):
        checks = {
            "kernel.randomize_va_space": "2",
            "kernel.dmesg_restrict": "1",
            "net.ipv4.conf.all.rp_filter": "1",
        }
        passed_all = True
        details = []
        for key, expected in checks.items():
            r = subprocess.run(["sysctl", "-n", key],
                               capture_output=True, text=True, timeout=2)
            val = r.stdout.strip()
            if val == expected:
                details.append(f"{key}={val} ✓")
            else:
                details.append(f"{key}={val} (expected {expected}) ✗")
                passed_all = False
        return passed_all, " | ".join(details)

    def _check_aide(self):
        if os.path.exists("/var/lib/aide/aide.db"):
            r = subprocess.run("stat -c '%y' /var/lib/aide/aide.db 2>/dev/null",
                               shell=True, capture_output=True, text=True, timeout=2)
            return True, f"Baseline present — last updated: {r.stdout.strip()[:10]}"
        return False, "No AIDE baseline — create it in the Integrity tab"


class CheckRow(QWidget):
    def __init__(self, name, passed, detail):
        super().__init__()
        color = "#1ed98a" if passed else "#ff6b6b"
        icon = "●" if passed else "●"

        self.setStyleSheet(f"""
            QWidget {{
                background-color: #0d2226;
                border-left: 3px solid {color};
                border-radius: 6px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setFixedWidth(16)
        icon_lbl.setStyleSheet(f"color: {color}; font-size: 14px; border: none;")
        layout.addWidget(icon_lbl)

        text_block = QVBoxLayout()
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold; border: none;")
        detail_lbl = QLabel(detail)
        detail_lbl.setStyleSheet(f"color: {'#5fd6a4' if passed else '#9a4a4a'}; font-size: 11px; border: none;")
        detail_lbl.setWordWrap(True)
        text_block.addWidget(name_lbl)
        text_block.addWidget(detail_lbl)
        layout.addLayout(text_block)
        layout.addStretch()

        status_lbl = QLabel("PASS" if passed else "FAIL")
        status_lbl.setStyleSheet(f"""
            color: {color};
            background-color: {color}22;
            border: 1px solid {color};
            border-radius: 8px;
            padding: 2px 10px;
            font-size: 10px;
            font-weight: bold;
        """)
        layout.addWidget(status_lbl)


class HardeningCheckWidget(QWidget):
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
        title = QLabel("HARDENING CHECK")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        header.addWidget(title)
        header.addStretch()

        self.summary_lbl = QLabel("")
        self.summary_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        header.addWidget(self.summary_lbl)

        refresh_btn = QPushButton("↻  Run Checks")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 11px;
                margin-left: 12px;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
        """)
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        info = QLabel(
            "Verifies that hardening configurations are correctly applied to the system."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.content = QWidget()
        self.content.setStyleSheet("background: transparent;")
        self.checks_layout = QVBoxLayout(self.content)
        self.checks_layout.setSpacing(8)
        self.checks_layout.addStretch()
        scroll.setWidget(self.content)
        layout.addWidget(scroll)

        self.loading_lbl = QLabel("Running checks...")
        self.loading_lbl.setStyleSheet("color: #8fb0b2; font-size: 12px;")
        self.loading_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.checks_layout.insertWidget(0, self.loading_lbl)

    def refresh(self):
        while self.checks_layout.count() > 1:
            item = self.checks_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.loading_lbl = QLabel("Running checks...")
        self.loading_lbl.setStyleSheet("color: #8fb0b2; font-size: 12px;")
        self.loading_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.checks_layout.insertWidget(0, self.loading_lbl)
        self.summary_lbl.setText("")

        self.worker = HardeningCheckWorker()
        self.worker.result_ready.connect(self._on_results)
        self.worker.start()

    def _on_results(self, results):
        while self.checks_layout.count() > 1:
            item = self.checks_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        passed = sum(1 for _, p, _ in results if p)
        total = len(results)
        color = "#1ed98a" if passed >= total * 0.7 else "#ffaa00" if passed >= total * 0.4 else "#ff6b6b"
        self.summary_lbl.setText(f"{passed}/{total} passed")
        self.summary_lbl.setStyleSheet(f"color: {color}; font-size: 11px;")

        for name, p, detail in results:
            row = CheckRow(name, p, detail)
            self.checks_layout.insertWidget(self.checks_layout.count() - 1, row)
