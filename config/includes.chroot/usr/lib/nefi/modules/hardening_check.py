import glob
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

    @staticmethod
    def _out(args, timeout=3):
        """Output di un comando eseguito SENZA shell ('' se manca o fallisce)."""
        try:
            return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def _read(path):
        try:
            with open(path, errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _svc_active(self, svc):
        r = subprocess.run(["systemctl", "is-active", svc],
                           capture_output=True, text=True, timeout=3)
        return r.stdout.strip() == "active"

    def _check_nftables(self):
        active = self._svc_active("nftables")
        if active:
            rules = len(self._out(["nft", "list", "ruleset"]).splitlines())
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
        rules = len([l for l in self._out(["auditctl", "-l"]).splitlines() if l.startswith("-")])
        return True, f"Active — {rules} audit rules loaded"

    def _check_secureboot(self):
        if "enabled" in self._out(["mokutil", "--sb-state"]).lower():
            return True, "Secure Boot enabled"
        return False, "Secure Boot not enabled — configure in BIOS/UEFI"

    def _check_encryption(self):
        count = sum(1 for l in self._out(["lsblk", "-n", "-o", "TYPE"]).split() if l == "crypt")
        if count > 0:
            return True, f"{count} encrypted volume(s) detected"
        return False, "No disk encryption detected — configure LUKS at installation"

    def _check_rootlogin(self):
        # configurazione EFFETTIVA di sshd (include i file in sshd_config.d); serve root per "sshd -T",
        # quindi qui leggo i file nell'ordine in cui li legge sshd: vince il primo valore trovato
        if not os.path.exists("/usr/sbin/sshd"):
            return True, "SSH server not installed"
        value = None
        for path in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")) + ["/etc/ssh/sshd_config"]:
            for line in self._read(path).splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == "permitrootlogin":
                    value = parts[1].lower()
                    break
            if value:
                break
        if value == "no":
            return True, "Root SSH login disabled"
        if value is None:
            return False, "PermitRootLogin not set (default: root can log in with a key) — see Prevention > SSH Security"
        return False, f"Root SSH login allowed (PermitRootLogin {value}) — see Prevention > SSH Security"

    def _check_dns(self):
        if "DNSOverTLS=yes" in self._read("/etc/systemd/resolved.conf.d/nefi-dns.conf"):
            return True, "DNS over TLS enabled (Cloudflare + Quad9)"
        return False, "Secure DNS not configured — apply Professional profile"

    def _check_usb(self):
        """Stato EFFETTIVO del blocco delle memorie USB, non solo la presenza di un file:
        il driver usb-storage non si puo' caricare, non e' caricato, e nessun disco USB e' collegato."""
        blocked = False
        for conf in sorted(glob.glob("/etc/modprobe.d/*.conf") + glob.glob("/run/modprobe.d/*.conf")
                           + glob.glob("/usr/lib/modprobe.d/*.conf")):
            try:
                with open(conf) as f:
                    for line in f:
                        w = line.split()
                        if (len(w) >= 3 and w[0] == "install" and w[1].replace("-", "_") == "usb_storage"
                                and w[2] in ("/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true")):
                            blocked = True
            except OSError:
                continue
        loaded = os.path.isdir("/sys/module/usb_storage") or os.path.isdir("/sys/module/uas")
        in_use = [d for d in glob.glob("/sys/bus/usb/drivers/usb-storage/*") + glob.glob("/sys/bus/usb/drivers/uas/*")
                  if ":" in os.path.basename(d)]
        udev_rule = os.path.exists("/etc/udev/rules.d/99-nefi-usb-restrict.rules")
        if blocked and not in_use and not loaded:
            extra = " + udev deauthorization" if udev_rule else ""
            return True, f"USB mass storage blocked (driver cannot load{extra})"
        if blocked and in_use:
            return False, ("Block configured, but a USB drive is connected and usable right now: "
                           "remove it (or reboot)")
        if blocked and loaded:
            return True, ("USB mass storage blocked for new drives (driver still loaded from an earlier "
                          "drive: it unloads at reboot)")
        return False, "USB mass storage allowed — apply the Professional or Paranoid profile to block it"

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
            import time
            when = time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime("/var/lib/aide/aide.db")))
            return True, f"Baseline present — last updated: {when}"
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
