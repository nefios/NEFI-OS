import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QScrollArea, QTextEdit, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

SCRIPT = "/opt/nefi/zerotrust/zerotrust.sh"

KNOWN_SUID = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/fusermount3",
    "/usr/bin/fusermount", "/usr/bin/firejail", "/usr/bin/ntfs-3g",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/xorg/Xorg.wrap", "/usr/sbin/pppd",
    "/usr/lib/eject/dmcrypt-get-device",
}


class ZTWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in p.stdout:
                self.output_line.emit(line.rstrip())
            p.wait()
            self.finished_ok.emit(p.returncode == 0)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class StatusWorker(QThread):
    status_ready = pyqtSignal(dict)

    def run(self):
        status = {}
        try:
            r = subprocess.run(["bash", SCRIPT, "status"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    status[k] = v
        except Exception:
            pass
        self.status_ready.emit(status)


class PillarCard(QFrame):
    def __init__(self, icon, title, desc):
        super().__init__()
        self.setMinimumHeight(110)
        self._set_border("#1a3a3f")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        top = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 20px; border: none;")
        top.addWidget(icon_lbl)
        top.addStretch()
        self.badge = QLabel("OFF")
        self.badge.setStyleSheet("color: #8fb0b2; font-size: 10px; font-weight: bold; border: none;")
        top.addWidget(self.badge)
        layout.addLayout(top)

        t = QLabel(title)
        t.setMinimumHeight(18)
        t.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold; border: none;")
        layout.addWidget(t)
        d = QLabel(desc)
        d.setWordWrap(True)
        d.setStyleSheet("color: #8fb0b2; font-size: 10px; border: none;")
        layout.addWidget(d)

    def _set_border(self, color):
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0d2226;
                border: 1px solid {color};
                border-radius: 10px;
            }}
        """)

    def set_on(self, on):
        if on:
            self.badge.setText("● ON")
            self.badge.setStyleSheet("color: #1ed98a; font-size: 10px; font-weight: bold; border: none;")
            self._set_border("#1ed98a55")
        else:
            self.badge.setText("● OFF")
            self.badge.setStyleSheet("color: #8fb0b2; font-size: 10px; font-weight: bold; border: none;")
            self._set_border("#1a3a3f")


class FindingRow(QFrame):
    COLORS = {"high": "#ff6b6b", "medium": "#ffaa00", "info": "#8fb0b2"}

    def __init__(self, severity, title, detail):
        super().__init__()
        color = self.COLORS.get(severity, "#8fb0b2")
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0d2226;
                border-left: 3px solid {color};
                border-radius: 6px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        sev = QLabel(severity.upper())
        sev.setFixedWidth(60)
        sev.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: bold; border: none;")
        layout.addWidget(sev)
        text = QVBoxLayout()
        text.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold; border: none;")
        d = QLabel(detail)
        d.setWordWrap(True)
        d.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        text.addWidget(t)
        text.addWidget(d)
        layout.addLayout(text)


class ZeroTrustWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self.audit_lines = []
        self.zt_active = False
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("ZERO TRUST MODE")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        # Banner
        self.banner = QFrame()
        self.banner.setMinimumHeight(70)
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(20, 10, 20, 10)
        text = QVBoxLayout()
        self.banner_title = QLabel("ZERO TRUST INACTIVE")
        self.banner_sub = QLabel("Never trust, always verify. Activate to apply least privilege, "
                                 "application control and network micro-segmentation.")
        self.banner_sub.setWordWrap(True)
        text.addWidget(self.banner_title)
        text.addWidget(self.banner_sub)
        bl.addLayout(text)
        bl.addStretch()

        self.activate_btn = QPushButton("⬡  Activate Zero Trust")
        self.activate_btn.setMinimumHeight(40)
        self.activate_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a; color: #061013; border: none;
                border-radius: 8px; padding: 0 20px; font-size: 13px; font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
        """)
        self.activate_btn.clicked.connect(self._toggle)
        bl.addWidget(self.activate_btn)
        layout.addWidget(self.banner)
        self._set_banner(False)

        # Pillars
        pillars = QHBoxLayout()
        pillars.setSpacing(12)
        self.p_net = PillarCard("🧱", "Micro-segmentation",
                                "Default-deny firewall. Outbound only DNS, HTTP/S, NTP, DHCP.")
        self.p_exec = PillarCard("🚫", "Application Control",
                                 "No execution from /tmp and /dev/shm.")
        self.p_ptrace = PillarCard("🛡", "Process Isolation",
                                   "ptrace restricted to administrators.")
        self.p_sudo = PillarCard("🔑", "Least Privilege",
                                 "sudo requires password on every use.")
        for p in (self.p_net, self.p_exec, self.p_ptrace, self.p_sudo):
            pillars.addWidget(p)
        layout.addLayout(pillars)

        # Audit
        audit_row = QHBoxLayout()
        audit_title = QLabel("LEAST PRIVILEGE AUDIT")
        audit_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        audit_row.addWidget(audit_title)
        audit_row.addStretch()
        self.audit_summary = QLabel("")
        self.audit_summary.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        audit_row.addWidget(self.audit_summary)

        btn_style = """
            QPushButton {
                background-color: #0d2226; color: #1ed98a; border: 1px solid #1ed98a;
                border-radius: 6px; padding: 5px 12px; font-size: 11px; margin-left: 8px;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
            QPushButton:disabled { color: #8fb0b2; border-color: #1a3a3f; }
        """
        self.audit_btn = QPushButton("▶  Run Audit")
        self.audit_btn.setStyleSheet(btn_style)
        self.audit_btn.clicked.connect(self._run_audit)
        audit_row.addWidget(self.audit_btn)

        self.blocked_btn = QPushButton("Show Blocked Connections")
        self.blocked_btn.setStyleSheet(btn_style)
        self.blocked_btn.clicked.connect(self._show_blocked)
        audit_row.addWidget(self.blocked_btn)
        layout.addLayout(audit_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.findings_content = QWidget()
        self.findings_content.setStyleSheet("background: transparent;")
        self.findings_layout = QVBoxLayout(self.findings_content)
        self.findings_layout.setSpacing(6)
        self.findings_layout.addStretch()
        scroll.setWidget(self.findings_content)
        layout.addWidget(scroll)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setFixedHeight(110)
        self.output_log.setStyleSheet("""
            QTextEdit {
                background-color: #051012; color: #1ed98a; border: 1px solid #1a3a3f;
                border-radius: 8px; font-family: monospace; font-size: 11px; padding: 8px;
            }
        """)
        self.output_log.setPlaceholderText("Zero Trust output will appear here...")
        layout.addWidget(self.output_log)

    # ── Banner / status ──────────────────────────────────
    def _set_banner(self, active):
        if active:
            self.banner.setStyleSheet("QFrame { background-color: #0b2a26; border: 2px solid #1ed98a; border-radius: 10px; }")
            self.banner_title.setText("⬡  ZERO TRUST ACTIVE")
            self.banner_title.setStyleSheet("color: #1ed98a; font-size: 16px; font-weight: bold; border: none;")
            self.banner_sub.setStyleSheet("color: #5fd6a4; font-size: 11px; border: none;")
            self.activate_btn.setText("✕  Deactivate Zero Trust")
            self.activate_btn.setStyleSheet("""
                QPushButton {
                    background-color: #ff6b6b22; color: #ff6b6b; border: 1px solid #ff6b6b;
                    border-radius: 8px; padding: 0 20px; font-size: 13px; font-weight: bold;
                }
                QPushButton:hover { background-color: #ff6b6b44; }
                QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; border-color: #1a3a3f; }
            """)
        else:
            self.banner.setStyleSheet("QFrame { background-color: #0d2226; border: 1px solid #1a3a3f; border-radius: 10px; }")
            self.banner_title.setText("ZERO TRUST INACTIVE")
            self.banner_title.setStyleSheet("color: #e0e0e0; font-size: 16px; font-weight: bold; border: none;")
            self.banner_sub.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
            self.activate_btn.setText("⬡  Activate Zero Trust")
            self.activate_btn.setStyleSheet("""
                QPushButton {
                    background-color: #1ed98a; color: #061013; border: none;
                    border-radius: 8px; padding: 0 20px; font-size: 13px; font-weight: bold;
                }
                QPushButton:hover { background-color: #14b874; }
                QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
            """)

    def refresh(self):
        self._sw = StatusWorker()
        self._sw.status_ready.connect(self._apply_status)
        self._sw.start()

    def _apply_status(self, s):
        self.zt_active = s.get("ZT_ACTIVE") == "true"
        self._set_banner(self.zt_active)
        self.p_net.set_on(s.get("NET_SEGMENTATION") == "true")
        self.p_exec.set_on(s.get("SHM_NOEXEC") == "true" or s.get("TMP_NOEXEC") == "true")
        try:
            self.p_ptrace.set_on(int(s.get("PTRACE_SCOPE", "0")) >= 2)
        except ValueError:
            self.p_ptrace.set_on(False)
        self.p_sudo.set_on(s.get("SUDO_STRICT") == "true")

    # ── Activate / deactivate ────────────────────────────
    def _toggle(self):
        if self.worker and self.worker.isRunning():
            return
        if not self.zt_active:
            reply = QMessageBox.question(
                self, "Activate Zero Trust",
                "Zero Trust will block all outbound traffic except DNS, HTTP/HTTPS, NTP and DHCP,\n"
                "disable execution from /tmp and /dev/shm, and require the sudo password every time.\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            action = "activate"
        else:
            action = "deactivate"

        self.output_log.clear()
        self.activate_btn.setEnabled(False)
        self.worker = ZTWorker(["pkexec", "bash", SCRIPT, action])
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(self._on_toggle_done)
        self.worker.start()

    def _on_toggle_done(self, ok):
        self.activate_btn.setEnabled(True)
        self.output_log.append("\n✓ Done." if ok else "\n✗ Operation failed.")
        self.refresh()

    # ── Audit ────────────────────────────────────────────
    def _clear_findings(self):
        while self.findings_layout.count() > 1:
            item = self.findings_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _add_finding(self, severity, title, detail):
        self.findings_layout.insertWidget(
            self.findings_layout.count() - 1, FindingRow(severity, title, detail)
        )

    def _run_audit(self):
        if self.worker and self.worker.isRunning():
            return
        self.audit_lines = []
        self._clear_findings()
        self.output_log.clear()
        self.output_log.append("Running least privilege audit...")
        self.audit_btn.setEnabled(False)
        self.worker = ZTWorker(["pkexec", "bash", SCRIPT, "audit"])
        self.worker.output_line.connect(self._on_audit_line)
        self.worker.finished_ok.connect(self._on_audit_done)
        self.worker.start()

    def _on_audit_line(self, line):
        if "|" in line and not line.startswith("[NEFI"):
            self.audit_lines.append(line)
        else:
            self.output_log.append(line)

    def _on_audit_done(self, ok):
        self.audit_btn.setEnabled(True)
        high = medium = 0
        uid0, sudoers, nopass, suid, wwdirs, listen = [], [], [], [], [], []
        for line in self.audit_lines:
            kind, _, value = line.partition("|")
            {"UID0": uid0, "SUDO": sudoers, "NOPASSWD": nopass,
             "SUID": suid, "WWDIR": wwdirs, "LISTEN": listen}.get(kind, []).append(value)

        extra_root = [u for u in uid0 if u != "root"]
        if extra_root:
            high += 1
            self._add_finding("high", "Extra accounts with UID 0",
                              f"{', '.join(extra_root)} — only root should have UID 0.")
        if nopass:
            high += 1
            self._add_finding("high", "Passwordless sudo rules (NOPASSWD)",
                              " | ".join(nopass[:3]))
        if sudoers:
            self._add_finding("info", f"Users with sudo rights: {len(sudoers)}",
                              ", ".join(sudoers))
        unusual = [f for f in suid if f not in KNOWN_SUID]
        if unusual:
            medium += 1
            self._add_finding("medium", f"Unusual SUID binaries: {len(unusual)}",
                              ", ".join(unusual[:8]))
        self._add_finding("info", f"Total SUID binaries: {len(suid)}",
                          "SUID binaries run with owner privileges — keep this list minimal.")
        if wwdirs:
            medium += 1
            self._add_finding("medium", "World-writable dirs without sticky bit",
                              ", ".join(wwdirs[:8]))
        exposed = [l for l in listen if not (l.startswith("127.") or l.startswith("[::1]"))]
        if exposed:
            medium += 1
            self._add_finding("medium", f"Services exposed to the network: {len(exposed)}",
                              ", ".join(exposed[:8]))

        if not high and not medium:
            self._add_finding("info", "No privilege issues found", "System follows least privilege.")
        color = "#ff6b6b" if high else "#ffaa00" if medium else "#1ed98a"
        self.audit_summary.setText(f"{high} high • {medium} medium")
        self.audit_summary.setStyleSheet(f"color: {color}; font-size: 11px;")
        self.output_log.append("\n✓ Audit completed." if ok else "\n✗ Audit failed.")

    # ── Blocked connections ──────────────────────────────
    def _show_blocked(self):
        if self.worker and self.worker.isRunning():
            return
        self.output_log.clear()
        self.output_log.append("Reading blocked connections (NEFI-ZT)...\n")
        self._blocked = []
        self.worker = ZTWorker(["pkexec", "journalctl", "-k", "--no-pager", "-n", "3000"])
        self.worker.output_line.connect(
            lambda l: self._blocked.append(l) if "NEFI-ZT" in l else None
        )
        self.worker.finished_ok.connect(self._on_blocked_done)
        self.worker.start()

    def _on_blocked_done(self, ok):
        if not self._blocked:
            self.output_log.append("No blocked connections logged.")
            return
        for line in self._blocked[-40:]:
            direction = "OUT" if "OUT-DROP" in line else "IN"
            parts = {kv.split("=")[0]: kv.split("=")[1]
                     for kv in line.split() if "=" in kv and kv.count("=") == 1}
            self.output_log.append(
                f"[{direction}] {parts.get('SRC', '?')} → {parts.get('DST', '?')} "
                f"{parts.get('PROTO', '')} dport={parts.get('DPT', '?')}"
            )
