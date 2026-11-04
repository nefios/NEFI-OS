"""NEFI Security Center — System: le 9 pagine di valutazione (dati da assessment.py)."""
import os
import subprocess

from PyQt6.QtWidgets import QHBoxLayout, QLabel, QTextEdit, QComboBox
from PyQt6.QtCore import QThread, pyqtSignal

from nefi_theme import C, Card, SectionLabel, GhostButton, Pill
from assessment import CategoryPage


class CmdWorker(QThread):
    line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for l in p.stdout:
                self.line.emit(l.rstrip())
            p.wait()
            self.finished_ok.emit(p.returncode == 0)
        except OSError as e:
            self.line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class ActionPage(CategoryPage):
    """CategoryPage con un riquadro 'Actions' e un log dei comandi."""
    def _actions_card(self, title):
        card = Card(padding=18)
        card.body.addWidget(SectionLabel(title))
        self.actions_row = QHBoxLayout()
        card.body.addLayout(self.actions_row)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(110)
        self.log.setPlaceholderText("Action output will appear here.")
        self.log.setStyleSheet(f"background: {C['bg']}; color: {C['accent']}; border: 1px solid {C['border']}; "
                               f"border-radius: 8px; font-family: monospace; font-size: 12px;")
        card.body.addWidget(self.log)
        self.extra.addWidget(card)
        self.cmd_worker = None

    def _cmd(self, cmd, title):
        if self.cmd_worker and self.cmd_worker.isRunning():
            return
        self.log.clear()
        self.log.append(title)
        self.cmd_worker = CmdWorker(cmd)
        self.cmd_worker.line.connect(self.log.append)
        self.cmd_worker.finished_ok.connect(lambda ok: (self.log.append("Done." if ok else "Failed."),
                                                        self.run_now()))
        self.cmd_worker.start()


class HardwarePage(CategoryPage):
    CATEGORY = "hardware"
    TITLE = "Hardware Security"
    SUBTITLE = "TPM, CPU vulnerabilities and microcode, IOMMU (DMA protection) and firmware updates."


class BootPage(CategoryPage):
    CATEGORY = "boot"
    TITLE = "Boot Integrity"
    SUBTITLE = "The boot chain: UEFI, Secure Boot, signed kernel modules, kernel lockdown and GRUB protection."


class KernelPage(CategoryPage):
    CATEGORY = "kernel"
    TITLE = "Kernel Security"
    SUBTITLE = "Kernel hardening parameters, AppArmor, audit rules and blocked kernel modules."


class IntegrityPage(CategoryPage):
    CATEGORY = "integrity"
    TITLE = "System Integrity"
    SUBTITLE = ("Package file checksums, AIDE baseline, unexpected SUID programs and permissions of critical files. "
                "Run a full AIDE comparison from DFIR > Integrity Control.")


SERVICES = [
    ("nftables.service", "Firewall"), ("apparmor.service", "AppArmor"), ("auditd.service", "Audit"),
    ("fail2ban.service", "fail2ban"), ("falco-modern-bpf.service", "Falco"), ("crowdsec.service", "CrowdSec"),
    ("crowdsec-firewall-bouncer.service", "CrowdSec bouncer"), ("clamav-freshclam.service", "ClamAV updates"),
    ("suricata.service", "Suricata"), ("nefi-assess.timer", "NEFI assessment"),
]


class ServicesPage(ActionPage):
    CATEGORY = "services"
    TITLE = "Security Services"
    SUBTITLE = ("Each service is checked by what it actually does (loaded rules, connected components, fresh "
                "signatures), not only by 'active'. Start, restart or stop them below.")

    def build_extra(self):
        self._actions_card("Manage services")
        self.svc = QComboBox()
        self.svc.setStyleSheet(f"QComboBox {{ background: {C['bg']}; color: {C['text']}; border: 1px solid "
                               f"{C['border2']}; border-radius: 6px; padding: 6px 10px; min-width: 260px; }}")
        for unit, name in SERVICES:
            self.svc.addItem(f"{name}  ({unit})", unit)
        self.svc.currentIndexChanged.connect(self._show_state)
        self.actions_row.addWidget(self.svc)
        self.state = Pill("…", "muted", 100)
        self.state.setFixedHeight(30)
        self.actions_row.addWidget(self.state)
        self.actions_row.addStretch()
        for label, verb, tone in (("Start", "start", "ok"), ("Restart", "restart", "muted"), ("Stop", "stop", "danger")):
            b = GhostButton(label, None, 34, tone=tone)
            b.clicked.connect(lambda _c, v=verb: self._svc(v))
            self.actions_row.addWidget(b)
        self._show_state()

    def _show_state(self):
        unit = self.svc.currentData()
        try:
            st = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            st = "unknown"
        self.state.setText(st or "unknown")
        self.state.set_tone("ok" if st == "active" else "danger" if st == "failed" else "muted")

    def _svc(self, verb):
        unit = self.svc.currentData()
        if unit not in {u for u, _ in SERVICES}:
            return
        self._cmd(["pkexec", "/usr/bin/systemctl", verb, unit], f"systemctl {verb} {unit} (admin password)…")

    def refresh(self, force=False):
        super().refresh(force)
        if hasattr(self, "svc"):
            self._show_state()


class PackagesPage(CategoryPage):
    CATEGORY = "packages"
    TITLE = "Package Security"
    SUBTITLE = ("Vulnerable packages (Debian security tracker via debsecan), services still running outdated "
                "libraries, package source signatures and package database health.")


class ConfigPage(CategoryPage):
    CATEGORY = "config"
    TITLE = "Configuration Audit"
    SUBTITLE = "Disk encryption, SSH, sudo, accounts, password policy and services listening on the network."


class BackupPage(ActionPage):
    CATEGORY = "backup"
    TITLE = "Backup & Recovery"
    SUBTITLE = ("Snapshots (Snapper on Btrfs, or Timeshift) and restore testing. "
                "Create and restore snapshots from System > Snapshots.")

    def build_extra(self):
        self._actions_card("Restore testing")
        info = QLabel("After you have checked that a snapshot or backup can really be restored (for example by "
                      "restoring a test file), record it here.")
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {C['text2']}; background: transparent;")
        self.actions_row.addWidget(info, 1)
        b = GhostButton("Record restore test", "check_sq", 34, tone="ok")
        b.clicked.connect(lambda: self._cmd(
            ["pkexec", "/bin/sh", "-c", "mkdir -p /var/lib/nefi/backup && date -Is > /var/lib/nefi/backup/last-restore-test"],
            "Recording a successful restore test (admin password)…"))
        self.actions_row.addWidget(b)
        go = GhostButton("Open Snapshots", "snapshot", 34)
        go.clicked.connect(lambda: self.window().open_module("snapshots") if hasattr(self.window(), "open_module") else None)
        self.actions_row.addWidget(go)


class UpdatesPage(ActionPage):
    CATEGORY = "updates"
    TITLE = "Update Health"
    SUBTITLE = ("Pending security updates, automatic updates actually running, freshness of package lists, "
                "pending reboot and release support.")

    def build_extra(self):
        self._actions_card("Update")
        self.actions_row.addStretch()
        b1 = GhostButton("Refresh package lists", "refresh", 34)
        b1.clicked.connect(lambda: self._cmd(["pkexec", "/usr/bin/apt-get", "update"],
                                             "apt-get update (admin password)…"))
        self.actions_row.addWidget(b1)
        b2 = GhostButton("Install security updates now", "download", 34, tone="ok")
        b2.clicked.connect(lambda: self._cmd(["pkexec", "/usr/bin/unattended-upgrade", "-v"],
                                             "Installing security updates with unattended-upgrade (admin password)…"))
        self.actions_row.addWidget(b2)
