import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QLineEdit,
    QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class SnapWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool, str)

    def __init__(self, action, args=None):
        super().__init__()
        self.action = action
        self.args = args or []

    def run(self):
        try:
            cmd = ["pkexec", "bash",
                   "/opt/nefi/snapshots/manage.sh",
                   self.action] + self.args
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            output = result.stdout + result.stderr
            for line in output.splitlines():
                self.output_line.emit(line)
            self.finished_ok.emit(result.returncode == 0, output)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False, str(e))


class SnapshotManagerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self.btrfs_supported = False
        self._build_ui()
        self._check_btrfs()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("SNAPSHOT MANAGER")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        # Status banner
        self.status_banner = QFrame()
        self.status_banner.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        banner_layout = QHBoxLayout(self.status_banner)
        banner_layout.setContentsMargins(16, 12, 16, 12)

        self.fs_icon = QLabel("💾")
        self.fs_icon.setStyleSheet("font-size: 24px; border: none;")
        banner_layout.addWidget(self.fs_icon)

        banner_text = QVBoxLayout()
        self.fs_label = QLabel("Checking filesystem...")
        self.fs_label.setStyleSheet(
            "color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;"
        )
        self.fs_sub = QLabel(
            "Snapshots require Btrfs filesystem"
        )
        self.fs_sub.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        banner_text.addWidget(self.fs_label)
        banner_text.addWidget(self.fs_sub)
        banner_layout.addLayout(banner_text)
        banner_layout.addStretch()

        self.setup_btn = QPushButton("Setup Snapper")
        self.setup_btn.setStyleSheet("""
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
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
        """)
        self.setup_btn.clicked.connect(self._setup_snapper)
        self.setup_btn.setEnabled(False)
        banner_layout.addWidget(self.setup_btn)
        layout.addWidget(self.status_banner)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.create_btn = QPushButton("📸  Create Snapshot")
        self.create_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a22;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 8px;
                padding: 10px 16px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; border-color: #1a3a3f; }
        """)
        self.create_btn.clicked.connect(self._create_snapshot)
        self.create_btn.setEnabled(False)
        btn_row.addWidget(self.create_btn)

        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("Snapshot description (optional)")
        self.desc_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                padding: 10px 12px;
                font-size: 12px;
            }
            QLineEdit:focus { border-color: #1ed98a; }
        """)
        btn_row.addWidget(self.desc_input)

        self.refresh_btn = QPushButton("↻  Refresh")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #8fb0b2;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                padding: 10px 16px;
                font-size: 12px;
            }
            QPushButton:hover { border-color: #1ed98a; color: #1ed98a; }
        """)
        self.refresh_btn.clicked.connect(self._load_snapshots)
        btn_row.addWidget(self.refresh_btn)
        layout.addLayout(btn_row)

        # Snapshot table
        snap_title = QLabel("SNAPSHOTS")
        snap_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(snap_title)

        self.snap_table = QTableWidget()
        self.snap_table.setColumnCount(5)
        self.snap_table.setHorizontalHeaderLabels([
            "ID", "Type", "Date", "Description", "Actions"
        ])
        self.snap_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                font-size: 12px;
                gridline-color: #1a3a3f;
            }
            QHeaderView::section {
                background-color: #061013;
                color: #8fb0b2;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #1a3a3f;
                font-size: 10px;
                letter-spacing: 1px;
            }
            QTableWidget::item {
                padding: 6px;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #0f3a30;
                color: #1ed98a;
            }
        """)
        self.snap_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.snap_table.verticalHeader().setVisible(False)
        self.snap_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        layout.addWidget(self.snap_table)

        # Output log
        log_title = QLabel("OUTPUT")
        log_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(log_title)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setFixedHeight(100)
        self.output_log.setStyleSheet("""
            QTextEdit {
                background-color: #051012;
                color: #1ed98a;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                font-family: monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        self.output_log.setPlaceholderText(
            "Snapshot operations output will appear here.\n"
            "Note: Snapshots require Btrfs filesystem."
        )
        layout.addWidget(self.output_log)

    def _check_btrfs(self):
        try:
            result = subprocess.run(
                ["bash", "/opt/nefi/snapshots/manage.sh", "check_btrfs"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            fs = ""
            for line in output.splitlines():
                if line.startswith("FILESYSTEM="):
                    fs = line.split("=")[1]
                if line.startswith("BTRFS_SUPPORTED=true"):
                    self.btrfs_supported = True

            if self.btrfs_supported:
                self.fs_label.setText(f"Filesystem: {fs} ✓ Snapshots supported")
                self.fs_label.setStyleSheet(
                    "color: #1ed98a; font-size: 13px; font-weight: bold; border: none;"
                )
                self.status_banner.setStyleSheet("""
                    QFrame {
                        background-color: #0b2a26;
                        border: 1px solid #1ed98a44;
                        border-radius: 8px;
                    }
                """)
                self.setup_btn.setEnabled(True)
                self.create_btn.setEnabled(True)
                self._load_snapshots()
            else:
                self.fs_label.setText(
                    f"Filesystem: {fs} — Snapshots not supported"
                )
                self.fs_label.setStyleSheet(
                    "color: #ffaa00; font-size: 13px; font-weight: bold; border: none;"
                )
                self.fs_sub.setText(
                    "Install NEFI OS on Btrfs to enable snapshots. "
                    "During installation, select Btrfs as the filesystem."
                )
        except Exception as e:
            self.fs_label.setText("Could not check filesystem")

    def _setup_snapper(self):
        self.output_log.clear()
        self.output_log.append("Setting up Snapper...")
        self.worker = SnapWorker("setup")
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(
            lambda ok, out: (
                self.output_log.append(
                    "\n✓ Snapper configured." if ok else "\n✗ Setup failed."
                ),
                self._load_snapshots() if ok else None
            )
        )
        self.worker.start()

    def _create_snapshot(self):
        desc = self.desc_input.text().strip() or \
               f"Manual snapshot {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}"
        self.output_log.clear()
        self.output_log.append(f"Creating snapshot: {desc}...")
        self.create_btn.setEnabled(False)
        self.worker = SnapWorker("create", [desc])
        self.worker.output_line.connect(self.output_log.append)
        self.worker.finished_ok.connect(self._on_create_done)
        self.worker.start()

    def _on_create_done(self, ok, output):
        self.create_btn.setEnabled(True)
        self.desc_input.clear()
        if ok:
            self.output_log.append("\n✓ Snapshot created successfully.")
            self._load_snapshots()
        else:
            self.output_log.append("\n✗ Failed to create snapshot.")

    def _load_snapshots(self):
        if not self.btrfs_supported:
            return
        self.worker = SnapWorker("list")
        self.worker.finished_ok.connect(self._parse_snapshots)
        self.worker.start()

    def _parse_snapshots(self, ok, output):
        self.snap_table.setRowCount(0)
        if not ok:
            return
        for line in output.splitlines():
            parts = line.split("|")
            if len(parts) >= 5 and parts[0].strip().isdigit():
                row = self.snap_table.rowCount()
                self.snap_table.insertRow(row)
                snap_id = parts[0].strip()
                snap_type = parts[1].strip()
                snap_date = parts[2].strip()
                snap_desc = parts[4].strip() if len(parts) > 4 else ""

                self.snap_table.setItem(row, 0, QTableWidgetItem(snap_id))
                self.snap_table.setItem(row, 1, QTableWidgetItem(snap_type))
                self.snap_table.setItem(row, 2, QTableWidgetItem(snap_date))
                self.snap_table.setItem(row, 3, QTableWidgetItem(snap_desc))

                # Pulsanti azione
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(4, 2, 4, 2)
                action_layout.setSpacing(4)

                rollback_btn = QPushButton("Rollback")
                rollback_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #ffaa0022;
                        color: #ffaa00;
                        border: 1px solid #ffaa00;
                        border-radius: 4px;
                        padding: 2px 8px;
                        font-size: 10px;
                    }
                    QPushButton:hover { background-color: #ffaa0044; }
                """)
                rollback_btn.clicked.connect(
                    lambda checked, sid=snap_id: self._rollback(sid)
                )
                action_layout.addWidget(rollback_btn)

                del_btn = QPushButton("Delete")
                del_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #ff6b6b22;
                        color: #ff6b6b;
                        border: 1px solid #ff6b6b;
                        border-radius: 4px;
                        padding: 2px 8px;
                        font-size: 10px;
                    }
                    QPushButton:hover { background-color: #ff6b6b44; }
                """)
                del_btn.clicked.connect(
                    lambda checked, sid=snap_id: self._delete(sid)
                )
                action_layout.addWidget(del_btn)
                self.snap_table.setCellWidget(row, 4, action_widget)

    def _rollback(self, snap_id):
        reply = QMessageBox.question(
            self, "Confirm Rollback",
            f"Roll back to snapshot #{snap_id}?\n\n"
            "This will revert all file changes since that snapshot was created.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.output_log.clear()
            self.output_log.append(f"Rolling back to snapshot #{snap_id}...")
            self.worker = SnapWorker("rollback", [snap_id])
            self.worker.output_line.connect(self.output_log.append)
            self.worker.finished_ok.connect(
                lambda ok, out: self.output_log.append(
                    "\n✓ Rollback completed. Reboot to apply." if ok
                    else "\n✗ Rollback failed."
                )
            )
            self.worker.start()

    def _delete(self, snap_id):
        reply = QMessageBox.question(
            self, "Delete Snapshot",
            f"Delete snapshot #{snap_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.output_log.clear()
            self.worker = SnapWorker("delete", [snap_id])
            self.worker.output_line.connect(self.output_log.append)
            self.worker.finished_ok.connect(
                lambda ok, out: (
                    self.output_log.append(
                        f"\n✓ Snapshot #{snap_id} deleted." if ok
                        else "\n✗ Delete failed."
                    ),
                    self._load_snapshots() if ok else None
                )
            )
            self.worker.start()

    def refresh(self):
        self._load_snapshots()
