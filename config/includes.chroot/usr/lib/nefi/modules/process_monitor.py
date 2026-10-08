import subprocess
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTreeWidget,
    QTreeWidgetItem, QFrame, QLineEdit,
    QHeaderView, QMenu, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QAction


class ProcessMonitorWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()
        title = QLabel("PROCESS MONITOR")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        header.addWidget(title)
        header.addStretch()

        self.proc_count = QLabel("0 processes")
        self.proc_count.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        header.addWidget(self.proc_count)

        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 6px;
                padding: 4px 12px;
                font-size: 11px;
                margin-left: 8px;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
        """)
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        # Search bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter by process name or PID...")
        self.search_bar.setStyleSheet("""
            QLineEdit {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
            }
            QLineEdit:focus { border-color: #1ed98a; }
        """)
        self.search_bar.textChanged.connect(self._filter_processes)
        layout.addWidget(self.search_bar)

        # Process tree
        self.tree = QTreeWidget()
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(["Process", "PID", "PPID", "User", "CPU%", "MEM%"])
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                font-size: 12px;
                outline: none;
            }
            QTreeWidget::item {
                padding: 3px;
                border: none;
            }
            QTreeWidget::item:selected {
                background-color: #0f3a30;
                color: #1ed98a;
            }
            QTreeWidget::item:hover {
                background-color: #1a3a3f;
            }
            QHeaderView::section {
                background-color: #061013;
                color: #8fb0b2;
                padding: 6px;
                border: none;
                border-bottom: 1px solid #1a3a3f;
                font-size: 10px;
                letter-spacing: 1px;
            }
            QTreeWidget::branch {
                background-color: #0d2226;
            }
        """)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_context_menu)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(4, Qt.SortOrder.DescendingOrder)
        self.tree.header().sectionClicked.connect(self._on_header_clicked)
        layout.addWidget(self.tree)

        # Info bar
        self.info_bar = QLabel("Right-click on a process for options")
        self.info_bar.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        layout.addWidget(self.info_bar)

        # Auto-refresh timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(10000)

    def _get_processes(self):
        try:
            result = subprocess.run(
                ["ps", "axo", "pid,ppid,user,pcpu,pmem,comm", "--no-headers",
                 "--sort=-pcpu"],
                capture_output=True, text=True, timeout=5
            )
            processes = []
            for line in result.stdout.splitlines():
                parts = line.split(None, 5)
                if len(parts) >= 6:
                    pid, ppid, user, cpu, mem, comm = parts
                    processes.append({
                        "pid": pid.strip(),
                        "ppid": ppid.strip(),
                        "user": user.strip(),
                        "cpu": cpu.strip(),
                        "mem": mem.strip(),
                        "name": comm.strip(),
                    })
            return processes
        except Exception:
            return []

    def _is_suspicious(self, proc):
        suspicious_names = [
            "nc", "ncat", "netcat", "nmap", "tcpdump",
            "wireshark", "metasploit", "msfconsole",
            "cryptominer", "xmrig", "minerd",
        ]
        suspicious_parents = [
            ("python", "bash"), ("python3", "bash"),
            ("php", "bash"), ("apache2", "bash"),
        ]
        name = proc["name"].lower()
        for s in suspicious_names:
            if s in name:
                return True
        return False

    def refresh(self):
        filter_text = self.search_bar.text().lower()
        self.tree.clear()
        processes = self._get_processes()

        pid_map = {p["pid"]: p for p in processes}
        children_map = {}
        roots = []

        for p in processes:
            ppid = p["ppid"]
            if ppid in pid_map and ppid != p["pid"]:
                children_map.setdefault(ppid, []).append(p)
            else:
                roots.append(p)

        def add_proc(proc, parent=None):
            name = proc["name"]
            pid = proc["pid"]

            if filter_text and filter_text not in name.lower() and filter_text not in pid:
                for child in children_map.get(pid, []):
                    add_proc(child, parent)
                return

            if parent:
                item = QTreeWidgetItem(parent)
            else:
                item = QTreeWidgetItem(self.tree)

            item.setText(0, name)
            item.setText(1, pid)
            item.setText(2, proc["ppid"])
            item.setText(3, proc["user"])
            item.setText(4, proc["cpu"] + "%")
            item.setText(5, proc["mem"] + "%")
            item.setData(0, Qt.ItemDataRole.UserRole, proc)

            # Colori
            try:
                cpu_val = float(proc["cpu"])
                if cpu_val > 50:
                    item.setForeground(4, QColor("#ff6b6b"))
                elif cpu_val > 20:
                    item.setForeground(4, QColor("#ffaa00"))
            except Exception:
                pass

            if self._is_suspicious(proc):
                for col in range(6):
                    item.setForeground(col, QColor("#ff6b6b"))
                item.setToolTip(0, "⚠ Suspicious process name")

            if proc["user"] == "root":
                item.setForeground(3, QColor("#ffaa00"))

            for child in children_map.get(pid, []):
                add_proc(child, item)

        for p in roots:
            add_proc(p)

        self.tree.expandToDepth(1)
        self.proc_count.setText(f"{len(processes)} processes")

    def _filter_processes(self, text):
        self.refresh()

    def _on_header_clicked(self, col):
        current = self.tree.header().sortIndicatorOrder()
        if current == Qt.SortOrder.AscendingOrder:
            self.tree.sortByColumn(col, Qt.SortOrder.DescendingOrder)
        else:
            self.tree.sortByColumn(col, Qt.SortOrder.AscendingOrder)

    def _show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return

        proc = item.data(0, Qt.ItemDataRole.UserRole)
        if not proc:
            return

        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 4px;
            }
            QMenu::item {
                padding: 6px 16px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #0f3a30;
                color: #1ed98a;
            }
        """)

        name = proc["name"]
        pid = proc["pid"]

        title_action = menu.addAction(f"{name} (PID {pid})")
        title_action.setEnabled(False)
        menu.addSeparator()

        kill_action = menu.addAction("🔴  Kill process (SIGKILL)")
        term_action = menu.addAction("🟡  Terminate process (SIGTERM)")
        menu.addSeparator()
        info_action = menu.addAction("ℹ  Process details")

        action = menu.exec(self.tree.mapToGlobal(pos))

        if action == kill_action:
            self._kill_process(pid, name, "KILL")
        elif action == term_action:
            self._kill_process(pid, name, "TERM")
        elif action == info_action:
            self._show_process_info(pid, name)

    def _kill_process(self, pid, name, signal):
        reply = QMessageBox.question(
            self,
            f"{'Kill' if signal == 'KILL' else 'Terminate'} Process",
            f"Are you sure you want to {'kill' if signal == 'KILL' else 'terminate'} "
            f"'{name}' (PID {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                subprocess.run(
                    ["kill", f"-{signal}", pid],
                    capture_output=True, timeout=5
                )
                self.info_bar.setText(f"Signal {signal} sent to PID {pid}")
                self.info_bar.setStyleSheet("color: #1ed98a; font-size: 11px;")
                QTimer.singleShot(3000, self.refresh)
            except Exception as e:
                self.info_bar.setText(f"Error: {e}")
                self.info_bar.setStyleSheet("color: #ff6b6b; font-size: 11px;")

    def _show_process_info(self, pid, name):
        try:
            result = subprocess.run(
                ["cat", f"/proc/{pid}/status"],
                capture_output=True, text=True, timeout=3
            )
            cmdline = subprocess.run(
                ["cat", f"/proc/{pid}/cmdline"],
                capture_output=True, text=True, timeout=3
            )
            cmd = cmdline.stdout.replace("\x00", " ").strip()
            info = f"PID: {pid}\nName: {name}\nCommand: {cmd}\n\n{result.stdout[:500]}"
            msg = QMessageBox(self)
            msg.setWindowTitle(f"Process Info — {name}")
            msg.setText(info)
            msg.setStyleSheet("""
                QMessageBox { background-color: #071417; }
                QLabel { color: #e0e0e0; font-family: monospace; font-size: 11px; }
                QPushButton {
                    background-color: #0d2226;
                    color: #1ed98a;
                    border: 1px solid #1ed98a;
                    border-radius: 6px;
                    padding: 6px 16px;
                }
            """)
            msg.exec()
        except Exception as e:
            self.info_bar.setText(f"Could not read process info: {e}")

    def refresh(self):
        self._refresh_tree()

    def _refresh_tree(self):
        filter_text = self.search_bar.text().lower() if hasattr(self, 'search_bar') else ""
        self.tree.clear()
        processes = self._get_processes()

        pid_map = {p["pid"]: p for p in processes}
        children_map = {}
        roots = []

        for p in processes:
            ppid = p["ppid"]
            if ppid in pid_map and ppid != p["pid"]:
                children_map.setdefault(ppid, []).append(p)
            else:
                roots.append(p)

        def add_proc(proc, parent=None):
            name = proc["name"]
            pid = proc["pid"]
            if filter_text and filter_text not in name.lower() and filter_text not in pid:
                for child in children_map.get(pid, []):
                    add_proc(child, parent)
                return
            item = QTreeWidgetItem(parent if parent else self.tree)
            item.setText(0, name)
            item.setText(1, pid)
            item.setText(2, proc["ppid"])
            item.setText(3, proc["user"])
            item.setText(4, proc["cpu"] + "%")
            item.setText(5, proc["mem"] + "%")
            item.setData(0, Qt.ItemDataRole.UserRole, proc)
            try:
                if float(proc["cpu"]) > 50:
                    item.setForeground(4, QColor("#ff6b6b"))
                elif float(proc["cpu"]) > 20:
                    item.setForeground(4, QColor("#ffaa00"))
            except Exception:
                pass
            if self._is_suspicious(proc):
                for col in range(6):
                    item.setForeground(col, QColor("#ff6b6b"))
            if proc["user"] == "root":
                item.setForeground(3, QColor("#ffaa00"))
            for child in children_map.get(pid, []):
                add_proc(child, item)

        for p in roots:
            add_proc(p)
        self.tree.expandToDepth(1)
        self.proc_count.setText(f"{len(processes)} processes")
