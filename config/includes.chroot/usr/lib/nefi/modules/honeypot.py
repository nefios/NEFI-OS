import subprocess
import os
import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame,
    QScrollArea, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QColor


class HoneypotProcess(QThread):
    output_line = pyqtSignal(str)

    def __init__(self, script):
        super().__init__()
        self.script = script
        self.process = None

    def run(self):
        try:
            self.process = subprocess.Popen(
                ["python3", self.script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in self.process.stdout:
                self.output_line.emit(line.rstrip())
        except Exception as e:
            self.output_line.emit(f"Error: {e}")

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process = None


class ConnectionCard(QFrame):
    def __init__(self, event):
        super().__init__()
        service = event.get("service", "unknown").upper()
        ip = event.get("src_ip", "unknown")
        ts = event.get("timestamp", "")[:19].replace("T", " ")
        path = event.get("path", "")
        method = event.get("method", "")
        data = event.get("data", "")

        color = "#ff6b6b" if service == "SSH" else "#ffaa00"

        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0d2226;
                border-left: 3px solid {color};
                border-radius: 6px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(12)

        svc_lbl = QLabel(service)
        svc_lbl.setFixedWidth(50)
        svc_lbl.setStyleSheet(f"""
            color: {color};
            font-size: 10px;
            font-weight: bold;
            border: none;
        """)
        layout.addWidget(svc_lbl)

        ip_lbl = QLabel(ip)
        ip_lbl.setFixedWidth(130)
        ip_lbl.setStyleSheet("color: #e0e0e0; font-size: 12px; font-family: monospace; border: none;")
        layout.addWidget(ip_lbl)

        detail = path if path else data[:40] if data else ""
        if method:
            detail = f"{method} {path}"
        detail_lbl = QLabel(detail)
        detail_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        layout.addWidget(detail_lbl)
        layout.addStretch()

        ts_lbl = QLabel(ts)
        ts_lbl.setStyleSheet("color: #4a676a; font-size: 10px; border: none;")
        layout.addWidget(ts_lbl)


class HoneypotWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.ssh_process = None
        self.http_process = None
        self.ssh_running = False
        self.http_running = False
        self._build_ui()
        self._load_events()

        # Auto-refresh events
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._load_events)
        self.refresh_timer.start(5000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("HONEYPOT")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        info = QLabel(
            "Deploy fake services to detect and monitor attackers. "
            "When someone connects to a honeypot, their IP and activity are logged."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Service cards
        services_title = QLabel("HONEYPOT SERVICES")
        services_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(services_title)

        services_row = QHBoxLayout()
        services_row.setSpacing(12)

        # SSH Honeypot card
        self.ssh_card = self._make_service_card(
            "SSH Honeypot", "Port 2222",
            "Simulates an SSH server. Logs brute force attempts and credentials.",
            "🔐", self._toggle_ssh
        )
        services_row.addWidget(self.ssh_card[0])

        # HTTP Honeypot card
        self.http_card = self._make_service_card(
            "HTTP Honeypot", "Port 8080",
            "Simulates a router admin panel. Logs web scanners and attacks.",
            "🌐", self._toggle_http
        )
        services_row.addWidget(self.http_card[0])
        layout.addLayout(services_row)

        # Stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)

        self.total_card = self._make_stat_card("Total Connections", "0")
        self.ssh_stat = self._make_stat_card("SSH Attempts", "0")
        self.http_stat = self._make_stat_card("HTTP Requests", "0")
        self.unique_ips = self._make_stat_card("Unique IPs", "0")

        for card, _ in [self.total_card, self.ssh_stat,
                         self.http_stat, self.unique_ips]:
            stats_row.addWidget(card)
        layout.addLayout(stats_row)

        # Events
        events_title = QLabel("RECENT CONNECTIONS")
        events_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(events_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.events_content = QWidget()
        self.events_content.setStyleSheet("background: transparent;")
        self.events_layout = QVBoxLayout(self.events_content)
        self.events_layout.setSpacing(6)
        self.events_layout.addStretch()
        scroll.setWidget(self.events_content)
        layout.addWidget(scroll)

        # Log output
        log_title = QLabel("SERVICE OUTPUT")
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
            "Start a honeypot service to see output here..."
        )
        layout.addWidget(self.output_log)

    def _make_service_card(self, name, port, desc, icon, toggle_fn):
        frame = QFrame()
        frame.setMinimumHeight(170)
        frame.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 10px;
            }
        """)
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(16, 14, 16, 14)
        fl.setSpacing(8)

        header = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 24px; border: none;")
        header.addWidget(icon_lbl)

        text = QVBoxLayout()
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet(
            "color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;"
        )
        port_lbl = QLabel(port)
        port_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        text.addWidget(name_lbl)
        text.addWidget(port_lbl)
        text.setSpacing(2)
        name_lbl.setMinimumHeight(20)
        port_lbl.setMinimumHeight(18)
        header.addLayout(text)
        header.addStretch()

        status_lbl = QLabel("● STOPPED")
        status_lbl.setStyleSheet(
            "color: #8fb0b2; font-size: 10px; font-weight: bold; border: none;"
        )
        header.addWidget(status_lbl)
        fl.addLayout(header)

        desc_lbl = QLabel(desc)
        desc_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        desc_lbl.setWordWrap(True)
        desc_lbl.setMinimumHeight(32)
        fl.addWidget(desc_lbl)

        btn = QPushButton("▶  Start")
        btn.setMinimumHeight(38)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a22;
                color: #1ed98a;
                border: 1px solid #1ed98a;
                border-radius: 6px;
                padding: 8px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1ed98a; color: #061013; }
        """)
        btn.clicked.connect(toggle_fn)
        fl.addWidget(btn)

        return frame, btn, status_lbl

    def _make_stat_card(self, label, value):
        card = QWidget()
        card.setMinimumHeight(80)
        card.setStyleSheet("""
            QWidget {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 10, 14, 10)
        lbl = QLabel(label.upper())
        lbl.setStyleSheet(
            "color: #8fb0b2; font-size: 10px; letter-spacing: 1px; border: none;"
        )
        val = QLabel(value)
        val.setStyleSheet(
            "color: #1ed98a; font-size: 22px; font-weight: bold; border: none;"
        )
        cl.addWidget(lbl)
        cl.addWidget(val)
        return card, val

    def _toggle_ssh(self):
        if not self.ssh_running:
            self._start_honeypot("ssh")
        else:
            self._stop_honeypot("ssh")

    def _toggle_http(self):
        if not self.http_running:
            self._start_honeypot("http")
        else:
            self._stop_honeypot("http")

    def _start_honeypot(self, service):
        script = f"/opt/nefi/honeypot/{service}_honeypot.py"
        self.output_log.append(f"Starting {service.upper()} honeypot...")

        if service == "ssh":
            self.ssh_process = HoneypotProcess(script)
            self.ssh_process.output_line.connect(self.output_log.append)
            self.ssh_process.start()
            self.ssh_running = True
            _, btn, status = self.ssh_card
            btn.setText("■  Stop")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #ff6b6b22;
                    color: #ff6b6b;
                    border: 1px solid #ff6b6b;
                    border-radius: 6px;
                    padding: 8px;
                    font-size: 12px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #ff6b6b44; }
            """)
            status.setText("● RUNNING")
            status.setStyleSheet(
                "color: #1ed98a; font-size: 10px; font-weight: bold; border: none;"
            )
        else:
            self.http_process = HoneypotProcess(script)
            self.http_process.output_line.connect(self.output_log.append)
            self.http_process.start()
            self.http_running = True
            _, btn, status = self.http_card
            btn.setText("■  Stop")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #ff6b6b22;
                    color: #ff6b6b;
                    border: 1px solid #ff6b6b;
                    border-radius: 6px;
                    padding: 8px;
                    font-size: 12px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #ff6b6b44; }
            """)
            status.setText("● RUNNING")
            status.setStyleSheet(
                "color: #1ed98a; font-size: 10px; font-weight: bold; border: none;"
            )

    def _stop_honeypot(self, service):
        if service == "ssh" and self.ssh_process:
            self.ssh_process.stop()
            self.ssh_running = False
            _, btn, status = self.ssh_card
            btn.setText("▶  Start")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #1ed98a22;
                    color: #1ed98a;
                    border: 1px solid #1ed98a;
                    border-radius: 6px;
                    padding: 8px;
                    font-size: 12px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #1ed98a; color: #061013; }
            """)
            status.setText("● STOPPED")
            status.setStyleSheet(
                "color: #8fb0b2; font-size: 10px; font-weight: bold; border: none;"
            )
            self.output_log.append("SSH honeypot stopped.")
        elif service == "http" and self.http_process:
            self.http_process.stop()
            self.http_running = False
            _, btn, status = self.http_card
            btn.setText("▶  Start")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #1ed98a22;
                    color: #1ed98a;
                    border: 1px solid #1ed98a;
                    border-radius: 6px;
                    padding: 8px;
                    font-size: 12px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #1ed98a; color: #061013; }
            """)
            status.setText("● STOPPED")
            status.setStyleSheet(
                "color: #8fb0b2; font-size: 10px; font-weight: bold; border: none;"
            )
            self.output_log.append("HTTP honeypot stopped.")

    def _load_events(self):
        all_events = []
        for log_file in [
            "/var/log/nefi/honeypot-ssh.json",
            "/var/log/nefi/honeypot-http.json"
        ]:
            if os.path.exists(log_file):
                try:
                    with open(log_file) as f:
                        for line in f:
                            try:
                                all_events.append(json.loads(line.strip()))
                            except Exception:
                                pass
                except Exception:
                    pass

        all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        while self.events_layout.count() > 1:
            item = self.events_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not all_events:
            empty = QLabel("No connections detected yet. Start a honeypot service.")
            empty.setStyleSheet("color: #8fb0b2; font-size: 12px;")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.events_layout.insertWidget(0, empty)
        else:
            for event in all_events[:50]:
                card = ConnectionCard(event)
                self.events_layout.insertWidget(
                    self.events_layout.count() - 1, card
                )

        # Update stats
        total = len(all_events)
        ssh_count = sum(1 for e in all_events if e.get("service") == "ssh")
        http_count = sum(1 for e in all_events if e.get("service") == "http")
        unique = len(set(e.get("src_ip", "") for e in all_events))

        self.total_card[1].setText(str(total))
        self.ssh_stat[1].setText(str(ssh_count))
        self.http_stat[1].setText(str(http_count))
        self.unique_ips[1].setText(str(unique))

    def refresh(self):
        self._load_events()

    def closeEvent(self, event):
        if self.ssh_process:
            self.ssh_process.stop()
        if self.http_process:
            self.http_process.stop()
        super().closeEvent(event)
