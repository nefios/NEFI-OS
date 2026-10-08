import subprocess
import os
import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit,
    QFrame, QLineEdit, QComboBox,
    QScrollArea, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Dati utente privati (non piu' in /tmp)
import os as _os
USER_DIR = _os.path.expanduser("~/.local/share/nefi")
_os.makedirs(USER_DIR, mode=0o700, exist_ok=True)
_os.chmod(USER_DIR, 0o700)   # chiave VirusTotal e IOC leggibili solo dall'utente
IOC_FILE = _os.path.join(USER_DIR, "custom-ioc.json")
APIKEY_FILE = _os.path.join(USER_DIR, "virustotal-key.txt")


class TIWorker(QThread):
    output_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def __init__(self, script, args=None):
        super().__init__()
        self.script = script
        self.args = args or []

    def run(self):
        try:
            cmd = ["bash", self.script] + self.args
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                self.output_line.emit(line.rstrip())
            process.wait()
            self.finished_ok.emit(process.returncode == 0)
        except Exception as e:
            self.output_line.emit(f"Error: {e}")
            self.finished_ok.emit(False)


class ThreatIntelWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.worker = None
        self._build_ui()
        self._load_status()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("THREAT INTELLIGENCE")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        sub_tabs = QTabWidget()
        sub_tabs.setStyleSheet("""
            QTabWidget::pane { border: none; background-color: #071417; }
            QTabBar { background-color: #0d2226; }
            QTabBar::tab {
                background-color: #0d2226;
                color: #8fb0b2;
                padding: 8px 16px;
                font-size: 11px;
                border-bottom: 2px solid transparent;
            }
            QTabBar::tab:selected { color: #1ed98a; border-bottom: 2px solid #1ed98a; }
            QTabBar::tab:hover { color: #14b874; }
        """)

        sub_tabs.addTab(self._build_feeds_tab(),    "  Feeds  ")
        sub_tabs.addTab(self._build_ioc_tab(),      "  IOC Manager  ")
        sub_tabs.addTab(self._build_search_tab(),   "  IOC Search  ")
        sub_tabs.addTab(self._build_settings_tab(), "  Settings  ")
        layout.addWidget(sub_tabs)

    def _build_feeds_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background-color: #071417;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        layout.setSpacing(12)

        self.status_cards = {}
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        for key, label, icon in [
            ("ip_feed",     "IP Blocklist",    "🌐"),
            ("url_feed",    "Malicious URLs",  "🔗"),
            ("yara_rules",  "YARA Rules",      "🧬"),
            ("last_update", "Last Update",     "🕐"),
        ]:
            card = QWidget()
            card.setStyleSheet("""
                QWidget {
                    background-color: #0d2226;
                    border: 1px solid #1a3a3f;
                    border-radius: 8px;
                }
            """)
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 10, 14, 10)
            cl.setSpacing(4)
            icon_lbl = QLabel(icon)
            icon_lbl.setStyleSheet("font-size: 18px; border: none;")
            name_lbl = QLabel(label)
            name_lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; letter-spacing: 1px; border: none;")
            val_lbl = QLabel("--")
            val_lbl.setStyleSheet("color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;")
            cl.addWidget(icon_lbl)
            cl.addWidget(name_lbl)
            cl.addWidget(val_lbl)
            self.status_cards[key] = val_lbl
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        update_btn = QPushButton("↻  Update Threat Intelligence Feeds")
        update_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
            QPushButton:disabled { background-color: #1a3a3f; color: #8fb0b2; }
        """)
        update_btn.clicked.connect(self._update_feeds)
        layout.addWidget(update_btn)

        self.feeds_log = QTextEdit()
        self.feeds_log.setReadOnly(True)
        self.feeds_log.setStyleSheet("""
            QTextEdit {
                background-color: #051012;
                color: #1ed98a;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                font-family: monospace;
                font-size: 11px;
                padding: 10px;
            }
        """)
        self.feeds_log.setPlaceholderText(
            "Press 'Update Feeds' to download latest threat intelligence.\n"
            "Requires internet connection.\n\n"
            "Sources: Feodo Tracker (botnet IPs), URLhaus (malicious URLs), YARA-Rules (malware signatures)"
        )
        layout.addWidget(self.feeds_log)
        return widget

    def _build_ioc_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background-color: #071417;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        layout.setSpacing(12)

        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        form_layout = QHBoxLayout(form_frame)
        form_layout.setContentsMargins(16, 12, 16, 12)
        form_layout.setSpacing(8)

        self.ioc_type = QComboBox()
        self.ioc_type.addItems(["IP", "Domain", "Hash MD5", "Hash SHA256", "URL"])
        self.ioc_type.setStyleSheet("""
            QComboBox {
                background-color: #061013;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 12px;
                min-width: 120px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
            }
        """)
        form_layout.addWidget(self.ioc_type)

        self.ioc_input = QLineEdit()
        self.ioc_input.setPlaceholderText("Enter IOC value (IP, domain, hash, URL...)")
        self.ioc_input.setStyleSheet("""
            QLineEdit {
                background-color: #061013;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QLineEdit:focus { border-color: #1ed98a; }
        """)
        self.ioc_input.returnPressed.connect(self._add_ioc)
        form_layout.addWidget(self.ioc_input)

        add_btn = QPushButton("Add IOC")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 6px;
                padding: 6px 16px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
        """)
        add_btn.clicked.connect(self._add_ioc)
        form_layout.addWidget(add_btn)
        layout.addWidget(form_frame)

        ioc_title = QLabel("CUSTOM IOC LIST")
        ioc_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(ioc_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.ioc_content = QWidget()
        self.ioc_content.setStyleSheet("background: transparent;")
        self.ioc_list_layout = QVBoxLayout(self.ioc_content)
        self.ioc_list_layout.setSpacing(6)
        self.ioc_list_layout.addStretch()
        scroll.setWidget(self.ioc_content)
        layout.addWidget(scroll)

        self._load_ioc_list()
        return widget

    def _build_search_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background-color: #071417;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        layout.setSpacing(12)

        info = QLabel(
            "Search for an IOC across threat intelligence feeds, active connections, "
            "and system logs. For IPs, also checks AbuseIPDB if API key is configured."
        )
        info.setStyleSheet("color: #d5e4e5; font-size: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        search_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter IP, domain, or hash to search...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                padding: 10px 16px;
                font-size: 13px;
            }
            QLineEdit:focus { border-color: #1ed98a; }
        """)
        self.search_input.returnPressed.connect(self._search_ioc)
        search_row.addWidget(self.search_input)

        self.search_type = QComboBox()
        self.search_type.addItems(["ip", "domain", "hash"])
        self.search_type.setStyleSheet("""
            QComboBox {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                padding: 10px 12px;
                font-size: 12px;
                min-width: 100px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #0d2226;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
            }
        """)
        search_row.addWidget(self.search_type)

        search_btn = QPushButton("Search")
        search_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 8px;
                padding: 10px 24px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
        """)
        search_btn.clicked.connect(self._search_ioc)
        search_row.addWidget(search_btn)
        layout.addLayout(search_row)

        self.search_log = QTextEdit()
        self.search_log.setReadOnly(True)
        self.search_log.setStyleSheet("""
            QTextEdit {
                background-color: #051012;
                color: #1ed98a;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                font-family: monospace;
                font-size: 11px;
                padding: 10px;
            }
        """)
        self.search_log.setPlaceholderText("Search results will appear here...")
        layout.addWidget(self.search_log)
        return widget

    def _build_settings_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background-color: #071417;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 16, 0, 0)
        layout.setSpacing(16)

        # AbuseIPDB API key
        api_frame = QFrame()
        api_frame.setStyleSheet("""
            QFrame {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        api_layout = QVBoxLayout(api_frame)
        api_layout.setContentsMargins(20, 16, 20, 16)
        api_layout.setSpacing(10)

        api_title = QLabel("VirusTotal API Key")
        api_title.setStyleSheet("color: #1ed98a; font-size: 13px; font-weight: bold;")
        api_layout.addWidget(api_title)

        api_info = QLabel(
            "VirusTotal checks IPs, domains, and file hashes against 70+ antivirus engines. "
            "Free tier: 500 queries/day. "
            "Get your free key at: virustotal.com"
        )
        api_info.setStyleSheet("color: #8fb0b2; font-size: 11px;")
        api_info.setWordWrap(True)
        api_layout.addWidget(api_info)

        key_row = QHBoxLayout()
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("Enter your VirusTotal API key...")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setStyleSheet("""
            QLineEdit {
                background-color: #061013;
                color: #e0e0e0;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
            }
            QLineEdit:focus { border-color: #1ed98a; }
        """)
        self.api_key_input.setText(self._load_apikey())
        key_row.addWidget(self.api_key_input)

        save_btn = QPushButton("Save Key")
        save_btn.setStyleSheet("""
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
        """)
        save_btn.clicked.connect(self._save_apikey)
        key_row.addWidget(save_btn)
        api_layout.addLayout(key_row)

        self.api_status = QLabel("")
        self.api_status.setStyleSheet("font-size: 11px;")
        api_layout.addWidget(self.api_status)
        layout.addWidget(api_frame)
        layout.addStretch()
        return widget

    def _load_apikey(self):
        try:
            with open(APIKEY_FILE) as f:
                return f.read().strip()
        except Exception:
            return ""

    def _save_apikey(self):
        key = self.api_key_input.text().strip()
        try:
            with open(APIKEY_FILE, "w") as f:
                f.write(key)
            self.api_status.setText("✓ API key saved for this session")
            self.api_status.setStyleSheet("color: #1ed98a; font-size: 11px;")
        except Exception as e:
            self.api_status.setText(f"✗ Error: {e}")
            self.api_status.setStyleSheet("color: #ff6b6b; font-size: 11px;")

    def _load_status(self):
        status_file = next((p for p in ("/var/lib/nefi/threat-intel/status.conf", _os.path.join(USER_DIR, "threat-intel", "status.conf")) if _os.path.exists(p)), "/var/lib/nefi/threat-intel/status.conf")
        if not os.path.exists(status_file):
            return
        try:
            with open(status_file) as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        if k == "LAST_UPDATE" and "last_update" in self.status_cards:
                            self.status_cards["last_update"].setText(v[:10])
                        elif k == "IOC_IPS" and "ip_feed" in self.status_cards:
                            self.status_cards["ip_feed"].setText(f"{v} IPs")
                        elif k == "YARA_FILES" and "yara_rules" in self.status_cards:
                            self.status_cards["yara_rules"].setText(f"{v} files")
        except Exception:
            pass

    def _update_feeds(self):
        self.feeds_log.clear()
        self.feeds_log.append("Updating threat intelligence feeds...")
        self.feeds_log.append("Requires internet connection.\n")
        self.worker = TIWorker("/opt/nefi/threat-intel/update-feeds.sh")
        self.worker.output_line.connect(self.feeds_log.append)
        self.worker.finished_ok.connect(self._on_feeds_done)
        self.worker.start()

    def _on_feeds_done(self, ok):
        self.feeds_log.append("\n✓ Feeds updated successfully." if ok else "\n✗ Update failed.")
        self._load_status()

    def _load_iocs(self):
        try:
            with open(IOC_FILE) as f:
                return json.load(f)
        except Exception:
            return []

    def _save_iocs(self, iocs):
        try:
            with open(IOC_FILE, "w") as f:
                json.dump(iocs, f, indent=2)
        except Exception as e:
            print(f"Error saving IOCs: {e}")

    def _add_ioc(self):
        value = self.ioc_input.text().strip()
        if not value:
            return
        ioc_type = self.ioc_type.currentText().lower().replace(" ", "_")
        iocs = self._load_iocs()
        if not any(i.get("value") == value for i in iocs):
            iocs.append({"type": ioc_type, "value": value, "vt_score": "pending"})
            self._save_iocs(iocs)
        self.ioc_input.clear()
        self._load_ioc_list()
        # Auto-check su VirusTotal se API key disponibile
        vt_key = self._load_apikey()
        if vt_key:
            self._auto_check_vt(value, ioc_type, vt_key)

    def _auto_check_vt(self, value, ioc_type, vt_key):
        simple_type = ioc_type.split("_")[0]
        worker = TIWorker(
            "/opt/nefi/threat-intel/search-ioc.sh",
            [value, simple_type, vt_key]
        )
        def on_result(line):
            if "[VIRUSTOTAL]" in line or "[CRITICAL]" in line or                "[WARNING]" in line or "[CLEAN]" in line:
                iocs = self._load_iocs()
                for i in iocs:
                    if i.get("value") == value:
                        if "[CRITICAL]" in line:
                            i["vt_score"] = "critical"
                        elif "[WARNING]" in line:
                            i["vt_score"] = "warning"
                        elif "[CLEAN]" in line:
                            i["vt_score"] = "clean"
                self._save_iocs(iocs)
                self._load_ioc_list()
        worker.output_line.connect(on_result)
        worker.start()
        self._vt_worker = worker

    def _manual_vt_check(self, value, ioc_type):
        vt_key = self._load_apikey()
        if not vt_key:
            return
        iocs = self._load_iocs()
        for i in iocs:
            if i.get("value") == value:
                i["vt_score"] = "pending"
        self._save_iocs(iocs)
        self._load_ioc_list()
        self._auto_check_vt(value, ioc_type, vt_key)

    def _remove_ioc(self, value):
        iocs = [i for i in self._load_iocs() if i.get("value") != value]
        self._save_iocs(iocs)
        self._load_ioc_list()

    def _load_ioc_list(self):
        while self.ioc_list_layout.count() > 1:
            item = self.ioc_list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        iocs = self._load_iocs()
        if not iocs:
            empty = QLabel("No custom IOCs added yet.")
            empty.setStyleSheet("color: #8fb0b2; font-size: 12px;")
            self.ioc_list_layout.insertWidget(0, empty)
            return

        for ioc in iocs:
            vt_score = ioc.get("vt_score", "unknown")
            if vt_score == "critical":
                border_color = "#ff6b6b"
                vt_text = "⚠ MALICIOUS"
                vt_color = "#ff6b6b"
            elif vt_score == "warning":
                border_color = "#ffaa00"
                vt_text = "⚠ SUSPICIOUS"
                vt_color = "#ffaa00"
            elif vt_score == "clean":
                border_color = "#1ed98a"
                vt_text = "✓ CLEAN"
                vt_color = "#1ed98a"
            elif vt_score == "pending":
                border_color = "#8fb0b2"
                vt_text = "⟳ CHECKING..."
                vt_color = "#8fb0b2"
            else:
                border_color = "#1a3a3f"
                vt_text = "— NOT CHECKED"
                vt_color = "#8fb0b2"

            row = QFrame()
            row.setStyleSheet(f"""
                QFrame {{
                    background-color: #0d2226;
                    border-left: 3px solid {border_color};
                    border-radius: 6px;
                }}
            """)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(12, 8, 12, 8)

            type_lbl = QLabel(ioc.get("type", "unknown").upper())
            type_lbl.setFixedWidth(90)
            type_lbl.setStyleSheet("color: #ffaa00; font-size: 10px; font-weight: bold; border: none;")
            val_lbl = QLabel(ioc.get("value", ""))
            val_lbl.setStyleSheet("color: #e0e0e0; font-size: 12px; border: none;")
            rl.addWidget(type_lbl)
            rl.addWidget(val_lbl)
            rl.addStretch()

            vt_lbl = QLabel(vt_text)
            vt_lbl.setStyleSheet(f"""
                color: {vt_color};
                background-color: {vt_color}11;
                border: 1px solid {vt_color};
                border-radius: 8px;
                padding: 2px 8px;
                font-size: 10px;
                font-weight: bold;
            """)
            rl.addWidget(vt_lbl)

            check_btn = QPushButton("VT Check")
            check_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #8fb0b2;
                    border: 1px solid #1a3a3f;
                    border-radius: 4px;
                    padding: 2px 8px;
                    font-size: 10px;
                }
                QPushButton:hover { border-color: #1ed98a; color: #1ed98a; }
            """)
            val = ioc.get("value", "")
            itype = ioc.get("type", "ip").split("_")[0]
            check_btn.clicked.connect(lambda checked, v=val, t=itype: self._manual_vt_check(v, t))
            rl.addWidget(check_btn)

            del_btn = QPushButton("✕")
            del_btn.setFixedWidth(28)
            del_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #8fb0b2;
                    border: 1px solid #1a3a3f;
                    border-radius: 4px;
                    font-size: 11px;
                }
                QPushButton:hover { border-color: #ff6b6b; color: #ff6b6b; }
            """)
            del_btn.clicked.connect(lambda checked, v=val: self._remove_ioc(v))
            rl.addWidget(del_btn)
            self.ioc_list_layout.insertWidget(
                self.ioc_list_layout.count() - 1, row
            )

    def _search_ioc(self):
        ioc = self.search_input.text().strip()
        if not ioc:
            return
        ioc_type = self.search_type.currentText()
        apikey = self._load_apikey() or "none"

        self.search_log.clear()
        self.search_log.append(f"Searching for: {ioc} (type: {ioc_type})\n")

        vt_key = self._load_apikey() or "none"
        self.worker = TIWorker(
            "/opt/nefi/threat-intel/search-ioc.sh",
            [ioc, ioc_type, vt_key]
        )
        self.worker.output_line.connect(self._on_search_line)
        self.worker.finished_ok.connect(
            lambda ok: self.search_log.append("\n✓ Search completed.")
        )
        self.worker.start()

    def _on_search_line(self, line):
        if "[CRITICAL]" in line or "[ALERT]" in line:
            self.search_log.setTextColor(__import__('PyQt6.QtGui', fromlist=['QColor']).QColor("#ff6b6b"))
        elif "[WARNING]" in line:
            self.search_log.setTextColor(__import__('PyQt6.QtGui', fromlist=['QColor']).QColor("#ffaa00"))
        elif "[CLEAN]" in line:
            self.search_log.setTextColor(__import__('PyQt6.QtGui', fromlist=['QColor']).QColor("#1ed98a"))
        elif "[MATCH]" in line:
            self.search_log.setTextColor(__import__('PyQt6.QtGui', fromlist=['QColor']).QColor("#ff6b6b"))
        else:
            self.search_log.setTextColor(__import__('PyQt6.QtGui', fromlist=['QColor']).QColor("#d5e4e5"))
        self.search_log.append(line)

    def refresh(self):
        self._load_status()
