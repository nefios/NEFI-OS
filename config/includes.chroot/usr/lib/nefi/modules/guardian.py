from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit,
    QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from guardian_worker import GuardianWorker

QUICK_PROMPTS = [
    "Analyze recent system logs",
    "Check for suspicious processes",
    "Guide me through forensic evidence collection",
    "Explain how to improve system hardening",
    "Check the status of security services",
]

WELCOME_ONLINE = (
    "Hello! I'm NEFI Guardian, your integrated AI for cybersecurity.\n\n"
    "I'm here to help you:\n"
    "• Analyze security logs and alerts\n"
    "• Guide you through incident response\n"
    "• Explain suspicious events and processes\n"
    "• Suggest hardening actions\n"
    "• Assist with threat hunting\n\n"
    "How can I help you today?"
)

WELCOME_OFFLINE = (
    "Hello! I'm NEFI Guardian, your integrated AI for cybersecurity.\n\n"
    "I'm here to help you:\n"
    "• Analyze security logs and alerts\n"
    "• Guide you through incident response\n"
    "• Explain suspicious events and processes\n"
    "• Suggest hardening actions\n"
    "• Assist with threat hunting\n\n"
    "⚠ The AI service is not yet active.\n\n"
    "To start it, open the terminal and type this command:\n\n"
    "    sudo nefi-ollama-setup\n\n"
    "This will start Ollama and download the AI model (about 4GB, first time only).\n"
    "When done, press the 'Reconnect' button above."
)

class MessageBubble(QFrame):
    def __init__(self, text, is_user=True, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        header = QHBoxLayout()
        role = QLabel("You" if is_user else "⬡ NEFI Guardian")
        role.setStyleSheet(f"""
            color: {'#8fb0b2' if is_user else '#1ed98a'};
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
        """)
        header.addWidget(role)
        header.addStretch()
        layout.addLayout(header)

        self.text_label = QLabel(text)
        self.text_label.setWordWrap(True)
        self.text_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.text_label.setStyleSheet(f"""
            color: {'#d5e4e5' if is_user else '#e0e0e0'};
            font-size: 13px;
            line-height: 1.5;
        """)
        layout.addWidget(self.text_label)

        if is_user:
            self.setStyleSheet("""
                QFrame {
                    background-color: #0d2226;
                    border: 1px solid #1a3a3f;
                    border-radius: 10px;
                    margin: 4px 80px 4px 4px;
                }
            """)
        else:
            self.setStyleSheet("""
                QFrame {
                    background-color: #0b2a26;
                    border: 1px solid #1ed98a33;
                    border-radius: 10px;
                    margin: 4px 4px 4px 80px;
                }
            """)


class GuardianWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self.messages = []
        self.current_bubble = None
        self.worker = None
        self._build_ui()
        self._check_ollama()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("NEFI GUARDIAN")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        header.addWidget(title)
        header.addStretch()

        self.reconnect_btn = QPushButton("Reconnect")
        self.reconnect_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d2226;
                color: #8fb0b2;
                border: 1px solid #1a3a3f;
                border-radius: 6px;
                padding: 4px 12px;
                font-size: 11px;
            }
            QPushButton:hover {
                border-color: #1ed98a;
                color: #1ed98a;
            }
        """)
        self.reconnect_btn.clicked.connect(self._check_ollama)
        header.addWidget(self.reconnect_btn)

        self.status_dot = QLabel("● Offline")
        self.status_dot.setStyleSheet("color: #ff6b6b; font-size: 11px; margin-left: 8px;")
        header.addWidget(self.status_dot)
        layout.addLayout(header)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid #1a3a3f;
                border-radius: 10px;
                background-color: #051012;
            }
        """)
        self.scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.chat_content = QWidget()
        self.chat_content.setStyleSheet("background-color: #051012;")
        self.chat_layout = QVBoxLayout(self.chat_content)
        self.chat_layout.setContentsMargins(12, 12, 12, 12)
        self.chat_layout.setSpacing(8)
        self.chat_layout.addStretch()
        self.scroll.setWidget(self.chat_content)
        layout.addWidget(self.scroll)

        quick_label = QLabel("QUICK ACTIONS")
        quick_label.setStyleSheet(
            "color: #8fb0b2; font-size: 10px; letter-spacing: 2px;"
        )
        layout.addWidget(quick_label)

        quick_row = QHBoxLayout()
        quick_row.setSpacing(8)
        for prompt in QUICK_PROMPTS:
            btn = QPushButton(prompt)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #0d2226;
                    color: #8fb0b2;
                    border: 1px solid #1a3a3f;
                    border-radius: 12px;
                    padding: 4px 10px;
                    font-size: 11px;
                }
                QPushButton:hover {
                    border-color: #1ed98a;
                    color: #1ed98a;
                }
            """)
            btn.clicked.connect(lambda checked, p=prompt: self._send(p))
            quick_row.addWidget(btn)
        layout.addLayout(quick_row)

        input_row = QHBoxLayout()
        input_row.setSpacing(8)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText(
            "Ask NEFI Guardian... e.g.: Analyze these logs, explain this alert..."
        )
        self.input_field.setStyleSheet("""
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
        self.input_field.returnPressed.connect(self._on_send)
        input_row.addWidget(self.input_field)

        self.send_btn = QPushButton("Send")
        self.send_btn.setFixedWidth(80)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #1ed98a;
                color: #061013;
                border: none;
                border-radius: 8px;
                padding: 10px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #14b874; }
            QPushButton:disabled {
                background-color: #1a3a3f;
                color: #8fb0b2;
            }
        """)
        self.send_btn.clicked.connect(self._on_send)
        input_row.addWidget(self.send_btn)
        layout.addLayout(input_row)

    def _check_ollama(self):
        try:
            import urllib.request
            urllib.request.urlopen(
                "http://127.0.0.1:11434/api/tags", timeout=2
            )
            self.status_dot.setText("● Online")
            self.status_dot.setStyleSheet("color: #1ed98a; font-size: 11px; margin-left: 8px;")
            self._clear_chat()
            self._add_guardian_message(WELCOME_ONLINE)
        except Exception:
            self.status_dot.setText("● Offline")
            self.status_dot.setStyleSheet("color: #ff6b6b; font-size: 11px; margin-left: 8px;")
            self._clear_chat()
            self._add_guardian_message(WELCOME_OFFLINE)

    def _clear_chat(self):
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.messages = []

    def _add_user_message(self, text):
        bubble = MessageBubble(text, is_user=True)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, bubble)
        self._scroll_bottom()

    def _add_guardian_message(self, text=""):
        bubble = MessageBubble(text, is_user=False)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, bubble)
        self._scroll_bottom()
        return bubble

    def _scroll_bottom(self):
        QTimer.singleShot(50, lambda: self.scroll.verticalScrollBar().setValue(
            self.scroll.verticalScrollBar().maximum()
        ))

    def _on_send(self):
        text = self.input_field.text().strip()
        if not text:
            return
        self.input_field.clear()
        self._send(text)

    def _send(self, text):
        if self.worker and self.worker.isRunning():
            return
        self._add_user_message(text)
        self.messages.append({"role": "user", "content": text})
        self.current_bubble = self._add_guardian_message("▋")
        self.send_btn.setEnabled(False)
        self.input_field.setEnabled(False)

        self.worker = GuardianWorker(self.messages.copy())
        self.worker.response_chunk.connect(self._on_chunk)
        self.worker.response_done.connect(self._on_done)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()

    def _on_chunk(self, text):
        if self.current_bubble:
            current = self.current_bubble.text_label.text()
            self.current_bubble.text_label.setText(
                text if current == "▋" else current + text
            )
            self._scroll_bottom()

    def _on_done(self):
        if self.current_bubble:
            final = self.current_bubble.text_label.text()
            self.messages.append({"role": "assistant", "content": final})
        self.send_btn.setEnabled(True)
        self.input_field.setEnabled(True)
        self.input_field.setFocus()
        self.current_bubble = None

    def _on_error(self, error):
        if self.current_bubble:
            self.current_bubble.text_label.setText(f"⚠ {error}")
            self.current_bubble.setStyleSheet("""
                QFrame {
                    background-color: #150707;
                    border: 1px solid #ff6b6b33;
                    border-radius: 10px;
                    margin: 4px 4px 4px 80px;
                }
            """)
        self.send_btn.setEnabled(True)
        self.input_field.setEnabled(True)
        self.current_bubble = None
