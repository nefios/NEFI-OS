import psutil
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QProgressBar, QFrame, QGridLayout
)
from PyQt6.QtCore import Qt

class MetricCard(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QWidget {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet("color: #8fb0b2; font-size: 10px; letter-spacing: 2px; border: none;")
        layout.addWidget(self.title_label)

        self.value_label = QLabel("--")
        self.value_label.setStyleSheet("color: #e0e0e0; font-size: 22px; font-weight: bold; border: none;")
        layout.addWidget(self.value_label)

        self.bar = QProgressBar()
        self.bar.setFixedHeight(6)
        self.bar.setTextVisible(False)
        self.bar.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 3px;
                background-color: #1a3a3f;
            }
            QProgressBar::chunk {
                background-color: #1ed98a;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.bar)

        self.sub_label = QLabel("")
        self.sub_label.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")
        layout.addWidget(self.sub_label)

    def update(self, value_text, percent, sub_text="", warning=False):
        self.value_label.setText(value_text)
        self.bar.setValue(int(percent))
        self.sub_label.setText(sub_text)
        color = "#ff6b6b" if warning else "#1ed98a"
        self.bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 3px;
                background-color: #1a3a3f;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
        border = "#ff6b6b" if warning else "#1a3a3f"
        self.setStyleSheet(f"""
            QWidget {{
                background-color: #0d2226;
                border: 1px solid {border};
                border-radius: 8px;
            }}
        """)


class SystemStatusWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("SYSTEM OVERVIEW")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        grid = QHBoxLayout()
        grid.setSpacing(16)
        self.cpu_card  = MetricCard("CPU")
        self.ram_card  = MetricCard("Memory")
        self.disk_card = MetricCard("Disk")
        self.up_card   = MetricCard("Uptime")
        grid.addWidget(self.cpu_card)
        grid.addWidget(self.ram_card)
        grid.addWidget(self.disk_card)
        grid.addWidget(self.up_card)
        layout.addLayout(grid)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1a3a3f;")
        layout.addWidget(sep)

        info_title = QLabel("SYSTEM INFORMATION")
        info_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(info_title)

        info_grid = QGridLayout()
        info_grid.setSpacing(8)
        self.info_labels = {}
        fields = [
            ("Kernel",      "kernel"),
            ("CPU cores",   "cores"),
            ("Swap",        "swap"),
            ("Processes",   "procs"),
        ]
        for i, (label, key) in enumerate(fields):
            lbl = QLabel(label.upper())
            lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; letter-spacing: 1px;")
            val = QLabel("--")
            val.setStyleSheet("color: #e0e0e0; font-size: 13px;")
            info_grid.addWidget(lbl, i // 2, (i % 2) * 2)
            info_grid.addWidget(val, i // 2, (i % 2) * 2 + 1)
            self.info_labels[key] = val
        layout.addLayout(info_grid)
        layout.addStretch()

    def refresh(self):
        import platform

        cpu = psutil.cpu_percent(interval=None)
        self.cpu_card.update(f"{cpu:.1f}%", cpu, f"{psutil.cpu_count()} cores", warning=cpu > 80)

        ram = psutil.virtual_memory()
        used = ram.used / 1024**3
        total = ram.total / 1024**3
        self.ram_card.update(f"{ram.percent:.0f}%", ram.percent,
                             f"{used:.1f} / {total:.1f} GB", warning=ram.percent > 85)

        disk = psutil.disk_usage('/')
        used_d = disk.used / 1024**3
        total_d = disk.total / 1024**3
        self.disk_card.update(f"{disk.percent:.0f}%", disk.percent,
                              f"{used_d:.1f} / {total_d:.1f} GB", warning=disk.percent > 90)

        uptime_sec = int(time.time() - psutil.boot_time())
        h = uptime_sec // 3600
        m = (uptime_sec % 3600) // 60
        self.up_card.update(f"{h}h {m}m", min(100, uptime_sec // 3600), "since boot")

        self.info_labels["kernel"].setText(platform.release())
        self.info_labels["cores"].setText(str(psutil.cpu_count(logical=True)))
        swap = psutil.swap_memory()
        self.info_labels["swap"].setText(f"{swap.used/1024**3:.1f} / {swap.total/1024**3:.1f} GB")
        self.info_labels["procs"].setText(str(len(psutil.pids())))
