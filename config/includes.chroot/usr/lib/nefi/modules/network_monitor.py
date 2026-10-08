import psutil
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

class NetworkMonitorWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #071417;")
        self._prev_io = psutil.net_io_counters()
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("NETWORK MONITOR")
        title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px;")
        layout.addWidget(title)

        iface_row = QHBoxLayout()
        iface_row.setSpacing(12)
        self.iface_cards = {}
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface in list(stats.keys())[:4]:
            card = self._make_iface_card(iface, stats, addrs)
            iface_row.addWidget(card)
        layout.addLayout(iface_row)

        io_title = QLabel("I/O TRAFFIC")
        io_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px; margin-top: 8px;")
        layout.addWidget(io_title)

        io_row = QHBoxLayout()
        io_row.setSpacing(12)

        self.sent_card = self._make_metric_card("SENT", "0 KB/s")
        self.recv_card = self._make_metric_card("RECEIVED", "0 KB/s")
        self.total_sent = self._make_metric_card("TOTAL TX", "0 MB")
        self.total_recv = self._make_metric_card("TOTAL RX", "0 MB")
        io_row.addWidget(self.sent_card[0])
        io_row.addWidget(self.recv_card[0])
        io_row.addWidget(self.total_sent[0])
        io_row.addWidget(self.total_recv[0])
        layout.addLayout(io_row)

        conn_title = QLabel("ACTIVE CONNECTIONS")
        conn_title.setStyleSheet("color: #8fb0b2; font-size: 11px; letter-spacing: 3px; margin-top: 8px;")
        layout.addWidget(conn_title)

        self.conn_table = QTableWidget()
        self.conn_table.setColumnCount(5)
        self.conn_table.setHorizontalHeaderLabels([
            "Proto", "Local Address", "Remote Address", "State", "PID"
        ])
        self.conn_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d2226;
                color: #e0e0e0;
                gridline-color: #1a3a3f;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
                font-size: 12px;
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
                padding: 4px 8px;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #0f3a30;
                color: #1ed98a;
            }
        """)
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.conn_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.conn_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.conn_table.verticalHeader().setVisible(False)
        layout.addWidget(self.conn_table)

    def _make_iface_card(self, iface, stats, addrs):
        card = QWidget()
        card.setStyleSheet("""
            QWidget {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(4)

        stat = stats.get(iface)
        is_up = stat.isup if stat else False
        ip = "--"
        if iface in addrs:
            for addr in addrs[iface]:
                if addr.family.name == "AF_INET":
                    ip = addr.address

        name_lbl = QLabel(iface.upper())
        name_lbl.setStyleSheet("color: #e0e0e0; font-size: 13px; font-weight: bold; border: none;")
        status_lbl = QLabel("● UP" if is_up else "● DOWN")
        status_lbl.setStyleSheet(f"color: {'#1ed98a' if is_up else '#ff6b6b'}; font-size: 11px; border: none;")
        ip_lbl = QLabel(ip)
        ip_lbl.setStyleSheet("color: #8fb0b2; font-size: 11px; border: none;")

        cl.addWidget(name_lbl)
        cl.addWidget(status_lbl)
        cl.addWidget(ip_lbl)
        return card

    def _make_metric_card(self, label, value):
        card = QWidget()
        card.setStyleSheet("""
            QWidget {
                background-color: #0d2226;
                border: 1px solid #1a3a3f;
                border-radius: 8px;
            }
        """)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(4)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #8fb0b2; font-size: 10px; letter-spacing: 1px; border: none;")
        val = QLabel(value)
        val.setStyleSheet("color: #1ed98a; font-size: 16px; font-weight: bold; border: none;")
        cl.addWidget(lbl)
        cl.addWidget(val)
        return card, val

    def refresh(self):
        curr = psutil.net_io_counters()
        sent_kb = (curr.bytes_sent - self._prev_io.bytes_sent) / 1024
        recv_kb = (curr.bytes_recv - self._prev_io.bytes_recv) / 1024
        self._prev_io = curr

        self.sent_card[1].setText(f"{sent_kb:.1f} KB/s")
        self.recv_card[1].setText(f"{recv_kb:.1f} KB/s")
        self.total_sent[1].setText(f"{curr.bytes_sent/1024**2:.1f} MB")
        self.total_recv[1].setText(f"{curr.bytes_recv/1024**2:.1f} MB")

        try:
            conns = psutil.net_connections(kind='inet')
            self.conn_table.setRowCount(0)
            for conn in conns[:100]:
                row = self.conn_table.rowCount()
                self.conn_table.insertRow(row)
                proto = "TCP" if conn.type.name == "SOCK_STREAM" else "UDP"
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "--"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "--"
                status = conn.status if conn.status else "--"
                pid = str(conn.pid) if conn.pid else "--"

                items = [proto, laddr, raddr, status, pid]
                for col, val in enumerate(items):
                    item = QTableWidgetItem(val)
                    item.setForeground(QColor("#1ed98a") if col == 3 and status == "ESTABLISHED" else QColor("#e0e0e0"))
                    self.conn_table.setItem(row, col, item)
        except Exception:
            pass
