import subprocess
import time
import os
import hashlib
from PyQt6.QtCore import QThread, pyqtSignal

CRITICAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/crontab",
    "/etc/hosts", "/etc/nsswitch.conf"
]

SUSPICIOUS_PATTERNS = [
    ("python", "bash"), ("python", "sh"), ("python3", "bash"),
    ("php", "bash"), ("php", "sh"),
    ("apache2", "bash"), ("nginx", "bash"),
    ("vim", "bash"), ("nano", "bash"),
]

SEVERITY_COLORS = {
    "info": "#8fb0b2",
    "low": "#1ed98a",
    "medium": "#ffaa00",
    "high": "#ff6b6b",
    "critical": "#ff0040",
}


class EDREvent:
    def __init__(self, category, severity, title, description, timestamp=None):
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.timestamp = timestamp or time.strftime("%Y-%m-%d %H:%M:%S")


class EDREngine(QThread):
    new_event = pyqtSignal(object)
    stats_update = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.running = True
        self.file_hashes = {}
        self.known_pids = set()
        self.known_connections = set()
        self.events_count = 0
        self.own_pid = str(os.getpid())

    def _hash_file(self, path):
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    def _init_baseline(self):
        for f in CRITICAL_FILES:
            if os.path.exists(f):
                self.file_hashes[f] = self._hash_file(f)

        try:
            result = subprocess.run(
                "ps -eo pid --no-headers", shell=True,
                capture_output=True, text=True, timeout=3
            )
            self.known_pids = set(result.stdout.split())
        except Exception:
            pass

    def _check_files(self):
        for f in CRITICAL_FILES:
            if not os.path.exists(f):
                continue
            new_hash = self._hash_file(f)
            old_hash = self.file_hashes.get(f)
            if old_hash and new_hash and old_hash != new_hash:
                self.new_event.emit(EDREvent(
                    "file", "high",
                    f"Critical file modified: {f}",
                    f"The file {f} has been modified. Previous hash differs from current. "
                    f"Check who made the change with: auditctl -w {f}"
                ))
            self.file_hashes[f] = new_hash

    def _check_processes(self):
        try:
            result = subprocess.run(
                "ps -eo pid,ppid,comm --no-headers", shell=True,
                capture_output=True, text=True, timeout=3
            )
            lines = result.stdout.strip().split("\n")
            current_pids = set()
            pid_map = {}

            for line in lines:
                parts = line.split(None, 2)
                if len(parts) < 3:
                    continue
                pid, ppid, comm = parts[0], parts[1], parts[2]
                current_pids.add(pid)
                pid_map[pid] = (ppid, comm)

            new_pids = current_pids - self.known_pids

            for pid in new_pids:
                ppid, comm = pid_map.get(pid, (None, ""))

                if ppid == self.own_pid:
                    continue

                parent_comm = pid_map.get(ppid, (None, ""))[1] if ppid else ""

                if ppid == self.own_pid or parent_comm.lower() in ("nefi-security-center",):
                    continue

                for parent_pattern, child_pattern in SUSPICIOUS_PATTERNS:
                    if parent_pattern in parent_comm.lower() and child_pattern in comm.lower():
                        self.new_event.emit(EDREvent(
                            "process", "high",
                            f"Suspicious behavior: {parent_comm} → {comm}",
                            f"Process '{parent_comm}' (PID {ppid}) launched '{comm}' (PID {pid}). "
                            f"This pattern is typical of web shells or exploits. Verify immediately."
                        ))

            self.known_pids = current_pids
            return len(current_pids)
        except Exception:
            return 0

    def _check_network(self):
        try:
            result = subprocess.run(
                "ss -tn state established --no-header 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=3
            )
            lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
            current_conns = set(lines)
            new_conns = current_conns - self.known_connections

            for conn in new_conns:
                parts = conn.split()
                if len(parts) >= 4:
                    remote = parts[3] if len(parts) > 3 else "unknown"
                    self.new_event.emit(EDREvent(
                        "network", "info",
                        f"New network connection",
                        f"New connection established to {remote}"
                    ))

            self.known_connections = current_conns
            return len(current_conns)
        except Exception:
            return 0

    def _check_persistence(self):
        try:
            result = subprocess.run(
                "find /etc/cron* /var/spool/cron -newermt '-60 seconds' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=3
            )
            files = result.stdout.strip()
            if files:
                self.new_event.emit(EDREvent(
                    "persistence", "medium",
                    "Crontab modification detected",
                    f"Recently modified cron files:\n{files}"
                ))
        except Exception:
            pass

    def run(self):
        self._init_baseline()
        self.new_event.emit(EDREvent(
            "info", "info",
            "NEFI EDR started",
            "Active monitoring: processes, critical files, network, persistence."
        ))

        while self.running:
            try:
                self._check_files()
                proc_count = self._check_processes()
                conn_count = self._check_network()
                self._check_persistence()

                self.stats_update.emit({
                    "processes": proc_count,
                    "connections": conn_count,
                    "files_monitored": len(self.file_hashes),
                })

            except Exception:
                pass

            time.sleep(5)

    def stop(self):
        self.running = False
