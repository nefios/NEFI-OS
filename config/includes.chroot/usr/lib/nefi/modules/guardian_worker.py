import json
import subprocess
import urllib.request
import urllib.error
from PyQt6.QtCore import QThread, pyqtSignal

SYSTEM_PROMPT = """You are NEFI Guardian, the AI assistant integrated into NEFI OS.
NEFI OS is a professional Linux distribution focused on defensive cybersecurity (Blue Team).

Your role is to:
- Analyze REAL system data provided in the context
- Explain security alerts clearly
- Identify anomalies in logs and processes
- Guide the user through incident response
- Suggest concrete hardening actions
- Assist with threat hunting

When analyzing system data:
1. Be specific — cite the real values you see
2. Identify concrete anomalies
3. Structure your response as: ANALYSIS, SEVERITY (Low/Medium/High/Critical), RECOMMENDED ACTIONS
4. If everything looks normal, say so clearly

Rules:
- Always respond in English
- Do not invent data that isn't in the context
- You are a Blue Team assistant — defense only
- If you don't have enough data, ask for it explicitly
- Be concise, maximum 150 words per response
"""

def get_system_context():
    """Collects real system data, quickly and lightly."""
    context = []

    try:
        services = "apparmor auditd nftables suricata clamav-daemon ufw"
        result = subprocess.run(
            ["systemctl", "is-active", *services.split()],
             capture_output=True, text=True, timeout=3
        )
        statuses = result.stdout.strip().split("\n")
        names = services.split()
        lines = [f"{n}: {s}" for n, s in zip(names, statuses)]
        context.append("SECURITY SERVICES:\n" + "\n".join(lines))
    except Exception:
        context.append("SECURITY SERVICES: not available")

    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.3)
        ram = psutil.virtual_memory()
        context.append(f"RESOURCES: CPU {cpu}% — RAM {ram.percent}%")
    except Exception:
        pass

    try:
        result = subprocess.run(
            "ps -e --no-headers | wc -l",
            shell=True, capture_output=True, text=True, timeout=2
        )
        context.append(f"ACTIVE PROCESSES: {result.stdout.strip()}")
    except Exception:
        pass

    try:
        result = subprocess.run(
            "ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}'",
            shell=True, capture_output=True, text=True, timeout=3
        )
        ports = result.stdout.strip()
        context.append(f"LISTENING PORTS:\n{ports if ports else 'none'}")
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["journalctl", "-n", "15", "--no-pager", "-p", "warning", "-o", "cat"],
            capture_output=True, text=True, timeout=3
        )
        logs = result.stdout.strip()
        context.append(f"RECENT LOGS (warning/error):\n{logs if logs else 'none'}")
    except Exception:
        pass

    return "\n\n".join(context)


class GuardianWorker(QThread):
    response_chunk = pyqtSignal(str)
    response_done  = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, messages, include_context=True):
        super().__init__()
        self.messages = messages
        self.include_context = include_context

    def run(self):
        try:
            messages = self.messages.copy()

            if self.include_context and messages:
                context = get_system_context()
                last_user_msg = messages[-1]["content"]
                messages[-1]["content"] = (
                    f"[REAL SYSTEM DATA]\n{context}\n\n"
                    f"[USER REQUEST]\n{last_user_msg}"
                )

            payload = {
                "model": "mistral",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT}
                ] + messages,
                "stream": True
            }

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                "http://127.0.0.1:11434/api/chat",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=180) as resp:
                for line in resp:
                    line = line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        content = obj.get("message", {}).get("content", "")
                        if content:
                            self.response_chunk.emit(content)
                        if obj.get("done", False):
                            break
                    except json.JSONDecodeError:
                        continue

            self.response_done.emit()

        except urllib.error.URLError:
            self.error_occurred.emit(
                "Ollama is not reachable.\n\nStart the service:\nsudo nefi-ollama-setup"
            )
        except Exception as e:
            self.error_occurred.emit(f"Error: {str(e)}")
