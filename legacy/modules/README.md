# legacy/modules/

Security Center modules that no page loads any more. They are kept for reference and are **not** packaged.

| Module | Replaced by |
|---|---|
| `edr.py`, `edr_engine.py` | The detection engine (`/opt/nefi/detection/`, `detection_pages.py`): it runs as root and also watches `/etc/shadow` and `/etc/sudoers` |
| `forensics.py` | `forensics_pages.py` (Evidence & Custody, Memory, Timeline, Disk) |
| `secureboot_monitor.py` | The Boot Integrity page (`system_pages.py`) |
| `security_status.py` | The Security Services page (`system_pages.py`) |
