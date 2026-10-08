#!/usr/bin/env python3
"""NEFI USB Guardian - salva la whitelist (eseguito come root via pkexec).
Legge il JSON da stdin, accetta solo voci valide, scrive in modo atomico."""
import json
import os
import re
import sys

WHITELIST_FILE = "/var/lib/nefi/usb-whitelist.json"
ACTIONS = ("allow", "readonly", "block")

try:
    data = json.loads(sys.stdin.read(1_000_000))
except ValueError:
    sys.exit("NEFI: whitelist non valida (JSON)")
if not isinstance(data, dict) or len(data) > 500:
    sys.exit("NEFI: whitelist non valida")
clean = {}
for serial, action in data.items():
    if not (isinstance(serial, str) and re.fullmatch(r"[\w .:+\-]{1,80}", serial) and action in ACTIONS):
        sys.exit("NEFI: voce non valida nella whitelist")
    clean[serial] = action

os.makedirs(os.path.dirname(WHITELIST_FILE), mode=0o755, exist_ok=True)
tmp = WHITELIST_FILE + ".tmp"
with open(tmp, "w") as f:
    json.dump(clean, f, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, WHITELIST_FILE)
print(f"NEFI: whitelist salvata ({len(clean)} dispositivi)")
