"""NEFI OS - lettura dello stato di Incident Response (/var/lib/nefi/ir/ir-state.conf).

Il file e' scritto da /opt/nefi/ir/state.sh: righe CHIAVE=valore, una per chiave.
Il parser e' comunque tollerante con i file delle versioni vecchie, che ripetevano le chiavi:
vince l'ULTIMO valore (prima si cercava "IR_ACTIVE=true" nel testo e l'IR risultava sempre attivo).
Nessuna dipendenza da Qt: si puo' testare con python3 da solo (tests/test_ir_state.py).
"""
import re

STATE_FILE = "/var/lib/nefi/ir/ir-state.conf"
_LINE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


def parse(text):
    """Testo del file -> dict {chiave: valore}; righe vuote, commenti e righe non valide ignorate."""
    state = {}
    for line in (text or "").splitlines():
        m = _LINE.match(line.strip())
        if m:
            state[m.group(1)] = m.group(2).strip()   # chiave ripetuta: vince l'ultima
    return state


def read(path=STATE_FILE):
    """Stato letto dal file; {} se manca, non e' leggibile o non e' testo."""
    try:
        with open(path, encoding="utf-8") as f:
            return parse(f.read())
    except (OSError, UnicodeDecodeError):
        return {}


def is_active(state):
    return str(state.get("IR_ACTIVE", "")).strip().lower() == "true"
