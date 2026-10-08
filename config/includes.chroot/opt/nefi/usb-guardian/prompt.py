#!/usr/bin/env python3
"""NEFI USB Guardian.

  prompt.py handle <dev>   eseguito come ROOT (udev -> systemd-run): whitelist,
                           chiede all'utente con sessione grafica, applica la scelta.
  prompt.py ask <testo>    eseguito come UTENTE: mostra la finestra e stampa
                           allow / readonly / block.

Sicurezza: nessun comando passa dalla shell; nome dispositivo e testi presi
dalla chiavetta vengono validati/ripuliti; se nessuno risponde -> block.
"""
import json
import os
import pwd
import re
import subprocess
import sys
import time

WHITELIST_FILE = "/var/lib/nefi/usb-whitelist.json"
LOG_FILE = "/var/log/nefi-usb-guardian.log"
ACTIONS = ("allow", "readonly", "block")
DEV_RE = re.compile(r"^sd[a-z]{1,2}$")


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except OSError:
        pass


def run(args, timeout=10):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(args, 1, "", "")


def clean(text, limit=60):
    """Testo fornito dalla chiavetta: solo caratteri innocui, lunghezza limitata."""
    return re.sub(r"[^\w .:+\-]", "", text or "")[:limit].strip() or "?"


def device_props(dev):
    out = run(["udevadm", "info", "--query=property", f"--name=/dev/{dev}"], timeout=5).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def load_whitelist():
    try:
        with open(WHITELIST_FILE) as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if isinstance(k, str) and v in ACTIONS}
    except (OSError, ValueError, AttributeError):
        return {}


def save_whitelist(data):
    os.makedirs(os.path.dirname(WHITELIST_FILE), mode=0o755, exist_ok=True)
    tmp = WHITELIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o644)
    os.replace(tmp, WHITELIST_FILE)


def graphical_user():
    """Utente con una sessione grafica locale attiva (Wayland o X11)."""
    for line in run(["loginctl", "list-sessions", "--no-legend"]).stdout.splitlines():
        sid = line.split()[0] if line.split() else ""
        if not sid:
            continue
        info = run(["loginctl", "show-session", sid, "-p", "Name", "-p", "Type",
                    "-p", "Active", "-p", "Remote"]).stdout
        p = dict(l.split("=", 1) for l in info.splitlines() if "=" in l)
        if p.get("Active") == "yes" and p.get("Type") in ("wayland", "x11") and p.get("Remote") != "yes":
            return p.get("Name")
    return None


def ask_user(user, text):
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return "block"
    rundir = f"/run/user/{pw.pw_uid}"
    env = ["env", f"XDG_RUNTIME_DIR={rundir}",
           f"DBUS_SESSION_BUS_ADDRESS=unix:path={rundir}/bus",
           "DISPLAY=:0", f"XAUTHORITY={pw.pw_dir}/.Xauthority"]
    if os.path.isdir(rundir):
        wl = sorted(f for f in os.listdir(rundir) if re.fullmatch(r"wayland-\d+", f))
        if wl:
            env.append(f"WAYLAND_DISPLAY={wl[0]}")
    res = run(["runuser", "-u", user, "--", *env, "/usr/bin/python3",
               os.path.abspath(__file__), "ask", text], timeout=300)
    lines = res.stdout.strip().splitlines()
    return lines[-1] if lines and lines[-1] in ACTIONS else "block"


def usb_sysfs_device(dev):
    """Cartella sysfs del dispositivo USB che contiene il disco (quella con 'authorized')."""
    path = os.path.realpath(f"/sys/class/block/{dev}")
    while path not in ("/", "/sys"):
        if os.path.exists(os.path.join(path, "idVendor")) and os.path.exists(os.path.join(path, "authorized")):
            return path
        path = os.path.dirname(path)
    return None


def apply_action(dev, action):
    parts = sorted(d for d in os.listdir("/sys/class/block") if d.startswith(dev) and d != dev)
    if action in ("readonly", "block"):
        for d in parts + [dev]:
            run(["umount", f"/dev/{d}"])
    if action == "readonly":
        for d in [dev] + parts:
            run(["blockdev", "--setro", f"/dev/{d}"])
    elif action == "block":
        usb = usb_sysfs_device(dev)
        if usb:
            try:
                with open(os.path.join(usb, "authorized"), "w") as f:
                    f.write("0")
            except OSError as e:
                log(f"{dev}: impossibile disattivare il dispositivo: {e}")


def handle(dev):
    if os.geteuid() != 0 or not DEV_RE.match(dev):
        return
    props = device_props(dev)
    vendor = clean(props.get("ID_VENDOR", "Unknown"), 30)
    model = clean(props.get("ID_MODEL", "USB Device"), 40)
    serial = clean(props.get("ID_SERIAL_SHORT") or props.get("ID_SERIAL", ""), 80)
    if serial == "?":
        serial = None          # senza seriale niente memoria: si chiede ogni volta

    whitelist = load_whitelist()
    if serial and serial in whitelist:
        action = whitelist[serial]
        log(f"{dev} {vendor} {model} [{serial}]: {action} (scelta salvata)")
    else:
        user = graphical_user()
        action = ask_user(user, f"{vendor} {model}") if user else "block"
        if serial:
            whitelist[serial] = action
            save_whitelist(whitelist)
        log(f"{dev} {vendor} {model} [{serial}]: {action} (utente: {user or 'nessuno'})")
    apply_action(dev, action)


def ask(text):
    from PyQt6.QtWidgets import QApplication, QMessageBox

    app = QApplication(sys.argv[:1])
    box = QMessageBox()
    box.setWindowTitle("NEFI USB Guardian")
    box.setText(f"USB device detected:\n\n{clean(text, 80)}\n\nHow do you want to proceed?")
    box.setIcon(QMessageBox.Icon.Warning)
    box.setStyleSheet("""
        QMessageBox { background-color: #071417; }
        QLabel { color: #e0e0e0; font-size: 13px; }
        QPushButton {
            background-color: #0d2226; color: #1ed98a; border: 1px solid #1ed98a;
            border-radius: 6px; padding: 8px 16px; min-width: 100px;
        }
        QPushButton:hover { background-color: #1ed98a; color: #061013; }
    """)
    allow_btn = box.addButton("Allow", QMessageBox.ButtonRole.AcceptRole)
    ro_btn = box.addButton("Read-only", QMessageBox.ButtonRole.ActionRole)
    box.addButton("Block", QMessageBox.ButtonRole.RejectRole)
    box.exec()
    clicked = box.clickedButton()
    print("allow" if clicked == allow_btn else "readonly" if clicked == ro_btn else "block")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "handle":
        handle(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "ask":
        ask(sys.argv[2])
