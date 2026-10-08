#!/bin/bash
# NEFI USB Guardian - eseguito come root (udev -> systemd-run) all'inserimento di un disco USB
DEV="${1:-}"
[[ "$DEV" =~ ^sd[a-z]{1,2}$ ]] || exit 0
exec /usr/bin/python3 /opt/nefi/usb-guardian/prompt.py handle "$DEV"
