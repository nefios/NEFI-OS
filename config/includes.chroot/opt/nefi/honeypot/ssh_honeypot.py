#!/usr/bin/env python3
"""NEFI SSH Honeypot — simulates an SSH server to detect attackers"""
import socket
import threading
import json
import os
from datetime import datetime

LOG_FILE = "/var/log/nefi/honeypot-ssh.json"
PORT = 2222

def log_event(ip, port, data):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "ssh",
        "src_ip": ip,
        "src_port": port,
        "data": data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"[SSH-HONEYPOT] Connection from {ip}:{port} — {data[:50]}")

def handle_client(conn, addr):
    ip, port = addr
    try:
        # Send fake SSH banner
        conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        data = conn.recv(1024)
        if data:
            log_event(ip, port, data.decode("utf-8", errors="replace"))
        # Keep connection alive briefly to gather more data
        for _ in range(3):
            try:
                more = conn.recv(1024)
                if more:
                    log_event(ip, port, more.decode("utf-8", errors="replace"))
            except Exception:
                break
    except Exception as e:
        log_event(ip, port, f"Connection error: {e}")
    finally:
        conn.close()

def main():
    print(f"[SSH-HONEYPOT] Starting on port {PORT}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    print(f"[SSH-HONEYPOT] Listening on 0.0.0.0:{PORT}")
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
        except Exception as e:
            print(f"[SSH-HONEYPOT] Error: {e}")

if __name__ == "__main__":
    main()
