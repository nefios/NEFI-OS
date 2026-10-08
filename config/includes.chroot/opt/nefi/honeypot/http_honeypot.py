#!/usr/bin/env python3
"""NEFI HTTP Honeypot — simulates a web server to detect attackers"""
import socket
import threading
import json
import os
from datetime import datetime

LOG_FILE = "/var/log/nefi/honeypot-http.json"
PORT = 8080

FAKE_PAGE = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html>
<html>
<head><title>Router Admin</title></head>
<body>
<h2>Router Administration Panel</h2>
<form method="post" action="/login">
Username: <input name="user"><br>
Password: <input type="password" name="pass"><br>
<input type="submit" value="Login">
</form>
</body>
</html>"""

def log_event(ip, port, method, path, headers, body=""):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "http",
        "src_ip": ip,
        "src_port": port,
        "method": method,
        "path": path,
        "headers": headers,
        "body": body[:500]
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"[HTTP-HONEYPOT] {method} {path} from {ip}:{port}")

def handle_client(conn, addr):
    ip, port = addr
    try:
        data = conn.recv(4096).decode("utf-8", errors="replace")
        if not data:
            return
        lines = data.split("\r\n")
        if lines:
            parts = lines[0].split(" ")
            method = parts[0] if len(parts) > 0 else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"
            headers = {}
            body = ""
            i = 1
            while i < len(lines) and lines[i]:
                if ":" in lines[i]:
                    k, v = lines[i].split(":", 1)
                    headers[k.strip()] = v.strip()
                i += 1
            if i < len(lines):
                body = "\r\n".join(lines[i+1:])
            log_event(ip, port, method, path, headers, body)
        conn.send(FAKE_PAGE)
    except Exception as e:
        print(f"[HTTP-HONEYPOT] Error: {e}")
    finally:
        conn.close()

def main():
    print(f"[HTTP-HONEYPOT] Starting on port {PORT}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    print(f"[HTTP-HONEYPOT] Listening on 0.0.0.0:{PORT}")
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
        except Exception as e:
            print(f"[HTTP-HONEYPOT] Error: {e}")

if __name__ == "__main__":
    main()
