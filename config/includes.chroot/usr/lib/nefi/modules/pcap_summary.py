"""NEFI OS - riepilogo di un file PCAP senza strumenti esterni e senza root.

Legge il formato pcap classico (quello scritto da tcpdump e da "dumpcap -P") e conta:
conversazioni, porte, richieste DNS, nomi dei server TLS (SNI) e host HTTP.
Serve per capire in pochi secondi cosa c'e' in una cattura; l'analisi vera si fa con Wireshark.
Nessuna dipendenza da Qt: si prova con tests/test_monitoring.py.
"""
import collections
import ipaddress
import re
import struct

MAX_PACKETS = 2_000_000
HOST_RE = re.compile(rb"\r\nHost:[ \t]*([^\r\n]{1,253})\r\n", re.I)
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _dns_name(data, off):
    labels = []
    for _ in range(64):
        if off >= len(data):
            return None
        n = data[off]
        if n == 0:
            return ".".join(labels)
        if n & 0xC0:                      # puntatore di compressione: nelle domande non serve seguirlo
            return ".".join(labels) or None
        off += 1
        labels.append(data[off:off + n].decode("ascii", "replace"))
        off += n
    return None


def dns_query(payload):
    """Nome chiesto in un pacchetto DNS (solo domande, non risposte), oppure None."""
    if len(payload) < 17:
        return None
    flags, qd = struct.unpack("!HH", payload[2:6])
    if flags & 0x8000 or qd < 1:
        return None
    return _dns_name(payload, 12)


def tls_sni(payload):
    """Nome del server in un ClientHello TLS, oppure None."""
    try:
        if len(payload) < 48 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 43                                         # record(5) + handshake(4) + versione(2) + random(32)
        p += 1 + payload[p]                            # session id
        p += 2 + struct.unpack("!H", payload[p:p + 2])[0]   # cipher suites
        p += 1 + payload[p]                            # compression
        end = p + 2 + struct.unpack("!H", payload[p:p + 2])[0]
        p += 2
        while p + 4 <= min(end, len(payload)):
            etype, elen = struct.unpack("!HH", payload[p:p + 4])
            p += 4
            if etype == 0 and elen >= 5:
                n = struct.unpack("!H", payload[p + 3:p + 5])[0]
                return payload[p + 5:p + 5 + n].decode("ascii", "replace").lower()
            p += elen
    except (IndexError, struct.error):
        pass
    return None


def _ip_layer(frame, linktype):
    """-> (versione IP, byte dal primo byte dell'intestazione IP) oppure (0, b'')."""
    if linktype == 1:                                  # Ethernet (con eventuali VLAN)
        off, etype = 14, frame[12:14]
        while etype in (b"\x81\x00", b"\x88\xa8") and len(frame) >= off + 4:
            etype, off = frame[off + 2:off + 4], off + 4
    elif linktype == 113:                              # Linux cooked v1
        off, etype = 16, frame[14:16]
    elif linktype == 276:                              # Linux cooked v2
        off, etype = 20, frame[0:2]
    elif linktype in (101, 228, 229, 12):              # IP senza intestazione di collegamento
        off, etype = 0, b"\x08\x00" if frame[:1] and frame[0] >> 4 == 4 else b"\x86\xdd"
    else:
        return 0, b""
    if etype == b"\x08\x00":
        return 4, frame[off:]
    if etype == b"\x86\xdd":
        return 6, frame[off:]
    return 0, b""


def summarize(path, max_packets=MAX_PACKETS):
    out = {"packets": 0, "bytes": 0, "first": None, "last": None, "truncated": False, "non_ip": 0,
           "error": ""}
    conv, ports, dns, sni, http, protos = (collections.Counter() for _ in range(6))
    conv_bytes = collections.Counter()
    try:
        f = open(path, "rb")
    except OSError as e:
        out["error"] = str(e)
        return out
    with f:
        head = f.read(24)
        if len(head) < 24:
            out["error"] = "empty file: no packets were captured"
            return out
        magic = head[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            out["error"] = "this file is in pcapng format: open it with Wireshark"
            return out
        else:
            out["error"] = "not a pcap file"
            return out
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(end + "I", head[20:24])[0] & 0xFFFF
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            sec, frac, incl, orig = struct.unpack(end + "IIII", rec)
            if incl > 262144 + 65536:
                out["error"] = "corrupted record: the summary stops here"
                break
            frame = f.read(incl)
            if len(frame) < incl:
                out["truncated"] = True            # ultima scrittura interrotta: normale se la cattura e' stata fermata
                break
            ts = sec + frac / (1e9 if nano else 1e6)
            out["first"] = ts if out["first"] is None else out["first"]
            out["last"] = ts
            out["packets"] += 1
            out["bytes"] += orig
            if out["packets"] >= max_packets:
                out["truncated"] = True
                break
            ver, ip = _ip_layer(frame, linktype)
            try:
                if ver == 4 and len(ip) >= 20:
                    ihl, proto = (ip[0] & 0x0F) * 4, ip[9]
                    src, dst = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
                    l4 = ip[ihl:]
                elif ver == 6 and len(ip) >= 40:
                    proto = ip[6]
                    src, dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
                    l4 = ip[40:]
                else:
                    out["non_ip"] += 1
                    continue
            except (ValueError, IndexError):
                out["non_ip"] += 1
                continue
            name = PROTO.get(proto, f"IP proto {proto}")
            protos[name] += 1
            a, b = sorted((src, dst))
            conv[(a, b, name)] += 1
            conv_bytes[(a, b, name)] += orig
            if proto in (6, 17) and len(l4) >= 8:
                sport, dport = struct.unpack("!HH", l4[:4])
                service = min(sport, dport) if min(sport, dport) < 1024 or max(sport, dport) >= 32768 else dport
                ports[f"{service}/{name}"] += 1
                if proto == 17:
                    payload = l4[8:]
                    if 53 in (sport, dport) or 5353 in (sport, dport):
                        q = dns_query(payload)
                        if q:
                            dns[q.lower()] += 1
                elif len(l4) >= 20:
                    payload = l4[(l4[12] >> 4) * 4:]
                    if payload:
                        if payload[0] == 0x16:
                            s = tls_sni(payload)
                            if s:
                                sni[s] += 1
                        elif dport in (80, 8080, 8000) and payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                            m = HOST_RE.search(payload[:2048])
                            if m:
                                http[m.group(1).decode("ascii", "replace").lower()] += 1
    out["protocols"] = protos.most_common(10)
    out["conversations"] = [(a, b, p, n, conv_bytes[(a, b, p)]) for (a, b, p), n in conv.most_common(25)]
    out["ports"] = ports.most_common(20)
    out["dns"] = dns.most_common(40)
    out["tls"] = sni.most_common(40)
    out["http"] = http.most_common(20)
    return out


def as_text(s):
    """Riepilogo leggibile (quello mostrato nella pagina Packet Capture)."""
    import time
    if s.get("error") and not s.get("packets"):
        return s["error"]
    fmt = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "?"   # noqa: E731
    lines = [f"{s['packets']} packets, {s['bytes'] / 1e6:.2f} MB on the wire, from {fmt(s['first'])} to {fmt(s['last'])}"]
    if s.get("truncated"):
        lines.append("(the file ends in the middle of a packet or is very large: the summary covers what was read)")
    if s.get("error"):
        lines.append("WARNING: " + s["error"])
    lines.append("\nProtocols: " + ", ".join(f"{p} {n}" for p, n in s.get("protocols", []))
                 + (f", non-IP {s['non_ip']}" if s.get("non_ip") else ""))
    lines.append("\nTop conversations (packets, bytes):")
    lines += [f"  {a:<39} <-> {b:<39} {p:<6} {n:>8} {by / 1e3:>10.1f} kB" for a, b, p, n, by in s.get("conversations", [])[:15]]
    for title, key in (("Services (port/protocol, packets)", "ports"), ("DNS names asked", "dns"),
                       ("TLS server names (SNI)", "tls"), ("HTTP hosts (unencrypted)", "http")):
        if s.get(key):
            lines.append(f"\n{title}:")
            lines += [f"  {n:>7}  {k}" for k, n in s[key][:20]]
    return "\n".join(lines)
