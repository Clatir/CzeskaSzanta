import pyshark
from collections import defaultdict

def normalize_tuple(ip1, port1, ip2, port2):
    a = (ip1, int(port1))
    b = (ip2, int(port2))
    return (a, b) if a <= b else (b, a)

def compute_sessions(path: str, local_ips=None):
    try:
        capture = pyshark.FileCapture(path, keep_packets=False)
    except Exception as e:
        return {
            "success": False,
            "message": f"Błąd podczas odczytu PCAP: {e}"
        }

    sessions = {}
    session_ids = {}
    session_counter = 0

    def get_session_id(key):
        nonlocal session_counter
        if key not in session_ids:
            session_ids[key] = session_counter
            session_counter += 1
        return session_ids[key]

    for pkt in capture:
        try:
            if "ip" not in pkt:
                continue

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            proto = pkt.highest_layer.upper()

            if proto not in ("TCP", "UDP"):
                continue

            if proto == "TCP":
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
            else:
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport

            key = normalize_tuple(src_ip, src_port, dst_ip, dst_port)
            sid = get_session_id(key)

            if sid not in sessions:
                sessions[sid] = {
                    "id": sid,
                    "protocol": proto,
                    "src_ip": key[0][0],
                    "src_port": key[0][1],
                    "dst_ip": key[1][0],
                    "dst_port": key[1][1],
                    "start_time": float(pkt.sniff_timestamp),
                    "end_time": float(pkt.sniff_timestamp),
                    "packet_count": 0,
                    "bytes_total": 0,
                    "tcp_flags": {"syn": 0, "ack": 0, "fin": 0, "rst": 0},
                    "direction": "UNKNOWN",
                    "anomalies": []
                }

            session = sessions[sid]

            ts = float(pkt.sniff_timestamp)
            session["end_time"] = ts
            session["packet_count"] += 1

            if hasattr(pkt, "length"):
                session["bytes_total"] += int(pkt.length)

            if proto == "TCP":
                flags = pkt.tcp.flags

                if "SYN" in flags:
                    session["tcp_flags"]["syn"] += 1
                if "ACK" in flags:
                    session["tcp_flags"]["ack"] += 1
                if "FIN" in flags:
                    session["tcp_flags"]["fin"] += 1
                if "RST" in flags:
                    session["tcp_flags"]["rst"] += 1

                if session["direction"] == "UNKNOWN":
                    if flags == "0x0002":
                        session["direction"] = "OUT"
                    elif flags == "0x0012":
                        session["direction"] = "IN"

        except Exception:
            continue

    return {
        "success": True,
        "total_sessions": len(sessions),
        "sessions": list(sessions.values())
    }
