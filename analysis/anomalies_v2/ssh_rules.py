def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "SSH",
        "severity": severity,
        "description": description,
        "details": details or {},
    }

def check_ssh(report_data):
    anomalies = []

    sessions_data = report_data.get("sessions", {})
    sessions = sessions_data.get("sessions", [])
    ip_analysis = report_data.get("ip_analysis", {})

    public_ips = set(ip_analysis.get("public_ips", []))

    # 1) Grupowanie sesji SSH po (dst_ip, dst_port) dla detekcji bruteforce
    buckets = {}
    for sess in sessions:
        if sess.get("protocol") != "TCP":
            continue

        dst_port = sess.get("dst_port")
        # zakładamy klasyczny SSH: 22 lub 2222
        if dst_port not in (22, 2222):
            continue

        key = (sess.get("dst_ip"), dst_port)
        buckets.setdefault(key, []).append(sess)

    for (dst_ip, dst_port), sess_list in buckets.items():
        if len(sess_list) >= 20:
            anomalies.append(
                _build_anomaly(
                    "SSH-001",
                    "high",
                    "Duża liczba krótkich sesji SSH do tego samego hosta (podejrzenie bruteforce).",
                    {
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "session_count": len(sess_list),
                    },
                )
            )

    # 2) Długie sesje SSH (duży transfer danych)
    for sess in sessions:
        if sess.get("protocol") != "TCP":
            continue
        dst_port = sess.get("dst_port")
        if dst_port not in (22, 2222):
            continue

        bytes_total = sess.get("bytes_total", 0)
        sid = sess.get("id")

        if bytes_total > 10_000_000:  # ~10 MB
            anomalies.append(
                _build_anomaly(
                    "SSH-002",
                    "medium",
                    "Duża ilość danych przesłana w sesji SSH (podejrzenie intensywnego użycia lub exfiltracji).",
                    {"session_id": sid, "bytes_total": bytes_total},
                )
            )

    # 3) SSH z adresu publicznego do adresu niepublicznego (wejście z zewnątrz)
    for sess in sessions:
        if sess.get("protocol") != "TCP":
            continue

        dst_port = sess.get("dst_port")
        if dst_port not in (22, 2222):
            continue

        src_ip = sess.get("src_ip")
        dst_ip = sess.get("dst_ip")

        if src_ip in public_ips and dst_ip not in public_ips:
            anomalies.append(
                _build_anomaly(
                    "SSH-003",
                    "high",
                    "Połączenie SSH z adresu publicznego do hosta lokalnego.",
                    {
                        "session_id": sess.get("id"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                    },
                )
            )

    return anomalies
