def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "SESSION",
        "severity": severity,
        "description": description,
        "details": details or {},
    }


def check_sessions(report_data):
    anomalies = []

    sessions_data = report_data.get("sessions", {})
    sessions = sessions_data.get("sessions", [])

    for sess in sessions:
        proto = sess.get("protocol")
        pkt_count = sess.get("packet_count", 0)
        bytes_total = sess.get("bytes_total", 0)
        sid = sess.get("id")
        direction = sess.get("direction")
        dst_port = sess.get("dst_port")

        # SESSION-001: TCP "scan-like" – bardzo mało pakietów
        if proto == "TCP" and pkt_count <= 2:
            anomalies.append(
                _build_anomaly(
                    "SESSION-001",
                    "medium",
                    "TCP session with only SYN/RST — potencjalny skan.",
                    {"session_id": sid, "packet_count": pkt_count},
                )
            )

        # SESSION-002: potencjalny UDP flood
        if proto == "UDP" and pkt_count > 1000:
            anomalies.append(
                _build_anomaly(
                    "SESSION-002",
                    "high",
                    "Bardzo duża liczba pakietów UDP.",
                    {"session_id": sid, "packet_count": pkt_count},
                )
            )

        # SESSION-003: duży transfer danych (exfil)
        if bytes_total > 5_000_000:
            anomalies.append(
                _build_anomaly(
                    "SESSION-003",
                    "high",
                    "Duża ilość przesłanych danych (możliwa exfiltracja).",
                    {"session_id": sid, "bytes_total": bytes_total},
                )
            )

        # SESSION-004: krótkie OUTBOUND flows – beacon-like
        if proto == "TCP" and direction == "OUT" and pkt_count < 10:
            anomalies.append(
                _build_anomaly(
                    "SESSION-004",
                    "medium",
                    "Jednokierunkowy OUTBOUND flow przypominający beaconing.",
                    {"session_id": sid, "packet_count": pkt_count},
                )
            )

        # SESSION-005: połączenia na wysokie porty
        if dst_port and dst_port > 50000:
            anomalies.append(
                _build_anomaly(
                    "SESSION-005",
                    "low",
                    f"Połączenie do wysokiego portu: {dst_port}",
                    {"session_id": sid, "dst_port": dst_port},
                )
            )

    return anomalies
