def detect_session_anomalies(sessions_data):
    anomalies = []

    sessions = sessions_data.get("sessions", [])

    for sess in sessions:
        proto = sess["protocol"]
        pkt_count = sess["packet_count"]
        bytes_total = sess["bytes_total"]
        sid = sess["id"]
        direction = sess.get("direction")

        if proto == "TCP" and pkt_count <= 2:
            anomalies.append({
                "protocol": "SESSION",
                "type": "tcp_scan_like",
                "severity": "medium",
                "description": "TCP session with only SYN/RST — potential scan.",
                "details": {"session_id": sid, "packet_count": pkt_count}
            })

        if proto == "UDP" and pkt_count > 1000:
            anomalies.append({
                "protocol": "SESSION",
                "type": "udp_flood_like",
                "severity": "high",
                "description": "Bardzo duża liczba pakietów UDP.",
                "details": {"session_id": sid, "packet_count": pkt_count}
            })

        if bytes_total > 5_000_000:
            anomalies.append({
                "protocol": "SESSION",
                "type": "large_data_session",
                "severity": "high",
                "description": "Duża ilość przesłanych danych (możliwa exfiltracja).",
                "details": {"session_id": sid, "bytes_total": bytes_total}
            })

        if proto == "TCP" and direction == "OUT" and pkt_count < 10:
            anomalies.append({
                "protocol": "SESSION",
                "type": "outbound_beacon_like",
                "severity": "medium",
                "description": "Jednokierunkowy OUTBOUND flow przypominający beaconing.",
                "details": {"session_id": sid, "packet_count": pkt_count}
            })

        dst_port = sess.get("dst_port")
        if dst_port and dst_port > 50000:
            anomalies.append({
                "protocol": "SESSION",
                "type": "high_port_connection",
                "severity": "low",
                "description": f"Połączenie do wysokiego portu: {dst_port}",
                "details": {"session_id": sid}
            })

    return anomalies
