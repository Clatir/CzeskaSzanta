def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "RDP",
        "severity": severity,
        "description": description,
        "details": details or {},
    }


def check_rdp(report_data):
    anomalies = []

    sessions_data = report_data.get("sessions", {})
    sessions = sessions_data.get("sessions", [])
    ip_analysis = report_data.get("ip_analysis", {})

    public_ips = set(ip_analysis.get("public_ips", []))

    rdp_sessions = [s for s in sessions if s.get("protocol") == "TCP"]

    # 1) RDP na nietypowych portach (nie 3389)
    unusual = []
    for sess in rdp_sessions:
        dst_port = sess.get("dst_port")
        if dst_port and dst_port != 3389:
            unusual.append(
                {
                    "session_id": sess.get("id"),
                    "dst_ip": sess.get("dst_ip"),
                    "dst_port": dst_port,
                }
            )

    if unusual:
        anomalies.append(
            _build_anomaly(
                "RDP-001",
                "medium",
                "RDP (lub RDP-like) obserwowany na nietypowych portach.",
                {"sessions": unusual},
            )
        )

    # 2) Duża liczba sesji RDP do tego samego hosta (potencjalny bruteforce)
    buckets = {}
    for sess in rdp_sessions:
        dst_port = sess.get("dst_port")
        if dst_port != 3389:
            continue
        key = (sess.get("dst_ip"), dst_port)
        buckets.setdefault(key, []).append(sess)

    for (dst_ip, dst_port), sess_list in buckets.items():
        if len(sess_list) >= 10:
            anomalies.append(
                _build_anomaly(
                    "RDP-002",
                    "high",
                    "Duża liczba sesji RDP do tego samego hosta (podejrzenie bruteforce lub intensywnego użycia).",
                    {
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "session_count": len(sess_list),
                    },
                )
            )

    # 3) RDP z adresu publicznego do hosta lokalnego
    for sess in rdp_sessions:
        dst_port = sess.get("dst_port")
        if dst_port != 3389:
            continue

        src_ip = sess.get("src_ip")
        dst_ip = sess.get("dst_ip")

        if src_ip in public_ips and dst_ip not in public_ips:
            anomalies.append(
                _build_anomaly(
                    "RDP-003",
                    "high",
                    "Połączenie RDP z adresu publicznego do hosta lokalnego.",
                    {
                        "session_id": sess.get("id"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                    },
                )
            )

    return anomalies
