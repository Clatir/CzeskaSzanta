def _build_corr(cid, severity, description, evidence=None):
    return {
        "id": cid,
        "severity": severity,
        "description": description,
        "protocols": ["TCP"],
        "evidence": evidence or {},
    }


def correlate_beaconing(report_data):
    correlations = []

    sessions_data = report_data.get("sessions", {})
    sessions = sessions_data.get("sessions", []) or []
    ip_analysis = report_data.get("ip_analysis", {}) or {}

    public_ips = set(ip_analysis.get("public_ips", []))

    # grupujemy krótkie OUT sesje po (src_ip, dst_ip)
    buckets = {}
    for sess in sessions:
        if sess.get("protocol") != "TCP":
            continue
        if sess.get("direction") != "OUT":
            continue

        pkt_count = sess.get("packet_count", 0)
        bytes_total = sess.get("bytes_total", 0)

        if pkt_count >= 10:
            continue
        if bytes_total >= 50_000:
            continue

        src_ip = sess.get("src_ip")
        dst_ip = sess.get("dst_ip")
        if not src_ip or not dst_ip:
            continue

        key = (src_ip, dst_ip)
        buckets.setdefault(key, []).append(sess)

    for (src_ip, dst_ip), sess_list in buckets.items():
        if len(sess_list) < 10:
            continue

        severity = "medium"
        if dst_ip in public_ips:
            severity = "high"

        correlations.append(
            _build_corr(
                "CORR-003",
                severity,
                "Wiele krótkich, małych OUT sesji TCP do tego samego hosta (wzorzec beaconingu/C2).",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "session_count": len(sess_list),
                    "sessions": [
                        {
                            "id": s.get("id"),
                            "packet_count": s.get("packet_count"),
                            "bytes_total": s.get("bytes_total"),
                        }
                        for s in sess_list
                    ],
                    "dst_is_public": dst_ip in public_ips,
                },
            )
        )

    return correlations
