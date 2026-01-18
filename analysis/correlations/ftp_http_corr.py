FTP_PORTS = {21}

def _build_corr(cid, severity, description, evidence=None):
    return {
        "id": cid,
        "severity": severity,
        "description": description,
        "protocols": ["FTP", "HTTP", "TLS"],
        "evidence": evidence or {},
    }

def _pair(a, b):
    if not a or not b:
        return None
    return (a, b)

def correlate_ftp_http(report_data):
    correlations = []

    l7 = report_data.get("l7", {}) or {}
    sessions_data = report_data.get("sessions", {}) or {}
    sessions = sessions_data.get("sessions", []) or []

    ftp_data = l7.get("ftp") or {}
    http_data = l7.get("http") or {}
    tls_data = l7.get("tls") or {}

    ftp_items = ftp_data.get("items", []) or []
    http_items = http_data.get("items", []) or []
    tls_items = tls_data.get("items", []) or []

    if not ftp_items:
        return correlations

    ftp_pairs = {}
    for it in ftp_items:
        src_ip = it.get("src_ip")
        dst_ip = it.get("dst_ip")
        p = _pair(src_ip, dst_ip)
        if not p:
            continue
        ftp_pairs.setdefault(p, {"commands": 0, "retr": 0, "stor": 0})
        ftp_pairs[p]["commands"] += 1
        cmd = str(it.get("command", "")).upper()
        if cmd == "RETR":
            ftp_pairs[p]["retr"] += 1
        if cmd == "STOR":
            ftp_pairs[p]["stor"] += 1

    http_pairs = {}
    for it in http_items:
        p = _pair(it.get("src_ip"), it.get("dst_ip"))
        if not p:
            continue
        http_pairs.setdefault(p, 0)
        http_pairs[p] += 1

    tls_pairs = {}
    for it in tls_items:
        p = _pair(it.get("src_ip"), it.get("dst_ip"))
        if not p:
            continue
        tls_pairs.setdefault(p, 0)
        tls_pairs[p] += 1

    pairs_http_tls = set(http_pairs.keys()) | set(tls_pairs.keys())
    common_pairs = set(ftp_pairs.keys()) & pairs_http_tls

    # mapujemy sesje FTP po (src_ip, dst_ip, dst_port)
    ftp_sessions = {}
    for s in sessions:
        if s.get("protocol") != "TCP":
            continue
        dst_port = s.get("dst_port")
        if dst_port not in FTP_PORTS:
            continue
        p = _pair(s.get("src_ip"), s.get("dst_ip"))
        if not p:
            continue
        ftp_sessions.setdefault(p, []).append(s)

    for p in sorted(common_pairs):
        src_ip, dst_ip = p
        ftp_stats = ftp_pairs[p]
        ftp_retr = ftp_stats["retr"]
        ftp_stor = ftp_stats["stor"]

        if (ftp_retr + ftp_stor) < 5:
            continue

        http_count = http_pairs.get(p, 0)
        tls_count = tls_pairs.get(p, 0)

        large_ftp_sess = [
            s for s in ftp_sessions.get(p, [])
            if s.get("bytes_total", 0) > 5_000_000
        ]

        severity = "medium"
        if large_ftp_sess:
            severity = "high"

        correlations.append(
            _build_corr(
                "CORR-005",
                severity,
                "Jednoczesne intensywne użycie FTP oraz HTTP/TLS z tym samym zdalnym hostem (potencjalna exfiltracja).",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ftp_retr": ftp_retr,
                    "ftp_stor": ftp_stor,
                    "http_count": http_count,
                    "tls_count": tls_count,
                    "large_ftp_sessions": [
                        {
                            "id": s.get("id"),
                            "bytes_total": s.get("bytes_total"),
                            "packet_count": s.get("packet_count"),
                        }
                        for s in large_ftp_sess
                    ],
                },
            )
        )

    return correlations
