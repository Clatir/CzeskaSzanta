def _build_corr(cid, severity, description, evidence=None):
    return {
        "id": cid,
        "severity": severity,
        "description": description,
        "protocols": ["SMTP", "HTTP", "TLS"],
        "evidence": evidence or {},
    }


def _pair(a, b):
    if not a or not b:
        return None
    return (a, b)


def correlate_smtp_http(report_data):
    correlations = []

    l7 = report_data.get("l7", {}) or {}

    smtp_data = l7.get("smtp") or {}
    http_data = l7.get("http") or {}
    tls_data = l7.get("tls") or {}

    smtp_items = smtp_data.get("items", []) or []
    http_items = http_data.get("items", []) or []
    tls_items = tls_data.get("items", []) or []

    if not smtp_items or (not http_items and not tls_items):
        return correlations

    smtp_pairs = {}
    for it in smtp_items:
        src_ip = it.get("src_ip")
        dst_ip = it.get("dst_ip")
        p = _pair(src_ip, dst_ip)
        if not p:
            continue
        smtp_pairs.setdefault(p, 0)
        smtp_pairs[p] += 1

    http_pairs = {}
    for it in http_items:
        src_ip = it.get("src_ip")
        dst_ip = it.get("dst_ip")
        p = _pair(src_ip, dst_ip)
        if not p:
            continue
        http_pairs.setdefault(p, 0)
        http_pairs[p] += 1

    tls_pairs = {}
    for it in tls_items:
        src_ip = it.get("src_ip")
        dst_ip = it.get("dst_ip")
        p = _pair(src_ip, dst_ip)
        if not p:
            continue
        tls_pairs.setdefault(p, 0)
        tls_pairs[p] += 1

    pairs_http_tls = set(http_pairs.keys()) | set(tls_pairs.keys())
    common_pairs = set(smtp_pairs.keys()) & pairs_http_tls

    for p in sorted(common_pairs):
        src_ip, dst_ip = p
        smtp_count = smtp_pairs.get(p, 0)
        http_count = http_pairs.get(p, 0)
        tls_count = tls_pairs.get(p, 0)

        if smtp_count < 5 and (http_count + tls_count) < 5:
            continue

        severity = "medium"
        if smtp_count >= 10 or (http_count + tls_count) >= 20:
            severity = "high"

        correlations.append(
            _build_corr(
                "CORR-004",
                severity,
                "Jednoczesna komunikacja SMTP oraz HTTP/TLS z tym samym zdalnym hostem.",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "smtp_count": smtp_count,
                    "http_count": http_count,
                    "tls_count": tls_count,
                },
            )
        )

    return correlations
