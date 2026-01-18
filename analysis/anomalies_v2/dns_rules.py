def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "DNS",
        "severity": severity,
        "description": description,
        "details": details or {},
    }


def _extract_domain(qname):
    if not qname:
        return None
    parts = str(qname).strip(".").split(".")
    if len(parts) < 2:
        return qname
    return ".".join(parts[-2:])


def check_dns(report_data, dns_data, sessions, ip_analysis):
    anomalies = []

    if not dns_data or not isinstance(dns_data, dict):
        return anomalies

    items = dns_data.get("items", [])
    if not items:
        return anomalies

    long_queries = 0
    domain_buckets = {}

    for it in items:
        qname = it.get("qname") or it.get("query") or ""
        qname = str(qname)
        if len(qname) > 80:
            long_queries += 1

        base = _extract_domain(qname)
        if base:
            domain_buckets[base] = domain_buckets.get(base, 0) + 1

    if long_queries > 0:
        anomalies.append(
            _build_anomaly(
                "DNS-001",
                "medium",
                "Wykryto długie nazwy w zapytaniach DNS (potencjalne tunelowanie lub DGA).",
                {"long_queries": long_queries},
            )
        )

    for dom, count in domain_buckets.items():
        if count >= 100:
            anomalies.append(
                _build_anomaly(
                    "DNS-002",
                    "medium",
                    "Duża liczba zapytań DNS do jednego domenowego sufiksu.",
                    {"domain": dom, "queries": count},
                )
            )

    return anomalies
