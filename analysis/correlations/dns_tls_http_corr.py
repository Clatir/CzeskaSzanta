def _build_corr(cid, severity, description, protocols, evidence=None):
    return {
        "id": cid,
        "severity": severity,
        "description": description,
        "protocols": protocols,
        "evidence": evidence or {},
    }


def _base_domain(name):
    if not name:
        return None
    name = str(name).strip(".").lower()
    parts = name.split(".")
    if len(parts) < 2:
        return name
    return ".".join(parts[-2:])


def correlate_dns_tls_http(report_data):
    correlations = []

    l7 = report_data.get("l7", {})

    dns_data = l7.get("dns") or {}
    tls_data = l7.get("tls") or {}
    http_data = l7.get("http") or {}

    dns_items = dns_data.get("items", []) or []
    tls_items = tls_data.get("items", []) or []
    http_items = http_data.get("items", []) or []

    if not dns_items and not tls_items and not http_items:
        return correlations

    dns_domains = {}
    tls_domains = {}
    http_domains = {}

    # DNS
    for it in dns_items:
        qname = it.get("qname") or it.get("query")
        base = _base_domain(qname)
        if not base:
            continue
        bucket = dns_domains.setdefault(base, {"count": 0, "samples": []})
        bucket["count"] += 1
        if len(bucket["samples"]) < 5:
            bucket["samples"].append(qname)

    # TLS
    for it in tls_items:
        sni = it.get("sni") or it.get("hostname")
        base = _base_domain(sni)
        if not base:
            continue
        bucket = tls_domains.setdefault(base, {"count": 0, "samples": []})
        bucket["count"] += 1
        if len(bucket["samples"]) < 5:
            bucket["samples"].append(sni)

    # HTTP
    for it in http_items:
        host = it.get("host")
        base = _base_domain(host)
        if not base:
            continue
        bucket = http_domains.setdefault(base, {"count": 0, "samples": []})
        bucket["count"] += 1
        if len(bucket["samples"]) < 5:
            bucket["samples"].append(host)

    all_domains = set(dns_domains) | set(tls_domains) | set(http_domains)

    for dom in sorted(all_domains):
        touches = []
        if dom in dns_domains:
            touches.append("DNS")
        if dom in tls_domains:
            touches.append("TLS")
        if dom in http_domains:
            touches.append("HTTP")

        # Interesują nas domeny, które pojawiły się co najmniej w dwóch warstwach
        if len(touches) < 2:
            continue

        evidence = {
            "domain": dom,
            "layers": touches,
            "dns": dns_domains.get(dom),
            "tls": tls_domains.get(dom),
            "http": http_domains.get(dom),
        }

        severity = "medium"
        # jeżeli domena jest widoczna we wszystkich trzech warstwach, trochę wyżej
        if len(touches) == 3:
            severity = "high"

        correlations.append(
            _build_corr(
                "CORR-001",
                severity,
                "Spójny łańcuch DNS → TLS → HTTP dla tej samej domeny.",
                ["DNS", "TLS", "HTTP"],
                evidence,
            )
        )

    return correlations
