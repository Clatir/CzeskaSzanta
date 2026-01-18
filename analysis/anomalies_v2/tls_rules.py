OLD_TLS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}


def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "TLS",
        "severity": severity,
        "description": description,
        "details": details or {},
    }


def check_tls(report_data, tls_data, sessions, ip_analysis):
    anomalies = []

    # oczekujemy listy rekordów TLS
    if not tls_data or not isinstance(tls_data, list):
        return anomalies

    old_version_count = 0
    versions_seen = set()

    for it in tls_data:
        ver = str(it.get("version", "")).upper()
        if ver:
            versions_seen.add(ver)
        if ver in OLD_TLS:
            old_version_count += 1

    if old_version_count > 0:
        anomalies.append(
            _build_anomaly(
                "TLS-001",
                "medium",
                "Wykryto sesje TLS z przestarzałymi wersjami protokołu.",
                {
                    "old_version_count": old_version_count,
                    "versions_seen": sorted(versions_seen),
                },
            )
        )

    return anomalies
