RISKY_COUNTRIES = {"RU", "CN", "IR", "KP"}

UNUSUAL_PROTOCOLS = {"SSDP", "GTP", "SIP", "MDNS"}


def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "GLOBAL",
        "severity": severity,
        "description": description,
        "details": details or {},
    }


def check_general(report_data):
    anomalies = []

    file_info = report_data.get("file_info", {})
    protocols = report_data.get("protocols", {})
    ip_analysis = report_data.get("ip_analysis", {})

    # GEN-001: bardzo mały capture
    if file_info.get("packet_count", 0) < 3:
        anomalies.append(
            _build_anomaly(
                "GEN-001",
                "low",
                "Plik PCAP zawiera bardzo mało pakietów.",
                {"packet_count": file_info.get("packet_count", 0)},
            )
        )

    # GEN-002 / GEN-003: ruch do krajów wysokiego ryzyka / duża liczba pakietów do kraju
    for country, count in ip_analysis.get("country_stats", {}).items():
        if country in RISKY_COUNTRIES:
            anomalies.append(
                _build_anomaly(
                    "GEN-002",
                    "high",
                    f"Ruch do kraju wysokiego ryzyka: {country}",
                    {"country": country, "count": count},
                )
            )

        if count > 50:
            anomalies.append(
                _build_anomaly(
                    "GEN-003",
                    "medium",
                    f"Duża liczba pakietów do kraju: {country}",
                    {"country": country, "count": count},
                )
            )

    # GEN-004: nietypowe protokoły w ruchu
    per_proto = protocols.get("per_protocol", {})
    for proto, count in per_proto.items():
        if proto in UNUSUAL_PROTOCOLS:
            anomalies.append(
                _build_anomaly(
                    "GEN-004",
                    "medium",
                    f"Nietypowy protokół w ruchu: {proto}",
                    {"protocol": proto, "count": count},
                )
            )

    return anomalies
