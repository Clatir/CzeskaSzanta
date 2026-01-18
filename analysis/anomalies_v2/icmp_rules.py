def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "ICMP",
        "severity": severity,
        "description": description,
        "details": details or {},
    }


def check_icmp(report_data):
    anomalies = []

    protocols = report_data.get("protocols", {})
    per_proto = protocols.get("per_protocol", {})
    icmp_count = per_proto.get("ICMP", 0)

    # ICMP-001: bardzo dużo pakietów ICMP
    if icmp_count > 500:
        anomalies.append(
            _build_anomaly(
                "ICMP-001",
                "medium",
                "Duża liczba pakietów ICMP (możliwy ping flood lub intensywny skan).",
                {"packet_count": icmp_count},
            )
        )

    # Jeśli kiedyś dodasz ICMP do session_manager, możesz tu dorzucić:
    # - echo-request bez echo-reply,
    # - długie serie od jednego źródła itd.

    return anomalies
