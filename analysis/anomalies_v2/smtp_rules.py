COMMON_SMTP_PORTS = {"25", "465", "587"}

def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "SMTP",
        "severity": severity,
        "description": description,
        "details": details or {},
    }

def check_smtp(report_data, smtp_data, sessions, ip_analysis):
    anomalies = []

    if not smtp_data or not isinstance(smtp_data, dict):
        return anomalies

    stats = smtp_data.get("stats", {})
    items = smtp_data.get("items", [])

    mail_from = stats.get("mail_from", 0)
    rcpt_to = stats.get("rcpt_to", 0)

    if rcpt_to >= 50:
        anomalies.append(
            _build_anomaly(
                "SMTP-001",
                "medium",
                "Duża liczba odbiorców w sesjach SMTP (potencjalny spam lub masowa wysyłka).",
                {"rcpt_to": rcpt_to},
            )
        )

    if mail_from >= 20:
        anomalies.append(
            _build_anomaly(
                "SMTP-002",
                "medium",
                "Duża liczba nadawców w sesjach SMTP (nietypowe zachowanie).",
                {"mail_from": mail_from},
            )
        )

    # SMTP po nietypowych portach
    unusual_ports = set()
    for it in items:
        dport = str(it.get("dst_port", "")).strip()
        if dport and dport not in COMMON_SMTP_PORTS:
            unusual_ports.add(dport)

    if unusual_ports:
        anomalies.append(
            _build_anomaly(
                "SMTP-003",
                "low",
                "Ruch SMTP obserwowany na niestandardowych portach.",
                {"ports": sorted(unusual_ports)},
            )
        )

    return anomalies
