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

    # oczekujemy listy rekordów SMTP
    if not smtp_data or not isinstance(smtp_data, list):
        return anomalies

    mail_from = 0
    rcpt_to = 0
    unusual_ports = set()

    for it in smtp_data:
        cmd = str(it.get("command") or "").upper()
        param = str(it.get("parameter") or "")
        dport = str(it.get("dst_port") or "").strip()

        # MAIL FROM
        if cmd == "MAIL" and param.upper().startswith("FROM:"):
            mail_from += 1

        # RCPT TO
        if cmd == "RCPT" and param.upper().startswith("TO:"):
            rcpt_to += 1

        # SMTP na niestandardowych portach
        if dport and dport not in COMMON_SMTP_PORTS:
            unusual_ports.add(dport)

    # SMTP-001: dużo odbiorców
    if rcpt_to >= 50:
        anomalies.append(
            _build_anomaly(
                "SMTP-001",
                "medium",
                "Duża liczba odbiorców w sesjach SMTP (potencjalny spam lub masowa wysyłka).",
                {"rcpt_to": rcpt_to},
            )
        )

    # SMTP-002: dużo nadawców
    if mail_from >= 20:
        anomalies.append(
            _build_anomaly(
                "SMTP-002",
                "medium",
                "Duża liczba nadawców w sesjach SMTP (nietypowe zachowanie).",
                {"mail_from": mail_from},
            )
        )

    # SMTP-003: ruch na nietypowych portach
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
