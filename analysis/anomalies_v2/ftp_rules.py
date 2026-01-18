def _build_anomaly(aid, severity, description, details=None):
    return {
        "id": aid,
        "protocol": "FTP",
        "severity": severity,
        "description": description,
        "details": details or {},
    }

def check_ftp(report_data, ftp_data, sessions, ip_analysis):
    anomalies = []

    if not ftp_data or not isinstance(ftp_data, dict):
        return anomalies

    stats = ftp_data.get("stats", {})
    items = ftp_data.get("items", [])

    retr = stats.get("retr", 0)
    stor = stats.get("stor", 0)

    if retr >= 20:
        anomalies.append(
            _build_anomaly(
                "FTP-001",
                "medium",
                "Duża liczba pobrań plików przez FTP (RETR).",
                {"retr": retr},
            )
        )

    if stor >= 20:
        anomalies.append(
            _build_anomaly(
                "FTP-002",
                "medium",
                "Duża liczba wysłanych plików przez FTP (STOR).",
                {"stor": stor},
            )
        )

    # (opcjonalnie) podejrzane rozszerzenia plików
    suspicious_ext = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr")
    sus_files = []

    for it in items:
        cmd = str(it.get("command", "")).upper()
        if cmd not in ("RETR", "STOR"):
            continue
        arg = str(it.get("arg", "")).lower()
        if any(arg.endswith(ext) for ext in suspicious_ext):
            sus_files.append({"command": cmd, "path": it.get("arg")})

    if sus_files:
        anomalies.append(
            _build_anomaly(
                "FTP-003",
                "high",
                "Transfer potencjalnie niebezpiecznych plików przez FTP.",
                {"files": sus_files},
            )
        )

    return anomalies
