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

    # oczekujemy listy rekordów
    if not ftp_data or not isinstance(ftp_data, list):
        return anomalies

    retr = 0
    stor = 0
    user = 0
    pw = 0

    suspicious_ext = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr")
    suspicious_files = []

    for it in ftp_data:
        cmd = str(it.get("command", "")).upper()
        arg = str(it.get("arg", "") or "")

        if cmd == "RETR":
            retr += 1
        elif cmd == "STOR":
            stor += 1
        elif cmd == "USER":
            user += 1
        elif cmd == "PASS":
            pw += 1

        if cmd in ("RETR", "STOR"):
            low_arg = arg.lower()
            if any(low_arg.endswith(ext) for ext in suspicious_ext):
                suspicious_files.append(
                    {
                        "command": cmd,
                        "path": arg,
                        "src_ip": it.get("src_ip"),
                        "dst_ip": it.get("dst_ip"),
                    }
                )

    # FTP-001: dużo pobrań plików
    if retr >= 20:
        anomalies.append(
            _build_anomaly(
                "FTP-001",
                "medium",
                "Duża liczba pobrań plików przez FTP (RETR).",
                {"retr": retr},
            )
        )

    # FTP-002: dużo wysłań plików
    if stor >= 20:
        anomalies.append(
            _build_anomaly(
                "FTP-002",
                "medium",
                "Duża liczba wysłanych plików przez FTP (STOR).",
                {"stor": stor},
            )
        )

    # FTP-003: potencjalnie niebezpieczne pliki
    if suspicious_files:
        anomalies.append(
            _build_anomaly(
                "FTP-003",
                "high",
                "Transfer potencjalnie niebezpiecznych plików przez FTP.",
                {"files": suspicious_files},
            )
        )

    return anomalies
