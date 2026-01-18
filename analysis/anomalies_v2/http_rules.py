SUSPICIOUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND"}
SUSPICIOUS_EXT = (
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".js",
    ".vbs",
    ".scr",
    ".jar",
    ".msi",
)


def _build_anomaly(aid, severity, description, protocol, details=None):
    return {
        "id": aid,
        "protocol": protocol,
        "severity": severity,
        "description": description,
        "details": details or {},
    }


def check_http(report_data, http_data, sessions, ip_analysis):
    anomalies = []

    # oczekujemy listy rekordów HTTP
    if not http_data or not isinstance(http_data, list):
        return anomalies

    # 1) Podejrzane metody HTTP
    for it in http_data:
        method = str(it.get("method", "")).upper()
        if method in SUSPICIOUS_METHODS:
            anomalies.append(
                _build_anomaly(
                    "HTTP-001",
                    "medium",
                    f"Użycie nietypowej metody HTTP: {method}",
                    "HTTP",
                    {
                        "method": method,
                        "host": it.get("host"),
                        "uri": it.get("uri"),
                    },
                )
            )

    # 2) Pobieranie potencjalnie niebezpiecznych plików
    for it in http_data:
        uri = it.get("uri") or ""
        uri_l = str(uri).lower()
        if any(uri_l.endswith(ext) for ext in SUSPICIOUS_EXT):
            anomalies.append(
                _build_anomaly(
                    "HTTP-002",
                    "high",
                    "Potencjalnie złośliwy plik pobierany przez HTTP.",
                    "HTTP",
                    {
                        "method": it.get("method"),
                        "host": it.get("host"),
                        "uri": uri,
                        "status_code": it.get("status_code"),
                    },
                )
            )

    # 3) Bardzo dużo żądań do jednego hosta
    host_counts = {}
    for it in http_data:
        host = it.get("host")
        if not host:
            continue
        host_counts[host] = host_counts.get(host, 0) + 1

    for host, count in host_counts.items():
        if count >= 100:  # próg możesz sobie później wyregulować
            anomalies.append(
                _build_anomaly(
                    "HTTP-003",
                    "medium",
                    "Duża liczba żądań HTTP do jednego hosta (potencjalny skan/bruteforce).",
                    "HTTP",
                    {"host": host, "request_count": count},
                )
            )

    return anomalies
