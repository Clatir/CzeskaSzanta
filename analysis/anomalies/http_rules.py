SUSPICIOUS_USER_AGENTS = [
    "curl", "wget", "python-requests", "powershell",
    "evilbot", "malware", "botnet", "scanner"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".zip", ".dll", ".js", ".scr", ".bat", ".cmd"
]

SUSPICIOUS_CONTENT_TYPES = [
    "application/octet-stream",
    "binary/octet-stream",
    "application/x-msdownload"
]

def detect_http_anomalies(entries):
    anomalies = []

    for e in entries:
        host = e.get("host")
        ua = e.get("user_agent")
        uri = e.get("uri")
        ctype = e.get("content_type")
        clen = e.get("content_length")
        method = e.get("method")

        if not host:
            anomalies.append({
                "protocol": "HTTP",
                "severity": "medium",
                "type": "Missing Host",
                "description": "Brak nagłówka Host w żądaniu HTTP.",
                "details": f"URI: {uri}"
            })

        if ua:
            for bad in SUSPICIOUS_USER_AGENTS:
                if bad.lower() in ua.lower():
                    anomalies.append({
                        "protocol": "HTTP",
                        "severity": "high",
                        "type": "Suspicious User-Agent",
                        "description": "Wykryto nietypowy User-Agent.",
                        "details": ua
                    })

        if uri:
            for ext in SUSPICIOUS_EXTENSIONS:
                if uri.lower().endswith(ext):
                    anomalies.append({
                        "protocol": "HTTP",
                        "severity": "high",
                        "type": "Suspicious File Download",
                        "description": f"Pobranie pliku {ext} przez HTTP",
                        "details": uri
                    })

        if ctype and ctype.lower() in SUSPICIOUS_CONTENT_TYPES:
            anomalies.append({
                "protocol": "HTTP",
                "severity": "high",
                "type": "Dangerous MIME Type",
                "description": f"Podejrzany typ Content-Type: {ctype}",
                "details": uri
            })

        if clen and clen.isdigit() and int(clen) > 5_000_000:
            anomalies.append({
                "protocol": "HTTP",
                "severity": "medium",
                "type": "Large File",
                "description": "Duży plik w odpowiedzi HTTP.",
                "details": f"Rozmiar: {clen} B, URI: {uri}"
            })

        if method and method not in ["GET", "POST", "HEAD"]:
            anomalies.append({
                "protocol": "HTTP",
                "severity": "low",
                "type": "Uncommon Method",
                "description": f"Nietypowa metoda HTTP: {method}",
                "details": uri
            })

    return anomalies
