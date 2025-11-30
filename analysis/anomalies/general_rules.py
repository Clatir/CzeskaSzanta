RISKY_COUNTRIES = {"RU", "CN", "IR", "KP"}

UNUSUAL_PROTOCOLS = {"SSDP", "GTP", "SIP", "MDNS"}

def detect_general_anomalies(report_data):
    anomalies = []

    file_info = report_data.get("file_info", {})
    protocols = report_data.get("protocols", {})
    ip_analysis = report_data.get("ip_analysis", {})

    if file_info.get("packet_count", 0) < 3:
        anomalies.append({
            "protocol": "GLOBAL",
            "type": "small_capture",
            "severity": "low",
            "description": "Plik PCAP zawiera bardzo mało pakietów.",
            "details": {"packet_count": file_info.get("packet_count")}
        })

    for country, count in ip_analysis.get("country_stats", {}).items():
        if country in RISKY_COUNTRIES:
            anomalies.append({
                "protocol": "GLOBAL",
                "type": "risky_country",
                "severity": "high",
                "description": f"Ruch do kraju wysokiego ryzyka: {country}",
                "details": {"country": country, "count": count}
            })

        if count > 50:
            anomalies.append({
                "protocol": "GLOBAL",
                "type": "high_volume_country",
                "severity": "medium",
                "description": f"Duża liczba pakietów do kraju: {country}",
                "details": {"country": country, "count": count}
            })

    per_proto = protocols.get("per_protocol", {})
    for proto, count in per_proto.items():
        if proto in UNUSUAL_PROTOCOLS:
            anomalies.append({
                "protocol": "GLOBAL",
                "type": "unusual_protocol",
                "severity": "medium",
                "description": f"Nietypowy protokół w ruchu: {proto}",
                "details": {"protocol": proto, "count": count}
            })

    return anomalies
