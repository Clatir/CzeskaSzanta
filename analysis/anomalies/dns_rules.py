import math

def shannon_entropy(s):
    if not s:
        return 0
    prob = [ float(s.count(c)) / len(s) for c in dict.fromkeys(list(s)) ]
    return - sum([ p * math.log(p, 2) for p in prob ])

def detect_dns_anomalies(entries):
    anomalies = []

    for e in entries:
        domain = e.get("query")
        resp = e.get("response")
        qtype = e.get("query_type")

        if domain and len(domain) > 50:
            anomalies.append({
                "protocol": "DNS",
                "severity": "medium",
                "type": "Long Domain",
                "description": "Podejrzanie długa nazwa domeny.",
                "details": domain
            })

        if domain:
            ent = shannon_entropy(domain)
            if ent > 4.0:
                anomalies.append({
                    "protocol": "DNS",
                    "severity": "high",
                    "type": "High Entropy Domain",
                    "description": "Możliwe DGA (Domain Generation Algorithm).",
                    "details": f"{domain} (entropy={ent:.2f})"
                })

        if qtype in ["16", "TXT"]:
            anomalies.append({
                "protocol": "DNS",
                "severity": "medium",
                "type": "TXT Record",
                "description": "Zapytanie o rekord TXT (często używane do malware C2).",
                "details": domain
            })

        if resp and resp.startswith(("10.", "192.168.", "172.16.")):
            anomalies.append({
                "protocol": "DNS",
                "severity": "low",
                "type": "Private DNS Response",
                "description": "DNS zwrócił adres prywatny.",
                "details": f"{domain} → {resp}"
            })

    return anomalies
