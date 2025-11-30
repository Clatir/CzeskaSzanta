SUSPICIOUS_CIPHERS = [
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_NULL_WITH_NULL_NULL"
]

def detect_tls_anomalies(entries):
    anomalies = []

    for e in entries:
        sni = e.get("sni")
        cipher = e.get("cipher")
        version = e.get("record_version")

        if not sni:
            anomalies.append({
                "protocol": "TLS",
                "severity": "medium",
                "type": "Missing SNI",
                "description": "Połączenie TLS bez SNI.",
                "details": ""
            })

        if cipher and cipher in SUSPICIOUS_CIPHERS:
            anomalies.append({
                "protocol": "TLS",
                "severity": "high",
                "type": "Weak Cipher",
                "description": f"Podejrzany szyfr TLS.",
                "details": cipher
            })

        if version and ("1.0" in version or "1.1" in version):
            anomalies.append({
                "protocol": "TLS",
                "severity": "medium",
                "type": "Old TLS Version",
                "description": f"Stara wersja TLS.",
                "details": version
            })

    return anomalies
