from analysis.anomalies.general_rules import detect_general_anomalies
from analysis.anomalies.session_rules import detect_session_anomalies

from analysis.anomalies.http_rules import detect_http_anomalies
from analysis.anomalies.dns_rules import detect_dns_anomalies
from analysis.anomalies.tls_rules import detect_tls_anomalies

def run_anomaly_detection(report_data):
    anomalies = []

    anomalies.extend(detect_general_anomalies(report_data))

    if "sessions" in report_data:
        anomalies.extend(detect_session_anomalies(report_data["sessions"]))

    l7 = report_data.get("l7", {})

    if l7.get("http"):
        anomalies.extend(detect_http_anomalies(l7["http"]))

    if l7.get("dns"):
        anomalies.extend(detect_dns_anomalies(l7["dns"]))

    if l7.get("tls"):
        anomalies.extend(detect_tls_anomalies(l7["tls"]))

    return anomalies
