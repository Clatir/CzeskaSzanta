from . import http_rules
from . import dns_rules
from . import tls_rules
from . import smtp_rules
from . import ftp_rules
from . import general_rules
from . import session_rules
from . import ssh_rules
from . import rdp_rules
from . import icmp_rules


def detect_anomalies(report_data):
    anomalies = []

    protocols = report_data.get("protocols", {})
    detected = set(protocols.get("detected", []))

    l7 = report_data.get("l7", {})
    sessions = report_data.get("sessions", {}).get("sessions", [])
    ip_analysis = report_data.get("ip_analysis", {})

    # 1) Reguły ogólne (GLOBAL)
    anomalies.extend(general_rules.check_general(report_data))

    # 2) Reguły sesyjne (SESSION)
    anomalies.extend(session_rules.check_sessions(report_data))

    # 3) Reguły per-protocol L7
    if "HTTP" in detected:
        anomalies.extend(
            http_rules.check_http(
                report_data,
                l7.get("http"),
                sessions,
                ip_analysis,
            )
        )

    if "DNS" in detected:
        anomalies.extend(
            dns_rules.check_dns(
                report_data,
                l7.get("dns"),
                sessions,
                ip_analysis,
            )
        )

    if "TLS" in detected:
        anomalies.extend(
            tls_rules.check_tls(
                report_data,
                l7.get("tls"),
                sessions,
                ip_analysis,
            )
        )

    if "SMTP" in detected:
        anomalies.extend(
            smtp_rules.check_smtp(
                report_data,
                l7.get("smtp"),
                sessions,
                ip_analysis,
            )
        )

    if "FTP" in detected:
        anomalies.extend(
            ftp_rules.check_ftp(
                report_data,
                l7.get("ftp"),
                sessions,
                ip_analysis,
            )
        )

    # 4) Reguły per-protocol dla protokołów bez L7 decoderów
    if "SSH" in detected:
        anomalies.extend(ssh_rules.check_ssh(report_data))

    if "RDP" in detected:
        anomalies.extend(rdp_rules.check_rdp(report_data))

    # ICMP możemy odpalać po wykryciu lub po samej statystyce per_protocol
    per_proto = protocols.get("per_protocol", {})
    if "ICMP" in detected or per_proto.get("ICMP", 0) > 0:
        anomalies.extend(icmp_rules.check_icmp(report_data))

    return anomalies
