from . import dns_tls_http_corr
from . import rdp_smb_corr
from . import beaconing_corr
from . import smtp_http_corr
from . import ftp_http_corr


def detect_correlations(report_data):
    correlations = []

    correlations.extend(
        dns_tls_http_corr.correlate_dns_tls_http(report_data)
    )

    correlations.extend(
        rdp_smb_corr.correlate_rdp_smb_exfil(report_data)
    )

    correlations.extend(
        beaconing_corr.correlate_beaconing(report_data)
    )

    correlations.extend(
        smtp_http_corr.correlate_smtp_http(report_data)
    )

    correlations.extend(
        ftp_http_corr.correlate_ftp_http(report_data)
    )

    return correlations
