import pyshark

def decode_tls(pcap_path):
    try:
        capture = pyshark.FileCapture(
            pcap_path,
            display_filter="tls",
            keep_packets=False
        )
    except Exception as e:
        return {"success": False, "message": f"Błąd TLS: {e}"}

    tls_entries = []

    try:
        for pkt in capture:
            tls = pkt.tls

            entry = {
                "src_ip": pkt.ip.src,
                "dst_ip": pkt.ip.dst,
                "handshake_type": getattr(tls, "handshake_type", None),
                "record_version": getattr(tls, "record_version", None),
                "sni": getattr(tls, "handshake_extensions_server_name", None),
                "cipher": getattr(tls, "handshake_ciphersuite", None)
            }

            tls_entries.append(entry)
    except:
        pass

    return {
        "success": True,
        "entries": tls_entries,
        "extracted_files": []
    }
