import pyshark

def decode_dns(pcap_path):
    try:
        capture = pyshark.FileCapture(
            pcap_path,
            display_filter="dns",
            keep_packets=False
        )
    except Exception as e:
        return {"success": False, "message": f"Błąd DNS: {e}"}

    dns_entries = []

    try:
        for pkt in capture:
            dns = pkt.dns

            entry = {
                "src_ip": pkt.ip.src,
                "dst_ip": pkt.ip.dst,
                "query": getattr(dns, "qry_name", None),
                "query_type": getattr(dns, "qry_type", None),
                "response": getattr(dns, "a", None),
                "ttl": getattr(dns, "ttl", None)
            }

            dns_entries.append(entry)
    except:
        pass

    capture.close()

    return {
        "success": True,
        "entries": dns_entries,
        "extracted_files": []   # DNS nic nie ekstraktuje
    }
