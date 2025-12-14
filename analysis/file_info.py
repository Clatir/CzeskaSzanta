import os
import hashlib
import pyshark

def get_file_info(path: str):
    if not os.path.isfile(path):
        return {
            "success": False,
            "message": "Plik nie istnieje."
        }

    size = os.path.getsize(path)
    sha256 = hashlib.sha256(open(path, "rb").read()).hexdigest()

    try:
        capture = pyshark.FileCapture(path, keep_packets=False)
    except Exception as e:
        return {
            "success": False,
            "message": f"Błąd podczas analizy PCAP: {e}"
        }

    first_ts = None
    last_ts = None
    count = 0

    try:
        for pkt in capture:
            ts = float(pkt.sniff_timestamp)
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            count += 1
    except Exception:
        pass

    capture.close()

    return {
        "success": True,
        "file": path,
        "size": size,
        "hash": sha256,
        "packet_count": count,
        "first_timestamp": first_ts,
        "last_timestamp": last_ts
    }
