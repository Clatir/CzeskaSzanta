import os
import subprocess
import hashlib
import pyshark

OUTPUT_DIR = "output/extracted_files"

def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def hash_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

def extract_http_files(pcap_path):
    ensure_output_dir()

    try:
        subprocess.run(
            ["tshark", "-r", pcap_path, "--export-objects", f"http,{OUTPUT_DIR}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except:
        return []

    files = []
    for filename in os.listdir(OUTPUT_DIR):
        path = os.path.join(OUTPUT_DIR, filename)
        if os.path.isfile(path):
            files.append(path)

    return files

def decode_http(pcap_path):
    try:
        capture = pyshark.FileCapture(
            pcap_path,
            display_filter="http",
            keep_packets=False
        )
    except Exception as e:
        return {"success": False, "message": f"Błąd HTTP: {e}"}

    http_entries = []

    try:
        for pkt in capture:
            http = pkt.http

            entry = {
                "src_ip": pkt.ip.src,
                "dst_ip": pkt.ip.dst,
                "method": getattr(http, "request_method", None),
                "host": getattr(http, "host", None),
                "uri": getattr(http, "request_uri", None),
                "user_agent": getattr(http, "user_agent", None),
                "status_code": getattr(http, "response_code", None),
                "content_type": getattr(http, "content_type", None),
                "content_length": getattr(http, "content_length", None)
            }

            http_entries.append(entry)

    except Exception:
        pass

    capture.close()

    extracted_paths = extract_http_files(pcap_path)

    extracted_info = []
    for path in extracted_paths:
        extracted_info.append({
            "filename": os.path.basename(path),
            "full_path": path,
            "size": os.path.getsize(path),
            "sha256": hash_file(path),
            "protocol": "HTTP"
        })

    return {
        "success": True,
        "entries": http_entries,
        "extracted_files": extracted_info
    }
