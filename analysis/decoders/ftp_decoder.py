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

def extract_ftp_files(pcap_path):
    ensure_output_dir()

    try:
        subprocess.run(
            ["tshark", "-r", pcap_path, "--export-objects", f"ftp,{OUTPUT_DIR}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        return []

    files = []
    for filename in os.listdir(OUTPUT_DIR):
        path = os.path.join(OUTPUT_DIR, filename)
        if os.path.isfile(path):
            files.append(path)

    return files

def decode_ftp(pcap_path):
    try:
        capture = pyshark.FileCapture(
            pcap_path,
            display_filter="ftp",
            keep_packets=False
        )
    except Exception as e:
        return {"success": False, "message": f"Błąd FTP: {e}"}

    ftp_entries = []

    try:
        for pkt in capture:
            try:
                ftp = pkt.ftp
            except AttributeError:
                continue

            entry = {
                "src_ip": getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else None,
                "dst_ip": getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else None,
                "src_port": getattr(pkt.tcp, "srcport", None) if hasattr(pkt, "tcp") else None,
                "dst_port": getattr(pkt.tcp, "dstport", None) if hasattr(pkt, "tcp") else None,
                "command": getattr(ftp, "request_command", None),
                "argument": getattr(ftp, "request_arg", None),
                "response_code": getattr(ftp, "response_code", None),
                "response_arg": getattr(ftp, "response_arg", None),
            }

            ftp_entries.append(entry)

    except Exception:
        pass

    capture.close()

    extracted_paths = extract_ftp_files(pcap_path)

    extracted_info = []
    for path in extracted_paths:
        extracted_info.append({
            "filename": os.path.basename(path),
            "full_path": path,
            "size": os.path.getsize(path),
            "sha256": hash_file(path),
            "protocol": "FTP"
        })

    return {
        "success": True,
        "entries": ftp_entries,
        "extracted_files": extracted_info
    }
