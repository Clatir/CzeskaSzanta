import os
import subprocess
import hashlib
import pyshark

OUTPUT_DIR = "output/extracted_files"


def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def extract_smtp_files(pcap_path):
    ensure_output_dir()

    try:
        subprocess.run(
            ["tshark", "-r", pcap_path, "--export-objects", f"smtp,{OUTPUT_DIR}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return []

    files = []
    for filename in os.listdir(OUTPUT_DIR):
        path = os.path.join(OUTPUT_DIR, filename)
        if os.path.isfile(path):
            files.append(path)

    return files


def decode_smtp(pcap_path):
    try:
        capture = pyshark.FileCapture(
            pcap_path,
            display_filter="smtp",
            keep_packets=False,
        )
    except Exception as e:
        return {"success": False, "message": f"Błąd SMTP: {e}"}

    smtp_entries = []

    try:
        for pkt in capture:
            try:
                smtp = pkt.smtp
            except AttributeError:
                continue

            # IP + porty (jeśli są obecne)
            if hasattr(pkt, "ip"):
                src_ip = getattr(pkt.ip, "src", None)
                dst_ip = getattr(pkt.ip, "dst", None)
            else:
                src_ip = dst_ip = None

            if hasattr(pkt, "tcp"):
                src_port = getattr(pkt.tcp, "srcport", None)
                dst_port = getattr(pkt.tcp, "dstport", None)
            else:
                src_port = dst_port = None

            command = (
                getattr(smtp, "req_command", None)
                or getattr(smtp, "command", None)
            )
            parameter = getattr(smtp, "req_parameter", None)
            response = getattr(smtp, "response", None)
            response_code = getattr(smtp, "response_code", None)

            entry = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "command": command,
                "parameter": parameter,
                "response": response,
                "response_code": response_code,
            }

            smtp_entries.append(entry)

    except Exception:
        # nie zabijamy całego dekodera przez pojedynczy zły pakiet
        pass

    capture.close()

    # eksport obiektów SMTP (wiadomości / załączników)
    extracted_paths = extract_smtp_files(pcap_path)

    extracted_info = []
    for path in extracted_paths:
        extracted_info.append({
            "filename": os.path.basename(path),
            "full_path": path,
            "size": os.path.getsize(path),
            "sha256": hash_file(path),
            "protocol": "SMTP",
        })

    return {
        "success": True,
        "entries": smtp_entries,
        "extracted_files": extracted_info,
    }
