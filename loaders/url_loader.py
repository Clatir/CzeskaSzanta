import requests
import hashlib
import os

def fetch_pcap_url(url: str):
    try:
        response = requests.get(url, timeout=15)
    except Exception as e:
        return {
            "success": False,
            "message": f"Błąd podczas pobierania: {e}"
        }

    if response.status_code != 200:
        return {
            "success": False,
            "message": f"Serwer zwrócił kod: {response.status_code}"
        }

    filename = os.path.basename(url)
    if not filename.endswith(".pcap"):
        filename = "downloaded_capture.pcap"

    try:
        with open(filename, "wb") as f:
            f.write(response.content)
    except Exception as e:
        return {
            "success": False,
            "message": f"Błąd zapisu pliku: {e}"
        }

    sha256 = hashlib.sha256(open(filename, "rb").read()).hexdigest()

    return {
        "success": True,
        "message": f"Pobrano PCAP jako {filename}",
        "file": filename,
        "hash": sha256,
        "url": url
    }
