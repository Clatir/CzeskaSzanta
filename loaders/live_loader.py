import time
import hashlib
from scapy.all import sniff, wrpcap, get_if_list

def live_capture(interface: str, duration: int):
    try:
        packets = sniff(iface=interface, timeout=duration)
    except PermissionError:
        return {
            "success": False,
            "message": "Brak uprawnień administratora do przechwytywania ruchu."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Błąd podczas sniffingu: {e}"
        }

    if len(packets) == 0:
        return {
            "success": False,
            "message": "Nie przechwycono żadnych pakietów."
        }

    timestamp = int(time.time())
    filename = f"live_capture_{timestamp}.pcap"
    wrpcap(filename, packets)

    sha256 = hashlib.sha256(open(filename, "rb").read()).hexdigest()

    return {
        "success": True,
        "message": f"Zapisano przechwycone pakiety do {filename}",
        "file": filename,
        "hash": sha256,
        "count": len(packets)
    }


def list_interfaces():
    try:
        return get_if_list()
    except Exception:
        return []
