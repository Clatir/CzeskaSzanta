import socket
import hashlib
import time

def receive_pcap(port: int, timeout: int = 60):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.bind(("0.0.0.0", port))
        s.listen(1)
    except Exception as e:
        return {
            "success": False,
            "message": f"Nie można otworzyć portu: {e}"
        }

    try:
        conn, addr = s.accept()
    except socket.timeout:
        return {
            "success": False,
            "message": "Upłynął czas oczekiwania na połączenie."
        }

    timestamp = int(time.time())
    filename = f"netcat_capture_{timestamp}.pcap"

    try:
        with open(filename, "wb") as f:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                f.write(data)
    except Exception as e:
        conn.close()
        return {
            "success": False,
            "message": f"Błąd zapisu danych: {e}"
        }

    conn.close()

    sha256 = hashlib.sha256(open(filename, "rb").read()).hexdigest()

    return {
        "success": True,
        "message": f"Odebrano PCAP i zapisano jako {filename}",
        "file": filename,
        "hash": sha256,
        "sender": addr[0]
    }
