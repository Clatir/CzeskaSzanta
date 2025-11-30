import paramiko
import hashlib
import os

def fetch_pcap_scp(host: str, username: str, password: str, remote_path: str):
    try:
        transport = paramiko.Transport((host, 22))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
    except Exception as e:
        return {
            "success": False,
            "message": f"Nie można połączyć z hostem: {e}"
        }

    filename = os.path.basename(remote_path)
    local_path = f"remote_{filename}"

    try:
        sftp.get(remote_path, local_path)
    except Exception as e:
        transport.close()
        return {
            "success": False,
            "message": f"Błąd podczas pobierania pliku: {e}"
        }

    transport.close()

    sha256 = hashlib.sha256(open(local_path, "rb").read()).hexdigest()

    return {
        "success": True,
        "message": f"Pobrano plik z maszyny zdalnej jako {local_path}",
        "file": local_path,
        "hash": sha256,
        "remote_path": remote_path
    }
