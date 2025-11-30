import os
import hashlib

def load_from_disk(path: str):
    if not os.path.isfile(path):
        return {
            "success": False,
            "message": "Plik nie istnieje."
        }

    sha256 = hashlib.sha256(open(path, "rb").read()).hexdigest()

    return {
        "success": True,
        "message": f"Wczytano plik {path}",
        "file": path,
        "hash": sha256
    }
