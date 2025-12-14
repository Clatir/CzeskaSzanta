import json
import os
import shutil
from datetime import datetime
from getpass import getpass

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import pdfencrypt


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _write_json(report_data, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)


def _zip_folder_with_password(src_dir, zip_path, password):
    password_bytes = password.encode("utf-8")

    try:
        import pyzipper
        with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password_bytes)
            for root, _, files in os.walk(src_dir):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, src_dir)
                    zf.write(full, arcname=rel)
        return {"success": True, "method": "AES", "zip": zip_path}
    except ImportError:
        import zipfile
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(src_dir):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, src_dir)
                    zinfo = zipfile.ZipInfo(rel)
                    zf.writestr(zinfo, open(full, "rb").read(), compress_type=zipfile.ZIP_DEFLATED)
        return {
            "success": True,
            "method": "NONE",
            "zip": zip_path,
            "warning": "Brak pyzipper → ZIP bez szyfrowania AES (standardowa biblioteka zipfile nie daje AES). Zainstaluj pyzipper, aby mieć ZIP-AES."
        }


def _pdf_report(report_data, pdf_path, password):
    enc = pdfencrypt.StandardEncryption(
        userPassword=password,
        ownerPassword=password,
        canPrint=1,
        canModify=0,
        canCopy=0,
        canAnnotate=0
    )

    c = canvas.Canvas(pdf_path, pagesize=A4, encrypt=enc)
    w, h = A4

    def header(title):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(20 * mm, h - 20 * mm, title)
        c.setLineWidth(1)
        c.line(20 * mm, h - 22 * mm, w - 20 * mm, h - 22 * mm)

    def kv(y, k, v):
        c.setFont("Helvetica-Bold", 10)
        c.drawString(20 * mm, y, k)
        c.setFont("Helvetica", 10)
        c.drawString(70 * mm, y, str(v)[:120])

    y = h - 35 * mm
    header("PCAP Forensic Analyzer — Raport końcowy")

    meta = report_data.get("file_info", {})
    kv(y, "Plik:", meta.get("file", "N/A")); y -= 6 * mm
    kv(y, "SHA256:", meta.get("hash", "N/A")); y -= 6 * mm
    kv(y, "Pakiety:", meta.get("packet_count", "N/A")); y -= 6 * mm
    kv(y, "Pierwszy pakiet:", meta.get("first_timestamp", "N/A")); y -= 6 * mm
    kv(y, "Ostatni pakiet:", meta.get("last_timestamp", "N/A")); y -= 10 * mm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Protokoły (L7)"); y -= 7 * mm
    c.setFont("Helvetica", 10)
    prot = report_data.get("protocols", {})
    for p in prot.get("detected", [])[:20]:
        c.drawString(25 * mm, y, f"- {p}"); y -= 5 * mm
        if y < 25 * mm:
            c.showPage()
            y = h - 25 * mm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Anomalie"); y -= 7 * mm
    c.setFont("Helvetica", 10)
    anoms = report_data.get("anomalies", [])
    if not anoms:
        c.drawString(25 * mm, y, "Brak wykrytych anomalii."); y -= 5 * mm
    else:
        for a in anoms[:40]:
            sev = str(a.get("severity", "n/a")).upper()
            typ = a.get("type", "unknown")
            desc = a.get("description", "")
            line = f"[{sev}] {typ}: {desc}"
            c.drawString(25 * mm, y, line[:140]); y -= 5 * mm
            if y < 25 * mm:
                c.showPage()
                y = h - 25 * mm

    c.showPage()
    c.save()


def generate_final_report(report_data, base_output_dir="reports", extracted_dir=None):
    _ensure_dir(base_output_dir)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_output_dir, stamp)
    _ensure_dir(out_dir)

    password = getpass("Podaj hasło do PDF/ZIP: ").strip()
    if not password:
        return {"success": False, "message": "Hasło nie może być puste."}

    json_path = os.path.join(out_dir, "report.json")
    _write_json(report_data, json_path)

    pdf_path = os.path.join(out_dir, "report.pdf")
    _pdf_report(report_data, pdf_path, password)

    zip_info = None
    if extracted_dir and os.path.isdir(extracted_dir):
        zip_path = os.path.join(out_dir, "extracted_files.zip")
        zip_info = _zip_folder_with_password(extracted_dir, zip_path, password)

    return {
        "success": True,
        "message": "Raport wygenerowany.",
        "output_dir": out_dir,
        "json": json_path,
        "pdf": pdf_path,
        "zip": zip_info
    }
