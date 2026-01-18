import json
import os
from datetime import datetime
from getpass import getpass
from textwrap import wrap

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
        with pyzipper.AESZipFile(
            zip_path,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES
        ) as zf:
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
                    with open(full, "rb") as fh:
                        data = fh.read()
                    zf.writestr(rel, data, compress_type=zipfile.ZIP_DEFLATED)
        return {
            "success": True,
            "method": "NONE",
            "zip": zip_path,
            "warning": (
                "Brak pyzipper → ZIP bez szyfrowania AES. "
                "Zainstaluj pyzipper, aby mieć ZIP-AES."
            )
        }


def _pdf_report(report_data, pdf_path, password, responsible_person):
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

    # Marginesy i podstawowe parametry
    MARGIN_LEFT = 20 * mm
    MARGIN_RIGHT = 20 * mm
    MARGIN_TOP = 20 * mm
    MARGIN_BOTTOM = 20 * mm
    LINE_HEIGHT = 5 * mm

    y = h - MARGIN_TOP

    def new_page():
        nonlocal y
        c.showPage()
        y = h - MARGIN_TOP

    def ensure_space(lines=1):
        nonlocal y
        if y - lines * LINE_HEIGHT < MARGIN_BOTTOM:
            new_page()

    def draw_wrapped(text, x, max_chars=100, bullet=None):
        """
        Proste zawijanie tekstu w oparciu o liczbę znaków.
        Nie jest idealnie zależne od szerokości w mm, ale
        respektuje marginesy i nie wychodzi poza prawą krawędź.
        """
        nonlocal y
        if text is None:
            return
        text = str(text)
        if not text:
            return

        lines = wrap(text, max_chars)
        for i, line in enumerate(lines):
            ensure_space()
            if bullet and i == 0:
                c.drawString(x, y, f"{bullet} {line}")
            else:
                prefix = "  " if bullet and i > 0 else ""
                c.drawString(x, y, prefix + line)
            y -= LINE_HEIGHT

    def section_title(title, level=1):
        nonlocal y
        ensure_space(2)
        if level == 1:
            c.setFont("Helvetica-Bold", 14)
        else:
            c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN_LEFT, y, title)
        y -= LINE_HEIGHT * 1.2
        if level == 1:
            c.setLineWidth(1)
            c.line(
                MARGIN_LEFT,
                y + LINE_HEIGHT * 0.4,
                w - MARGIN_RIGHT,
                y + LINE_HEIGHT * 0.4
            )
            y -= LINE_HEIGHT * 0.5

    def kv(label, value, max_chars=80):
        nonlocal y
        ensure_space()
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN_LEFT, y, f"{label}:")
        c.setFont("Helvetica", 10)
        y -= LINE_HEIGHT
        draw_wrapped(value, MARGIN_LEFT + 10 * mm, max_chars=max_chars)
        y -= LINE_HEIGHT * 0.3

    # ========= STRONA TYTUŁOWA =========
    c.setFont("Helvetica-Bold", 16)
    c.drawString(MARGIN_LEFT, y, "PCAP Forensic Analyzer — Raport końcowy")
    y -= LINE_HEIGHT * 2

    c.setFont("Helvetica", 11)
    draw_wrapped(f"Osoba odpowiedzialna za raport: {responsible_person}", MARGIN_LEFT, max_chars=90)
    draw_wrapped(
        "Data wygenerowania: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        MARGIN_LEFT,
        max_chars=90
    )
    y -= LINE_HEIGHT

    # ========= 1. METADANE I INFORMACJE O PLIKU =========
    section_title("1. Metadane i informacje o pliku", level=1)

    metadata = report_data.get("metadata", {})
    if metadata:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN_LEFT, y, "1.1 Metadane źródła")
        y -= LINE_HEIGHT * 1.2
        c.setFont("Helvetica", 10)
        kv("Źródło", metadata.get("source", "N/A"))
        kv("Ścieżka pliku", metadata.get("file_path", "N/A"))
        kv("SHA256 (źródło)", metadata.get("sha256", "N/A"))
        y -= LINE_HEIGHT * 0.5

    file_info = report_data.get("file_info", {})
    if file_info:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN_LEFT, y, "1.2 Informacje o pliku PCAP")
        y -= LINE_HEIGHT * 1.2
        c.setFont("Helvetica", 10)

        kv("Plik", file_info.get("file", "N/A"))
        kv("Rozmiar [bajtów]", file_info.get("size", "N/A"))
        kv("SHA256", file_info.get("hash", "N/A"))
        kv("Liczba pakietów", file_info.get("packet_count", "N/A"))
        kv("Pierwszy znacznik czasowy", file_info.get("first_timestamp", "N/A"))
        kv("Ostatni znacznik czasowy", file_info.get("last_timestamp", "N/A"))

    # ========= 2. PROTOKOŁY I FLOW_MAP =========
    section_title("2. Protokoły i statystyki", level=1)

    protocols = report_data.get("protocols", {})
    if protocols:
        detected = protocols.get("detected", [])
        per_proto = protocols.get("per_protocol", {})
        confidence = protocols.get("confidence", {})
        flow_map = protocols.get("flow_map", {})
        total_packets = protocols.get("total_packets", None)

        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN_LEFT, y, "2.1 Zestawienie protokołów L7")
        y -= LINE_HEIGHT * 1.2
        c.setFont("Helvetica", 10)

        if total_packets is not None:
            kv("Łączna liczba pakietów", total_packets)

        if detected:
            kv("Wykryte protokoły", ", ".join(detected))

        if per_proto:
            ensure_space(2)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(MARGIN_LEFT, y, "Statystyki per protokół:")
            y -= LINE_HEIGHT * 1.2
            c.setFont("Helvetica", 10)

            for proto_name in sorted(per_proto.keys()):
                cnt = per_proto.get(proto_name, 0)
                conf = confidence.get(proto_name, 0.0)
                ensure_space()
                line = f"- {proto_name}: pakiety={cnt}, pewność={conf:.2f}"
                draw_wrapped(line, MARGIN_LEFT + 5 * mm, max_chars=90)

        if flow_map:
            ensure_space(2)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(MARGIN_LEFT, y, "2.2 Mapa przepływów (flow_map)")
            y -= LINE_HEIGHT * 1.2
            c.setFont("Helvetica", 9)

            # Prosta „tabelka” tekstowa
            ensure_space()
            c.drawString(MARGIN_LEFT, y, "Flow key / L4 / total / top L7")
            y -= LINE_HEIGHT

            for flow_key, info in flow_map.items():
                l4 = info.get("l4", "N/A")
                total = info.get("total", 0)
                counts = info.get("counts", {})
                top_l7 = ", ".join(
                    f"{p}:{n}" for p, n in sorted(counts.items(), key=lambda x: -x[1])
                ) or "-"
                line = f"- {flow_key} | {l4} | pakiety={total} | L7={top_l7}"
                draw_wrapped(line, MARGIN_LEFT + 5 * mm, max_chars=100)

    # ========= 3. ANALIZA ADRESÓW IP =========
    section_title("3. Analiza adresów IP", level=1)

    ip_analysis = report_data.get("ip_analysis", {})
    if ip_analysis:
        public_ips = ip_analysis.get("public_ips", [])
        private_ips = ip_analysis.get("private_ips", [])
        country_stats = ip_analysis.get("country_stats", {})

        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN_LEFT, y, "3.1 Podsumowanie adresów")
        y -= LINE_HEIGHT * 1.2
        c.setFont("Helvetica", 10)

        kv("Liczba unikalnych IP publicznych", len(public_ips))
        if private_ips:
            kv("Liczba unikalnych IP prywatnych", len(private_ips))

        if public_ips:
            ensure_space()
            c.setFont("Helvetica-Bold", 10)
            c.drawString(MARGIN_LEFT, y, "Lista IP publicznych:")
            y -= LINE_HEIGHT * 1.1
            c.setFont("Helvetica", 9)
            for ip in public_ips:
                draw_wrapped(ip, MARGIN_LEFT + 5 * mm, max_chars=90, bullet="-")

        if country_stats:
            ensure_space(2)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(MARGIN_LEFT, y, "3.2 Ruch wg krajów (country_stats)")
            y -= LINE_HEIGHT * 1.2
            c.setFont("Helvetica", 9)
            for country, count in sorted(country_stats.items(), key=lambda x: -x[1]):
                line = f"{country}: {count} pakietów"
                draw_wrapped(line, MARGIN_LEFT + 5 * mm, max_chars=90, bullet="-")

    # ========= 4. SESJE TCP/UDP =========
    section_title("4. Sesje TCP/UDP", level=1)

    sessions_data = report_data.get("sessions", {})
    if sessions_data and sessions_data.get("success", False):
        total_sessions = sessions_data.get("total_sessions", 0)
        sessions = sessions_data.get("sessions", [])

        c.setFont("Helvetica", 10)
        kv("Łączna liczba sesji", total_sessions)

        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN_LEFT, y, "Lista sesji:")
        y -= LINE_HEIGHT * 1.2
        c.setFont("Helvetica", 9)

        for s in sessions:
            ensure_space(3)
            sid = s.get("id")
            proto = s.get("protocol")
            src_ip = s.get("src_ip")
            src_port = s.get("src_port")
            dst_ip = s.get("dst_ip")
            dst_port = s.get("dst_port")
            pkt_count = s.get("packet_count")
            bytes_total = s.get("bytes_total")
            direction = s.get("direction", "UNKNOWN")

            line1 = f"Sesja ID {sid} | {proto} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | kierunek={direction}"
            line2 = f"Pakiety={pkt_count}, bajty={bytes_total}"

            draw_wrapped(line1, MARGIN_LEFT + 5 * mm, max_chars=100, bullet="-")
            draw_wrapped(line2, MARGIN_LEFT + 10 * mm, max_chars=100)

    # ========= 5. DANE L7 =========
    section_title("5. Dane warstwy aplikacji (L7)", level=1)

    l7 = report_data.get("l7", {})

    def _render_l7_list(proto_name, items, fields):
        nonlocal y
        if not items:
            return
        ensure_space(2)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN_LEFT, y, f"5.{_render_l7_list.counter} {proto_name}")
        _render_l7_list.counter += 1
        y -= LINE_HEIGHT * 1.2
        c.setFont("Helvetica", 9)

        for it in items:
            ensure_space()
            parts = []
            for label, key in fields:
                val = it.get(key)
                if val is not None:
                    parts.append(f"{label}={val}")
            if not parts:
                continue
            line = ", ".join(parts)
            draw_wrapped(line, MARGIN_LEFT + 5 * mm, max_chars=105, bullet="-")

    _render_l7_list.counter = 1

    if isinstance(l7, dict):
        # DNS
        dns_items = l7.get("dns") or l7.get("DNS")
        if isinstance(dns_items, list):
            _render_l7_list(
                "DNS",
                dns_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("query", "query"),
                    ("type", "query_type"),
                    ("response", "response"),
                    ("ttl", "ttl"),
                ],
            )

        # HTTP
        http_items = l7.get("http") or l7.get("HTTP")
        if isinstance(http_items, list):
            _render_l7_list(
                "HTTP",
                http_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("method", "method"),
                    ("host", "host"),
                    ("uri", "uri"),
                    ("status", "status_code"),
                    ("ctype", "content_type"),
                    ("clen", "content_length"),
                ],
            )

        # FTP
        ftp_items = l7.get("ftp") or l7.get("FTP")
        if isinstance(ftp_items, list):
            _render_l7_list(
                "FTP",
                ftp_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("cmd", "command"),
                    ("arg", "argument"),
                    ("code", "reply_code"),
                ],
            )

        # SMTP
        smtp_items = l7.get("smtp") or l7.get("SMTP")
        if isinstance(smtp_items, list):
            _render_l7_list(
                "SMTP",
                smtp_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("cmd", "command"),
                    ("arg", "argument"),
                    ("mail_from", "mail_from"),
                    ("rcpt_to", "rcpt_to"),
                ],
            )

        # TLS
        tls_items = l7.get("tls") or l7.get("TLS")
        if isinstance(tls_items, list):
            _render_l7_list(
                "TLS",
                tls_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("version", "record_version"),
                    ("sni", "sni"),
                    ("cipher", "cipher"),
                    ("handshake", "handshake_type"),
                ],
            )

    # ========= 6. ANOMALIE =========
    section_title("6. Wykryte anomalie", level=1)

    anomalies = report_data.get("anomalies", [])
    c.setFont("Helvetica", 10)

    if not anomalies:
        draw_wrapped("Brak wykrytych anomalii.", MARGIN_LEFT + 5 * mm, max_chars=100)
    else:
        for a in anomalies:
            proto = a.get("protocol", "N/A")
            atype = a.get("type", "unknown")
            sev = str(a.get("severity", "n/a")).upper()
            desc = a.get("description", "")
            details = a.get("details", {})

            ensure_space(3)
            c.setFont("Helvetica-Bold", 10)
            title = f"[{sev}] {proto} / {atype}"
            draw_wrapped(title, MARGIN_LEFT + 5 * mm, max_chars=100, bullet="-")

            c.setFont("Helvetica", 9)
            if desc:
                draw_wrapped(desc, MARGIN_LEFT + 10 * mm, max_chars=105)
            if details:
                # wypisz szczegóły jako klucz=wartość
                for dk, dv in details.items():
                    line = f"{dk}: {dv}"
                    draw_wrapped(line, MARGIN_LEFT + 10 * mm, max_chars=105)

    # ========= 7. WYEKSTRAHOWANE PLIKI =========
    section_title("7. Wyekstrahowane pliki", level=1)

    extracted_files = report_data.get("extracted_files", [])
    c.setFont("Helvetica", 10)

    if not extracted_files:
        draw_wrapped(
            "Brak wyekstrahowanych plików z protokołów aplikacyjnych.",
            MARGIN_LEFT + 5 * mm,
            max_chars=100
        )
    else:
        for f in extracted_files:
            ensure_space(4)
            fname = f.get("filename") or f.get("name")
            full = f.get("full_path", "")
            size = f.get("size", 0)
            sha = f.get("sha256", "")
            proto = f.get("protocol", "UNKNOWN")

            c.setFont("Helvetica-Bold", 10)
            draw_wrapped(
                f"- {fname} (protokoł: {proto})",
                MARGIN_LEFT + 5 * mm,
                max_chars=100
            )
            c.setFont("Helvetica", 9)
            if full:
                draw_wrapped(f"Ścieżka: {full}", MARGIN_LEFT + 10 * mm, max_chars=105)
            draw_wrapped(f"Rozmiar: {size} bajtów", MARGIN_LEFT + 10 * mm, max_chars=105)
            if sha:
                draw_wrapped(f"SHA256: {sha}", MARGIN_LEFT + 10 * mm, max_chars=105)

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

    responsible_person = input("Podaj osobę odpowiedzialną za raport: ")
    if not responsible_person:
        return {"success": False, "message": "Osoba odpowiedzialna nie może być pusta."}

    json_path = os.path.join(out_dir, "report.json")
    _write_json(report_data, json_path)

    pdf_path = os.path.join(out_dir, "report.pdf")
    _pdf_report(report_data, pdf_path, password, responsible_person)

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
        "zip": zip_info,
    }
