import json
import os
from datetime import datetime
from getpass import getpass
from textwrap import wrap

from xml.sax.saxutils import escape

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    ListFlowable,
    ListItem,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
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
        canAnnotate=0,
    )

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        encrypt=enc,
    )

    styles = getSampleStyleSheet()
    body = styles["Normal"]
    body.fontName = "Helvetica"
    body.fontSize = 10
    body.leading = 12

    small = ParagraphStyle(
        name="Small",
        parent=body,
        fontSize=9,
        leading=11,
    )

    h1 = ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=14,
        spaceBefore=12,
        spaceAfter=6,
    )

    h2 = ParagraphStyle(
        name="SubSectionTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        spaceBefore=8,
        spaceAfter=4,
    )

    story = []

    def section_title(text):
        story.append(Spacer(1, 6))
        story.append(Paragraph(text, h1))
        story.append(Spacer(1, 4))

    def subsection_title(text):
        story.append(Spacer(1, 4))
        story.append(Paragraph(text, h2))
        story.append(Spacer(1, 2))

    def kv(label, value, style=body):
        val = "-" if value is None else str(value)
        story.append(Paragraph(f"<b>{escape(str(label))}:</b> {escape(val)}", style))
        story.append(Spacer(1, 2))

    # ===================== STRONA TYTUŁOWA =====================
    story.append(Paragraph("PCAP Forensic Analyzer — Raport końcowy", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            f"Osoba odpowiedzialna za raport: {escape(responsible_person or '-')}",
            body,
        )
    )
    story.append(
        Paragraph(
            "Data wygenerowania: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            body,
        )
    )
    story.append(Spacer(1, 12))

    # ===================== 1. METADANE =====================
    section_title("1. Metadane i informacje o pliku")

    metadata = report_data.get("metadata", {})
    if metadata:
        subsection_title("1.1 Metadane źródła")
        kv("Źródło", metadata.get("source"))
        kv("Ścieżka pliku", metadata.get("file_path"))
        kv("SHA256 (źródło)", metadata.get("sha256"))

    file_info = report_data.get("file_info", {})
    if file_info:
        subsection_title("1.2 Informacje o pliku PCAP")
        kv("Plik", file_info.get("file"))
        kv("Rozmiar [bajtów]", file_info.get("size"))
        kv("SHA256", file_info.get("hash"))
        kv("Liczba pakietów", file_info.get("packet_count"))
        kv("Pierwszy znacznik czasowy", file_info.get("first_timestamp"))
        kv("Ostatni znacznik czasowy", file_info.get("last_timestamp"))

    # ===================== 2. PROTOKOŁY =====================
    section_title("2. Protokoły i statystyki")

    protocols = report_data.get("protocols", {})
    if protocols:
        detected = protocols.get("detected", [])
        per_proto = protocols.get("per_protocol", {})
        confidence = protocols.get("confidence", {})
        total_packets = protocols.get("total_packets", None)

        subsection_title("2.1 Zestawienie protokołów L7")

        if total_packets is not None:
            kv("Łączna liczba pakietów", total_packets)

        if detected:
            kv("Wykryte protokoły", ", ".join(sorted(detected)))

        if per_proto:
            data = [["Protokół", "Pakiety", "Pewność"]]
            for proto in sorted(per_proto.keys()):
                cnt = per_proto.get(proto, 0)
                conf = confidence.get(proto, 0.0)
                data.append([proto, str(cnt), f"{conf:.2f}"])

            t = Table(data, hAlign="LEFT")
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                    ]
                )
            )
            story.append(t)
            story.append(Spacer(1, 8))

        # 2.2 FLOW MAP – ciaśniejsze kolumny
        flow_map = protocols.get("flow_map", {})
        if isinstance(flow_map, dict) and flow_map:
            subsection_title("2.2 Mapa przepływów (flow_map)")

            data = [["Flow", "L4", "Pakiety", "Najczęstsze L7"]]
            for flow_key, info in flow_map.items():
                if isinstance(info, dict):
                    l4 = info.get("l4", "N/A")
                    total = info.get("total", 0)
                    counts = info.get("counts", {})
                    top_l7 = ", ".join(
                        f"{p}:{n}"
                        for p, n in sorted(counts.items(), key=lambda x: -x[1])
                    ) or "-"
                    data.append(
                        [str(flow_key), str(l4), str(total), top_l7]
                    )

            if len(data) > 1:
                # węższy "Flow" i "Pakiety", więcej miejsca na kolumnę L7
                t = Table(
                    data,
                    hAlign="LEFT",
                    colWidths=[83 * mm, 12 * mm, 15 * mm, 60 * mm],
                )
                t.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
                story.append(t)
                story.append(Spacer(1, 8))

    # ===================== 3. IP ANALYSIS =====================
    section_title("3. Analiza adresów IP")

    ip_analysis = report_data.get("ip_analysis", {})
    if ip_analysis:
        public_ips = ip_analysis.get("public_ips", [])
        private_ips = ip_analysis.get("private_ips", [])
        country_stats = ip_analysis.get("country_stats", {})

        subsection_title("3.1 Podsumowanie adresów")
        kv("Unikalne IP publiczne", len(public_ips))
        kv("Unikalne IP prywatne", len(private_ips))

        if public_ips:
            story.append(Paragraph("<b>Lista IP publicznych:</b>", body))
            items = [
                ListItem(Paragraph(escape(ip), small), bulletColor=colors.black)
                for ip in public_ips
            ]
            story.append(ListFlowable(items, bulletType="bullet"))
            story.append(Spacer(1, 6))

        if country_stats:
            subsection_title("3.2 Ruch wg krajów")
            data = [["Kraj", "Pakiety"]]
            for country, count in sorted(country_stats.items(), key=lambda x: -x[1]):
                data.append([country, str(count)])
            t = Table(data, hAlign="LEFT")
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ]
                )
            )
            story.append(t)
            story.append(Spacer(1, 8))

    # ===================== 4. SESJE =====================
    section_title("4. Sesje TCP/UDP")

    sessions_data = report_data.get("sessions", {})
    if sessions_data and sessions_data.get("success", False):
        total_sessions = sessions_data.get("total_sessions", 0)
        sessions = sessions_data.get("sessions", [])

        kv("Łączna liczba sesji", total_sessions)

        if sessions:
            data = [["ID", "Proto", "Kierunek", "Źródło", "Cel", "Pakiety", "Bajty"]]
            for s in sessions:
                data.append(
                    [
                        str(s.get("id")),
                        str(s.get("protocol")),
                        str(s.get("direction", "UNKNOWN")),
                        f"{s.get('src_ip')}:{s.get('src_port')}",
                        f"{s.get('dst_ip')}:{s.get('dst_port')}",
                        str(s.get("packet_count")),
                        str(s.get("bytes_total")),
                    ]
                )
            t = Table(
                data,
                hAlign="LEFT",
                colWidths=[12 * mm, 14 * mm, 20 * mm, 45 * mm, 45 * mm, 18 * mm, 22 * mm],
            )
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(t)
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("Brak informacji o sesjach.", body))
        story.append(Spacer(1, 4))

    # ===================== 5. L7 DATA =====================
    section_title("5. Dane warstwy aplikacji (L7)")

    l7 = report_data.get("l7", {})

    def _soft_wrap_value(val, max_chunk=80):
        """
        Proste zawijanie: escapuje tekst i wstawia <br/> co max_chunk znaków.
        Bez żadnych zero-width space'ów.
        """
        if val is None:
            return ""
        s = escape(str(val))
        if len(s) <= max_chunk:
            return s
        chunks = [s[i : i + max_chunk] for i in range(0, len(s), max_chunk)]
        return "<br/>".join(chunks)

    def render_l7_records(proto_name, items, fields):
        """
        fields – lista (label, key).
        Każdy rekord jest osobnym blokiem z nagłówkiem "Rekord N"
        i polami łamanymi co max_chunk znaków.
        """
        if not items:
            return

        subsection_title(proto_name)

        for idx, it in enumerate(items, start=1):
            story.append(Paragraph(f"<b>Rekord {idx}</b>", small))

            for label, key in fields:
                value = it.get(key)
                if value is None:
                    continue

                txt = _soft_wrap_value(value, max_chunk=64)
                story.append(
                    Paragraph(f"<b>{escape(str(label))}:</b> {txt}", small)
                )

            story.append(Spacer(1, 4))

    if isinstance(l7, dict):
        dns_items = l7.get("dns") or l7.get("DNS")
        if isinstance(dns_items, list):
            render_l7_records(
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

        http_items = l7.get("http") or l7.get("HTTP")
        if isinstance(http_items, list):
            render_l7_records(
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

        ftp_items = l7.get("ftp") or l7.get("FTP")
        if isinstance(ftp_items, list):
            render_l7_records(
                "FTP",
                ftp_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("cmd", "command"),
                    ("arg", "argument"),
                    ("code", "response_code"),
                ],
            )

        smtp_items = l7.get("smtp") or l7.get("SMTP")
        if isinstance(smtp_items, list):
            render_l7_records(
                "SMTP",
                smtp_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("cmd", "command"),
                    ("param", "parameter"),
                    ("resp", "response"),
                    ("code", "response_code"),
                ],
            )

        tls_items = l7.get("tls") or l7.get("TLS")
        if isinstance(tls_items, list):
            render_l7_records(
                "TLS",
                tls_items,
                [
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("version", "version"),
                    ("sni", "sni"),
                    ("cipher", "cipher"),
                ],
            )

    # ===================== 6. ANOMALIE =====================
    section_title("6. Wykryte anomalie")

    anomalies = report_data.get("anomalies", [])
    if not anomalies:
        story.append(Paragraph("Brak wykrytych anomalii.", body))
        story.append(Spacer(1, 4))
    else:
        for a in anomalies:
            proto = a.get("protocol", "N/A")
            atype = a.get("id", "unknown")
            sev = str(a.get("severity", "n/a")).upper()
            desc = a.get("description", "")
            details = a.get("details", {})

            story.append(
                Paragraph(f"<b>[{escape(sev)}] {escape(proto)} / {escape(atype)}</b>", small)
            )
            if desc:
                story.append(Paragraph(escape(desc), small))
            if details:
                for dk, dv in details.items():
                    story.append(
                        Paragraph(f"{escape(str(dk))}: {escape(str(dv))}", small)
                    )
            story.append(Spacer(1, 4))
            
    # ===================== 7. KORELACJE =====================
    section_title("7. Korelacje między protokołami")

    correlations = report_data.get("correlations", [])
    if not correlations:
        story.append(
            Paragraph("Brak znalezionych korelacji między protokołami.", body)
        )
    else:
        for corr in correlations:
            cid = corr.get("id", "N/A")
            sev = str(corr.get("severity", "n/a")).upper()
            desc = corr.get("description", "")
            prots = corr.get("protocols", [])
            evidence = corr.get("evidence", {})

            header = (
                f"<b>[{escape(sev)}] {escape(cid)}</b> — protokoły: "
                f"{escape(', '.join(prots) if prots else 'N/A')}"
            )
            story.append(Paragraph(header, small))
            if desc:
                story.append(Paragraph(escape(desc), small))
            if evidence:
                for ek, ev in evidence.items():
                    story.append(
                        Paragraph(
                            f"{escape(str(ek))}: {escape(str(ev))}", small
                        )
                    )
            story.append(Spacer(1, 4))

    # ===================== 8. WYEKSTRAHOWANE PLIKI =====================
    section_title("8. Wyekstrahowane pliki")

    extracted_files = report_data.get("extracted_files", [])
    if not extracted_files:
        story.append(
            Paragraph(
                "Brak wyekstrahowanych plików z protokołów aplikacyjnych.",
                body,
            )
        )
        story.append(Spacer(1, 4))
    else:
        for idx, f in enumerate(extracted_files, start=1):
            story.append(Paragraph(f"<b>Plik {idx}</b>", small))

            fname = f.get("filename") or f.get("name") or ""
            proto = f.get("protocol", "UNKNOWN")
            size = f.get("size", 0)
            sha = f.get("sha256", "")
            full = f.get("full_path", "")

            story.append(
                Paragraph(f"<b>Nazwa:</b> {escape(str(fname))}", small)
            )
            story.append(
                Paragraph(f"<b>Protokół:</b> {escape(str(proto))}", small)
            )
            story.append(
                Paragraph(f"<b>Rozmiar [B]:</b> {escape(str(size))}", small)
            )
            story.append(
                Paragraph(
                    f"<b>SHA256:</b> {_soft_wrap_value(sha, max_chunk=64)}",
                    small,
                )
            )
            story.append(
                Paragraph(
                    f"<b>Ścieżka:</b> {_soft_wrap_value(full, max_chunk=64)}",
                    small,
                )
            )
            story.append(Spacer(1, 6))

    doc.build(story)


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
