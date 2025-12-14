from itertools import count
import os
import platform
import time
from unittest import result

class ForensicApp:
    def __init__(self):
        self.report_data = {}

    def clear(self):
        os.system("cls" if platform.system() == "Windows" else "clear")

    def is_file_loaded(self):
        return bool(self.report_data.get("metadata", {}).get("file_path"))

    def main_menu(self):
        while True:
            self.clear()
            print("==========================================")
            print("      PCAP FORENSIC ANALYZER v1.0       ")
            print("==========================================")
            print("ŹRÓDŁA DANYCH:")
            print("[1] Wczytaj PCAP z dysku")
            print("[2] Przechwytywanie transmisji live")
            print("[3] Pobierz PCAP z maszyny zdalnej (SCP)")
            print("[4] Odbierz PCAP przez sieć (Netcat)")
            print("[5] Pobierz PCAP z URL")
            print("")
            print("ANALIZA:")
            print("[6] Informacje o pliku")
            print("[7] Lista protokołów")
            print("[8] Analiza pochodzenia pakietów")
            print("[9] Sesje TCP/UDP (IN/OUT)")
            print("[10] Ekstrakcja danych L7")
            print("[11] Wykrywanie anomalii")
            print("")
            print("RAPORT:")
            print("[12] Raport końcowy (JSON/HTML/AES)")
            print("")
            print("[0] Wyjście")

            choice = input("\nWybierz opcję: ").strip()

            match choice:
                case "1":
                    self.load_from_disk()
                case "2":
                    self.load_live_capture()
                case "3":
                    self.load_from_ssh()
                case "4":
                    self.load_netcat_mode()
                case "5":
                    self.load_from_url()
                case "6":
                    self.show_file_info()
                case "7":
                    self.show_protocols()
                case "8":
                    self.show_ip_analysis()
                case "9":
                    self.show_sessions()
                case "10":
                    self.extract_l7()
                case "11":
                    self.detect_anomalies()
                case "12":
                    self.generate_report()
                case "0":
                    self.clear()
                    print("Zamykanie programu...")
                    time.sleep(1)
                    return
                case _:
                    print("Nieprawidłowa opcja!")
                    time.sleep(1)

    def init_report_data(self, source, file_path, sha256):
        self.report_data = {
            "metadata": {
                "source": source,
                "file_path": file_path,
                "sha256": sha256
            },
            "file_info": {},
            "protocols": {},
            "ip_analysis": {},
            "sessions": {},
            "l7": {
                "http": [],
                "dns": [],
                "tls": []
            },
            "anomalies": [],
            "extracted_files": []
        }

    def load_from_disk(self):
        from loaders.disk_loader import load_from_disk as disk

        self.clear()
        print("=== Wczytywanie PCAP z dysku ===")
        path = input("Podaj ścieżkę do pliku: ").strip()

        result = disk(path)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return

        self.init_report_data("disk", result["file"], result["hash"])
        print(f"[✓] {result['message']}")
        print(f"SHA256: {result['hash']}")
        input("Enter...")

    def load_live_capture(self):
        from loaders.live_loader import list_interfaces, live_capture

        self.clear()
        print("=== Przechwytywanie transmisji na żywo ===\n")
        interfaces = list_interfaces()

        if not interfaces:
            print("[!] Nie znaleziono interfejsów.")
            input("Enter...")
            return

        print("Dostępne interfejsy:")
        for i, iface in enumerate(interfaces):
            print(f"[{i}] {iface}")
        try:
            idx = int(input("\nWybierz interfejs: "))
            iface = interfaces[idx]
        except:
            print("Nieprawidłowy wybór.")
            input("Enter...")
            return
        try:
            duration = int(input("Podaj czas przechwytywania (sekundy): "))
        except:
            print("Nieprawidłowy czas.")
            input("Enter...")
            return
        
        self.clear()
        print(f"[+] Przechwytywanie na interfejsie: {iface}")
        print(f"[+] Czas: {duration} sekund\n")

        result = live_capture(iface, duration)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return

        self.init_report_data("live", result["file"], result["hash"])
        print(f"[✓] {result['message']}")
        print(f"Liczba pakietów: {result['count']}")
        print(f"SHA256: {result['hash']}")
        input("Enter...")

    def load_from_ssh(self):
        from loaders.ssh_loader import fetch_pcap_scp

        self.clear()
        print("=== Pobieranie PCAP z maszyny zdalnej (SCP) ===")
        host = input("Podaj adres IP hosta: ").strip()
        username = input("Podaj nazwę użytkownika: ").strip()
        password = input("Podaj hasło: ").strip()
        remote_path = input("Podaj ścieżkę do pliku na hoście zdalnym: ").strip()

        result = fetch_pcap_scp(host, username, password, remote_path)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return

        self.init_report_data("ssh", result["file"], result["hash"])
        print(f"[✓] {result['message']}")
        print(f"SHA256: {result['hash']}")
        input("Enter...")

    def load_netcat_mode(self):
        from loaders.netcat_loader import receive_pcap

        self.clear()
        print("=== Odbieranie PCAP przez sieć (Netcat) ===")
        print("Uruchom na maszynie zdalnej np:")
        print("tcpdump -i eth0 -w - | nc <TWÓJ_IP> 9999\n")

        try:
            port = int(input("Port nasłuchu [domyślnie 9999]: ").strip() or "9999")
        except:
            print("Nieprawidłowy port.")
            input("Enter...")
            return
        print("\n[+] Oczekiwanie na połączenie...\n")

        result = receive_pcap(port)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return

        self.init_report_data("netcat", result["file"], result["hash"])
        print(f"[✓] {result['message']}")
        print(f"Nadawca: {result['sender']}")
        print(f"SHA256: {result['hash']}")
        input("Enter...")

    def load_from_url(self):
        from loaders.url_loader import fetch_pcap_url

        self.clear()
        print("=== Pobieranie PCAP z URL (HTTP/HTTPS) ===\n")

        url = input("Podaj URL do pliku PCAP: ").strip()

        if not url.startswith("http://") and not url.startswith("https://"):
            print("[!] URL musi zaczynać się od http:// lub https://")
            input("Enter...")
            return

        print("\n[+] Pobieranie...")

        result = fetch_pcap_url(url)
        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return

        self.init_report_data("url", result["file"], result["hash"])
        print(f"[✓] {result['message']}")
        print(f"Źródło: {result['url']}")
        print(f"SHA256: {result['hash']}")
        input("Enter...")

    def show_file_info(self):
        from analysis.file_info import get_file_info

        self.clear()
        print("=== Informacje o pliku PCAP ===")

        if not self.is_file_loaded():
            print("[!] Nie wczytano żadnego pliku PCAP.")
            input("Enter...")
            return
        
        file_path = self.report_data["metadata"]["file_path"]
        result = get_file_info(file_path)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return
        
        self.report_data["file_info"] = result
        print(f"Plik: {result['file']}")
        print(f"Rozmiar: {result['size']} bajtów")
        print(f"SHA256: {result['hash']}")
        print(f"Liczba pakietów: {result['packet_count']}")
        print(f"Pierwszy pakiet: {result['first_timestamp']}")
        print(f"Ostatni pakiet: {result['last_timestamp']}")
        input("Enter...")

    def show_protocols(self):
        from analysis.protocol_detection.protocol_engine import detect_protocols

        self.clear()
        print("=== Lista protokołów w PCAP ===")

        if not self.is_file_loaded():
            print("[!] Nie wczytano żadnego pliku PCAP.")
            input("Enter...")
            return

        file_path = self.report_data["metadata"]["file_path"]
        result = detect_protocols(file_path)

        self.report_data["protocols"] = result
        print(f"Liczba pakietów: {result['total_packets']}")
        print("Protokoły:")
        for proto, count in result["per_protocol"].items():
            if count > 0:
                print(f"{proto}: {count} pkt | conf={result['confidence'][proto]:.2f}")
        input("Enter...")

    def show_ip_analysis(self):
        from analysis.ip_analysis import analyze_ips

        self.clear()
        print("=== Analiza IP (publiczne + kraje) ===\n")

        if not self.is_file_loaded():
            print("[!] Najpierw wczytaj plik.")
            input("Enter...")
            return

        file_path = self.report_data["metadata"]["file_path"]
        result = analyze_ips(file_path)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return

        self.report_data["ip_analysis"] = result
        print("Publiczne IP:")
        for ip in result["public_ips"]:
            print(" -", ip)

        print("\nKraje:")
        for country, count in result["country_stats"].items():
            print(f" {country}: {count} pakietów")
        input("\nEnter...")

    def show_sessions(self):
        from analysis.session_manager import compute_sessions
        from analysis.session_protocol_binder import bind_sessions_to_protocols

        self.clear()
        print("=== Sesje TCP/UDP (IN/OUT) ===\n")

        if not self.is_file_loaded():
            print("[!] Najpierw wczytaj plik.")
            input("Enter...")
            return
        
        file_path = self.report_data["metadata"]["file_path"]
        result = compute_sessions(file_path)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return
        
        if "protocols" in self.report_data:
            result = bind_sessions_to_protocols(result, self.report_data["protocols"])
        
        self.report_data["sessions"] = result

        print(f"Wykryto sesji: {result['total_sessions']}\n")

        for sess in result["sessions"][:10]:
            print(f"ID {sess['id']} | {sess['protocol']} | "
                f"{sess['src_ip']}:{sess['src_port']} -> "
                f"{sess['dst_ip']}:{sess['dst_port']} | "
                f"{sess['direction']} | {sess['packet_count']} pkt")
        if result['total_sessions'] > 10:
            print("... (więcej w raporcie)")

        input("\nEnter...")

    def extract_l7(self):
        from analysis.decoders.generic_decoder import decode_all_l7

        self.clear()
        print("=== Ekstrakcja danych L7 ===\n")
        if not self.is_file_loaded():
            print("[!] Najpierw wczytaj plik.")
            input("Enter...")
            return
        
        filepath = self.report_data["metadata"]["file_path"]
        present_protocols = self.report_data.get("protocols", {}).get("detected", [])

        result = decode_all_l7(filepath, present_protocols)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return
        
        self.report_data["l7"] = result["l7_data"]
        self.report_data["extracted_files"] = result["extracted_files"]

        print("=== Podsumowanie L7 ===")
        print(f"HTTP: {len(result['l7_data']['http'])}")
        print(f"DNS : {len(result['l7_data']['dns'])}")
        print(f"TLS : {len(result['l7_data']['tls'])}")

        print(f"Wyodrębnione pliki: {len(result['extracted_files'])}")

        input("Enter...")

    def detect_anomalies(self):
        from analysis.anomalies.anomaly_engine import run_anomaly_detection

        self.clear()
        print("=== Wykrywanie anomalii ===\n")

        if not self.is_file_loaded():
            print("[!] Najpierw wczytaj plik.")
            input("Enter...")
            return

        anomalies = run_anomaly_detection(self.report_data)
        self.report_data["anomalies"] = anomalies

        if not anomalies:
            print("Brak wykrytych anomalii.")
            input("Enter...")
            return

        for a in anomalies:
            print(f"[{a['severity'].upper()}] ({a['protocol']}) {a['type']}")
            print(f"   {a['description']}")
            if a.get("details"):
                print(f"   → {a['details']}\n")
        input("Enter...")

    def generate_report(self):
        from reporting.report_generator import generate_final_report

        self.clear()
        print("=== Generowanie raportu końcowego ===\n")

        if not self.report_data:
            print("[!] Brak danych w report_data. Najpierw wykonaj analizę (file info / protocols / sessions / ip / anomalies).")
            input("Enter...")
            return

        extracted_dir = None

        result = generate_final_report(self.report_data, base_output_dir="reports", extracted_dir=extracted_dir)

        if not result["success"]:
            print("[!]", result["message"])
            input("Enter...")
            return

        print("[✓]", result["message"])
        print("Katalog:", result["output_dir"])
        print("JSON:", result["json"])
        print("PDF :", result["pdf"])

        if result.get("zip"):
            z = result["zip"]
            print("ZIP :", z.get("zip"))
            if z.get("warning"):
                print("[!]", z["warning"])

        input("\nEnter...")


if __name__ == "__main__":
    app = ForensicApp()
    app.main_menu()