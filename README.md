## Wymagania

- Python 3.13
- `tshark` zainstalowany w systemie


## Utworzenie i aktywacja wirtualnego środowiska

```bash
python3.13 -m venv <ścieżka_do_utworzenia_środowiska>
source <ścieżka_do_środowiska>/bin/activate
```

## Instalacja bibliotek

```bash
pip3.13 install -r requirements.txt
```

## Włączenie programu

```bash
python3.13 pcap_analyzer.py
```