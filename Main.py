import pyshark
import os
import time
import keyboard




cap = pyshark.FileCapture('ipv4frags.pcap')
pathToCap = 'ipv4frags.pcap'

def FileMetadata(pathToFile = pathToCap):
    
    fileStats = os.stat(pathToFile)            

    fileSize = fileStats.st_size,
    filePermition=oct(fileStats.st_mode)[-3:]
    creationTime=time.ctime(fileStats.st_ctime)
    lastModified=time.ctime(fileStats.st_mtime)
    lastOpened=time.ctime(fileStats.st_atime)

    statList=[fileSize,filePermition,creationTime,lastModified,lastOpened]

    print(f"Metadane pliku {pathToCap} \n")
    print(f"Rozmiar pliku {fileSize} KB\n")
    print(f"Uprawnienia (oct) pliku {filePermition} \n")
    print(f"Czas utworzenia pliku {creationTime} \n")
    print(f"Czas ostatniej modyfikacji pliku {lastModified} \n")
    print(f"Czas ostatniego otwarcia pliku {lastOpened} \n")
    print(f"Nacisnij dowolny klawisz aby przejść do menu głównego")
    print(keyboard.read_key())
    MainMenu()
    print("\n")

    

    




def MainMenu ():
    mainMenuOption = input("Analizator PCAP - wybierz opcję \n" \
    "1. Wyswietl metadane zrzutu PCAP \n" \
    "2. Zobacz ciekawostke dnia \n")

    match mainMenuOption:
        case "1":
            print("Metadane")
            FileMetadata()
        case "2":
            print("Ogonopowieść można również stworzyć w notatniku")
            MainMenu()

        case _:
            print("Wybierz jedna z dostepnych opcji")
            MainMenu()


MainMenu()

