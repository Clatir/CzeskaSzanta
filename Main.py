import pyshark
import datetime
import os
import time as tm
import shutil

import subprocess





def GoToMainMenu():
    input("Naciśnij enter aby przejść do menu głównego")
    subprocess.run(['clear'])
    MainMenu()




def FileMetadata(pathToFile):
    subprocess.run(['clear'])
    pathToFile = str("NetworkData/"+pathToFile)
    
    fileStats= os.stat(pathToFile)            

    fileSize = fileStats.st_size,
    filePermition=oct(fileStats.st_mode)[-3:]
    creationTime=tm.ctime(fileStats.st_ctime)
    lastModified=tm.ctime(fileStats.st_mtime)
    lastOpened=tm.ctime(fileStats.st_atime)

    statList=[fileSize,filePermition,creationTime,lastModified,lastOpened]

    print(f"Metadane pliku {pathToFile} \n")
    print(f"Rozmiar pliku {fileSize} KB\n")
    print(f"Uprawnienia (oct) pliku {filePermition} \n")
    print(f"Czas utworzenia pliku {creationTime} \n")
    print(f"Czas ostatniej modyfikacji pliku {lastModified} \n")
    print(f"Czas ostatniego otwarcia pliku {lastOpened} \n")
    GoToMainMenu()
    print("\n")


def ExtractFTP(pathToFile,dirName):
        
        if(os.path.isdir(f"{dirName}/FTP")) == True:
            pass
        else:
            os.mkdir(f"{dirName}/FTP")
        dirName+="/FTP"


        if(os.path.isdir(f"tmp")) == True:
            pass
        else:
            os.mkdir(f"tmp")

        subprocess.run(["tshark", "-r",
        str(pathToFile),"--export-object",f'ftp-data,tmp']
        
        )
        subprocess.run(['clear'])
                      

        for tmpFile in os.listdir("tmp"):
            tmpFilename = os.fsdecode(tmpFile)
            print(tmpFilename)
            for file in os.listdir(f"{dirName}"):
                filename = os.fsdecode(file)
                if tmpFilename == filename:
                    os.remove(os.path.join(dirName,filename))

        subprocess.run(["tshark", "-r",
        str(pathToFile),"--export-object",f'ftp-data,{dirName}'])
        subprocess.run(['clear'])


        shutil.rmtree("tmp")  

                


def ExtractHTTP(pathToFile,dirName):
        
        if(os.path.isdir(f"{dirName}/HTTP")) == True:
            pass
        else:
            os.mkdir(f"{dirName}/HTTP")
        dirName+="/HTTP"






        if(os.path.isdir(f"tmp")) == True:
            pass
        else:
            os.mkdir(f"tmp")

        subprocess.run(["tshark", "-r",
        str(pathToFile),"--export-object",f'http,tmp']
        
        )
        subprocess.run(['clear'])
                      

     

        for tmpFile in os.listdir("tmp"):
            tmpFilename = os.fsdecode(tmpFile)
            print(tmpFilename)
            
            for file in os.listdir(f"{dirName}"):
                filename = os.fsdecode(file)
                
                if tmpFilename == filename:
                    os.remove(os.path.join(dirName,filename))

        subprocess.run(["tshark", "-r",
        str(pathToFile),"--export-object",f'http,{dirName}'])
        subprocess.run(['clear'])

        shutil.rmtree("tmp")  




def ExtractData(selectedFile):
        subprocess.run(['clear'])
        pathToFile = str("NetworkData/"+selectedFile)
        
        
        
        inputdir = "NetworkData"
        dirName= selectedFile+"_ExtractedFiles"

        EnsureDirExists(dirName)

        ExtractFTP(pathToFile,dirName)
        ExtractHTTP(pathToFile,dirName)

   
        print(f"Odnaleziono następujące pliki w zrzucie {selectedFile}\n")

        print("Pliki przesłane za pomocą FTP \n")
        
        fileNumber=1
        filenames = next(os.walk(f"{dirName}/FTP"), (None, None, []))[2]  
        for i in filenames:
            print (f"{fileNumber}. {i}")
            fileNumber+=1
                
        print("\n")

        print("Pliki przesłane za pomocą HTTTP")
        fileNumber=1  
        filenames = next(os.walk(f"{dirName}/HTTP"), (None, None, []))[2]  
        for i in filenames:
            print (f"{fileNumber}. {i}")
            fileNumber+=1
        print("\n") 

        
        GoToMainMenu()


def AnalyserMenu (selectedFile):
    subprocess.run(['clear'])
    anlyserMenuOption = input(f"Możliwe dzałania na pliku {selectedFile} \n" \
    "1. Wyswietl metadane \n" \
    "2. Wyeksportuj przesłane pliki podczas transmisji \n" \
    "Wpisanie numeru z poza zakresu spowoduje przejście do menu głównego \n")
    match anlyserMenuOption:
        case "1":
            
            
            FileMetadata(selectedFile)
            
        case "2":
            
            ExtractData(selectedFile)         
            
        case _:
            MainMenu()

def LiveAquisitionMenu():
    subprocess.run(['clear'])
    liveCaptureOption=input("Wybierz tryb akwizycji danych \n" \
    "1. Tryb prosty \n" \
    "2. Tryb zaawansowany \n" \
    "Wybór opcji z poza zakresu spowoduje przejście do menu głównego\n ")
    match liveCaptureOption:
        case "1":
            SimpleLiveCapture()
            
        case "2":
            AdvancedLiveCapture()
            
        case _:
            GoToMainMenu()

def MOTD():
    subprocess.run(['clear'])
    print("Ogonopowieść można również stworzyć w notatniku")
    GoToMainMenu()


def EnsureDirExists(dirName):

    if(os.path.isdir(dirName)) == True:
        pass
    else:
        os.mkdir(dirName)



def SelectFile (dataFolderPath="NetworkData"):
    
    EnsureDirExists("NetworkData")
    filenames = next(os.walk(dataFolderPath), (None, None, []))[2]  
    
    if len(filenames) == 0:
        print("Kolego, w folderze NetworkData nic nie ma. Lepiej prędko wrzuć tu jakiś plik .pcap \n")
        GoToMainMenu()


    
    subprocess.run(['clear'])


    
    print(f"Dostępne pliki: ")
    fileNumber=1
    for i in filenames:
        if (i.endswith(".pcap")):
            print (f"{fileNumber}. {i}")
            fileNumber+=1
    selectedFileNumber = input("Wpisz numer pliku, który chcesz analizować \n" \
    "Wpisanie wartości z poza zakresu spowoduje przejście do menu głównego \n ")
    try:
        subprocess.run(['clear'])
        print(f"Wybrano plik {filenames[int(selectedFileNumber)-1]}")
    except:
        
        MainMenu()

    selectedFile=filenames[int(selectedFileNumber)-1]
    return(selectedFile)


def SimpleLiveCapture():
            subprocess.run(['clear'])
            date = datetime.datetime.now()
            defaultFilename =  str(date.strftime("%B"))  + "_" + str(date.year) + "-" + str(date.month) + "-" + str(date.day) + ".pcap"
            customFilename = input("Podaj pod jaką nazwą pliku zapisać zapis ruchu sieciowego.\n" \
            "W przypadku braku podania nazwy zostanie zastosowana nazwa domyślna\n")           

            defaultCaptureTime=120

            customCaptureTime = input("Podaj w sekundach przez jaki czas rejestrować ruch sieciowy.\n" \
                                    
            "W przypadku braku podania czasu program będzie przechwytywał ruch przez 120s\n") 

            if customFilename=="":
                fileName=defaultFilename
            else:
                fileName=str(f"{customFilename}.pcap")

            

            if customCaptureTime=="":
                captureTime=defaultCaptureTime
            else:
                captureTime=int(customCaptureTime)


            EnsureDirExists("NetworkData")

            fileName = f"NetworkData/{fileName}"

            output = open(fileName, "w")
            
            capture = pyshark.LiveCapture(interface="enp0s3", output_file=fileName)
            capture.sniff(timeout=captureTime)
            output.close()

            GoToMainMenu()


def AdvancedLiveCapture():
            allPorts=False
            subprocess.run(['clear'])
            date = datetime.datetime.now()
            defaultFilename =  str(date.strftime("%B"))  + "_" + str(date.year) + "-" + str(date.month) + "-" + str(date.day) + ".pcap"
            customFilename = input("Podaj pod jaką nazwą pliku zapisać zapis ruchu sieciowego.\n" \
            "W przypadku braku podania nazwy zostanie zastosowana nazwa domyślna\n")           

            defaultCaptureTime=120

            directionToListen=""

            customCaptureTime = input("Podaj w sekundach przez jaki czas rejestrować ruch sieciowy.\n" \
                                    
            "W przypadku braku podania czasu zostanie zastosowana nazwa domyślna [120s]\n") 

            if customFilename=="":
                fileName=defaultFilename
            else:
                fileName=str(f"{customFilename}.pcap")

            

            if customCaptureTime=="":
                captureTime=defaultCaptureTime
            else:
                try:
                    val = int(customCaptureTime)
                except ValueError:
                    print("Podano niepoprawną wartość. \n"
                    "Będzie konieczne ponowne określenie parametrów nasłuchiwania")
                    tm.sleep(2)
                    AdvancedLiveCapture()
                captureTime=int(customCaptureTime)

                
                

            
            portToListen = input("Podaj na jakim porcie chcesz nasłuchiwać.\n" \
            "W przypadku braku podania portu zostaną uwzględnione wszystkie porty\n")

            if portToListen=="":
                allPorts=True
            else:
               
                try:
                    val = int(portToListen)
                except ValueError:
                    print("Podano niepoprawną wartość. \n"
                    "Będzie konieczne ponowne określenie parametrów nasłuchiwania")
                    tm.sleep(2)
                    AdvancedLiveCapture()
                portToListen = f"port {portToListen}"

                

            

            

            directionToListen=input("Podaj w jakim kierunku chcesz nasłuchiwać. [in/out/inout]\n" \
            "Domyślnie zostanie zastosowane nasłuchiwanie dwukieronkowe\n") 


            match directionToListen:
                case "in":
                    pass
                    
                case "out":
                    pass
                
                case "inout":
                    pass
                    
                case _:
                   directionToListen="inout"

            validateChecksums=input("Czy chcesz walidować sumy kontrolne. [y/n]\n"
            "Domyślnie sumy kontrolne są walidowane\n")
            
            match validateChecksums:
                case "y":
                    pass
                    
                case "n":
                    pass
                    
                case _:
                   validateChecksums="y"


            
            EnsureDirExists("NetworkData")

            




        
                
            
            if allPorts == False and validateChecksums =="y":
                subprocess.run([f"timeout", f"{captureTime}", "tcpdump", f"-Q{directionToListen}",f"-w {fileName}",f"{portToListen}",f"-i{"any"}"])
            elif allPorts == False and validateChecksums =="n":
                subprocess.run([f"timeout", f"{captureTime}", "tcpdump", f"-Q{directionToListen}",f"-w {fileName}",f"{portToListen}","--dont-verify-checksums",f"-i{"any"}"])
            
            elif allPorts == True and validateChecksums =="y":
                subprocess.run([f"timeout", f"{captureTime}", "tcpdump", f"-Q{directionToListen}",f"-w {fileName}",f"-i{"any"}"])
            
            else:
                 subprocess.run([f"timeout", f"{captureTime}", "tcpdump", f"-Q{directionToListen}",f"-w {fileName}","--dont-verify-checksums",f"-i{"any"}"])
            
            print(f"Zapisalem plik pod nazwa {os.path.abspath(fileName)}")
            os.replace(f"{fileName}",f"NetworkData/{fileName}")

            GoToMainMenu
            


         



def MainMenu ():
    subprocess.run(['clear'])    


    mainMenuOption = input("Analizator PCAP - wybierz opcję \n" \
    "1. Rozpocznij analize pliku \n" \
    "2. Zobacz ciekawostke dnia \n" \
    "3. Akwizycja Live (wymaga uprawnień root) \n"
    )

    match mainMenuOption:
        case "1":
            selectedFile=SelectFile()
            AnalyserMenu(selectedFile)         

        case "2":
            MOTD()
        case "3":
            if (os.geteuid() ) == 0:
                LiveAquisitionMenu()
            else:
                print("Wymagane jest uruchomienie programu z uprawnieniami administratora \n")
                GoToMainMenu()
            


        case _:
            print("Wybierz jedna z dostepnych opcji")
            MainMenu()


MainMenu()

