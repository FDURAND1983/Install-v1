@echo off
:: %~dp0 correspond au dossier actuel où se trouve le script .bat
set "folder=%~dp0"
:: Changer url du fichier
set "url=../install.ps1"
set "dest=%folder%install.ps1"

echo [+] Emplacement : %folder%
echo [+] Telechargement du script...

:: Téléchargement via PowerShell
powershell -Command "Invoke-WebRequest -Uri '%url%' -OutFile '%dest%'"

if exist "%dest%" (
    echo [+] Telechargement reussi.
    echo [+] Execution du script PowerShell...
    
    :: Exécution du script local
    powershell -ExecutionPolicy Bypass -File "%dest%"
) else (
    echo [!] Erreur : Le fichier n'a pas pu etre telecharge.
)


pause
