# fork du script du Julien Donizel by fdurand1983
# --- SÉCURITÉ CONSOLE ET FLUX ---
function Write-Host { }
function Write-Output { }
$ProgressPreference = 'SilentlyContinue'

# --- VÉRIFICATION DES DROITS ADMINISTRATEUR ---
# On vérifie si le script est lancé en tant qu'administrateur
$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Si non, on tente de se relancer avec les droits élevés
    try {
        $newProcess = @{
            FilePath     = "powershell.exe"
            ArgumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            Verb         = "RunAs"
            ErrorAction  = "Stop"
        }
        Start-Process @newProcess
    }
    catch { } # L'utilisateur a probablement cliqué 'Non' sur la fenêtre UAC. On quitte silencieusement.
    exit # On quitte le script courant (non-admin) dans tous les cas.
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- VARIABLES GLOBALES ---
$ScriptDir = "C:\SimplyKiosk"
$WorkDir = "C:\ProgramData\PowerToysDeploy"
if (!(Test-Path $ScriptDir)) { New-Item -ItemType Directory -Path $ScriptDir -Force | Out-Null }
$LogFile = Join-Path $ScriptDir "deploy_$(Get-Date -Format 'yyyyMMdd').log"

#   --- COULEURS ---
$ColorViolet    = [System.Drawing.ColorTranslator]::FromHtml("#8E44AD") # Violet
$ColorOrange    = [System.Drawing.ColorTranslator]::FromHtml("#E67E22") # Orange
$ColorBg        = [System.Drawing.ColorTranslator]::FromHtml("#FDFEFE") # Blanc cassé
$ColorWhite     = [System.Drawing.Color]::White
$ColorDarkGray  = [System.Drawing.ColorTranslator]::FromHtml("#2C3E50")

# --- INTERFACE GRAPHIQUE ---
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Assistant de Déploiement Simply Copy"
$Form.Size = New-Object System.Drawing.Size(650, 520)
$Form.StartPosition = "CenterScreen"
$Form.BackColor = $ColorBg
$Form.FormBorderStyle = "FixedDialog"
$Form.TopMost = $true

# Header Panel
$HeaderPanel = New-Object System.Windows.Forms.Panel
$HeaderPanel.Size = New-Object System.Drawing.Size(650, 60)
$HeaderPanel.BackColor = $ColorViolet
$Form.Controls.Add($HeaderPanel)

# Titre dans le Header
$TitleLabel = New-Object System.Windows.Forms.Label
$TitleLabel.Text = "SIMPLY COPY INSTALLER"
$TitleLabel.ForeColor = $ColorWhite
$TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$TitleLabel.Location = New-Object System.Drawing.Point(20, 15)
$TitleLabel.AutoSize = $true
$HeaderPanel.Controls.Add($TitleLabel)

# Zone de Statut (RichTextBox)
$StatusBox = New-Object System.Windows.Forms.RichTextBox
$StatusBox.Location = New-Object System.Drawing.Point(25, 80)
$StatusBox.Size = New-Object System.Drawing.Size(585, 230)
$StatusBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$StatusBox.ReadOnly = $true
$StatusBox.BackColor = $ColorWhite
$StatusBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$Form.Controls.Add($StatusBox)

#   Barre de Progression
$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$ProgressBar.Location = New-Object System.Drawing.Point(25, 330)
$ProgressBar.Size = New-Object System.Drawing.Size(585, 20)
$Form.Controls.Add($ProgressBar)

# Bouton Lancer l'Installation (Orange)
$StartBtn = New-Object System.Windows.Forms.Button
$StartBtn.Text = "LANCER L'INSTALLATION"
$StartBtn.Location = New-Object System.Drawing.Point(120, 390)
$StartBtn.Size = New-Object System.Drawing.Size(200, 45)
$StartBtn.BackColor = $ColorOrange
$StartBtn.ForeColor = $ColorWhite
$StartBtn.FlatStyle = "Flat"
$StartBtn.FlatAppearance.BorderSize = 0
$StartBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$Form.Controls.Add($StartBtn)

# Bouton Quitter (Gris Foncé)
$ExitBtn = New-Object System.Windows.Forms.Button
$ExitBtn.Text = "QUITTER"
$ExitBtn.Location = New-Object System.Drawing.Point(350, 390)
$ExitBtn.Size = New-Object System.Drawing.Size(180, 45)
$ExitBtn.BackColor = $ColorDarkGray
$ExitBtn.ForeColor = $ColorWhite
$ExitBtn.FlatStyle = "Flat"
$ExitBtn.FlatAppearance.BorderSize = 0
$Form.Controls.Add($ExitBtn)

# --- FONCTIONS UTILITAIRES ---
# Met à jour l'interface utilisateur (log et barre de progression)
function Update-UI ([string]$msg, [System.Drawing.Color]$color, [int]$percent = -1) {
    $ts = Get-Date -Format "HH:mm:ss"
    $Form.Invoke([Action]{
        $StatusBox.SelectionStart = $StatusBox.TextLength
        $StatusBox.SelectionColor = $color
        $StatusBox.AppendText("[$ts] $msg`r`n")
        $StatusBox.ScrollToCaret()
        if ($percent -ge 0) { $ProgressBar.Value = $percent }
    })
    "[$ts] $msg" | Out-File $LogFile -Append -Encoding UTF8
}
# Vérifie si un logiciel est installé via le registre
function Is-Installed ([string]$NameLike) {
    return Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
           Where-Object { $_.DisplayName -and $_.DisplayName -like "*$NameLike*" } | Select-Object -First 1
}

# --- ACTIONS ---

# FERMETURE PROPRE SANS POP-UP
$ExitBtn.Add_Click({ 
    $Form.Close()
    $Form.Dispose()
    Stop-Process -Id $PID -Force 
})

$StartBtn.Add_Click({
    $StartBtn.Enabled = $false
    $ExitBtn.Enabled = $false
    $Form.ControlBox = $false
    $Form.Refresh()
    
    try {
        Update-UI "Démarrage du déploiement Simply Copy..." $ColorViolet 5
        
        # 1. Chocolatey INSTALLATION
        if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
            Update-UI "Installation de Chocolatey..." $ColorViolet 10
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            $installScript = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
            Invoke-Expression $installScript
            Update-UI "Chocolatey installé." $ColorOrange 20
        }

        # 2. Logiciels ISNTALLATION
        if ($null -eq (Is-Installed "PowerToys")) {
            Update-UI "Installation de PowerToys..." $ColorViolet 30
            & choco install powertoys -y --no-progress
            Update-UI "PowerToys installé." $ColorOrange 45
        }

        if ($null -eq (Is-Installed "LibreOffice")) {
            Update-UI "Installation de LibreOffice..." $ColorViolet 55
            & choco install libreoffice-fresh -y --no-progress
            Update-UI "LibreOffice installé." $ColorOrange 65
        }

        # 3. Configuration (CORRECTION INCLUDEUSERNAME)
        Update-UI "Configuration de l'environnement..." $ColorViolet 70
        
        # Méthode robuste pour récupérer le nom d'utilisateur sans IncludeUserName
        $CurrentUserName = $env:USERNAME
        if ($CurrentUserName -eq "SYSTEM") {
            $CurrentUserName = (Get-WmiObject -Class Win32_ComputerSystem).UserName.Split('\')[-1]
        }
        # Chemins
        $PowerToysDest = "C:\Users\$CurrentUserName\AppData\Local\Microsoft\PowerToys"
        $PowerToysExe  = "C:\Program Files\PowerToys\PowerToys.exe"
        # Installation de la configuration PowerToys
        # Remplacer l'adresse de téléchargement
        $ZipUrl        = "../powertoys-config.zip"
        $ZipPath       = Join-Path $WorkDir "powertoys-config.zip"
        $Extract       = Join-Path $WorkDir "config"
        $targetDir     = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

        if (!(Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
        # Installation de SimplyKiosk
        # Remplacer l'adresse de téléchargement
        Update-UI "Téléchargement SimplyKiosk-Setup..." $ColorOrange 75
            Start-BitsTransfer -Source ".." -Destination (Join-Path $targetDir "SimplyKiosk-Setup.exe")
        # Installation de la configuration PowerToys
        Update-UI "Téléchargement Config ZIP..." $ColorOrange 80
            Start-BitsTransfer -Source $ZipUrl -Destination $ZipPath
        #  Extraction et copie
        Update-UI "Application des paramètres PowerToys..." $ColorViolet 85
            # Arrêt de PowerToys si en cours d'exécution
            Get-Process -Name "PowerToys*" -ErrorAction SilentlyContinue | Stop-Process -Force
            # Petite pause pour s'assurer que le processus est bien arrêté
            Start-Sleep -Seconds 2
            # Extraction
            Expand-Archive -Path $ZipPath -DestinationPath $Extract -Force
            # Copie
            if (!(Test-Path $PowerToysDest)) { New-Item -ItemType Directory -Path $PowerToysDest -Force | Out-Null }
            Copy-Item -Path "$Extract\*" -Destination $PowerToysDest -Recurse -Force

        # 4. Registre
        Update-UI "Sécurisation AutoRun..." $ColorViolet 90
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
        # 5. Bloquer l'ajout de comptes Microsoft
        Update-UI "Blocage des comptes Microsoft..." $ColorViolet 95
            # Méthode 1 : Policies System (Classique)
            $sysPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            if (!(Test-Path $sysPolicy)) { New-Item -Path $sysPolicy -Force | Out-Null }
            New-ItemProperty -Path $sysPolicy -Name "NoConnectedUser" -Value 3 -PropertyType DWord -Force | Out-Null

            # Méthode 2 : Policies MicrosoftAccount (Complémentaire efficace)
            $msPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
            if (!(Test-Path $msPolicy)) { New-Item -Path $msPolicy -Force | Out-Null }
            New-ItemProperty -Path $msPolicy -Name "DisableUserAuth" -Value 1 -PropertyType DWord -Force | Out-Null

            # Méthode 3 : PolicyManager (AllowYourAccount)
            $pmPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount"
            if (Test-Path $pmPath) {
                Set-ItemProperty -Path $pmPath -Name "value" -Value 0 -Force -ErrorAction SilentlyContinue
            }
            
            # Méthode 4 : Désactivation du service d'authentification (Radical)
            Update-UI "Arrêt du service Microsoft Account..." $ColorViolet 98
            Stop-Service -Name "wlidsvc" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "wlidsvc" -StartupType Disabled -ErrorAction SilentlyContinue
            
            # Méthode 5 : Policy BlockMicrosoftAccount (Complémentaire)
            $polWinSys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            if (!(Test-Path $polWinSys)) { New-Item -Path $polWinSys -Force | Out-Null }
            New-ItemProperty -Path $polWinSys -Name "BlockMicrosoftAccount" -Value 1 -PropertyType DWord -Force | Out-Null

        # 6. Auto-destruction des scripts d'installation
        Update-UI "Planification du nettoyage post-redémarrage..." $ColorViolet 99
        # Chemin vers le script ps1 actuel et le script bat qui l'a lancé
        $ps1Path = $MyInvocation.MyCommand.Path
        $batPath = Join-Path (Split-Path $ps1Path) "install.bat"

        # On s'assure que les fichiers existent avant de planifier leur suppression
        if ((Test-Path $ps1Path) -and (Test-Path $batPath)) {
            # Commande pour supprimer les fichiers après un court délai au prochain démarrage.
            # Le délai (ping) laisse le temps à la session de s'ouvrir complètement.
            $command = 'cmd.exe /c "ping 127.0.0.1 -n 10 > nul & del ""{0}"" & del ""{1}"""' -f $ps1Path, $batPath

            # Ajout de la commande au registre pour exécution unique à la prochaine connexion de l'utilisateur
            $runOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Set-ItemProperty -Path $runOnceKey -Name "SimplyKioskCleanup" -Value $command -Force | Out-Null
        }

        if (Test-Path $PowerToysExe) { Start-Process -FilePath $PowerToysExe }
        # Fin
        Update-UI "TERMINÉ. Redémarrage dans 5 secondes..." $ColorOrange 100
        $ExitBtn.Text = "REDÉMARRAGE..."
        $ExitBtn.BackColor = $ColorViolet
        $Form.Refresh()
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }
    catch {
        Update-UI "ERREUR : $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        $ExitBtn.Enabled = $true
        $Form.ControlBox = $true
    }
    finally {
        if (Test-Path $WorkDir) { Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
})

[System.Windows.Forms.Application]::Run($Form)
