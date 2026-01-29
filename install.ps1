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
$TitleLabel.Text = "SIMPLY COPY"
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

        # 1.5. Installation et Configuration AnyDesk pour la reconnexion
        Update-UI "Vérification d'AnyDesk pour l'accès distant..." $ColorViolet 25
        if ($null -eq (Is-Installed "AnyDesk")) {
            Update-UI "Installation d'AnyDesk..." $ColorViolet 26
            & choco install anydesk -y --no-progress
            Update-UI "AnyDesk installé." $ColorOrange 28
        }

        # Configuration de l'accès non-surveillé
        # IMPORTANT: Changez "VotreMotDePasseSecurise" pour un mot de passe robuste de votre choix.
        $anydeskPassword = "Kiosk2026" 
        Update-UI "Configuration de l'accès non-surveillé pour AnyDesk..." $ColorViolet 29
        try {
            $anydeskExe = "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
            if (-not (Test-Path $anydeskExe)) { $anydeskExe = "C:\Program Files\AnyDesk\AnyDesk.exe" }

            if (Test-Path $anydeskExe) {
                # Démarrage du service si nécessaire et attente de l'ID
                Start-Service "AnyDesk" -ErrorAction SilentlyContinue
                $anydeskId = ""
                for ($i = 0; $i -lt 5; $i++) {
                    # Méthode robuste pour récupérer l'ID via StandardOutput
                    $pinfoId = New-Object System.Diagnostics.ProcessStartInfo
                    $pinfoId.FileName = $anydeskExe
                    $pinfoId.Arguments = "--get-id"
                    $pinfoId.RedirectStandardOutput = $true
                    $pinfoId.UseShellExecute = $false
                    $pinfoId.CreateNoWindow = $true
                    $procGetId = New-Object System.Diagnostics.Process
                    $procGetId.StartInfo = $pinfoId
                    $procGetId.Start() | Out-Null
                    $anydeskId = $procGetId.StandardOutput.ReadToEnd().Trim()
                    $procGetId.WaitForExit()

                    if (![string]::IsNullOrWhiteSpace($anydeskId)) { break }
                    Start-Sleep -Seconds 2
                }
                if ([string]::IsNullOrWhiteSpace($anydeskId)) { $anydeskId = "Non détecté (Service non prêt ?)" }

                Update-UI "------------------------------------------------------------" $ColorOrange
                Update-UI "!!! ID ANYDESK POUR RECONNEXION : $anydeskId" $ColorOrange
                #Update-UI "!!! MOT DE PASSE : $anydeskPassword" $ColorOrange
                Update-UI "------------------------------------------------------------" $ColorOrange

                # Méthode robuste pour définir le mot de passe via StandardInput
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = $anydeskExe
                $pinfo.Arguments = "--set-password"
                $pinfo.RedirectStandardInput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.CreateNoWindow = $true
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start()
                $p.StandardInput.WriteLine($anydeskPassword)
                $p.StandardInput.Close()
                $p.WaitForExit()

                if ($p.ExitCode -eq 0) {
                    Update-UI "Accès non-surveillé configuré avec succès." $ColorOrange 29
                } else {
                    Update-UI "Erreur lors de la configuration du mot de passe AnyDesk (Code: $($p.ExitCode))." ([System.Drawing.Color]::Red) 29
                }

                # Affichage d'une popup pour être sûr que l'utilisateur voit l'ID
                [System.Windows.Forms.MessageBox]::Show("Id de connexion : $anydeskId`n`nNotez ces informations pour vous reconnecter après le redémarrage.", "Connexion AnyDesk", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
        } catch {
            Update-UI "Erreur config AnyDesk: $($_.Exception.Message). Reconnexion manuelle requise." ([System.Drawing.Color]::Red) 29
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
            
            # Déplacement des raccourcis vers le bureau Public pour qu'ils soient visibles par tous les utilisateurs (ex: Kiosk)
            $publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
            $currentUserDesktop = [Environment]::GetFolderPath("Desktop")
            $loShortcuts = Get-ChildItem -Path $currentUserDesktop -Filter "LibreOffice*.lnk" -ErrorAction SilentlyContinue
            foreach ($shortcut in $loShortcuts) {
                $destPath = Join-Path $publicDesktop $shortcut.Name
                if (-not (Test-Path $destPath)) {
                    Move-Item -Path $shortcut.FullName -Destination $destPath -Force -ErrorAction SilentlyContinue
                }
            }
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
        $DefaultPowerToysDest = "C:\Users\Default\AppData\Local\Microsoft\PowerToys"
        $PowerToysExe  = "C:\Program Files\PowerToys\PowerToys.exe"
        # Installation de la configuration PowerToys
        # Remplacer l'adresse de téléchargement
        $ZipUrl        = "https://speedscan.bzh/fichier/powertoys-config.zip"
        $Simplyurl     = "https://speedscan.bzh/fichier/SimplyKiosk-Setup.exe"
        $ZipPath       = Join-Path $WorkDir "powertoys-config.zip"
        $Extract       = Join-Path $WorkDir "config"
        $targetDir     = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

        if (!(Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
        # Installation de SimplyKiosk
        # Remplacer l'adresse de téléchargement
        Update-UI "Téléchargement SimplyKiosk-Setup..." $ColorOrange 75
            Start-BitsTransfer -Source $simplyurl -Destination (Join-Path $targetDir "SimplyKiosk-Setup.exe")
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
            # Copie vers le profil Default pour que tous les futurs utilisateurs (ex: Kiosk) en héritent
            if (!(Test-Path $DefaultPowerToysDest)) { New-Item -ItemType Directory -Path $DefaultPowerToysDest -Force | Out-Null }
            Copy-Item -Path "$Extract\*" -Destination $DefaultPowerToysDest -Recurse -Force

        # 4. Registre
        Update-UI "Sécurisation AutoRun..." $ColorViolet 90
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
        # 5. Bloquer l'ajout de comptes Microsoft
        #$isMicrosoftAccount = $false
        #$isDomainAccount = $false
        #try {
            # Cette commande identifie si le compte local est lié à un compte Microsoft.
            # Elle échoue sur les comptes de domaine, ce qui est géré par le bloc catch.
         #   $currentUser = Get-LocalUser -Name $env:USERNAME -ErrorAction Stop
          #  if ($currentUser.PrincipalSource -eq 'MicrosoftAccount') {
           #     $isMicrosoftAccount = $true
            #}
        #}
        #catch {
            # L'échec de Get-LocalUser indique probablement un compte de domaine.
        #    $isDomainAccount = $true
        #}

        #if ($isMicrosoftAccount) {
         #   Update-UI "Compte Microsoft détecté. Création d'un compte local de secours..." $ColorViolet 95
            
            # Résolution dynamique du nom du groupe Administrateurs via SID (S-1-5-32-544) pour compatibilité FR/EN
          #  $adminGroupObj = Get-LocalGroup | Where-Object { $_.SID -like "*S-1-5-32-544" } | Select-Object -First 1
           # $adminGroupName = if ($adminGroupObj) { $adminGroupObj.Name } else { "Administrators" }

            #$newUser = "Kiosk"
            #if (-not (Get-LocalUser -Name $newUser -ErrorAction SilentlyContinue)) {
             #   try {
             #       New-LocalUser -Name $newUser -NoPassword -FullName "Kiosk User" -Description "Compte local créé par SimplyKiosk" -ErrorAction Stop | Out-Null
             #       Set-LocalUser -Name $newUser -PasswordNeverExpires $true -ErrorAction Stop
             #       Update-UI "Compte local '$newUser' créé (sans mot de passe)." $ColorOrange 95

             #       Update-UI "Ajout du compte '$newUser' au groupe $adminGroupName..." $ColorViolet 96
             #       Add-LocalGroupMember -Group $adminGroupName -Member $newUser -ErrorAction Stop
             #       Update-UI "Compte '$newUser' ajouté aux administrateurs." $ColorOrange 96
             #   } catch {
             #       Update-UI "Erreur création/ajout groupe : $($_.Exception.Message)" ([System.Drawing.Color]::Red)
             #   }
            #} else {
            #    Update-UI "Le compte local '$newUser' existe déjà. Vérification des droits admin..." $ColorViolet 95
            #    Add-LocalGroupMember -Group $adminGroupName -Member $newUser -ErrorAction SilentlyContinue
            #}

            # Déplacement de l'exécutable vers le bureau Public
            #$setupFile = Join-Path $targetDir "SimplyKiosk-Setup.exe"
            #$publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
            #if (Test-Path $setupFile) {
            #    Move-Item -Path $setupFile -Destination $publicDesktop -Force -ErrorAction SilentlyContinue
            #}

            # Désactivation OOBE (Questions confidentialité & Animation bienvenue)
            #$OOBEPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"
            #if (!(Test-Path $OOBEPath)) { New-Item -Path $OOBEPath -Force | Out-Null }
            #Set-ItemProperty -Path $OOBEPath -Name "DisablePrivacyExperience" -Value 1 -Type DWord -Force
            #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -Force
        #}
        #elseif ($isDomainAccount) {
        #    Update-UI "Compte de domaine détecté. Blocage des comptes MS ignoré." $ColorViolet 95
        #}
        #else {
            # Le compte est un compte local pur, on peut appliquer le blocage.
         #   Update-UI "Application du blocage des comptes Microsoft..." $ColorViolet 95
            # Méthode 1 : Policies System (Classique) & Méthode 2 : Policies MicrosoftAccount
          #  New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null | New-ItemProperty -Name "NoConnectedUser" -Value 3 -PropertyType DWord -Force | Out-Null
           # New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Force | Out-Null | New-ItemProperty -Name "DisableUserAuth" -Value 1 -PropertyType DWord -Force | Out-Null
            # Méthode 3 : PolicyManager (AllowYourAccount)
            # $pmPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount"
            #if (Test-Path $pmPath) {
           #     Set-ItemProperty -Path $pmPath -Name "value" -Value 0 -Force -ErrorAction SilentlyContinue
           # }
            # Méthode 4 : Désactivation du service d'authentification (Radical)
           # Update-UI "Arrêt du service Microsoft Account..." $ColorViolet 98
           # Stop-Service -Name "wlidsvc" -Force -ErrorAction SilentlyContinue
           # Set-Service -Name "wlidsvc" -StartupType Disabled -ErrorAction SilentlyContinue
            # Méthode 5 : Policy BlockMicrosoftAccount (Complémentaire)
            #$polWinSys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            #if (!(Test-Path $polWinSys)) { New-Item -Path $polWinSys -Force | Out-Null }
            #New-ItemProperty -Path $polWinSys -Name "BlockMicrosoftAccount" -Value 1 -PropertyType DWord -Force | Out-Null
        #}
        # 6. Auto-destruction des scripts d'installation
            Update-UI "Planification du nettoyage post-redémarrage..." $ColorViolet 99
            # Utilisation de $PSCommandPath qui est plus fiable dans les scripts récents
            $ps1Path = $PSCommandPath
            $scriptDir = Split-Path -Parent $ps1Path
            $batPath = Join-Path $scriptDir "install.bat"
            if (![string]::IsNullOrEmpty($ps1Path) -and (Test-Path $ps1Path)) {
                # Création d'un script batch de nettoyage dans un dossier système temporaire
                # Cela permet de l'exécuter en tant que SYSTEM via le planificateur de tâches
                # et de contourner les problèmes de permissions entre utilisateurs (ex: Kiosk vs User).
                $cleanupBatPath = "$env:SystemRoot\Temp\SimplyKioskCleanup.bat"
                
                $batContent = @"
@echo off
timeout /t 10 /nobreak > nul
if exist "$ps1Path" del /f /q "$ps1Path"
if exist "$batPath" del /f /q "$batPath"
schtasks /Delete /TN "SimplyKioskCleanup" /F
del /f /q "%~f0"
"@
                Set-Content -Path $cleanupBatPath -Value $batContent -Encoding Ascii -Force

                # Création de la tâche planifiée (SYSTEM / ONLOGON)
                $schArgs = '/Create /TN "SimplyKioskCleanup" /TR "{0}" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F' -f $cleanupBatPath
                Start-Process "schtasks.exe" -ArgumentList $schArgs -NoNewWindow -Wait
            }

        if (Test-Path $PowerToysExe) { Start-Process -FilePath $PowerToysExe -ErrorAction SilentlyContinue }

        if ($isMicrosoftAccount) {
            Update-UI "Configuration de l'ouverture de session automatique (Kiosk)..." $ColorViolet 98
            # Configuration de l'AutoLogon pour le compte Kiosk
            $AutoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            Set-ItemProperty -Path $AutoLogonPath -Name "DefaultUserName" -Value "Kiosk" -Force
            Set-ItemProperty -Path $AutoLogonPath -Name "DefaultDomainName" -Value "." -Force
            Set-ItemProperty -Path $AutoLogonPath -Name "DefaultPassword" -Value "" -Force
            Set-ItemProperty -Path $AutoLogonPath -Name "AutoAdminLogon" -Value "1" -Force
            # Autoriser l'AutoLogon avec un mot de passe vide
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 0 -Type DWord -Force

            Update-UI "TERMINÉ. Redémarrage pour connexion automatique..." $ColorOrange 100
            $ExitBtn.Text = "REDÉMARRAGE..."
            $ExitBtn.BackColor = $ColorViolet
            $Form.Refresh()
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        } else {
            Update-UI "TERMINÉ. Redémarrage dans 5 secondes..." $ColorOrange 100
            $ExitBtn.Text = "REDÉMARRAGE..."
            $ExitBtn.BackColor = $ColorViolet
            $Form.Refresh()
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        }
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
