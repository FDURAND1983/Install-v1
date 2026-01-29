# Définition des variables pour le test
$ColorViolet = "Cyan" # Simule votre variable de couleur
function Update-UI($message, $couleur, $valeur) {
    Write-Host "UI UPDATE [$valeur%] : $message" -ForegroundColor $couleur
}

# --- DÉBUT DU BLOC À TESTER ---
$isMicrosoftAccount = $false
$isDomainAccount = $false

try {
    # On tente de récupérer l'utilisateur local
    $currentUser = Get-LocalUser -Name $env:USERNAME -ErrorAction Stop
    
    # Vérification de la source du compte
    if ($currentUser.PrincipalSource -eq 'MicrosoftAccount') {
        $isMicrosoftAccount = $true
    }
}
catch {
    # Si Get-LocalUser échoue, le compte n'est pas géré localement (Domaine/AzureAD)
    $isDomainAccount = $true
}

# Logique de sortie
if ($isMicrosoftAccount) {
    Update-UI "Compte Microsoft déjà utilisé pour la session. Blocage ignoré." $ColorViolet 95
}
elseif ($isDomainAccount) {
    Update-UI "Compte de domaine détecté. Blocage des comptes MS ignoré." $ColorViolet 95
}
else {
    Update-UI "Compte local standard détecté." "White" 95
}
# --- FIN DU BLOC À TESTER ---

# Affichage des variables pour vérification technique
Write-Host "`n--- Diagnostic technique ---" -DarkGray
Write-Host "isMicrosoftAccount : $isMicrosoftAccount"
Write-Host "isDomainAccount    : $isDomainAccount"