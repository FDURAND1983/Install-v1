# 👋 Notice

# **⚠️ Important pour les développeurs :** Pensez à mettre à jour les URL de téléchargement dans les scripts avant le déploiement final !
##  **Ligne 178 et 187 du fichier install.ps1** 
##  **Ligne 5 du fichier install.bat**

---

## ✨ Fonctionnalités

Le script `Install.ps1` automatise les tâches suivantes :

*   📦 **Gestionnaire de paquets** : Installation automatique de Chocolatey si absent.
*   🛠️ **Logiciels essentiels** : Installation silencieuse de :
    *   Microsoft PowerToys
    *   LibreOffice
*   ⚙️ **Configuration sur mesure** :
    *   Mise en place de votre configuration PowerToys personnalisée.
    *   Récupération de l'installateur `SimplyKiosk-Setup.exe`.
*   🔒 **Sécurité & Sérénité** :
    *   Désactivation de l'AutoRun pour plus de sécurité.
    *   **Protection des comptes** : Blocage des connexions aux comptes Microsoft personnels (via Registre et Stratégies) pour garantir un usage professionnel.

---

## 🚀 Comment l'utiliser ?

### Méthode rapide (Recommandée)
Pour une installation sans effort :
1.  Faites un clic droit sur le fichier `install.bat`.
2.  Choisissez **⚠️⚠️⚠️"Exécuter en tant qu'administrateur"⚠️⚠️⚠️**.

Le script se chargera de télécharger la dernière version et de lancer l'installation.

### Méthode manuelle (PowerShell)
Si vous préférez la ligne de commande :
1.  Ouvrez PowerShell en tant qu'administrateur.
2.  Lancez la commande suivante :
    ```powershell
    .\install.ps1
    ```

---

## 📝 Notes importantes

*   🛡️ **Droits Administrateur** : Pour fonctionner correctement, l'outil a besoin de privilèges élevés. Une fenêtre UAC peut apparaître pour vous demander confirmation.
*   🔄 **Redémarrage automatique** : Une fois l'installation terminée, le poste redémarrera automatiquement sous 5 secondes pour bien appliquer tous les changements.
*   📂 **Suivi & Logs** : Vous retrouverez le détail des opérations dans le dossier `C:\SimplyKiosk\`.

---
*© Tous droits réservés à DURAND Frédéric*