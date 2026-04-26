# 🖼️ Stéganographie

Extraire des informations cachées (flags) à partir de photos, vidéos, fichiers audio, etc.

---

## 🔍 Inspection & Métadonnées

### exiftool
```bash
exiftool filename.ext
```
Extrait toutes les **métadonnées** d'un fichier (date de création, appareil photo, coordonnées GPS, logiciel utilisé, commentaires, etc.). Les CTF cachent souvent le flag directement dans les métadonnées.

---

### strings
```bash
strings filename.ext
strings -n 8 filename.ext   # filtre les chaînes d'au moins 8 caractères
```
Extrait toutes les **chaînes de caractères lisibles** (ASCII/Unicode) présentes dans un fichier binaire. Rapide et efficace pour un premier coup d'œil.

---

### pngcheck
```bash
pngcheck -v filename.png
```
Vérifie l'intégrité des **chunks** d'un fichier PNG. Un fichier est structuré en blocs (chunks), chacun avec un type, des données et un checksum. L'option `-v` (verbose) liste tous les chunks et permet de détecter des chunks corrompus ou inhabituels qui pourraient contenir des données cachées.

---

### xxd
```bash
xxd filename.ext
xxd filename.ext | less   # pour naviguer dans un grand fichier
```
Affiche le contenu binaire d'un fichier sous forme de **dump hexadécimal** lisible, accompagné de sa représentation ASCII. Utile pour inspecter les en-têtes de fichiers, détecter des signatures, ou repérer des données anormales.

---

## 🧩 Détection & Extraction de données cachées

### zsteg
```bash
zsteg filename.png
zsteg -a filename.png   # teste toutes les combinaisons possibles
```
Outil spécialisé pour détecter de la stéganographie dans les images **PNG et BMP**. Il analyse les bits des pixels en cherchant des données cachées, notamment via la technique **LSB (Least Significant Bit)**.

> **C'est quoi le LSB ?**
> Chaque pixel est composé de valeurs RGB (ex : Rouge = `11001010`). Le **dernier bit** (le moins significatif) a un impact si faible sur la couleur qu'il est visuellement imperceptible. On peut donc le remplacer par un bit de données cachées sans que ça se voie à l'œil nu.

---

### binwalk
```bash
binwalk filename.ext          # liste les fichiers/signatures détectés
binwalk -e filename.ext       # extrait automatiquement les fichiers trouvés
binwalk -e --run-as=root filename.ext  # si des erreurs de permission surviennent
```
Parcourt un fichier et **répertorie les fichiers cachés ou embarqués** en détectant leurs signatures (magic bytes). L'option `-e` extrait automatiquement tout ce qui est trouvé dans un dossier `_filename.ext.extracted/`.

---

### foremost
```bash
foremost filename.ext
foremost -o output_dir/ filename.ext   # spécifier le dossier de sortie
```
Outil de **récupération de fichiers** basé sur les en-têtes et pieds de fichiers (file carving). Crée un dossier `output/` et y place tous les fichiers récupérés, organisés par type (jpg, png, zip, etc.). Alternative à `binwalk -e`.

---

### steghide
```bash
steghide info filename.jpg                          # vérifie si des données sont cachées
steghide extract -sf filename.jpg                   # extrait les données (demande un mot de passe)
steghide extract -sf filename.jpg -p "password"     # avec mot de passe connu
```
Outil de stéganographie pour **cacher ou extraire des données** dans des fichiers image (JPEG, BMP) ou audio (WAV, AU). Chiffre les données avec un mot de passe. En CTF, le mot de passe est parfois vide (appuyer sur Entrée suffit).

---

## 🖥️ Outils graphiques

| Outil | Usage |
|---|---|
| **GIMP** | Éditeur d'image complet. Permet de manipuler les couches, canaux de couleur (R, G, B, Alpha) et les niveaux pour révéler des éléments visuellement cachés. |
| **stegSolve** | Outil Java spécialisé CTF. Permet de cycler rapidement sur les plans de bits (bit planes) de chaque canal de couleur pour détecter des images ou textes cachés. |

---

## 📦 Fichiers ZIP

> **Header PK** : la signature magique (magic bytes) `PK` au début d'un fichier indique qu'il s'agit d'un **fichier ZIP** (du nom de Phil Katz, créateur du format). Repérable avec `xxd`.

### zip2john + john (brute force)
```bash
zip2john archive.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
`zip2john` extrait le hash du mot de passe du fichier ZIP dans un format exploitable par **John the Ripper**. `john` effectue ensuite une attaque par dictionnaire pour retrouver le mot de passe.

---

## 🔓 Craquage de Hash

### john (John the Ripper)
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --show hash.txt   # affiche les mots de passe déjà craqués
```
Outil de craquage de mots de passe par attaque **dictionnaire ou brute force**. `rockyou.txt` est la wordlist par défaut sur Kali Linux, contenant des millions de mots de passe courants. Note : l'option est `--wordlist` (sans `s`).

---

### hashid
```bash
hashid <hash>
hashid -m <hash>   # affiche aussi le mode john/hashcat correspondant
```
Identifie le ou les **algorithmes de hachage** potentiellement utilisés pour produire un hash donné (MD5, SHA1, SHA256, bcrypt, etc.). Indispensable avant de lancer un craquage pour choisir le bon mode.

---

## 🌐 Outils utiles pour le Web

| Outil | Usage | Lien |
|---|---|---|
| **Burp Suite** | Intercepter et modifier les requêtes HTTP | [portswigger.net](https://portswigger.net/burp) |
| **jwt.io** | Décoder / modifier des tokens JWT | [jwt.io](https://jwt.io) |
| **base64decode.org** | Décoder du Base64 | [base64decode.org](https://www.base64decode.org) |
| **CyberChef** | Encodage / décodage / crypto / transformations | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) |
| **ffuf** | Fuzzing de fichiers et répertoires cachés | [github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) |
| **sqlmap** | Automatiser la détection et l'exploitation d'injections SQL | [sqlmap.org](https://sqlmap.org) |
| **SecLists** | Collection de wordlists pour fuzzing et brute force | [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) |
