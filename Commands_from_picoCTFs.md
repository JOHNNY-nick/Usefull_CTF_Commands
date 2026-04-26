# CTF Commands Cheatsheet
---

## 🌐 Network & Connexion

### SSH
```bash
ssh -p <PORT> <USER_NAME>@<IP_Address_OR_Domain_Name>
```
Connexion à une machine distante via SSH sur un port spécifique. Par défaut SSH utilise le port 22, l'option `-p` permet de spécifier un port différent.

---

### Netcat (nc)
```bash
nc <Domain_Name_OR_IP> <PORT>
```
Outil polyvalent ("couteau suisse du réseau") permettant de se connecter à un serveur sur un port spécifique via TCP/UDP. Très utilisé en CTF pour interagir directement avec des services ou des challenges exposés sur un port.

---

## 🔐 Encodage & Décodage

### Base64
```bash
echo "<ENCODED_STRING>" | base64 -d
# ou depuis un fichier
base64 -d encoded_file.txt
```
Décodage d'un message encodé en Base64. `base64 -d` lit depuis l'entrée standard (stdin) ou un fichier — on ne lui passe pas directement la chaîne en argument, il faut piper (`|`) ou rediriger depuis un fichier.

---

### Reverse (rev)
```bash
echo "gnirts esrevni" | rev
cat file.txt | rev
```
Inverse chaque ligne caractère par caractère. Lit depuis stdin ou un fichier via pipe.

---

### Translate (tr)
```bash
tr 'set1' 'set2'
# Exemple ROT13 :
echo "Hello" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
Remplace chaque caractère de `set1` par le caractère correspondant (même position) dans `set2`. Les ensembles sont écrits **sans virgules ni espaces** entre les caractères. Supporte les plages (`A-Z`, `a-z`, `0-9`). Classiquement utilisé en CTF pour des chiffrements par substitution comme ROT13.

---

## 🐍 Python one-liners

### Afficher un caractère par son code ASCII (Python)
```python
python3 -c "print('\xNN' * N)"
```
Permet d'afficher le caractère dont `NN` est le code hexadécimal ASCII, répété `N` fois. C'est une syntaxe **Python** (pas bash). Exemple : `'\x41' * 3` affiche `AAA`.

---

## 🛠️ Manipulation de fichiers

### Exécution de commandes en séquence
```bash
cmd1 ; cmd2 ; cmd3
```
Exécute les commandes l'une après l'autre, indépendamment du succès ou de l'échec des précédentes. (À distinguer de `&&` qui stoppe la chaîne si une commande échoue.)

---

### Concaténation de fichiers (cat)
```bash
cat part1 part2 part3 ... > output_file
```
Combine plusieurs fichiers en les concaténant dans l'ordre donné et redirige le résultat dans `output_file`. Utile lorsqu'un fichier (image, archive, etc.) a été découpé en plusieurs parties.

---

### Décompression ZIP
```bash
unzip archive.zip
unzip archive.zip -d output_directory/
```
Décompresse une archive `.zip`. L'option `-d` permet de spécifier un répertoire de destination.

---

## 👤 Permissions & Élévation de privilèges

### sudo -l
```bash
sudo -l
```
Liste **toutes** les commandes que l'utilisateur courant est autorisé à exécuter via `sudo`, ainsi que leurs conditions (avec ou sans mot de passe, sur quels hôtes, sous quel utilisateur). Indispensable en CTF pour identifier des vecteurs de privilege escalation.

---

## ✏️ Éditeurs de texte

### Emacs
```bash
emacs <file>
```
Éditeur de texte en ligne de commande, au même titre que `vi`/`vim` ou `nano`. Emacs est particulièrement puissant et extensible, avec ses propres raccourcis clavier (`Ctrl+X Ctrl+S` pour sauvegarder, `Ctrl+X Ctrl+C` pour quitter, etc.).

---

## 🔑 Cryptographie & RSA

### Conversion Hex → Binaire (xxd)
```bash
xxd -r -p key.hex > private.pem
```
Convertit un fichier contenant un dump hexadécimal en données binaires. `-r` active le mode inverse (hex → binaire), `-p` indique un format hexadécimal plain (sans adresses ni ASCII). En CTF, utilisé pour reconstruire une clé privée RSA au format PEM à partir de sa représentation hexadécimale.

---

### Déchiffrement RSA (openssl)
```bash
openssl pkeyutl -decrypt -inkey private.pem -in encrypted_file -out decrypted.txt
```
Déchiffre un fichier chiffré avec une clé publique RSA, en utilisant la clé privée correspondante (`private.pem`). Le résultat est écrit dans `decrypted.txt`.

---

## 🧬 Analyse de binaires

### GDB (GNU Debugger)
```bash
gdb ./binary_file
```
Débogueur interactif pour les programmes compilés. Offre un shell interactif permettant de : poser des breakpoints, exécuter pas à pas, inspecter les registres et la mémoire, désassembler du code, et analyser le comportement d'un binaire. Incontournable pour les challenges de type **pwn** et **reverse engineering**.

Commandes GDB utiles :
- `run` — lance le programme
- `disassemble <function>` — désassemble une fonction
- `break *<address>` — pose un breakpoint à une adresse
- `x/s <address>` — affiche une chaîne en mémoire
- `info registers` — affiche les registres

---

### checksec
```bash
checksec --file=./binary
# ou
checksec ./binary
```
Analyse les protections de sécurité activées sur un binaire ELF. Permet d'identifier les protections présentes et donc les vulnérabilités potentiellement exploitables :

| Protection | Description |
|---|---|
| **RELRO** | Protège la GOT contre l'écrasement |
| **Stack Canary** | Détecte les stack buffer overflows |
| **NX** | Empêche l'exécution de code sur la pile |
| **PIE** | Randomise l'adresse de base du binaire (ASLR) |

---

### file
```bash
file ./binary
```
Inspecte un fichier et identifie son type réel (indépendamment de l'extension). Pour un binaire, affiche des informations comme l'architecture, le type ELF, et indique notamment si le binaire est **stripped** ou non.

> **Stripped binary** : binaire dont les symboles de débogage ont été retirés (noms de fonctions, variables, etc.) pour le rendre plus léger. Un binaire stripped est plus difficile à analyser avec GDB ou Ghidra car les noms de fonctions ne sont plus disponibles.

## Remove Duplicate Lines Ignoring Specific Columns

Deduplicate any file based on a subset of columns, ignoring specific fields by index.

### Case 1 — Ignore the first `N` contiguous columns

```bash
awk '{key=""; for(i=N+1;i<=NF;i++) key=key" "$i; if(!seen[key]++) print}' input.txt > deduped.txt
```

> Replace `N` with the number of leading columns to ignore.

### Case 2 — Ignore any non-contiguous columns

```bash
awk 'BEGIN{split("1 3 5", skip, " ")} {key=""; for(i=1;i<=NF;i++){found=0; for(j in skip) if(skip[j]==i){found=1; break}; if(!found) key=key" "$i}; if(!seen[key]++) print}' input.txt > deduped.txt
```

> Replace `"1 3 5"` with the indices of the columns you want to ignore.

### Examples

Given this file:
