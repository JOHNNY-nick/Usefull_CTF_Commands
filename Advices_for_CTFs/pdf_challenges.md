# 🚩 CTF — Analyse de fichiers PDF (Cheatsheet)

> Guide pratique pour les challenges CTF impliquant des fichiers PDF ou des fichiers déguisés en PDF.

---

## 🔎 Étape 0 — Le fichier est-il vraiment un PDF ?

Avant tout, vérifier le **vrai format** du fichier, indépendamment de son extension.

```bash
# Vérifier le type réel
file challenge.pdf

# Inspecter les magic bytes bruts
xxd challenge.pdf | head -20

# Laisser binwalk identifier le format (et les fichiers embarqués)
binwalk challenge.pdf
```

### Magic bytes courants

| Magic bytes (hex)     | Vrai format        |
|-----------------------|--------------------|
| `25 50 44 46` (`%PDF`)| PDF légitime       |
| `89 50 4E 47`         | PNG                |
| `FF D8 FF`            | JPEG               |
| `47 49 46 38`         | GIF                |
| `50 4B 03 04`         | ZIP / DOCX / JAR   |
| `1F 8B`               | GZIP               |
| `52 61 72 21`         | RAR                |
| `7F 45 4C 46`         | ELF (binaire Linux)|
| `4D 5A`               | EXE (Windows)      |

### Exemple concret — PNG déguisé en PDF

```
$ binwalk challenge.pdf

DECIMAL    HEXADECIMAL    DESCRIPTION
-----------------------------------------------
0          0x0            PNG image, 800 x 600, 8-bit/color RGB, non-interlaced
91         0x5B           Zlib compressed data, compressed
```

➡️ **Solution** : simplement renommer le fichier avec la bonne extension.

```bash
cp challenge.pdf challenge.png
# Ouvrir l'image → le flag est souvent visible directement
```

> **Note** : Le Zlib à l'offset 91 est normal pour un PNG — les pixels sont toujours compressés en interne. Ce n'est pas un fichier caché.

---

## 📦 Méthodes classiques en CTF avec des PDFs

### 1. Structure du fichier corrompue

Le header `%PDF-`, la xref table ou le trailer ont été modifiés pour empêcher l'ouverture.

```bash
pdfid.py challenge.pdf
pdf-parser.py challenge.pdf
hexdump -C challenge.pdf | head -30
```

### 2. Texte / contenu caché

- Texte blanc sur fond blanc
- Opacité à 0
- Calques (layers) non visibles

```bash
# Sélectionner tout le texte dans un lecteur PDF
# Ou extraire programmatiquement
pdftotext challenge.pdf -
```

### 3. Streams compressés

Les objets PDF sont encodés en **FlateDecode (zlib)**, **ASCIIHexDecode**, etc. La décompression peut révéler le flag.

```bash
# Lister les objets
pdf-parser.py challenge.pdf

# Extraire et décompresser un objet spécifique
pdf-parser.py --filter --object <N> challenge.pdf

# Décompression manuelle
zlib-flate -uncompress < stream.bin
```

### 4. Fichiers embarqués

Un fichier (image, ZIP, texte…) est attaché à l'intérieur du PDF.

```bash
binwalk -e challenge.pdf       # Extraction automatique
foremost challenge.pdf         # Récupération par magic bytes
pdfextract challenge.pdf       # Extraction dédiée PDF
```

### 5. Protection par mot de passe

```bash
# Tenter de déchiffrer
qpdf --decrypt challenge.pdf output.pdf

# Bruteforce
pdf2john challenge.pdf > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 10500 hash.txt rockyou.txt
```

### 6. JavaScript embarqué / Métadonnées

Du code JavaScript ou des métadonnées XMP peuvent contenir le flag ou un indice.

```bash
exiftool challenge.pdf         # Métadonnées
peepdf challenge.pdf           # Analyse complète + JS
```

---

## 🛠️ Workflow recommandé

```bash
# 1. Identifier le vrai format
file challenge.pdf
xxd challenge.pdf | head -5

# 2. Scanner avec binwalk
binwalk challenge.pdf
binwalk -e challenge.pdf       # Si des fichiers sont détectés

# 3. Analyser la structure PDF (si c'est bien un PDF)
pdfid.py challenge.pdf
pdf-parser.py challenge.pdf

# 4. Extraire le texte
pdftotext challenge.pdf -

# 5. Extraire et décompresser les streams
pdf-parser.py --filter --object <N> challenge.pdf

# 6. Lire les métadonnées
exiftool challenge.pdf

# 7. Analyse complète
peepdf challenge.pdf
```

---

## 🧰 Outils utiles

| Outil          | Usage principal                          |
|----------------|------------------------------------------|
| `file`         | Identifier le vrai type de fichier       |
| `xxd` / `hexdump` | Inspecter les magic bytes             |
| `binwalk`      | Détecter et extraire des fichiers cachés |
| `foremost`     | Récupération de fichiers par magic bytes |
| `pdfid.py`     | Analyse rapide de la structure PDF       |
| `pdf-parser.py`| Analyse détaillée des objets PDF         |
| `peepdf`       | Analyse complète + JavaScript            |
| `pdftotext`    | Extraction du texte                      |
| `exiftool`     | Lecture des métadonnées                  |
| `qpdf`         | Déchiffrement de PDFs protégés           |
| `pdf2john`     | Extraction du hash pour John/Hashcat     |
| `zlib-flate`   | Décompression manuelle de streams        |

---

## 💡 Réflexes à avoir

1. **Ne jamais faire confiance à l'extension** — toujours vérifier avec `file` et `xxd`
2. **`binwalk` en premier** sur tout fichier suspect
3. Si le PDF s'ouvre mais semble vide → chercher du **texte invisible**
4. Si `binwalk` trouve plusieurs fichiers → extraire avec `binwalk -e`
5. Toujours lire les **métadonnées** avec `exiftool`

---

*Cheatsheet réalisée à partir de challenges CTF réels — bonne chance ! 🏁*
