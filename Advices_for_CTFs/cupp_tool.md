# 🔐 CUPP — Common User Passwords Profiler

> A practical guide for cybersecurity learners and CTF participants.

---

## 1. Introduction

**CUPP** (Common User Passwords Profiler) is an open-source Python tool designed to generate **highly targeted, personalized wordlists** based on information gathered about a specific individual. Rather than relying on generic dictionaries, CUPP crafts password candidates derived from personal data — names, dates, hobbies, pets, and more.

### Purpose

Humans tend to use predictable patterns when creating passwords: their pet's name, a birthday, a nickname followed by a lucky number. CUPP exploits this behavioral tendency to dramatically reduce the search space during a password-cracking attempt.

### Typical Use Cases

| Context | Description |
|---|---|
| **CTF (Capture The Flag)** | Generating wordlists targeting fictional personas in challenge scenarios |
| **Penetration Testing** | Creating custom dictionaries during authorized red-team engagements |
| **Forensic Investigations** | Assisting investigators in recovering access to accounts with proper authorization |
| **Security Awareness Training** | Demonstrating how personal data makes weak passwords to end users |

---

## 2. How CUPP Works

CUPP operates on a simple but powerful principle: **people are the weakest link**. By collecting personal information about a target, it assembles thousands of plausible password candidates.

### 2.1 Interactive Mode

CUPP's most prominent feature is its **interactive interview mode**. It prompts the operator for:

- First name, last name, and nickname
- Partner's name and nickname
- Child's name and nickname
- Pet's name
- Date of birth (target, partner, child)
- Company name
- Keywords (favorite bands, sports teams, hobbies)
- Special characters and numbers to append

From these inputs, CUPP generates combinations, applying various mutations automatically.

### 2.2 Wordlist Profiling

CUPP can also **ingest an existing wordlist** and enhance it by:

- Appending common special characters (`!`, `@`, `#`, `$`, `123`, etc.)
- Prepending and appending numbers
- Applying mixed-case variations

### 2.3 Leet Substitutions

CUPP supports **leet speak (1337) substitutions**, transforming standard characters into their numeric equivalents:

| Original | Leet |
|---|---|
| `a` | `4` |
| `e` | `3` |
| `i` | `1` |
| `o` | `0` |
| `s` | `5` |

For example, `password` becomes `p4ssw0rd`, `p@$$w0rd`, and many other variants.

### 2.4 Alecto DB Integration

CUPP integrates with the **Alecto Database**, a collection of default credentials for routers, switches, and common network devices. This is useful when testing infrastructure that may still run factory-default passwords.

### 2.5 Output

All generated passwords are written to a `.txt` wordlist file (e.g., `john.txt`), ready to be fed into cracking tools.

---

## 3. Installation

### Option A — Clone from GitHub (Recommended)

```bash
git clone https://github.com/Mebus/cupp.git
cd cupp
python3 cupp.py --help
```

### Option B — Install via PyPI

```bash
pip install cupp
cupp --help
```

### Requirements

- Python 3.x
- No additional dependencies for core functionality

---

## 4. Usage Examples

### 4.1 Interactive Profiling Mode

Launch the guided interview to build a custom wordlist:

```bash
python3 cupp.py -i
```

CUPP will prompt for personal information and generate a file named after the target (e.g., `john.txt`).

**Example session:**

```
[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked!

> First Name: John
> Surname: Doe
> Nickname: johnny
> Birthdate (DDMMYYYY): 15081990
> Partner's name: Jane
...
[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to john.txt, counting 3847 words.
```

---

### 4.2 Profile an Existing Wordlist

Enhance a pre-existing dictionary with mutations and appended characters:

```bash
python3 cupp.py -w wordlist.txt
```

This outputs a new, augmented wordlist file.

---

### 4.3 Download Large Wordlists

CUPP can download curated large wordlists from its repository:

```bash
python3 cupp.py -l
```

A menu is presented allowing you to select and download community wordlists.

---

### 4.4 Use Alecto DB for Default Credentials

Parse the Alecto database and output default username/password pairs:

```bash
python3 cupp.py -a
```

Useful when targeting routers, switches, or IoT devices that may not have had their credentials changed.

---

### 4.5 Quick Reference — All Flags

```
python3 cupp.py -h

Options:
  -i    Interactive mode (generate wordlist from personal info)
  -w    Profile an existing wordlist file
  -l    Download large wordlists from repository
  -a    Parse default credentials from Alecto DB
  -v    Verbose mode
  -q    Quiet mode (no banner)
```

---

## 5. Bilingual Recap (FR / EN)

| Commande (FR) | Command (EN) | Description |
|---|---|---|
| `python3 cupp.py -i` | `python3 cupp.py -i` | Lancer le mode interactif pour profiler une cible | Launch interactive mode to profile a target |
| `python3 cupp.py -w liste.txt` | `python3 cupp.py -w wordlist.txt` | Améliorer une liste de mots existante | Enhance an existing wordlist with mutations |
| `python3 cupp.py -l` | `python3 cupp.py -l` | Télécharger de grandes listes de mots | Download large pre-built wordlists |
| `python3 cupp.py -a` | `python3 cupp.py -a` | Utiliser la base Alecto (identifiants par défaut) | Use Alecto DB for default device credentials |
| `python3 cupp.py -v` | `python3 cupp.py -v` | Mode verbeux (plus de détails) | Verbose mode for detailed output |

### FR/EN Key Terminology

| Terme (Français) | Term (English) |
|---|---|
| Liste de mots | Wordlist |
| Substitution leet | Leet speak substitution |
| Profilage | Profiling |
| Identifiants par défaut | Default credentials |
| Test d'intrusion autorisé | Authorized penetration testing |
| Cible | Target |
| Dictionnaire personnalisé | Custom dictionary |

---

## 6. Ethical Notes

> ⚠️ **CUPP is a tool for authorized security testing and educational purposes only.**

### Rules of Engagement

- **Always obtain written authorization** before testing any system, account, or network you do not personally own.
- CUPP is permitted in **CTF environments**, **sandboxed lab setups**, and **authorized red-team engagements**.
- Generating wordlists targeting real individuals **without consent** may violate privacy laws, computer fraud statutes, and cybersecurity regulations in your jurisdiction (e.g., CFAA in the US, NIS2 in the EU, loi informatique et libertés in France).

### What CUPP Is Not

- ❌ A tool for unauthorized access to accounts
- ❌ A stalking or harassment instrument
- ❌ A substitute for proper legal authorization

**Misuse of CUPP can result in criminal prosecution.** The tool is distributed for legitimate security research and education.

---

## 7. Conclusion

CUPP is a deceptively simple yet remarkably effective tool that underscores a fundamental truth in cybersecurity: **technical vulnerabilities are often less exploitable than human predictability**.

### Why CUPP Is Valuable in Security Training

- It makes the concept of **password hygiene** tangible and immediate
- It demonstrates why **personal information should never influence passwords**
- It provides CTF participants with a competitive edge when facing human-modeled targets
- It fits seamlessly into a **standard penetration testing workflow**

### Recommended Tool Combinations

| Tool | How to Combine with CUPP |
|---|---|
| **Hydra** | Feed CUPP wordlists to brute-force SSH, FTP, HTTP login forms |
| **John the Ripper** | Use CUPP output as a custom wordlist for offline hash cracking |
| **Hashcat** | Combine CUPP lists with rules (e.g., `best64.rule`) for advanced attacks |
| **Medusa** | Multi-protocol brute-forcing using CUPP-generated dictionaries |

**Example pipeline:**

```bash
# Step 1: Generate a personalized wordlist
python3 cupp.py -i

# Step 2: Use the wordlist with Hydra against an SSH service
hydra -l john -P john.txt ssh://192.168.1.100

# Step 3: Or crack a local hash with John the Ripper
john --wordlist=john.txt hash.txt
```

---

*Document produced for educational purposes. Always hack ethically and legally.* 🛡️
