# Binary Decoding in CTF — A Complete Guide

---

## Table of Contents

1. [What is a Binary File of 1s and 0s?](#1-what-is-a-binary-file-of-1s-and-0s)
2. [Step 0 — Always Triage First](#2-step-0--always-triage-first)
3. [Classic Method 1 — Binary to ASCII](#3-classic-method-1--binary-to-ascii)
4. [Classic Method 2 — Binary to Image](#4-classic-method-2--binary-to-image)
5. [Classic Method 3 — Binary to Raw File (via Magic Bytes)](#5-classic-method-3--binary-to-raw-file-via-magic-bytes)
6. [Classic Method 4 — LSB vs MSB](#6-classic-method-4--lsb-vs-msb)
7. [The Method Used on digits.bin](#7-the-method-used-on-digitsbin)
8. [Magic Bytes — The File Fingerprint](#8-magic-bytes--the-file-fingerprint)

---

## 1. What is a Binary File of 1s and 0s?

When you encounter a file that contains only the characters `'0'` and `'1'`, it means some data has been **serialized as a binary string**. Each `0` or `1` is not a raw bit at the hardware level — it is a literal ASCII character stored in a text file.

The goal is to figure out what the original data was before this textual representation was created. There are several classic ways to approach this.

---

## 2. Step 0 — Always Triage First

Before trying any decoding, gather key statistics about the file. These numbers will tell you which method to try.

```bash
# Get total number of characters (= total bits)
wc -c file.txt

# Count only 1s and 0s (exclude whitespace/newlines)
cat file.txt | tr -d '\n ' | wc -c

# Visually inspect the raw content
head -c 200 file.txt
```

Then run this Python triage script:

```python
import math

data = open('file.txt').read().replace('\n', '').replace(' ', '')

print(f"Total bits  : {len(data)}")
print(f"% 8         : {len(data) % 8}")    # 0 → likely standard bytes
print(f"% 7         : {len(data) % 7}")    # 0 → might be 7-bit ASCII
print(f"sqrt        : {math.sqrt(len(data)):.2f}")  # whole → might be square image
print(f"Unique chars: {set(data)}")         # should only be {'0', '1'}
print(f"Count 1s    : {data.count('1')}")
print(f"Count 0s    : {data.count('0')}")
```

### How to interpret the results

| Result | What it suggests |
|---|---|
| `total % 8 == 0` | Standard byte-aligned data → try ASCII or raw file |
| `total % 7 == 0` | Might be 7-bit ASCII encoding |
| `sqrt` is a whole number | Might be a square bitmap image |
| Ratio of 1s/0s ≈ 50/50 | Likely encrypted or compressed data |
| Ratio very unbalanced | Likely plain text (natural language has many 0s) |

---

## 3. Classic Method 1 — Binary to ASCII

### Concept

This is the most common trick in CTF challenges. Every character in standard ASCII is represented by a number from 0 to 127, which fits in **7 or 8 bits**. The challenge author encodes a secret message by converting each character to its 8-bit binary representation.

```
'A' → ASCII 65  → 01000001
'B' → ASCII 66  → 01000010
'C' → ASCII 67  → 01000011
```

So the string `"ABC"` becomes `"010000010100001001000011"`.

Your job is to reverse this: split the bit string into 8-bit chunks and convert each back to a character.

### How it works — step by step

```
Binary string: "0100000101000010"
                ↓        ↓
Split by 8:   "01000001" "01000010"
                ↓        ↓
int(..., 2):    65        66
                ↓        ↓
chr(...):      'A'       'B'
```

The expression `int("01000001", 2)` converts a binary string to an integer using **base 2**. The `2` here means "interpret this string in base 2 (binary)". Then `chr(65)` gives back the character `'A'`.

### Implementation

```python
data = open('file.txt').read().replace('\n', '').replace(' ', '')

# MSB first (standard — try this first)
result = ''.join(chr(int(data[i:i+8], 2)) for i in range(0, len(data), 8))
print(result)
```

### What `range(0, len(data), 8)` does

This generates indices `0, 8, 16, 24, ...` — every 8 steps. So `data[i:i+8]` cuts out each consecutive 8-character chunk.

### Check if the result makes sense

```python
# Count printable characters
printable = sum(1 for c in result if c.isprintable())
print(f"Printable: {printable}/{len(result)}")

# If ratio is high, you likely have readable text
# If low, the data is something else (image, archive, etc.)
```

---

## 4. Classic Method 2 — Binary to Image

### Concept

Sometimes the 1s and 0s represent **pixels**: `1` = white, `0` = black (or the inverse). This technique is used to encode QR codes, barcodes, pixel art, or hidden images.

The key clue is that `total bits ≈ width × height`. If the square root of the bit count is close to a whole number, it's very likely a square image.

### Implementation

```python
from PIL import Image
import math

data = open('file.txt').read().replace('\n', '').replace(' ', '')

# Try as a square image
size = int(math.sqrt(len(data)))
img = Image.new('1', (size, size))          # '1' = 1-bit per pixel (black & white)
img.putdata([int(b) * 255 for b in data])   # 0 → black, 1 → white
img.save('output.png')
```

### If the image is not square

Try common standard dimensions:

```python
# Try different width/height combinations
candidates = [(100, 100), (128, 128), (64, 64), (200, 150), (640, 480)]

for w, h in candidates:
    if w * h <= len(data):
        img = Image.new('1', (w, h))
        img.putdata([int(b) * 255 for b in data[:w*h]])
        img.save(f'output_{w}x{h}.png')
        print(f"Saved {w}x{h}")
```

### Tips

- If the image looks like noise → try inverting (swap 0s and 1s)
- If it looks distorted → try swapping width and height
- If you see a QR code → use a QR reader tool or `zbarimg` on Linux

---

## 5. Classic Method 3 — Binary to Raw File (via Magic Bytes)

### Concept

The 1s and 0s can represent **any binary file**: a JPEG image, a ZIP archive, a PDF, an ELF executable, etc. In this case, you convert the bit string back to raw bytes and save it, then let the OS or tools identify what it is.

This method is tried when ASCII decoding gives mostly non-printable characters (low printable ratio) but the data still seems structured.

### Implementation

```python
data = open('file.txt').read().replace('\n', '').replace(' ', '')

# Convert the entire bit string to raw bytes
n_bytes = len(data) // 8
raw = int(data, 2).to_bytes(n_bytes, byteorder='big')

# Save to disk
with open('output.bin', 'wb') as f:
    f.write(raw)
```

### How `int(data, 2).to_bytes(n, 'big')` works

`int(data, 2)` treats the **entire** bit string as one giant binary number and converts it to a Python integer. For example, `int("1101", 2)` = 13.

`.to_bytes(n, 'big')` converts that integer back into exactly `n` bytes, using **big-endian** order (most significant byte first — the standard for network protocols and most file formats).

### Identify the output file

```bash
# Let the OS figure out the file type
file output.bin

# Inspect the first few bytes in hex (magic bytes)
python3 -c "
data = open('output.bin', 'rb').read()
print(data[:16].hex())
print(data[:16])
"

# Look for embedded files or structures
binwalk output.bin

# Full hex dump
hexdump -C output.bin | head -20
```

---

## 6. Classic Method 4 — LSB vs MSB

### Concept

**MSB** (Most Significant Bit) means the leftmost bit in a group is the "biggest" (worth 2⁷ = 128). This is the standard convention used everywhere.

**LSB** (Least Significant Bit) means the leftmost bit is the "smallest" (worth 2⁰ = 1). Some hardware protocols, certain compression algorithms, and some CTF challenges use this reversed order.

```
MSB: "01000001" → 0×128 + 1×64 + 0×32 + ... + 1×1 = 65 = 'A'  ✅ standard
LSB: "01000001" → reversed → "10000010" → 130 = '?'
```

### How to try both

```python
data = open('file.txt').read().replace('\n', '').replace(' ', '')

# MSB first (standard — always try first)
msb = ''.join(chr(int(data[i:i+8], 2)) for i in range(0, len(data), 8))

# LSB first (reverse each 8-bit chunk before converting)
lsb = ''.join(chr(int(data[i:i+8][::-1], 2)) for i in range(0, len(data), 8))

print("MSB:", msb[:100])
print("LSB:", lsb[:100])
```

The `[::-1]` slice reverses a string in Python. So `"01000001"[::-1]` = `"10000010"`.

### When to use LSB

- Data from hardware/serial ports (UART, I²C, SPI protocols often use LSB)
- Steganography challenges that hide data in the least significant bits of image pixels
- Some older compression/encoding schemes
- When MSB gives garbage but the printable ratio is high (close to a valid encoding)

---

## 7. The Method Used on `digits.bin`

Here is a precise reconstruction of every step taken to decode the file.

### Step 1 — Identify the file nature

```bash
file /mnt/user-data/uploads/digits.bin
# → ASCII text, with very long lines (65536), with no line terminators

wc -c /mnt/user-data/uploads/digits.bin
# → 71160 bytes (= 71160 characters = 71160 bits)
```

The file is **pure ASCII text**, all on one line — meaning it's a raw stream of `'0'` and `'1'` characters.

### Step 2 — Triage the bit count

```python
data = open('digits.bin').read().strip()

len(data)        # → 71160
len(data) % 8   # → 0   ✅ perfectly byte-aligned
len(data) % 7   # → 5   ✗
sqrt(71160)      # → 266.76  ✗ not a perfect square
```

The bit count is divisible by 8 with no remainder → we have exactly **8,895 bytes** of data. The square root is not a whole number, so a square pixel grid is unlikely.

### Step 3 — Attempt MSB-first ASCII decoding

```python
result = ''.join(chr(int(data[i:i+8], 2)) for i in range(0, len(data), 8))
print(result[:20])
# → ÿØÿà  JFIF ...
```

The first few characters decoded to `ÿ Ø ÿ à` followed by the text `JFIF`.

### Step 4 — Recognize the magic bytes

```
Decoded:  ÿ    Ø    ÿ    à    J    F    I    F
Hex:      FF   D8   FF   E0   4A   46   49   46
```

`FF D8 FF` is the universally recognized **JPEG file signature**. `JFIF` stands for *JPEG File Interchange Format*, the standard JPEG container. This is a **100% unambiguous identification** — no other file format starts with these bytes.

### Step 5 — Convert to a raw binary file and save

```python
data = open('digits.bin').read().strip()

# 1. Convert the entire bit string to one big integer
big_int = int(data, 2)

# 2. Convert that integer to raw bytes (8895 bytes, big-endian)
raw_bytes = big_int.to_bytes(len(data) // 8, byteorder='big')

# 3. Save as JPEG
with open('decoded.jpg', 'wb') as f:
    f.write(raw_bytes)
```

Opening `decoded.jpg` reveals the hidden image — which likely contains the CTF flag.

### Visual Summary

```
"11111111 11011000 11111111 11100000 00000000 00010000 01001010 01000110..."
     ↓         ↓        ↓        ↓        ↓        ↓        ↓        ↓
   0xFF      0xD8     0xFF     0xE0     0x00     0x10     0x4A     0x46
     ÿ         Ø        ÿ        à        .        .        J        F
                                                        
     └─────────────────────────────────────────────────────────────────┘
                      JPEG magic bytes → save as .jpg → 🖼️ flag image
```

---

## 8. Magic Bytes — The File Fingerprint

### What are magic bytes?

Every standard file format starts with a fixed sequence of bytes at the very beginning of the file. These are called **magic bytes** (or **magic numbers** or **file signatures**). They exist so that programs — and humans — can identify a file's format reliably, regardless of its extension.

For example, a file named `photo.txt` that starts with `FF D8 FF` is actually a JPEG, no matter what its name says.

The `file` command on Linux uses a database of magic bytes (`/usr/share/misc/magic`) to identify files. You can inspect magic bytes yourself by reading the first bytes in hex:

```python
with open('mystery_file', 'rb') as f:
    header = f.read(16)
    print(header.hex())   # → e.g. ffd8ffe0 (JPEG)
    print(header)         # → raw bytes view
```

```bash
# With hexdump
hexdump -C mystery_file | head -3

# With xxd
xxd mystery_file | head -3

# Quick python one-liner
python3 -c "print(open('mystery_file','rb').read(16).hex())"
```

### Famous Format Magic Bytes

| Format | Magic Bytes (Hex) | ASCII Representation | Notes |
|---|---|---|---|
| **JPEG** | `FF D8 FF` | `ÿØÿ` | All JPEGs start with these 3 bytes |
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG....` | 8-byte signature, very distinctive |
| **GIF** | `47 49 46 38` | `GIF8` | Followed by `37 61` (GIF87a) or `39 61` (GIF89a) |
| **PDF** | `25 50 44 46 2D` | `%PDF-` | Followed by version, e.g. `%PDF-1.4` |
| **ZIP** | `50 4B 03 04` | `PK..` | Named after Phil Katz, ZIP's creator |
| **RAR** | `52 61 72 21 1A 07` | `Rar!..` | |
| **7-Zip** | `37 7A BC AF 27 1C` | `7z¼¯'.` | |
| **ELF** | `7F 45 4C 46` | `.ELF` | Linux/Unix executables and shared libs |
| **PE (EXE/DLL)** | `4D 5A` | `MZ` | Windows executables — initials of Mark Zbikowski |
| **MP3** | `49 44 33` | `ID3` | ID3 tag header; or `FF FB` for raw MPEG frames |
| **MP4 / MOV** | `66 74 79 70` | `ftyp` | At offset 4, not byte 0 |
| **OGG** | `4F 67 67 53` | `OggS` | |
| **FLAC** | `66 4C 61 43` | `fLaC` | |
| **WAV** | `52 49 46 46` | `RIFF` | Followed by `57 41 56 45` (`WAVE`) at offset 8 |
| **BMP** | `42 4D` | `BM` | Windows Bitmap |
| **WEBP** | `52 49 46 46 ... 57 45 42 50` | `RIFF....WEBP` | RIFF container, WEBP at offset 8 |
| **SQLite** | `53 51 4C 69 74 65 20 33 00` | `SQLite 3.` | |
| **Class (Java)** | `CA FE BA BE` | `ÊÞÎÞ` | Java bytecode — "cafe babe" |
| **Gzip** | `1F 8B` | `..` | Used by `.gz` and `.tar.gz` |
| **Bzip2** | `42 5A 68` | `BZh` | |
| **XZ** | `FD 37 7A 58 5A 00` | `ý7zXZ.` | |
| **PCAP** | `D4 C3 B2 A1` | `ÔÃÒÁ` | Wireshark packet capture (little-endian) |
| **PCAPNG** | `0A 0D 0D 0A` | `....` | Newer Wireshark format |
| **Tar** | `75 73 74 61 72` | `ustar` | At offset 257, not byte 0 |
| **PEM cert** | `2D 2D 2D 2D 2D 42 45 47 49 4E` | `-----BEGIN` | Base64-encoded certificate |
| **SSH key** | `6F 70 65 6E 73 73 68` | `openssh` | OpenSSH private key file |
| **Zlib** | `78 9C` | `x.` | Default compression level |

### A practical identification script

```python
MAGIC = {
    bytes.fromhex('ffd8ff'):               'JPEG Image',
    bytes.fromhex('89504e470d0a1a0a'):     'PNG Image',
    bytes.fromhex('47494638'):             'GIF Image',
    bytes.fromhex('25504446'):             'PDF Document',
    bytes.fromhex('504b0304'):             'ZIP Archive',
    bytes.fromhex('526172211a07'):         'RAR Archive',
    bytes.fromhex('377abcaf271c'):         '7-Zip Archive',
    bytes.fromhex('7f454c46'):             'ELF Executable (Linux)',
    bytes.fromhex('4d5a'):                 'PE Executable (Windows .exe/.dll)',
    bytes.fromhex('494433'):               'MP3 Audio (ID3 tag)',
    bytes.fromhex('664c6143'):             'FLAC Audio',
    bytes.fromhex('4f676753'):             'OGG Audio/Video',
    bytes.fromhex('52494646'):             'WAV/WEBP/AVI (RIFF container)',
    bytes.fromhex('1f8b'):                 'Gzip Compressed',
    bytes.fromhex('425a68'):               'Bzip2 Compressed',
    bytes.fromhex('cafebabe'):             'Java Class File',
    bytes.fromhex('53514c69746520332e'):   'SQLite Database',
    bytes.fromhex('d4c3b2a1'):             'PCAP Packet Capture',
}

def identify(filepath):
    with open(filepath, 'rb') as f:
        header = f.read(16)
    for magic, name in MAGIC.items():
        if header.startswith(magic):
            return name
    return f'Unknown — hex: {header[:8].hex()}'

print(identify('mystery_file'))
```

### In a CTF context

When you decode a bit string and get a non-printable result, **always check the magic bytes first** before assuming the decoding is wrong. The workflow is:

```
Decode bits → raw bytes → check first 4–8 bytes in hex
                                     ↓
                          Match against magic byte table
                                     ↓
                          Rename file with correct extension
                                     ↓
                          Open / extract / analyze
```

Magic bytes are the single most reliable way to identify what you are really dealing with in a CTF — file extensions can be faked, but magic bytes rarely lie.
