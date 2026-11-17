# SPI Password Sniffing: Flash-Bus Analysis and Offline MD5 Hash Recovery

> **Project type:** Hardware / embedded-system security analysis  
> **Primary tools:** PulseView + SPI flash/EEPROM decoder, `hashid`, Hashcat, Kali Linux  
> **Evidence:** Seven-slide PowerPoint and seven-page PDF supplied with this project  
> **Outcome shown:** A candidate MD5 hash associated with an SPI flash write was tested offline; Hashcat recovered the demonstration password `admin123` from the full digest.

## Table of contents

1. [Project overview](#1-project-overview)
2. [Objective and threat model](#2-objective-and-threat-model)
3. [Scope, equipment, and evidence](#3-scope-equipment-and-evidence)
4. [SPI flash fundamentals](#4-spi-flash-fundamentals)
5. [End-to-end workflow](#5-end-to-end-workflow)
6. [Stage 1 — Capture and decode SPI traffic](#6-stage-1--capture-and-decode-spi-traffic)
7. [Stage 2 — Identify the page-program transaction](#7-stage-2--identify-the-page-program-transaction)
8. [Stage 3 — Convert the payload from hexadecimal to ASCII](#8-stage-3--convert-the-payload-from-hexadecimal-to-ascii)
9. [Stage 4 — Identify and validate the candidate hash](#9-stage-4--identify-and-validate-the-candidate-hash)
10. [Stage 5 — Perform the documented offline dictionary test](#10-stage-5--perform-the-documented-offline-dictionary-test)
11. [Results and evidence summary](#11-results-and-evidence-summary)
12. [Critical observations and limitations](#12-critical-observations-and-limitations)
13. [Security implications and mitigations](#13-security-implications-and-mitigations)
14. [Reproducing the analysis](#14-reproducing-the-analysis)
15. [Troubleshooting and further investigation](#15-troubleshooting-and-further-investigation)
16. [Repository structure and source attribution](#16-repository-structure-and-source-attribution)

---

## 1. Project overview

This project examines an **SPI flash/EEPROM communication trace** to determine whether data observable on a physical serial bus contains credential-related material. The supplied evidence follows a progression from a decoded logic-analyzer capture to a suspected hexadecimal hash string and then to offline password recovery.

The investigation has five distinct stages:

1. Observe activity on the SPI bus with a logic analyzer and inspect the traces in **PulseView**.
2. Decode flash commands, including repeated status-register reads and a page-program operation.
3. Extract a sequence of payload bytes and interpret their values as printable **ASCII characters**, rather than as an arbitrary binary blob.
4. Recognize that the reconstructed value resembles a 32-character hexadecimal **MD5** digest and examine candidate algorithms using `hashid`.
5. Run **Hashcat mode `0` (raw MD5)** against an offline dictionary. The screenshot records a successful match to `admin123`.

### Important distinction

The title *password sniffing* describes the project's security motivation. **The evidence does not show a plaintext password being transmitted on the SPI bus.** The central bus transaction contains a segment of an ASCII-encoded, hexadecimal value; the password recovery occurs later through an **offline dictionary attack** on the full MD5 digest. It is more precise to describe the demonstrated path as **physical SPI traffic inspection → hash material identification → offline password recovery**.

### High-level attack path

```text
Authorized test device
        │
        ▼
SPI flash / EEPROM bus signals
        │   (capture with logic analyzer)
        ▼
PulseView + SPI flash protocol decoder
        │
        ├── 0x05  Read Status Register (RDSR)
        └── 0x02  Page Program (PP)
                   │
                   ▼
              30-byte payload
                   │  (hex bytes → ASCII)
                   ▼
       Partial MD5-like hexadecimal text
                   │  (complete digest confirmed
                   │   separately in Hashcat evidence)
                   ▼
         32-character raw MD5 digest
                   │  (offline wordlist test)
                   ▼
              `admin123`
```

## 2. Objective and threat model

### Research objective

Determine whether credential-related data can be inferred from **observable SPI flash traffic** and whether weak password storage practices could expose a password once a usable hash is obtained.

### Assumed attacker position

A person who can **physically observe a device's SPI bus** through accessible test points or other authorized measurement access. This is a *physical / local hardware* threat model, not a remote packet-sniffing exercise.

### Conditions needed for the demonstrated path

- The relevant SPI signals must be observable with adequate electrical and timing fidelity.
- The capture must include a transaction containing relevant data rather than only status polling.
- The data must be interpreted correctly (byte order, command boundaries, payload versus address fields).
- A **complete, valid digest** must be available before testing Hashcat in raw-MD5 mode.
- The password must be among the dictionary candidates for the wordlist-based recovery to succeed.

**Authorization:** Perform hardware monitoring and password testing only on hardware, accounts, and hashes you own or are explicitly authorized to assess. The example hash and password in this README are retained as research evidence; do not treat them as permission to access another device.

## 3. Scope, equipment, and evidence

### Tools visible or named in the supplied material

| Component / tool | Role | Evidence status |
| --- | --- | --- |
| Target with SPI flash/EEPROM traffic | Source of the captured serial transactions | SPI flash protocol is decoded; exact device and board model are not identified in these slides |
| Logic analyzer | Captures digital transitions | Implied by PulseView traces; analyzer hardware model is not stated |
| **PulseView** | Viewing waveforms and protocol-decoder output | Directly visible on slides 1–3 |
| SPI flash/EEPROM protocol decoder | Resolves `PP`, `RDSR`, address and data | Directly visible on slides 1–3 |
| Hexadecimal-to-ASCII converter | Displays bytes as text | Directly visible on slide 4 |
| **Kali Linux** | Analysis environment | Visible terminal on slides 6–7 |
| **`hashid`** | Suggests candidate digest formats | Visible on slide 6 |
| **Hashcat** | Offline dictionary-based digest comparison | Visible on slide 7 (`hashcat v7.1.2`) |
| `rockyou.txt` | Candidate-password dictionary | Explicitly shown in slide 7 command |

The PulseView screenshot's toolbar displays **24 MHz**. Without the native capture/configuration file, this is best described as the displayed acquisition setting, not an independently verified effective sampling rate. The precise SPI mode, line-to-channel map, target voltage, flash part number, and capture-file format are **not provided**.

### Original source artifacts

- `Attack_path__Password_sniffing.pptx` — 7 slides.
- `Attack_path__Password_sniffing(1).pdf` — 7 pages.

These two supplied artifacts depict substantially the same investigation. The PowerPoint's original embedded screenshots are included in [`assets/`](assets/) for transparent evidence review.

## 4. SPI flash fundamentals

SPI (Serial Peripheral Interface) is a synchronous serial bus frequently used between an embedded controller and a flash/EEPROM memory device.

| Signal | Typical meaning | Relevance to this analysis |
| --- | --- | --- |
| **SCLK** | Serial clock driven by controller | Defines sampling instants for bits |
| **MOSI / IO0** | Controller-to-peripheral data | Carries flash commands, addresses, and write data in a standard single-I/O transaction |
| **MISO / IO1** | Peripheral-to-controller data | Carries status or readback data |
| **CS# / SS#** | Active-low chip-select | Separates transactions and frames command boundaries |
| **GND** | Common reference | Required for correct, safe logic-analyzer measurement |

The source images show digital channels **D0–D7**, but **do not explicitly document which D-channel maps to which SPI signal**. That assignment must be confirmed from the original project wiring or PulseView decoder configuration; do not assume D0 is CLK or any other particular signal solely from the screenshot.

### Flash instructions identified in the trace

| Opcode | Conventional name | Function | Observed in the supplied slides |
| --- | --- | --- | --- |
| `0x06` | **WREN** — Write Enable | Permits a subsequent write/program operation on many SPI NOR flash devices | A standalone `06` transfer immediately preceding the documented program transaction on slide 3 |
| `0x02` | **PP** — Page Program | Programs data starting at a specified flash address | `02 00 01 30 ...` on slide 3, decoded as a program at `0x000130` |
| `0x05` | **RDSR** — Read Status Register | Requests device status information | Repeated transactions on slides 1–3 |

These meanings are conventional for many SPI NOR flash devices and align with the visible decoder labels. **Device-specific** bit definitions, page sizes, and exact command behavior require the target flash datasheet.

## 5. End-to-end workflow

| Stage | Input | Processing | Output |
| --- | --- | --- | --- |
| **Capture** | Electrical SPI activity | Logic analyzer records transitions | Digital traces |
| **Decode** | Digital traces | SPI and SPI flash/EEPROM protocol decoding in PulseView | Opcode, address, MOSI/MISO bytes |
| **Extract** | Page-program payload | Separate data from `0x02` command and three address bytes | 30 observed payload bytes |
| **Interpret** | Payload bytes | Convert hex-encoded byte values to ASCII | A 30-character fragment |
| **Reconcile** | 30-byte fragment + 31-character conversion screenshot + final Hashcat screenshot | Compare lengths and exact characters | Complete 32-character candidate MD5 digest recorded in final evidence |
| **Classify** | Full hexadecimal digest | Assess algorithm candidates with `hashid`; verify size/format | MD5 as a viable hypothesis |
| **Test** | Full digest + local wordlist | Hashcat offline dictionary comparison (`-m 0`) | Recovered demonstration password |
| **Validate** | Recovered password | Recalculate MD5 independently | Matching full digest |

## 6. Stage 1 — Capture and decode SPI traffic

![PulseView showing repeated SPI flash RDSR transactions](assets/01-status-register-reads.png)

*Figure 1 — Source: slide 1 / PDF page 1. PulseView identifies two `Read status register (RDSR)` commands in the displayed window.*

### Observations

The initial overview shows periods in which the monitored lines are relatively static and periods of repeated flash status-register reads. The decoder displays **`RDSR`**, and the MOSI transfer annotation in the screenshot is **`05 00 03 03`**, while the displayed MISO annotation is **`FF 03 03 00`** for the illustrated transactions.

The source's commentary interprets the behavior as a bus remaining idle because no other SPI slave/master provides input and describes recurring activity after a reset. **Those are original analyst interpretations, not conclusions established solely by the screenshots.** In particular:

- An SPI bus can be idle between perfectly valid transactions.
- Status-register polling may be normal during flash program/erase operations.
- Reading `0xFF` is not, by itself, sufficient proof of a disconnected slave.
- A reset event and the presence or absence of additional peripherals cannot be established without the device timeline, wiring, and fuller capture.

### How to inspect a comparable authorized capture

1. Attach a logic analyzer with a **shared ground** and voltage-compatible inputs to the relevant SPI lines of the test fixture.
2. Capture the clock, chip-select, and both data lines, ideally from before the triggering device activity until the bus settles.
3. Open the recording in PulseView and assign the correct channels to the SPI decoder.
4. Set the actual clock polarity/phase, word length, bit order, and chip-select behavior from the target's specification and waveform.
5. Add a flash/EEPROM decoder and inspect **transaction boundaries**, not just the raw data bytes.
6. Focus on transactions that write or read memory; status polling can provide useful context but usually does not itself contain a credential hash.

The screenshots do not provide a native PulseView capture, so independent redetection of edges, protocol mode, or decoder configuration is not possible from the evidence alone.

## 7. Stage 2 — Identify the page-program transaction

![PulseView SPI flash page-program payload](assets/02-spi-page-program.png)

*Figure 2 — Source: slide 3 / PDF page 3. The decoder labels a `Page program` operation at `0x000130` with **30 bytes** of data, followed by a status-register read.*

### Key decoded fields

| Field | Value visible in screenshot | Interpretation |
| --- | --- | --- |
| Preceding standalone opcode | `06` | Consistent with write-enable (`WREN`) |
| Program opcode | `02` | Standard page-program opcode |
| Address bytes | `00 01 30` | 24-bit address `0x000130` |
| Decoded payload length | **30 bytes** | Actual page-program data field shown by the decoder |
| Following opcode | `05` | Status-register read (`RDSR`) |

The complete MOSI frame for the page-program operation is of the form:

```text
02 | 00 01 30 | 31 39 32 30 32 33 61 37 62 62 64 37 33 32 35 30
   |          | 35 31 36 66 30 36 39 64 66 31 38 62 35 30
 │       │                            │
 │       │                            └─ 30 data bytes
 │       └─ 3-byte address = 0x000130
 └─ PP command (0x02)
```

**Extracted payload, 30 bytes:**

```text
31 39 32 30 32 33 61 37 62 62 64 37 33 32 35 30
35 31 36 66 30 36 39 64 66 31 38 62 35 30
```

Each of these bytes happens to be an ASCII code for a printable character. Decoding the **30-byte page-program payload** produces:

```text
192023a7bbd73250516f069df18b50
```

> **Length check:** The exact page-program payload on slide 3 contains **30** bytes and therefore decodes to **30** ASCII characters. Neither the leading `0` nor the last `0` of the eventual full MD5 string is proven to be in this **specific 30-byte payload**. The source's other screenshots provide additional characters, but not a raw capture showing how all 32 bytes were acquired.

### Why the address matters

The decoder places this write at **`0x000130`**, a concrete memory location that can be used to correlate an authorized flash dump or firmware analysis with the bus trace. It is not, by itself, proof that the contents are authentication material; that conclusion requires corroboration from memory layout, code references, or other device evidence.

## 8. Stage 3 — Convert the payload from hexadecimal to ASCII

![Hex to ASCII conversion screenshot showing 31 characters](assets/03-ascii-hex-conversion.png)

*Figure 3 — Source: slide 4 / PDF page 4. The manual conversion screen includes a **leading `0x30`** that is not part of the 30-byte program-data field in Figure 2.*

The conversion screenshot contains the following **31** input bytes:

```text
30 31 39 32 30 32 33 61 37 62 62 64 37 33 32 35
30 35 31 36 66 30 36 39 64 66 31 38 62 35 30
```

The output is:

```text
0192023a7bbd73250516f069df18b50
```

This is **31 characters**, not 32. The extra starting `0x30` corresponds to ASCII **`0`**. The screenshot's annotation correctly raises a question about the missing character.

![Statement in the provided material describing the 31-character text](assets/04-31-character-note.png)

*Figure 4 — Source: slide 5 / PDF page 5. An accompanying note describes writing this 31-character string starting at **`0x0001`**.*

**Address discrepancy:** The textual note in Figure 4 references **`0x0001`**, whereas the protocol decoder in Figure 2 reports a page-program transaction at **`0x000130`**. The slides do not explain whether the note refers to a separate operation, an illustrative example, or a mistaken address. The README preserves both values instead of silently treating them as equivalent.

### Comparing the evidence side by side

| Evidence | String | Length |
| --- | --- | ---: |
| Slide 3: 30-byte page-program payload, decoded as ASCII | `192023a7bbd73250516f069df18b50` | **30** |
| Slide 4/5: manually converted hex/ASCII text | `0192023a7bbd73250516f069df18b50` | **31** |
| Slide 7: Hashcat target / recovered digest | `0192023a7bbd73250516f069df18b500` | **32** |

The final digest has **one additional trailing `0`** relative to the 31-character conversion screenshot. That character is visible in the **Hashcat target**, but the supplied capture does not independently show where it came from.

## 9. Stage 4 — Identify and validate the candidate hash

![hashid candidate modes](assets/05-hashid-candidates.png)

*Figure 5 — Source: slide 6 / PDF page 6. `hashid -m hash.txt.save` lists multiple candidate hash types; MD5 (Hashcat mode 0) is highlighted as the candidate tested first.*

### Why MD5 was considered

A **32-character hexadecimal value** is structurally compatible with a **128-bit digest** such as raw MD5: `32 hex digits × 4 bits/digit = 128 bits`. That resemblance is a useful starting point, not proof of the algorithm. Multiple formats can have the same length and character set, which is why `hashid` displays many possibilities in the screenshot.

The final Hashcat screenshot provides this complete test digest:

```text
0192023a7bbd73250516f069df18b500
```

Its length is 32 hexadecimal characters, and it matches **the MD5 digest of `admin123`**. This can be checked independently without relying on the Hashcat wordlist result:

```python
import hashlib

candidate_password = "admin123"
expected_digest = "0192023a7bbd73250516f069df18b500"

observed = hashlib.md5(candidate_password.encode("utf-8")).hexdigest()
assert observed == expected_digest
print("MD5 verification passed:", observed)
```

Expected output:

```text
MD5 verification passed: 0192023a7bbd73250516f069df18b500
```

This proves that the demonstration password **hashes to the full digest** shown on slide 7. It does **not** independently prove that the target firmware uses raw MD5 for login verification; confirming that would require examining the authentication implementation or a relevant controlled device test.

## 10. Stage 5 — Perform the documented offline dictionary test

![Hashcat offline MD5 dictionary attack result](assets/06-hashcat-md5-recovery.png)

*Figure 6 — Source: slide 7 / PDF page 7. Hashcat reports `Status: Cracked`, `Hash.Mode: 0 (MD5)` and the digest–plaintext pair.*

### Command visible in the evidence

```bash
hashcat -m 0 hash.txt.save /usr/share/wordlists/rockyou.txt
```

Where:

- `hashcat`: password-hash analysis utility;
- `-m 0`: selects raw **MD5**;
- `hash.txt.save`: the local file containing the **full** digest;
- `/usr/share/wordlists/rockyou.txt`: the local candidate-password dictionary.

The captured output includes:

```text
0192023a7bbd73250516f069df18b500:admin123

Status...........: Cracked
Hash.Mode........: 0 (MD5)
```

### What the screenshot demonstrates

- **Hashcat version:** `v7.1.2` is visible in the terminal.
- **Compute device:** the displayed OpenCL/PoCL backend uses a **12th Gen Intel Core i5-1235U CPU**.
- **Wordlist:** `/usr/share/wordlists/rockyou.txt`, with **14,344,392** candidates reported in the dictionary cache.
- **Test result:** Hashcat found a matching candidate and marked the session **Cracked**.
- **Elapsed time:** the status block displays **0 seconds** as a rounded value for this particular run; it is not a dependable general cracking-time benchmark.

**Interpretation:** The demonstrated success depends on a known, easily guessed password being in the tested dictionary. It should **not** be generalized to strong passwords, memory-hard password hashes, or the claim that every MD5 digest can be recovered quickly.

## 11. Results and evidence summary

| Finding | Evidence | Confidence / scope |
| --- | --- | --- |
| PulseView decoded SPI flash/EEPROM transactions | Slides 1–3 | **Directly visible** |
| Repeated `RDSR` commands occur in the shown interval | Slides 1–2 | **Directly visible**; cause not fully established |
| A program operation targets `0x000130` | Slide 3 | **Directly visible in decoder output** |
| The program operation has 30 bytes of payload | Slide 3 | **Directly visible in decoder output** |
| Those 30 bytes form printable ASCII | Slide 3, independently decoded | **Validated byte conversion** |
| A 31-character related string was manually assembled | Slides 4–5 | **Directly visible**; first byte's provenance is not shown |
| A full 32-character candidate MD5 digest was supplied to Hashcat | Slide 7 | **Directly visible**; final character's SPI origin is not shown |
| The full digest matches `MD5("admin123")` | Slide 7 + independent digest calculation | **Validated mathematical match** |
| Hashcat recovered `admin123` using the `rockyou.txt` dictionary | Slide 7 | **Directly visible** |
| The device's login mechanism accepts this password | Not shown | **Not established** |
| A slave was disconnected or the SPI bus was truly nonresponsive | Original commentary only | **Not established** |

### Main outcome

The evidence supports a working example of **recovering a weak password from a known MD5 hash through an offline dictionary attack**. The hardware trace is important because it shows a **candidate source of credential-like text on an observable SPI flash write bus**. However, the trace fragment is shorter than the final hash; treating the SPI capture as a complete standalone extraction would overstate what the slides demonstrate.

## 12. Critical observations and limitations

### 12.1 The 30 / 31 / 32-character issue

This is the most significant evidence gap:

1. The SPI **page-program data field** contains exactly **30 bytes**.
2. The subsequent converter uses **31 bytes**, adding an initial `0x30` (`0`).
3. The final Hashcat target contains **32 hex characters**, with one more trailing `0`.

To attribute the **entire** MD5 hash to the device, the investigation should identify where the missing bytes were read or written, or confirm them from an independently acquired full flash dump. Avoid describing them as observed in the 30-byte transaction when they are not.

### 12.2 Memory-address mismatch

The decoder states **`0x000130`**, while slide 5 states **`0x0001`**. Both are preserved verbatim. An original capture, annotated memory map, or flash dump can resolve the difference.

### 12.3 Read-versus-write distinction

Figure 2 shows a **Page Program** operation, i.e., data being **written to flash**, rather than a memory read returning that data to the controller. It is still possible to observe sensitive values on MOSI during an insecure write operation, but the description should not say the hash was read from flash in this captured transaction.

### 12.4 Unknown device, connection and execution context

The files do not establish:

- Target board or flash part number;
- Precise analyzer channel-to-pin mapping;
- Supply voltage, SPI mode, or signal integrity checks;
- Whether the page write is associated with provisioning, authentication, or another feature;
- Whether the final digest is stored or used for live authentication;
- Whether an actual reset occurred at the point described in slide 2;
- Whether the bus was connected to one or several peripherals;
- A native capture file or complete SPI transaction log.

### 12.5 No demonstrated live-device compromise

The terminal output proves the **offline digest-to-password match**. It does not show successful device login, privilege escalation, remote access, firmware modification, or a subsequent application exploit. Those should not be claimed in a project description without separate evidence.

## 13. Security implications and mitigations

### What this case illustrates

An accessible embedded memory bus can reveal information that developers may have assumed was hidden inside a device. **ASCII-encoded hash strings** are particularly easy to recognize in a decoded memory transaction. If passwords are protected only by **unsalted, fast hashes** such as raw MD5 and users choose predictable passwords, a captured or dumped digest may be susceptible to offline dictionary testing.

### Recommended defensive measures

| Risk | Suggested mitigation |
| --- | --- |
| Credential-related data exposed on physical serial buses | Reassess the requirement to persist credentials; protect sensitive storage and hardware interfaces, with platform-supported encryption and key protection where available |
| Raw MD5 or other fast, unsalted password hashes | Use a suitable **salted, deliberately expensive password-hashing algorithm**, such as Argon2id (or a supported equivalent), when the platform and authentication architecture allow |
| Default or weak passwords | Use unique, high-entropy device credentials; require credential changes where appropriate; avoid universal shared secrets |
| Easy access to flash, debug, or probe pins | Control physical access, review test-point exposure, and apply documented debug/production locks as appropriate |
| Firmware integrity and credential handling gaps | Use secure boot / verified updates and review credential lifecycle and provisioning procedures where supported |
| Misinterpretation of partial bus captures | Retain raw captures, record pin mappings and decoder settings, and correlate with flash dumps and firmware logic |

**Platform caveat:** Password hashing, flash encryption, secure boot, secure elements, and anti-tamper controls depend on the specific embedded hardware. They should be selected from the device's actual capabilities and threat model, not assumed to be present here.

## 14. Reproducing the analysis

These steps replicate the **analysis and offline validation** of the supplied demonstration on a system and data you are authorized to test. The original hardware capture **cannot** be regenerated from the screenshots alone.

### 14.1 Basic software requirements

- Python 3 for byte and digest validation;
- PulseView and a compatible logic analyzer to collect **new** hardware captures;
- `hashid` and Hashcat for local hash-format exploration and offline tests;
- An appropriately licensed local test wordlist, if performing the dictionary step.

No exact dependency versions other than the screenshot's Hashcat version are established by the supplied files.

### 14.2 Validate the observed SPI payload

```python
# Save as verify_payload.py, or paste into a local Python REPL.
spi_payload_hex = (
    "31 39 32 30 32 33 61 37 62 62 64 37 33 32 35 30 "
    "35 31 36 66 30 36 39 64 66 31 38 62 35 30"
)

payload = bytes.fromhex(spi_payload_hex)
text = payload.decode("ascii")

assert len(payload) == 30
assert text == "192023a7bbd73250516f069df18b50"

print(f"Program data: {len(payload)} bytes")
print(f"ASCII: {text}")
```

Expected output:

```text
Program data: 30 bytes
ASCII: 192023a7bbd73250516f069df18b50
```

### 14.3 Validate all three observed strings

```python
import hashlib

program_ascii = "192023a7bbd73250516f069df18b50"    # 30 chars, slide 3
manual_ascii  = "0192023a7bbd73250516f069df18b50"   # 31 chars, slide 4
full_digest   = "0192023a7bbd73250516f069df18b500" # 32 chars, slide 7

assert len(program_ascii) == 30
assert len(manual_ascii) == 31
assert len(full_digest) == 32
assert full_digest[1:31] == program_ascii
assert full_digest[:31] == manual_ascii
assert hashlib.md5(b"admin123").hexdigest() == full_digest
print("All byte counts and the demonstration MD5 match are verified.")
```

### 14.4 Run the same offline Hashcat test on the known demonstration digest

Create a **local test file** containing the *full* 32-character hash:

```bash
printf '%s\n' '0192023a7bbd73250516f069df18b500' > hash.txt.save
```

Identify likely formats (candidate identification only):

```bash
hashid -m hash.txt.save
```

Repeat the recorded dictionary test, **only against this authorized test hash**:

```bash
hashcat -m 0 hash.txt.save /usr/share/wordlists/rockyou.txt
```

Show any recovered test result for that file:

```bash
hashcat -m 0 --show hash.txt.save
```

The wordlist path is the one shown in the supplied Kali Linux terminal. It may not exist on every installation. The success condition is an offline match to the known demonstration digest; it is **not** a device login.

### 14.5 For a new capture, preserve sufficient evidence

Record at least:

- Device and flash identifiers, board revision, and capture date;
- Probe connection diagram and voltage compatibility;
- SCLK, MOSI, MISO and CS# channel assignment;
- Analyzer sample rate, trigger, SPI mode and decoder settings;
- Native capture file and an exported transaction log (including command, address, direction and bytes);
- Exact raw bytes **before** ASCII interpretation;
- Evidence establishing the provenance of **all** digest characters;
- A reproducible, authorized validation procedure and any environmental restrictions.

## 15. Troubleshooting and further investigation

| Problem / question | What to check |
| --- | --- |
| Decoder shows nonsense bytes | Verify CS# polarity, channel assignment, sample rate, SPI mode and clock edges |
| MISO is consistently `FF` | Check the target's electrical levels, chip-select, power, wiring, expected idle state and transaction context; do not assume “no slave” |
| Captured content looks like text but is too short | Inspect neighboring write transactions, record boundaries, address continuity, and any corroborating flash dump |
| `hashid` reports multiple candidates | Treat output as suggestions; validate with application context, hash structure, and controlled known inputs |
| Hashcat rejects the candidate hash | Confirm the complete correct number of hex characters and line formatting, and use an appropriate mode |
| Hashcat returns no match | The candidate may be wrong or absent from the wordlist; this does **not** prove the digest is incorrect |
| Slide 5 address does not match slide 3 | Confirm whether `0x0001` is merely a note/example and inspect the original `0x000130` transaction |
| Password recovery succeeds but device login does not | The digest may relate to another purpose or authentication may have other checks; do not claim device compromise without evidence |

### Priority next steps

1. **Recover the native PulseView capture** or original exported transaction data, if available.
2. **Trace the byte immediately before and after** the 30-byte payload to explain the transition to the 31- and 32-character strings.
3. **Reconcile `0x0001` versus `0x000130`** against the original flash transaction and memory map.
4. **Identify the flash and board** and document the signal mapping and device-specific status bits.
5. **Correlate the candidate digest** with a flash dump or firmware authentication routine, using only authorized access.
6. **Retest after mitigation** to determine whether a credential hash remains observable and whether weak password hashing has been removed.

## 16. Repository structure and source attribution

### Suggested directory layout

```text
SPI_Password_Sniffing_README/
├── README.md
└── assets/
    ├── 01-status-register-reads.png
    ├── 02-spi-page-program.png
    ├── 03-ascii-hex-conversion.png
    ├── 04-31-character-note.png
    ├── 05-hashid-candidates.png
    └── 06-hashcat-md5-recovery.png
```

The images are extracted **without recreating or modifying the underlying evidence** from the provided PowerPoint slides. Captions and interpretations are editorial additions in this README.

### Evidence-to-section map

| Source location | Subject | Primary README sections |
| --- | --- | --- |
| Slide 1 / PDF p. 1 | PulseView overview; repeated RDSR | §§ 4, 6 |
| Slide 2 / PDF p. 2 | Commentary about constant/reset-related and idle portions | §§ 6, 12 |
| Slide 3 / PDF p. 3 | WREN, page program at `0x000130`, 30-byte data, RDSR | §§ 7–8 |
| Slide 4 / PDF p. 4 | Hex-to-ASCII conversion; 31-character result | § 8 |
| Slide 5 / PDF p. 5 | Note describing 31-character string and address `0x0001` | §§ 8, 12 |
| Slide 6 / PDF p. 6 | `hashid` candidate algorithms | § 9 |
| Slide 7 / PDF p. 7 | Hashcat dictionary test; MD5 digest and `admin123` | §§ 9–11 |

### Evidence provenance and editorial standards

Statements labeled **directly visible** come from the screenshots or slide text. The independent MD5 check and byte-count comparisons are **reproducible analysis** performed from displayed values. General SPI principles and defensive recommendations provide explanatory context, not additional claimed observations about the unknown target device.

---

**Project takeaway:** A hardware bus trace exposed credential-like ASCII data associated with an SPI flash page-program operation, and the supplied offline Hashcat run successfully recovered `admin123` from a full raw-MD5 digest. The most important remaining validation is to establish **where all 32 digest characters originated** and whether this digest was actually used for the device's authentication process.
