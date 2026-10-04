# Forense-Framework

**Windows-focused digital forensics framework** with case management, a verifiable chain of custody, artifact
analysis modules, a super-timeline, a web interface and CLI, and forensic reports in **Spanish and English**.

> 🇪🇸 Versión en español: [README.md](README.md)

```
forense demo ./lab          # builds a fictitious intrusion scenario and analyses it
forense web -w ./lab        # open http://127.0.0.1:8765
```

## Principles

| Principle | How |
|---|---|
| **Evidence is never modified** | Everything is opened read-only. `--copy` works on a hash-verified, read-only working copy. SQLite databases (browsers) are copied to a temporary folder before being opened. |
| **Hash identification** | Every evidence item gets MD5, SHA-1 and SHA-256. Directories are hashed through a sorted manifest of all their files. |
| **Tamper-evident chain of custody** | Every action (evidence added, verification, analysis, export, report, deletion) is stored in a SHA-256 hash-chained log. |
| **Verifiable results** | Each analysis stores the SHA-256 of all of its results. `forense verify` re-checks evidence, custody and results. |
| **Reproducibility** | Module, options, evidence, analyst and UTC time are recorded for every run. |
| **Findings are leads** | Detections state the rule that fired; the analyst confirms them against the source records. |

Methodology references: RFC 3227, ISO/IEC 27037, ISO/IEC 27042, UNE 71506.

## Installation

Python **3.10+** on Windows, Linux or macOS. Dependencies: `evtx` (Rust EVTX parser, prebuilt wheels) and `Flask`.

```powershell
git clone https://github.com/Ruby570bocadito/Forense-Framework.git
cd Forense-Framework
py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1      # Linux/macOS: python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

Language: `-L es|en` anywhere on the command line, the `FORENSE_LANG` variable, or the system locale.

## CLI

Every command has an English name and a Spanish alias.

| Command | Purpose |
|---|---|
| `forense new DIR -n NAME -i INVESTIGATOR [-r REF] [-o ORG]` | Create a case |
| `forense -c CASE evidence add PATH [--copy] [-d DESC]` | Register evidence (hashes it) |
| `forense -c CASE evidence list` / `evidence verify [ID]` | List / verify evidence |
| `forense modules` | Available modules and options |
| `forense -c CASE triage EV-001` | Run every module that finds artifacts |
| `forense -c CASE analyze MODULE EV-001 [-o key=value]` | Run one module (`all` = every evidence item) |
| `forense -c CASE analyses` / `show N [--artifact X]` | Analyses and their records |
| `forense -c CASE findings [--min-severity high]` | Findings by severity |
| `forense -c CASE timeline [--from] [--to] [--search] [--source]` | Super-timeline |
| `forense -c CASE export {analysis N,timeline,findings,custody} -o FILE` | CSV (Excel-friendly) or JSON |
| `forense -c CASE custody [--verify]` | Chain of custody |
| `forense -c CASE verify` | Full integrity check (exit code 2 on failure) |
| `forense -c CASE report [--verify] [-L es]` | Self-contained HTML report |
| `forense web [-w WORKSPACE] [--port 8765] [--password X]` | Web interface |

## Web interface

Workspace with all cases, dashboard, evidence registration and verification (background jobs), module runner with
per-module options, one-click triage, paginated and searchable results, findings, filterable timeline, chain of custody,
reports in either language, CSV/JSON exports, ES/EN switch and an *Analyst* field recorded in the custody chain.
It listens on `127.0.0.1` by default, uses CSRF tokens and security headers, and supports a password (`--password`).

## Modules

| Module | Artifacts | Detects |
|---|---|---|
| `evtx` | `*.evtx` (Security, System, PowerShell, Sysmon, Defender, RDP, TaskScheduler, WMI, BITS) | Brute force and **logon after brute force**, log clearing, user creation and privileged group changes, services and scheduled tasks, suspicious command lines, malicious PowerShell, Defender detections/tampering, WMI persistence, RDP from public IPs |
| `registry` | SYSTEM, SOFTWARE, SAM, NTUSER.DAT, Amcache.hve | Host profile, time zone, network, **USB devices**, services, **ShimCache**, **BAM**, OS install, programs, network profiles, **Run keys**, Winlogon, **IFEO**, AppInit_DLLs, SAM accounts, **UserAssist**, RecentDocs, RunMRU, TypedPaths, searches, RDP destinations, Amcache SHA-1 |
| `lnk` | `*.lnk`, `*.customDestinations-ms` | Opened files, network paths, **removable media** (volume serial/label), source machine and **MAC**, Startup persistence |
| `recyclebin` | `$Recycle.Bin\<SID>\$I*` | Original path, size, deletion time, user, recoverable content |
| `browsers` | Chrome, Edge, Brave, Opera, Firefox | History, downloads, executable downloads, paste/file-sharing services |
| `mft` | `$MFT` | $SI/$FN timeline, deleted entries, full paths, **Zone.Identifier** download URLs, **timestomping** |
| `inventory` | Any folder | Metadata, hashes, real type by signature, **disguised files**, Sleuth Kit bodyfile |
| `ioc` | Any file | ASCII/UTF-16 strings, URLs, IPs, e-mails, registry keys, watchlist (`-o watchlist=`) |
| `hashset` | Any folder | MD5/SHA-1/SHA-256 hash list matches (`-o hash_list=`) |
| `carving` | Raw image | JPEG, PNG, GIF, PDF and ZIP recovered with structural validation |

## What to analyse

Folders and files: triage collections (KAPE `KapeTriage`, Velociraptor, CyLR), images mounted read-only (Arsenal Image
Mounter, `ewfmount`, FTK Imager), or individual artifacts (an `.evtx`, a hive, an exported `$MFT`, a `dd` image for
carving).

## Known limitations

Registry transaction logs are not replayed (dirty hives are flagged); E01 images and in-image file systems are not
parsed (mount them first); `$ATTRIBUTE_LIST` extension records are not merged; carving only recovers contiguous files;
`NetworkList` dates are shown in local time; detections are heuristic leads; the web server is Flask's built-in one,
meant for local use.

## Roadmap

Prefetch (with Windows 10/11 Xpress Huffman decompression), SRUM, ShellBags and automatic Jump Lists; E01/VMDK and
NTFS without mounting; registry transaction log replay; YARA and Sigma; memory (Volatility 3); signed reports and PDF
export; Linux/macOS as analysed systems.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
ruff check forense tests
```

CI runs on Linux and Windows with Python 3.10 and 3.12, plus an end-to-end demo run.
