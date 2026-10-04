# Forense-Framework

**Windows-focused digital forensics framework**: case management, verifiable chain of custody, E01/raw disk images,
live collection, artifact and memory analysis, Sigma and YARA rules, super timeline, analyst review, web UI and CLI,
and expert reports in **English and Spanish**.

> 🇪🇸 Versión en español: [README.md](README.md)

```
forense demo ./lab          # creates a fictitious intrusion scenario and analyses it
forense web -w ./lab        # open http://127.0.0.1:8765
```

---

## Contents

1. [Principles](#principles)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [CLI workflow](#cli-workflow)
5. [Disk images and live collection](#disk-images-and-live-collection)
6. [Memory](#memory)
7. [Analyst review](#analyst-review)
8. [Web interface](#web-interface)
9. [Analysis modules](#analysis-modules)
10. [Sigma and YARA rules](#sigma-and-yara-rules)
11. [Integrity and chain of custody](#integrity-and-chain-of-custody)
12. [Architecture and writing a module](#architecture-and-writing-a-module)
13. [Known limitations](#known-limitations)
14. [Roadmap](#roadmap)
15. [Development](#development)
16. [License](#license)

## Principles

| Principle | How it is enforced |
|---|---|
| **Evidence is never modified** | Everything is opened read-only. With `--copy` the work is done on a hash-verified, read-only working copy. Disk images are read without mounting them. SQLite databases (browsers) are copied to a temporary folder before being opened. |
| **Identification by hash** | Every evidence item is registered with MD5, SHA-1 and SHA-256. Directories are hashed through a sorted manifest of all their files, so any addition, removal, rename or change alters it. |
| **Tamper-evident chain of custody** | Every action (evidence registration, derived evidence, verification, analysis, review, export, report, deletion) is written to a SHA-256 hash chain. Altering an entry breaks the chain. |
| **Verifiable results** | Each analysis stores the SHA-256 of all its results. `forense verify` recomputes evidence, custody and result hashes. |
| **Traceable derived data** | Whatever is extracted from an image is registered as derived evidence, with its own hash and linked to the image and to the analysis that produced it. |
| **Reproducibility** | The module, options, evidence, analyst and time (UTC) of each run are recorded. The output of external tools (Volatility) is kept verbatim. |
| **Findings ≠ conclusions** | Detections are leads that name the rule that fired. The analyst confirms or dismisses them and writes the report conclusions. |

Methodological references: RFC 3227, ISO/IEC 27037, ISO/IEC 27042 and UNE 71506.

## Installation

Requirements: **Python 3.10 or later** (Windows, Linux or macOS). Every dependency ships prebuilt binaries for
Windows, Linux and macOS: `evtx` (EVTX), `Flask` (web and reports), `PyYAML` (Sigma), `olefile` (Jump Lists),
`libscca-python` (Prefetch), `libesedb-python` (SRUM), `libewf-python` (E01), `pytsk3` (NTFS, The Sleuth Kit) and
`yara-x` (YARA).

**Windows (PowerShell):**

```powershell
git clone https://github.com/Ruby570bocadito/Forense-Framework.git
cd Forense-Framework
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .                 # use ".[memory]" to also install Volatility 3
forense --version
```

**Linux / macOS:**

```bash
git clone https://github.com/Ruby570bocadito/Forense-Framework.git
cd Forense-Framework
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[memory]"
```

The language is chosen with `-L en|es` (anywhere on the command line), the `FORENSE_LANG` variable or, failing both,
the system locale.

## Quick start

```bash
forense demo ./lab -a "Your name"
```

This generates a **fictitious** scenario: the compromised workstation `WS-CONTAB01`. It contains a triage collection
(hives, `$MFT`, Prefetch, ShellBags, shell links, Recycle Bin, Chrome/Firefox history…), a raw image for carving, the
workstation memory (Volatility 3 outputs), a known-bad hash list, an IOC list and a YARA rule. It then creates the
case `lab/case_demo`, registers the three evidence items, runs triage and the intelligence modules and produces more
than 40 findings: an IFEO debugger on `sethc.exe`, timestomping, `Run` key persistence, a service in
`C:\Windows\Temp`, mimikatz and rclone execution, a fake `svchost.exe` talking to the Internet, a hidden process,
code injected into `explorer.exe`, a USB drive and deleted files.

```bash
forense -c lab/case_demo findings
forense -c lab/case_demo timeline --from 2026-09-14T02:00 --to 2026-09-14T05:00
forense -c lab/case_demo report -L en
forense web -w lab
```

## CLI workflow

Every command has an English name and a Spanish alias.

| English | Spanish | Purpose |
|---|---|---|
| `forense new DIR -n NAME -i INVESTIGATOR [-r REFERENCE] [-o ORGANIZATION]` | `nuevo` | Create a case |
| `forense -c CASE info` | `info` | Case summary |
| `forense -c CASE evidence add PATH [--copy] [-d DESCRIPTION]` | `evidencia agregar` | Register evidence (computes hashes) |
| `forense -c CASE evidence list` / `verify [ID]` | `listar` / `verificar` | List evidence or verify its integrity |
| `forense modules` | `modulos` | Available modules and their options |
| `forense -c CASE triage EV-001` | `triaje` | Run every module that finds artifacts (images are extracted first) |
| `forense -c CASE image EV-001 [--verify] [-p PATTERN] [--all-files] [--triage]` | `imagen` | Extract the artifacts of an E01/raw/VHD image as derived evidence |
| `forense collect DEST [--source \\.\C:] [--volatile] [--add-to-case]` | `recolectar` | Live collection on Windows |
| `forense -c CASE analyze MODULE EV-001 [-o key=value]` | `analizar` | Run one module (`all` = every evidence item) |
| `forense -c CASE analyses` / `show N [--artifact X]` | `analisis` / `mostrar` | Analyses and their records |
| `forense -c CASE findings [--min-severity high] [--status confirmed]` | `hallazgos` | Findings sorted by severity, with their review status |
| `forense -c CASE review N confirmed\|false_positive\|needs_review [-n NOTE]` | `revisar` | Review a finding |
| `forense -c CASE bookmark N [-n NOTE] [--remove]` | `destacar` | Bookmark a timeline event |
| `forense -c CASE conclusions [--text T \| --file F]` | `conclusiones` | Show or write the (versioned) conclusions |
| `forense -c CASE timeline [--from] [--to] [--search] [--source] [--bookmarked]` | `cronologia` | Super timeline |
| `forense -c CASE export {analysis N,timeline,findings,custody} -o FILE` | `exportar` | CSV (Excel friendly) or JSON |
| `forense -c CASE custody [--verify]` | `custodia` | Chain of custody |
| `forense -c CASE verify` | `verificar` | Full verification (exit code 2 if anything fails) |
| `forense -c CASE report [--verify] [-L es]` | `informe` | Self-contained HTML report |
| `forense sigma check PATH` / `sigma download DIR` | `sigma` | Validate Sigma rules or download SigmaHQ's |
| `forense web [-w WORKSPACE] [--port 8765] [--password X]` | `web` | Web interface |

Common options: `-c/--case` (or the `FORENSE_CASE` variable), `-a/--analyst` (who appears in the custody log) and
`-L/--lang`.

Full example (PowerShell):

```powershell
forense new ./2026-017 -n "File server intrusion" -i "R. Garcia" -r "CASE-2026/017"
forense -c ./2026-017 evidence add E:\acquisitions\FS01.E01 -d "FS01 disk (FTK Imager)"
forense -c ./2026-017 image EV-001 --verify --triage
forense -c ./2026-017 evidence add E:\acquisitions\FS01.mem -d "FS01 memory"
forense -c ./2026-017 analyze memory EV-003
forense -c ./2026-017 analyze hashset EV-002 -o hash_list=C:\intel\malware_sha256.txt
forense -c ./2026-017 analyze yara EV-002 -o rules=C:\intel\yara
forense -c ./2026-017 findings --min-severity medium
forense -c ./2026-017 review 12 confirmed -n "Matches 4688 on the domain controller"
forense -c ./2026-017 conclusions --file conclusions.md
forense -c ./2026-017 report --verify
```

## Disk images and live collection

### Images

Formats: **E01/Ex01** (EnCase, FTK Imager, ewfacquire), **raw/dd**, **split raw** (`.001`, `.002`…) and **fixed VHD**.
MBR/GPT partitions and file systems are read with The Sleuth Kit **without mounting anything**, so locked files
(`$MFT`, hives, SRUM, EVTX) are obtained as well.

```bash
forense -c CASE evidence add laptop.E01
forense -c CASE image EV-001 --verify          # checks the acquisition MD5/SHA-1, then extracts
forense -c CASE triage EV-002                  # EV-002 = extracted artifacts (derived evidence)
```

- `--verify` recomputes the media hashes and compares them with those stored in the E01; a mismatch is a critical
  finding.
- By default the **Windows triage profile** is extracted (hives and their `.LOG` files, `$MFT`, EVTX, SRUM, tasks,
  Prefetch, Amcache, `setupapi`, NTUSER/UsrClass, Recent, Startup, PowerShell and browser history, `$Recycle.Bin`,
  executables in temporary folders). `-p "Users/*/Desktop/**"` adds patterns and `--all-files` extracts everything.
- Every NTFS volume is written to `C/`, `D/`… keeping modification times, and each extracted file is recorded with
  its original path, size, MD5, SHA-256, MACB times and MFT entry number.
- `triage` on an image does the extraction automatically.

### Live collection

On a running Windows system (as administrator), `collect` reads the **raw volume** (`\\.\C:`) with The Sleuth Kit to
copy locked artifacts, without relying on VSS or external tools:

```powershell
forense collect E:\collection_PC01 --volatile
forense -c E:\case collect E:\collection_PC01 --add-to-case --copy
```

- It copies the same triage profile to `DEST\C\…` and writes `manifest.csv` (path, size, SHA-256, MD5, times and MFT
  entry of every file) and `collection.json` (host, user, tool, start and end, manifest SHA-256 and errors).
- `--volatile` also saves processes, services, connections (`netstat -anob`), network configuration, DNS cache, ARP,
  routes, sessions, shares, scheduled tasks and `systeminfo`.
- `--source` accepts another volume or an image. Capture RAM with a dedicated tool (WinPmem, DumpIt, Magnet RAM
  Capture) **before** collecting from disk, following the order of volatility.

## Memory

The `memory` module analyses Windows memory dumps with **Volatility 3**: `info`, `pslist`, `psscan`, `pstree`,
`cmdline`, `netscan`, `malfind` and `svcscan`.

```bash
pip install -e ".[memory]"
forense -c CASE evidence add PC01.raw
forense -c CASE analyze memory EV-003                        # downloads Microsoft symbols when needed
forense -c CASE analyze memory EV-003 -o symbols=D:\symbols -o offline=yes -o plugins=pslist,psscan,netscan
```

- Volatility runs as a separate process and its JSON output is kept verbatim in the analysis folder.
- If you already ran Volatility (`vol -r json -f mem.raw windows.pslist > pslist.json`), register the folder with the
  JSON files and they are **imported** directly (the file name must contain the plugin name).
- Detects: **hidden processes** (in `psscan` but not in `pslist`), **unexpected parents** of system processes
  (`lsass.exe`, `services.exe`, `svchost.exe`…), duplicated instances, interpreters spawned by Office or services
  (WMI, IIS, SQL Server), **impersonation** (`svchost.exe` outside `System32`) and look-alike names (`scvhost.exe`),
  offensive and remote-access tools (also with the name truncated to 15 characters), suspicious command lines,
  **external connections** from interpreters or processes in suspicious locations, **injected code** (`malfind`,
  more severe with a PE header and less in JIT processes) and suspicious services.

## Analyst review

Findings are leads. Each one can be marked **confirmed**, **false positive** or **needs review** with a note, and key
timeline events can be **bookmarked**. Everything is kept in an append-only history and in the chain of custody,
with who and when.

The case **conclusions** are written by the analyst (free text, versioned). The report includes them together with
the findings grouped by review status and the bookmarked events.

## Web interface

```bash
forense web -w ./cases            # http://127.0.0.1:8765
```

- **Workspace**: list of cases and new-case form.
- **Overview**: indicators, relevant findings, evidence and one-click triage (disk images included).
- **Evidence**: registration by path (hashed in the background), hashes, origin of derived evidence and integrity
  verification.
- **Analyses**: per-module form with its options, automatic triage, paginated results with per-artifact search and
  CSV export.
- **Findings** with review (confirm, dismiss, note), **Timeline** (date, text, source, severity and bookmark filters),
  **Conclusions**, **Chain of custody** and **Reports** (in the language you choose).
- **ES/EN** selector and **Analyst** field: the name is recorded in every custody action.

Security: listens on `127.0.0.1` by default, every form carries a CSRF token, security headers (CSP,
`X-Frame-Options`) are sent and a password can be required with `--password` (HTTP Basic). If you expose it on a
network, put it behind HTTPS.

## Analysis modules

| Module | Artifacts | Detects |
|---|---|---|
| `evtx` | `*.evtx` (Security, System, PowerShell, Sysmon, Defender, RDP, TaskScheduler, WMI, BITS) | Brute force and **logon after brute force**, log clearing (1102/104), new users and privileged group changes, services (7045/4697) and tasks created, suspicious commands (4688/Sysmon 1), malicious PowerShell (4104), Defender detections and tampering, WMI persistence, RDP from public IPs and **Sigma rules** |
| `registry` | SYSTEM, SOFTWARE, SAM, NTUSER.DAT, Amcache.hve | Computer, time zone, network, **USB** (first/last connection), services, **ShimCache**, **BAM**, OS and install, installed programs, network profiles, **Run/RunOnce**, Winlogon, **IFEO**, AppInit_DLLs, SAM accounts, **UserAssist**, RecentDocs, RunMRU, TypedPaths, searches, RDP destinations, Amcache with SHA-1 |
| `prefetch` | `*.pf` (XP to Windows 11, compressed format included) | Program execution: run count, last 8 run times, volume and loaded files; offensive tools and execution from suspicious locations |
| `srum` | `SRUDB.dat` | Bytes sent and received per application and user, connectivity, CPU/disk usage; **possible exfiltration** |
| `shellbags` | `UsrClass.dat`, `NTUSER.DAT` | Folders browsed, including USB, network and already deleted folders |
| `jumplists` | `*.automaticDestinations-ms`, `*.customDestinations-ms` | Files opened per application, RDP connections, removable drives, suspicious arguments |
| `lnk` | `*.lnk` | Opened files, network paths, **removable drives** (serial and label), source machine and **MAC**, Startup folder persistence |
| `recyclebin` | `$Recycle.Bin\<SID>\$I*` | Original path, size, deletion time, user and whether the content (`$R`) is recoverable |
| `browsers` | Chrome, Edge, Brave, Opera (`History`), Firefox (`places.sqlite`) | History, downloads, **downloaded executables**, file-sharing and paste services |
| `mft` | `$MFT` | $SI/$FN timeline, deleted entries, full paths, **Zone.Identifier** (download URL), **timestomping** |
| `memory` | Memory dump or Volatility 3 JSON outputs | See [Memory](#memory) |
| `image` | E01/Ex01, raw, split raw, fixed VHD | See [Disk images](#disk-images-and-live-collection) |
| `inventory` | Any folder | Metadata, hashes, real type by signature, **disguised files**, timeline and Sleuth Kit compatible *bodyfile* (`mactime`) |
| `ioc` | Any file | ASCII/UTF-16 strings, URLs, IPs, e-mails, registry keys and watchlist (`-o watchlist=`) |
| `hashset` | Any folder | Matches against MD5/SHA-1/SHA-256 hash lists (`-o hash_list=`) |
| `yara` | Any folder | YARA rule matches (`-o rules=`), with the severity given by the rule |
| `carving` | Raw image / unallocated space | Recovers JPEG, PNG, GIF, PDF and ZIP, validating their internal structure |

The Windows modules and `inventory` run during **triage** when they find artifacts (`memory` does not, as it can be
slow). Severities: critical, high, medium, low and info.

What can be registered as evidence:

- **Disk images** (E01, raw, fixed VHD) and **memory dumps**.
- **Triage collections**: the one made by `forense collect`, [KAPE](https://www.kroll.com/kape) (`KapeTriage`
  target), Velociraptor or CyLR. Register the whole folder.
- **Images mounted read-only** (Arsenal Image Mounter, `ewfmount`).
- **Loose artifacts**: an `.evtx`, a hive, an `$MFT`, an `SRUDB.dat`, a Prefetch folder…

## Sigma and YARA rules

**Sigma**: the `evtx` module applies 15 built-in rules (Office spawning a shell, LSASS access, Kerberoasting, DCSync,
PsExec, pass-the-hash, shadow copy deletion…) plus the ones you provide:

```bash
forense sigma download ./sigma                 # SigmaHQ Windows rules
forense sigma check ./sigma                    # how many are supported
forense -c CASE analyze evtx EV-001 -o sigma_rules=./sigma -o sigma_min_level=high
```

The engine supports selections, keywords, wildcards, the usual modifiers (`contains`, `startswith`, `endswith`,
`all`, `re`, `windash`, `cidr`, `base64`, `base64offset`, `wide`, `exists`, comparisons, `fieldref`) and conditions
(`and`, `or`, `not`, parentheses, `1 of`, `all of`, `them`). `process_creation` is evaluated on Sysmon 1 and on
Security 4688.

**YARA** (YARA-X engine): `forense -c CASE analyze yara EV-002 -o rules=C:\intel\yara`. The finding severity comes
from the rule's `severity` metadata.

## Integrity and chain of custody

```
custody(seq, timestamp, action, actor, details, prev_hash, hash)
hash = SHA-256(canonical JSON of {seq, timestamp, action, actor, details, prev_hash})
```

- `forense -c CASE custody --verify` detects modified, deleted or reordered entries.
- The **head hash** (that of the last entry) is shown in the report and by `custody`. Write it down outside the case
  (in the minutes, an e-mail or the case file) to anchor the chain: not even someone rewriting the whole database can
  then hide tampering.
- Every report and export records its own SHA-256 in the chain.
- Derived evidence records which evidence and which analysis it comes from.

Case layout:

```
case/
├── forense.db     SQLite (WAL): case, evidence, custody, results, events, findings and reviews
├── evidence/      verified read-only working copies (--copy)
├── analyses/      generated files (extracted artifacts, Volatility outputs, carving, bodyfile…)
├── reports/       HTML reports
└── exports/       CSV/JSON exports
```

## Architecture and writing a module

```
forense/
├── core/        case (SQLite), review, custody, hashing, signatures, heuristics, exports
├── parsers/     regf, lnk, $I, $MFT, ShimCache, EVTX, SRUM, shell items, Jump Lists, Volatility
├── image/       disk images (libewf + The Sleuth Kit) and pattern-based extractor
├── sigma/       Sigma engine and built-in rules
├── modules/     windows/ (evtx, registry, prefetch, srum, shellbags, jumplists, lnk, recyclebin, browsers, mft, memory)
│                generic/ (image, inventory, ioc, hashset, yara, carving)
├── collector.py live collection
├── report/      HTML report (Jinja2)
├── web/         Flask interface (templates, static files, background jobs)
├── demo/        demo scenario and synthetic artifact builders
├── locales/     es.json / en.json
└── cli.py
```

Data is stored with language-neutral codes (`evtx.log_cleared`, `usb_device`, `program_executed`…) and translated
when displayed, so the same case can be reviewed or reported in either language.

A new module:

```python
from forense.core.utils import find_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register


@register
class BitsModule(Module):
    name = "bits"
    category = "windows"
    triage = True
    options = (Option("max_files", 1000, "int"),)

    def discover(self, target):
        return find_files(target, lambda p: p.name.lower() == "qmgr.db")

    def analyze(self, ctx: AnalysisContext) -> None:
        for path in self.discover(ctx.target)[: ctx.options["max_files"]]:
            rel = relative_name(path, ctx.target)
            ...
            ctx.record("bits_job", {"file": rel, "url": url, "destination": dest})
            ctx.event(created, "bits_job", f"BITS: {url} → {dest}", rel)
            if suspicious:
                ctx.finding("bits.suspicious_job", "high", created, url=url)
        ctx.summary["jobs"] = n
```

Then import it in `forense/modules/__init__.py` and add its texts to `locales/es.json` and `locales/en.json`
(`module.bits.title`, `.description`, `.opt.*`, `finding.bits.suspicious_job.title/.description`,
`artifact.bits_job`, `etype.bits_job`). `tests/test_i18n.py` reports any missing translation.

## Known limitations

- **Hives with pending changes**: transaction logs (`.LOG1`/`.LOG2`) are extracted but not replayed. A finding warns
  that recent data may be missing.
- **Images**: VMDK, VHDX and dynamic VHD are not read (convert to raw with `qemu-img`), nor BitLocker-encrypted
  volumes (decrypt them first) or volume shadow copies (VSS).
- **Live collection**: the volume is read while the system runs, so a file that changes during the copy may be
  inconsistent (the recorded hash is that of the copy).
- **Memory**: Volatility needs the symbols of the exact Windows build (downloaded from Microsoft or given with
  `-o symbols=`). Only Windows dumps are analysed.
- **$MFT**: attributes of extension records (`$ATTRIBUTE_LIST`) of heavily fragmented files are not merged.
- **Carving**: only contiguous (non-fragmented) files are recovered. A PDF ends at its first `%%EOF`.
- **Local times**: network profile times (`NetworkList`) are shown as system local time, unconverted.
- **Heuristics**: detection rules are leads to prioritise work, not verdicts.
- The web interface uses Flask's built-in server, meant for local use by one analyst or a small team.

## Roadmap

- Replaying registry transaction logs and recovering deleted keys
- Volume shadow copies (VSS), VMDK/VHDX and BitLocker
- More artifacts: BITS, WMI (`OBJECTS.DATA`), `$UsnJrnl`, `$LogFile`, Windows Timeline, notifications
- Digital signature of reports and PDF export
- Linux and macOS as analysed systems

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q        # tests (real artifacts in tests/data; everything else is generated synthetically)
ruff check forense tests   # style
```

CI runs the tests on Linux and Windows with Python 3.10 and 3.12, plus a full run of the demo scenario. The origin and
license of the test data are listed in [tests/data/README.md](tests/data/README.md).

## License

[Apache License 2.0](LICENSE). Dependencies keep their own licenses: libewf, libscca and libesedb (LGPL-3.0+),
The Sleuth Kit (IPL-1.0 / CPL-1.0) and pytsk3 (Apache-2.0), YARA-X (BSD-3-Clause), evtx (MIT/Apache-2.0), Flask
(BSD-3-Clause). Volatility 3 is optional, runs as a separate process and is distributed under the Volatility Software
License.
