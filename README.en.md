# Forense-Framework

**Windows-focused digital forensics framework**: case management, verifiable chain of custody, disk images (E01, raw,
VHD/VHDX, VMDK, QCOW2) with VSS shadow copies and BitLocker, live collection, more than 20 Windows artifact modules
plus memory analysis, Sigma and YARA rules, super timeline, program execution overview, **MITRE ATT&CK map with an
incident storyline**, **STIX 2.1** indicators, **automated** analysis (from evidence to report in one command, or by
dropping evidence into a folder), analyst review, web UI with a graphical dashboard and CLI, and expert reports in
HTML and **PDF** in **English and Spanish**.

> 🇪🇸 Versión en español: [README.md](README.md)

```
forense demo ./lab          # creates a fictitious intrusion scenario and analyses it
forense web -w ./lab        # open http://127.0.0.1:8765
```

---

## Contents

1. [Principles](#principles)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Quick start](#quick-start)
5. [CLI workflow](#cli-workflow)
6. [Automation](#automation)
7. [Disk images and live collection](#disk-images-and-live-collection)
8. [Memory](#memory)
9. [Program execution](#program-execution)
10. [Analyst review](#analyst-review)
11. [MITRE ATT&CK, storyline and indicators](#mitre-attck-storyline-and-indicators)
12. [Reports](#reports)
13. [Web interface](#web-interface)
14. [Analysis modules](#analysis-modules)
15. [Sigma and YARA rules](#sigma-and-yara-rules)
16. [Integrity and chain of custody](#integrity-and-chain-of-custody)
17. [Architecture and writing a module](#architecture-and-writing-a-module)
18. [Known limitations](#known-limitations)
19. [Roadmap](#roadmap)
20. [Development](#development)
21. [License](#license)

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

Pick whichever suits you. In every case `forense doctor` then checks that everything works.

**1. Windows installer** (no administrator rights). Creates an isolated environment in `%LOCALAPPDATA%\Forense`, adds
`forense` to the PATH, creates the `Documents\Forense` cases folder, the configuration and a Start menu shortcut that
opens the web interface:

```powershell
irm https://raw.githubusercontent.com/Ruby570bocadito/Forense-Framework/main/install/install.ps1 | iex
# or from a clone of the repository:
powershell -ExecutionPolicy Bypass -File install\install.ps1 -WithMemory     # -WithMemory adds Volatility 3
```

Options: `-Workspace D:\Cases`, `-InstallPython` (installs Python 3.12 with winget if missing), `-NoShortcut`,
`-Uninstall` (cases are left untouched).

**2. Linux and macOS installer** (in `~/.local/share/forense`, links `~/.local/bin/forense`):

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/Forense-Framework/main/install/install.sh | sh
sh install/install.sh --with-memory --workspace ~/Cases     # from a clone of the repository
```

**3. Windows executable, no Python needed**: download `forense-<version>-windows-x64.zip` from
[Releases](https://github.com/Ruby570bocadito/Forense-Framework/releases), unzip it and run `forense\forense.exe`.
Handy on isolated lab machines (it can travel on a USB drive). Memory analysis additionally needs Python with
`volatility3`, or the path of `vol.exe` (`-o vol_path=`).

**4. Docker** (web interface, CLI and PDF with Chromium included):

```bash
docker compose up -d                       # http://127.0.0.1:8765, password in FORENSE_WEB_PASSWORD
docker run --rm -v "$PWD/cases:/cases" -v "/path/evidence:/evidence:ro" ghcr.io/ruby570bocadito/forense-framework \
       auto /evidence/laptop.E01 --new /cases/laptop
```

Evidence is mounted read-only (`:ro`). `docker build --build-arg WITH_MEMORY=1 .` includes Volatility 3.

**5. Manual, with pip** (Python 3.10 or later):

```bash
git clone https://github.com/Ruby570bocadito/Forense-Framework.git
cd Forense-Framework
python -m venv .venv && . .venv/bin/activate      # Windows: py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[memory]"                         # without [memory] Volatility 3 is not installed
forense doctor
```

Every dependency ships prebuilt binaries for Windows, Linux and macOS: `evtx` (EVTX), `Flask` (web and reports),
`PyYAML` (Sigma, configuration), `olefile` (Jump Lists), `libscca-python` (Prefetch), `libesedb-python` (SRUM),
`libewf-python` (E01), `libvhdi-python`, `libvmdk-python` and `libqcow-python` (virtual disks), `libvshadow-python`
(VSS), `libbde-python` (BitLocker), `pytsk3` (NTFS, The Sleuth Kit) and `yara-x` (YARA). PDFs use Microsoft Edge
(present on every Windows 10/11), Chrome or Chromium; another browser can be set with `FORENSE_BROWSER`.

`forense doctor` lists every component with its version and purpose, warns about what is missing (Volatility, a
browser for PDF, intelligence lists that do not exist, a cases folder that cannot be written…) and exits with an
error if something essential is missing; `--json` gives the result to scripts.

The language is chosen with `-L en|es` (anywhere on the command line), the `FORENSE_LANG` variable, the configuration
or, failing all of them, the system locale.

## Configuration

`forense config init` creates a commented file (`%APPDATA%\Forense\config.yaml` on Windows,
`~/.config/forense/config.yaml` on Linux/macOS, or the one in `FORENSE_CONFIG` / `--config`). Command-line options
always take precedence.

```yaml
analyst: "R. Garcia"            # default name in the chain of custody
language: en
organization: "Example CERT"
workspace: 'D:\Cases'           # cases folder for the web, forense auto and forense watch
intel:
  hash_lists: ['D:\intel\malware_sha256.txt']
  watchlists: ['D:\intel\iocs.txt']
  yara_rules: ['D:\intel\yara']
  sigma_rules: 'D:\intel\sigma'  # forense sigma download D:\intel\sigma
  sigma_min_level: medium
image: {vss: true}               # also extract from volume shadow copies
memory: {symbols: 'D:\symbols', offline: false}
report: {languages: [en, es], pdf: true}
automation: {playbook: full}
web: {host: 127.0.0.1, port: 8765}
```

`forense config show` prints the effective configuration and `forense config path` where it lives.

## Quick start

```bash
forense demo ./lab -a "Your name"
```

This generates a **fictitious** scenario: the compromised workstation `WS-CONTAB01`. It contains a triage collection
(hives, `$MFT`, `$UsnJrnl`, Prefetch, ShellBags, scheduled tasks, WMI repository, PowerShell history, Windows
Timeline, `setupapi`, shell links, Recycle Bin, Chrome/Firefox history…), a raw image for carving, the
workstation memory (Volatility 3 outputs), a known-bad hash list, an IOC list and a YARA rule. It then creates the
case `lab/case_demo`, registers the three evidence items, runs triage and the intelligence modules and produces more
than 50 findings: an IFEO debugger on `sethc.exe`, timestomping, persistence in a `Run` key, a hidden task and a WMI
subscription, a service in `C:\Windows\Temp`, mimikatz and rclone execution (and their deletion according to the
USN journal), a fake `svchost.exe` talking to the Internet, a hidden process, code injected into `explorer.exe`, an
encoded command in the clipboard, a USB drive, deleted files and, recovered from the free space of the registry,
the PsExec service and a `Run` value the attacker removed.

```bash
forense -c lab/case_demo findings
forense -c lab/case_demo timeline --from 2026-09-14T02:00 --to 2026-09-14T05:00
forense -c lab/case_demo attack --summary        # ATT&CK tactics and a draft storyline
forense -c lab/case_demo report --pdf -L en
forense web -w lab --open
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
| `forense -c CASE image EV-001 [--verify] [--vss] [--bitlocker-recovery -] [-p PATTERN] [--all-files] [--triage]` | `imagen` | Extract the artifacts of an image as derived evidence |
| `forense collect DEST [--source \\.\C:] [--volatile] [--add-to-case]` | `recolectar` | Live collection on Windows |
| `forense -c CASE analyze MODULE EV-001 [-o key=value]` | `analizar` | Run one module (`all` = every evidence item) |
| `forense -c CASE analyses` / `show N [--artifact X]` | `analisis` / `mostrar` | Analyses and their records |
| `forense -c CASE findings [--min-severity high] [--status confirmed]` | `hallazgos` | Findings sorted by severity, with their review status |
| `forense -c CASE review N confirmed\|false_positive\|needs_review [-n NOTE]` | `revisar` | Review a finding |
| `forense -c CASE bookmark N [-n NOTE] [--remove]` | `destacar` | Bookmark a timeline event |
| `forense -c CASE conclusions [--text T \| --file F]` | `conclusiones` | Show or write the (versioned) conclusions |
| `forense -c CASE timeline [--from] [--to] [--search] [--source] [--bookmarked]` | `cronologia` | Super timeline |
| `forense -c CASE execution [--search X] [--suspicious]` | `ejecucion` | Programs executed according to every source |
| `forense -c CASE export {analysis N,timeline,findings,execution,stix,custody} -o FILE` | `exportar` | CSV (Excel friendly), JSON or STIX 2.1 |
| `forense -c CASE attack [--summary]` | `mitre` | MITRE ATT&CK techniques observed or a draft incident storyline |
| `forense -c CASE custody [--verify]` | `custodia` | Chain of custody |
| `forense -c CASE verify` | `verificar` | Full verification (exit code 2 if anything fails) |
| `forense -c CASE report [--verify] [--pdf] [-L es]` | `informe` | Self-contained HTML report (and PDF) |
| `forense auto EVIDENCE… [--new DIR] [-p PLAYBOOK]` | `auto` | From evidence to report in one command |
| `forense watch FOLDER [-w WORKSPACE] [--once]` | `vigilar` | Automatically process whatever is dropped into a folder |
| `forense config [show\|init\|path]` | `configuracion` | Configuration |
| `forense correlate [-w WORKSPACE] [--type T] [--json]` | `correlacionar` | Items shared between cases |
| `forense doctor` | `diagnostico` | Check the installation |
| `forense sigma check PATH` / `sigma download DIR` | `sigma` | Validate Sigma rules or download SigmaHQ's |
| `forense web [-w WORKSPACE] [--port 8765] [--password X] [--open]` | `web` | Web interface |

Common options: `-c/--case` (or the `FORENSE_CASE` variable), `-a/--analyst` (who appears in the custody log; the
configured one by default), `-L/--lang` and `--config FILE`. In `timeline`, `--to 2026-09-14` includes the whole day.

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

## Automation

`forense auto` registers the evidence (in an existing case with `-c`, a new one with `--new`, or the configured cases
folder), runs a **playbook** and leaves the report and exports ready:

```powershell
forense auto E:\acquisitions\PC-042.E01 --new D:\Cases\PC-042 -i "R. Garcia"
forense -c D:\Cases\2026-017 auto E:\acquisitions\FS01.mem          # add to the case and analyse
```

| Playbook | Steps |
|---|---|
| `triage` | triage (images are extracted first; memory goes to Volatility) → report |
| `quick` | registry, Prefetch, EVTX, tasks, PowerShell and `$MFT` → report |
| `full` (default) | triage → intelligence from the configuration (hashes, IOCs, YARA, Sigma) → report → exports (findings, timeline, execution and STIX) |

A custom playbook is a YAML file with `steps:`; each step is `triage`, `memory`, `intel`, `modules` (with per-module
options), `report` (languages, PDF) or `export`:

```yaml
steps:
  - triage
  - modules: {evtx: {sigma_rules: 'D:\intel\sigma', sigma_min_level: high}}
  - intel
  - report: {languages: [en, es], pdf: true}
  - export: [findings, stix]
```

**Watched folder**: `forense watch D:\Inbox -w D:\Cases` creates a case for every file or folder dropped into
`D:\Inbox` and processes it with the playbook. It waits until the copy has finished (size and time stable between two
polls), ignores `.part`/`.tmp`, remembers what was processed in `D:\Cases\.forense-watch.json`, and an item that fails
does not stop the others. `--once` processes what is there and exits (handy in a scheduled task).

In the web interface, the **Automatic** button of each evidence item runs the playbook in the background.

## Disk images and live collection

### Images

Formats: **E01/Ex01** (EnCase, FTK Imager, ewfacquire), **raw/dd**, **split raw** (`.001`, `.002`…), fixed, dynamic
and differencing **VHD and VHDX** (the parent disk is looked up in the same folder), **VMDK** and **QCOW2**. MBR/GPT
partitions and file systems are read with The Sleuth Kit **without mounting anything**, so locked files (`$MFT`, hives,
SRUM, EVTX) and alternate data streams such as `$UsnJrnl:$J` are obtained as well.

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
- **Volume shadow copies (VSS)** are always listed (with their creation time, also on the timeline). With `--vss` the
  triage profile is also extracted from every shadow copy, keeping only the files that differ from the live volume
  (`C_vss1/`, `C_vss2/`…): older hive versions, deleted event logs or removed tools.
- **BitLocker** (BitLocker To Go included) is decrypted with the 48-digit recovery password (`--bitlocker-recovery -`
  asks for it without echo), the password or the `.BEK` startup key. Keys are **never stored** in the case: the
  custody log only keeps a SHA-256 fingerprint that proves which key was used. A volume that cannot be decrypted
  raises a finding explaining what is missing.

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

## Program execution

`forense -c CASE execution` (and the **Execution** web page) gathers in one row per program everything Prefetch,
Amcache, ShimCache, BAM, UserAssist, SRUM, the Windows Timeline, 4688/Sysmon 1 events, RunMRU and memory say about it.
Each source writes paths its own way (`\VOLUME{…}\USERS\…`, `\Device\HarddiskVolume3\…`, `%ProgramFiles%`,
known-folder GUIDs…); they are normalised to join them, giving first and last execution, run count, users, SHA-1,
command lines and the supporting sources. Offensive and remote-access tools, names imitating system binaries
(`scvhost.exe`) and suspicious locations are flagged. ShimCache and Amcache prove presence, not execution, and are
treated as such. The table can be exported (`export execution`) and is part of the report.

## Analyst review

Findings are leads. Each one can be marked **confirmed**, **false positive** or **needs review** with a note, and key
timeline events can be **bookmarked**. Everything is kept in an append-only history and in the chain of custody,
with who and when.

The case **conclusions** are written by the analyst (free text, versioned). The report includes them together with
the findings grouped by review status and the bookmarked events.

## MITRE ATT&CK, storyline and indicators

Each finding is mapped to **MITRE ATT&CK** techniques by its kind (persistence in `Run` → T1547.001, timestomping →
T1070.006…), by the rules that fired (encoded PowerShell, `ExecutionPolicy Bypass`…), by the tools it names
(mimikatz → T1003, rclone → T1567.002, AnyDesk → T1219) and by the tags of Sigma rules. With that:

- `forense attack` and the **ATT&CK** page show the matrix of tactics and techniques observed, when each was first
  seen and the findings that support it (linked). Low-severity or dismissed findings do not count; confirmed ones
  always do.
- **Incident storyline**: the phases in kill-chain order and a **draft** narrative (`attack --summary`, or the button
  on the ATT&CK page that takes it to the conclusions) for the analyst to review and complete.
- **Indicators of compromise**: `export stix` produces a **STIX 2.1** bundle with the hashes, IPs, domains, URLs and
  e-mail addresses from the findings (hash lists, YARA, watchlists, memory connections, downloads) and from flagged
  programs, plus the ATT&CK techniques, ready for MISP, OpenCTI or a SIEM. Legitimate domains (downloads from
  7-zip.org, for instance) are left out.

### Cross-case correlation

`forense correlate -w WORKSPACE` (and the **Cross-case correlation** page of the web interface, linked from the list
of cases) finds what the cases of a workspace share: indicators of compromise, **USB devices by serial number** (the
same stick on two computers), IP addresses (memory connections, network and RDP logons, RDP destinations, UNC paths),
computer names and domain accounts of remote logons. With `-c CASE` it shows only that case's items, and the case
overview gets a **Seen in other cases** panel. The index of each case is kept in `WORKSPACE/.forense-correlation`
and rebuilt only when its chain of custody changes; cases are never modified. Options: `--type usb`,
`--min-cases 3`, `--json`.

## Reports

`forense report` writes a self-contained HTML file (no scripts or external resources) and `--pdf` also the PDF, both
with their SHA-256 in the chain of custody. Structure:

1. Cover page with the case data and a confidentiality notice, and contents.
2. **Executive summary**: key figures, incident period, findings-by-severity and activity charts, key findings and
   the incident sequence by ATT&CK tactic.
3. Analyst conclusions (versioned, with their hash).
4. ATT&CK techniques observed and indicators of compromise.
5. Evidence with hashes and integrity, findings by review status (with their techniques), bookmarked events, program
   execution, chronology, analyses performed (options and results hash), full chain of custody and methodology.

The PDF is A4 with the case ID and "page x / y" in the footer and no table rows split across pages. In the web
interface, the **Reports** page produces either one in the language you choose.

## Web interface

```bash
forense web -w ./cases            # http://127.0.0.1:8765
```

- **Workspace**: list of cases and new-case form.
- **Overview**: key figures, activity chart of the incident period with the findings at their time (each bar opens
  the timeline of that interval), findings by severity, key findings, techniques per ATT&CK tactic, and evidence with
  **Automatic** (full playbook) and **Triage** buttons. Charts come with a table view and tooltips and follow the
  system light or dark theme.
- **ATT&CK**: matrix of techniques observed, incident sequence and draft storyline.
- **Evidence**: registration by path (hashed in the background), hashes, origin of derived evidence and integrity
  verification.
- **Analyses**: per-module form with its options, automatic triage, paginated results with per-artifact search and
  CSV export.
- **Findings** with review (confirm, dismiss, note), **Timeline** (date, text, source, severity and bookmark filters),
  **Conclusions**, **Chain of custody** and **Reports** (in the language you choose).
- **ES/EN** selector and **Analyst** field: the name is recorded in every custody action.

Security: listens on `127.0.0.1` by default, every form carries a CSRF token, security headers (CSP,
`X-Frame-Options`) are sent and a password can be required with `--password` or `FORENSE_WEB_PASSWORD` (HTTP Basic).
If you expose it on a network, put it behind HTTPS. `--open` opens the browser on start; `/healthz` answers without a
password for container health checks.

## Analysis modules

| Module | Artifacts | Detects |
|---|---|---|
| `evtx` | `*.evtx` (Security, System, PowerShell, Sysmon, Defender, RDP, TaskScheduler, WMI, BITS) | Brute force and **logon after brute force**, log clearing (1102/104), new users and privileged group changes, services (7045/4697) and tasks created, suspicious commands (4688/Sysmon 1), malicious PowerShell (4104), Defender detections and tampering, WMI persistence, RDP from public IPs and **Sigma rules** |
| `registry` | SYSTEM, SOFTWARE, SAM, NTUSER.DAT, Amcache.hve | Computer, time zone, network, **USB** (first/last connection), services, **ShimCache**, **BAM**, OS and install, installed programs, network profiles, **Run/RunOnce**, Winlogon, **IFEO**, AppInit_DLLs, SAM accounts, **UserAssist**, RecentDocs, RunMRU, TypedPaths, searches, RDP destinations, Amcache with SHA-1, **deleted keys and values** (removed services, tasks, IFEO entries and commands) |
| `prefetch` | `*.pf` (XP to Windows 11, compressed format included) | Program execution: run count, last 8 run times, volume and loaded files; offensive tools and execution from suspicious locations |
| `srum` | `SRUDB.dat` | Bytes sent and received per application and user, connectivity, CPU/disk usage; **possible exfiltration** |
| `shellbags` | `UsrClass.dat`, `NTUSER.DAT` | Folders browsed, including USB, network and already deleted folders |
| `jumplists` | `*.automaticDestinations-ms`, `*.customDestinations-ms` | Files opened per application, RDP connections, removable drives, suspicious arguments |
| `lnk` | `*.lnk` | Opened files, network paths, **removable drives** (serial and label), source machine and **MAC**, Startup folder persistence |
| `recyclebin` | `$Recycle.Bin\<SID>\$I*` | Original path, size, deletion time, user and whether the content (`$R`) is recoverable |
| `browsers` | Chrome, Edge, Brave, Opera (`History`), Firefox (`places.sqlite`) | History, downloads, **downloaded executables**, file-sharing and paste services |
| `mft` | `$MFT` | $SI/$FN timeline, deleted entries, full paths, **Zone.Identifier** (download URL), **timestomping** |
| `usnjrnl` | `$Extend\$UsnJrnl:$J` | File creation, deletion and renaming with full paths (through the `$MFT`); offensive tools, executables created and deleted, deleted Prefetch and EVTX, **mass renaming (ransomware)** and mass deletion |
| `tasks` | `Windows\System32\Tasks` | Scheduled tasks: author, triggers, account, actions; **hidden tasks**, tasks running interpreters or binaries from suspicious locations, as SYSTEM |
| `wmi` | `wbem\Repository\OBJECTS.DATA` | **WMI persistence** (filter + CommandLine/ActiveScript consumer), deleted subscriptions included |
| `psreadline` | `ConsoleHost_history.txt` | Each user's PowerShell commands: downloads, encoded execution, Defender tampering, offensive tools |
| `wintimeline` | `ActivitiesCache.db` | Applications and documents used, time in focus and **clipboard history** |
| `setupapi` | `setupapi.dev.log` | First connection of USB and portable devices (vendor, model, serial number), converted to UTC |
| `memory` | Memory dump or Volatility 3 JSON outputs | See [Memory](#memory) |
| `image` | E01/Ex01, raw, VHD/VHDX, VMDK, QCOW2 | See [Disk images](#disk-images-and-live-collection) |
| `inventory` | Any folder | Metadata, hashes, real type by signature, **disguised files**, timeline and Sleuth Kit compatible *bodyfile* (`mactime`) |
| `ioc` | Any file | ASCII/UTF-16 strings, URLs, IPs, e-mails, registry keys and watchlist (`-o watchlist=`) |
| `hashset` | Any folder | Matches against MD5/SHA-1/SHA-256 hash lists (`-o hash_list=`) |
| `yara` | Any folder | YARA rule matches (`-o rules=`), with the severity given by the rule |
| `carving` | Raw image / unallocated space | Recovers JPEG, PNG, GIF, PDF and ZIP, validating their internal structure |

The Windows modules and `inventory` run during **triage** when they find artifacts (`memory` does not, as it can be
slow). Severities: critical, high, medium, low and info.

What can be registered as evidence:

- **Disk images** (E01, raw, VHD/VHDX, VMDK, QCOW2) and **memory dumps**.
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
├── reports/       HTML and PDF reports
└── exports/       CSV/JSON/STIX exports
```

## Architecture and writing a module

```
forense/
├── core/        case (SQLite), review, custody, hashing, signatures, heuristics, time zones, execution, exports
├── parsers/     regf (+ transaction logs), lnk, $I, $MFT, $UsnJrnl, ShimCache, EVTX, SRUM, shell items, Jump Lists,
│                Volatility
├── image/       containers (libewf, libvhdi, libvmdk, libqcow), BitLocker, VSS, The Sleuth Kit and extractor
├── sigma/       Sigma engine and built-in rules
├── modules/     windows/ (evtx, registry, prefetch, srum, shellbags, jumplists, lnk, recyclebin, browsers, mft,
│                usnjrnl, tasks, wmi, psreadline, wintimeline, setupapi, memory)
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

- **Hives with pending changes** are recovered in memory by replaying their transaction logs (`.LOG`, `.LOG1`,
  `.LOG2`, old and new formats, Marvin32 hashes validated); when the logs were not collected a finding warns that
  recent data may be missing. **Deleted keys and values** are recovered from the free space of the hive (and from
  cells left unlinked), with their full or partial path; their data are leads, since the data cell may have been
  reused after the deletion.
- **Images**: volumes encrypted with other systems (VeraCrypt, LUKS) and file systems The Sleuth Kit does not support
  (ReFS, APFS) are not read.
- **Live collection**: the volume is read while the system runs, so a file that changes during the copy may be
  inconsistent (the recorded hash is that of the copy).
- **Memory**: Volatility needs the symbols of the exact Windows build (downloaded from Microsoft or given with
  `-o symbols=`). Only Windows dumps are analysed.
- **$MFT**: attributes of extension records (`$ATTRIBUTE_LIST`) of heavily fragmented files are not merged.
- **Carving**: only contiguous (non-fragmented) files are recovered. A PDF ends at its first `%%EOF`.
- **Local times** (network profiles, `setupapi`) are converted to UTC with the time zone rules of the SYSTEM hive of
  the same evidence (daylight saving time included); without it they are kept as local time.
- **WMI**: the repository is searched for strings (like PyWMIPersistenceFinder), not parsed as a full CIM database.
- **Heuristics**: detection rules are leads to prioritise work, not verdicts.
- The web interface uses Flask's built-in server, meant for local use by one analyst or a small team.

## Roadmap

- More artifacts: BITS (`qmgr.db`), `$LogFile`, notifications, RDP Bitmap Cache, Microsoft Defender (MPLog)
- Digital signature of reports
- Cross-case correlation and intelligence import from MISP/OpenCTI
- Linux and macOS as analysed systems

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q        # tests (real artifacts in tests/data; everything else is generated synthetically)
ruff check forense tests   # style
```

CI runs the tests on Linux and Windows with Python 3.10 and 3.12, a full run of the demo scenario and both installers
(install, run and uninstall). Pushing a `v*` tag runs the `release` workflow, which builds the wheel and sdist, the
Windows executable (PyInstaller, `packaging/forense.spec`, tested with the demo and a PDF) and the Docker image on
GitHub Container Registry, and attaches them to the release. The origin and
license of the test data are listed in [tests/data/README.md](tests/data/README.md).

## License

[Apache License 2.0](LICENSE). Dependencies keep their own licenses: libewf, libscca and libesedb (LGPL-3.0+),
The Sleuth Kit (IPL-1.0 / CPL-1.0) and pytsk3 (Apache-2.0), YARA-X (BSD-3-Clause), evtx (MIT/Apache-2.0), Flask
(BSD-3-Clause). Volatility 3 is optional, runs as a separate process and is distributed under the Volatility Software
License.
