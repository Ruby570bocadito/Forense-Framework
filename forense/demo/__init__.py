"""Synthetic demo scenario: a compromised Windows workstation.

``generate_demo`` writes a triage collection (registry hives, $MFT, shell
links, Recycle Bin, browser history, files), a raw disk image for carving and
reference lists (known-bad hashes, IOC watchlist). Everything is fictitious:
IP addresses are documentation ranges (RFC 5737) and domains use
``.example``.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from forense.demo import builders as b

HOST = "WS-CONTAB01"
USER = "maria"
USER_SID = "S-1-5-21-1004336348-1177238915-682003330-1001"
T0 = datetime(2026, 9, 14, 2, 10, tzinfo=timezone.utc)  # start of the intrusion
MALWARE = b"MZ" + b"\x90" * 62 + b"This program cannot be run in DOS mode.\r\n" + b"FORENSE-DEMO-IMPLANT" * 20


def _t(minutes: float) -> datetime:
    return T0 + timedelta(minutes=minutes)


def _touch(path: Path, when: datetime) -> None:
    """Give a demo file a realistic modification/access time."""
    os.utime(path, (when.timestamp(), when.timestamp()))


def generate_demo(dest: Path) -> dict[str, Path]:
    """Create the demo files under ``dest``. Returns the main paths."""
    dest = Path(dest)
    triage = dest / "triage_WS-CONTAB01"
    c = triage / "C"
    _system_hive(c / "Windows/System32/config/SYSTEM")
    _software_hive(c / "Windows/System32/config/SOFTWARE")
    _sam_hive(c / "Windows/System32/config/SAM")
    _ntuser_hive(c / f"Users/{USER}/NTUSER.DAT")
    _amcache_hive(c / "Windows/appcompat/Programs/Amcache.hve")
    _links(c / f"Users/{USER}/AppData/Roaming/Microsoft/Windows")
    _recycle_bin(c / "$Recycle.Bin" / USER_SID)
    _browsers(c / f"Users/{USER}/AppData")
    _files(c)
    _mft(c / "$MFT")
    _prefetch(c / "Windows/Prefetch")
    _usrclass(c / f"Users/{USER}/AppData/Local/Microsoft/Windows/UsrClass.dat")

    image = dest / "disk_unallocated.img"
    _disk_image(image)
    memory = dest / f"memory_{HOST}"
    _memory(memory)

    malware_sha256 = hashlib.sha256(MALWARE).hexdigest()
    hashes = dest / "known_bad_hashes.txt"
    hashes.write_text(
        "# Known-bad hashes (demo)\n"
        f"{malware_sha256}  FORENSE-DEMO implant (svchost.exe)\n"
        f"{'0' * 63}1  unrelated sample\n", encoding="utf-8")
    watchlist = dest / "ioc_watchlist.txt"
    watchlist.write_text("# IOC watchlist (demo)\n198.51.100.23\nupdate-cdn.example\nexfil@proton.example\n",
                         encoding="utf-8")
    yara_rules = dest / "rules.yar"
    yara_rules.write_text(
        'rule forense_demo_implant : demo\n{\n    meta:\n        description = "FORENSE-DEMO implant (fictitious)"\n'
        '        severity = "critical"\n    strings:\n        $marker = "FORENSE-DEMO-IMPLANT"\n'
        '        $mz = { 4D 5A }\n    condition:\n        $mz at 0 and $marker\n}\n', encoding="utf-8")
    return {"triage": triage, "image": image, "memory": memory, "hashes": hashes, "watchlist": watchlist,
            "yara": yara_rules}


# -- registry ---------------------------------------------------------------
def _system_hive(path: Path) -> None:
    h = b.HiveBuilder(embedded_name="\\??\\C:\\Windows\\System32\\Config\\SYSTEM", default_time=_t(-60 * 24 * 90))
    h.value("Select", "Current", b.REG_DWORD, 1)
    cs = "ControlSet001"
    h.value(f"{cs}\\Control\\ComputerName\\ComputerName", "ComputerName", b.REG_SZ, HOST)
    h.value(f"{cs}\\Control\\TimeZoneInformation", "TimeZoneKeyName", b.REG_SZ, "Romance Standard Time")
    h.value(f"{cs}\\Control\\TimeZoneInformation", "ActiveTimeBias", b.REG_DWORD, 0xFFFFFF88)  # -120 -> UTC+2
    h.value(f"{cs}\\Control\\Windows", "ShutdownTime", b.REG_BINARY, b.to_filetime(_t(300)).to_bytes(8, "little"))
    iface = f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces\\{{4f2a7c10-1111-4c3e-9a55-0d1e2f3a4b5c}}"
    h.value(iface, "EnableDHCP", b.REG_DWORD, 1)
    h.value(iface, "DhcpIPAddress", b.REG_SZ, "192.0.2.45")
    h.value(iface, "DhcpServer", b.REG_SZ, "192.0.2.1")
    h.value(iface, "DhcpDomain", b.REG_SZ, "contoso.example")
    # USB mass storage connected during the intrusion.
    dev = f"{cs}\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP"
    inst = f"{dev}\\60A44C3FAE2BE2B0E9160123&0"
    h.key(inst, _t(95))
    h.value(inst, "FriendlyName", b.REG_SZ, "Kingston DataTraveler 3.0 USB Device")
    props = f"{inst}\\Properties\\{{83da6326-97a6-4088-9453-a1923f573b29}}"
    for code, when in (("0064", _t(90)), ("0066", _t(90)), ("0067", _t(140))):
        h.value(f"{props}\\{code}", "", 0xFFFF0010, b.to_filetime(when).to_bytes(8, "little"))
    # Services: one legitimate, one malicious.
    h.value(f"{cs}\\Services\\Spooler", "ImagePath", b.REG_EXPAND_SZ, "%SystemRoot%\\System32\\spoolsv.exe")
    h.value(f"{cs}\\Services\\Spooler", "Start", b.REG_DWORD, 2)
    h.key(f"{cs}\\Services\\WinUpdateSvc", _t(42))
    h.value(f"{cs}\\Services\\WinUpdateSvc", "ImagePath", b.REG_EXPAND_SZ,
            "C:\\Windows\\Temp\\wupd.exe -k netsvcs")
    h.value(f"{cs}\\Services\\WinUpdateSvc", "Start", b.REG_DWORD, 2)
    h.value(f"{cs}\\Services\\WinUpdateSvc", "DisplayName", b.REG_SZ, "Windows Update Helper")
    shim = b.build_shimcache_win10([
        ("C:\\Users\\Public\\svchost.exe", _t(25)),
        ("C:\\Windows\\Temp\\wupd.exe", _t(41)),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", _t(-60 * 24 * 30)),
    ])
    h.value(f"{cs}\\Control\\Session Manager\\AppCompatCache", "AppCompatCache", b.REG_BINARY, shim)
    bam = f"{cs}\\Services\\bam\\State\\UserSettings\\{USER_SID}"
    for exe, when in (("\\Device\\HarddiskVolume3\\Users\\Public\\svchost.exe", _t(26)),
                      ("\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", _t(30)),
                      ("\\Device\\HarddiskVolume3\\Program Files\\7-Zip\\7zG.exe", _t(85))):
        h.value(bam, exe, b.REG_BINARY, b.to_filetime(when).to_bytes(8, "little") + b"\x00" * 16)
    h.save(path)


def _software_hive(path: Path) -> None:
    h = b.HiveBuilder(embedded_name="emRoot\\System32\\Config\\SOFTWARE", default_time=_t(-60 * 24 * 90))
    cv = "Microsoft\\Windows NT\\CurrentVersion"
    h.value(cv, "ProductName", b.REG_SZ, "Windows 10 Pro")
    h.value(cv, "DisplayVersion", b.REG_SZ, "23H2")
    h.value(cv, "CurrentBuild", b.REG_SZ, "22631")
    h.value(cv, "UBR", b.REG_DWORD, 4169)
    h.value(cv, "EditionID", b.REG_SZ, "Professional")
    h.value(cv, "InstallDate", b.REG_DWORD, int(datetime(2025, 3, 2, 9, 15, tzinfo=timezone.utc).timestamp()))
    h.value(cv, "RegisteredOwner", b.REG_SZ, "Contoso Contabilidad")
    h.value(f"{cv}\\Winlogon", "Shell", b.REG_SZ, "explorer.exe")
    h.value(f"{cv}\\Winlogon", "Userinit", b.REG_SZ, "C:\\Windows\\system32\\userinit.exe,")
    h.key(f"{cv}\\Image File Execution Options\\sethc.exe", _t(48))
    h.value(f"{cv}\\Image File Execution Options\\sethc.exe", "Debugger", b.REG_SZ, "C:\\Windows\\System32\\cmd.exe")
    run = "Microsoft\\Windows\\CurrentVersion\\Run"
    h.key(run, _t(27))
    h.value(run, "SecurityHealth", b.REG_EXPAND_SZ, "%windir%\\system32\\SecurityHealthSystray.exe")
    h.value(run, "OneDriveSetup", b.REG_SZ, "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background")
    unin = "Microsoft\\Windows\\CurrentVersion\\Uninstall"
    for key, name, version, publisher, when in (
            ("7-Zip", "7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", _t(80)),
            ("{90160000-0011-0000-1000-0000000FF1CE}", "Microsoft Office Professional Plus 2016", "16.0.4266",
             "Microsoft Corporation", _t(-60 * 24 * 60))):
        h.key(f"{unin}\\{key}", when)
        h.value(f"{unin}\\{key}", "DisplayName", b.REG_SZ, name)
        h.value(f"{unin}\\{key}", "DisplayVersion", b.REG_SZ, version)
        h.value(f"{unin}\\{key}", "Publisher", b.REG_SZ, publisher)
    prof = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{0A1B2C3D-0000-4000-8000-000000000001}"
    h.value(prof, "ProfileName", b.REG_SZ, "CONTOSO-CORP")
    h.value(prof, "NameType", b.REG_DWORD, 6)
    h.value(prof, "DateCreated", b.REG_BINARY, bytes.fromhex("e9070300000002000b000f0000000000"))
    h.value(prof, "DateLastConnected", b.REG_BINARY, bytes.fromhex("ea0709000100100004000a0000000000"))
    h.save(path)


def _sam_hive(path: Path) -> None:
    h = b.HiveBuilder(embedded_name="\\SystemRoot\\System32\\Config\\SAM", default_time=_t(-60 * 24 * 90))
    users = "SAM\\Domains\\Account\\Users"
    accounts = (
        ("Administrador", 500, None, True, False, _t(-60 * 24 * 90)),
        ("Invitado", 501, None, True, False, _t(-60 * 24 * 90)),
        (USER, 1001, _t(15), False, False, _t(-60 * 24 * 85)),
        ("soporte", 1002, _t(55), False, True, _t(50)),
    )
    for name, rid, last_logon, disabled, no_pwd, created in accounts:
        h.key(f"{users}\\Names\\{name}", created)
        h.value(f"{users}\\Names\\{name}", "", rid, b"")
        h.value(f"{users}\\{rid:08X}", "F", b.REG_BINARY,
                b.sam_f_value(rid, last_logon, created, None, logons=12 if last_logon else 0,
                              disabled=disabled, password_not_required=no_pwd))
    h.save(path)


def _ntuser_hive(path: Path) -> None:
    import codecs

    h = b.HiveBuilder(default_time=_t(-60 * 24 * 30))
    explorer = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    ua = f"{explorer}\\UserAssist\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count"
    for program, runs, when in (
            ("{6D809377-6AF0-444B-8957-A3773F02200E}\\Microsoft Office\\root\\Office16\\EXCEL.EXE", 57, _t(-60)),
            ("C:\\Users\\Public\\svchost.exe", 1, _t(25)),
            ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe", 3, _t(30))):
        h.value(ua, codecs.encode(program, "rot_13"), b.REG_BINARY, b.userassist_data(runs, when))
    h.key(f"{explorer}\\RunMRU", _t(24))
    h.value(f"{explorer}\\RunMRU", "a", b.REG_SZ,
            "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\\1")
    h.value(f"{explorer}\\RunMRU", "b", b.REG_SZ, "excel\\1")
    h.value(f"{explorer}\\RunMRU", "MRUList", b.REG_SZ, "ab")
    h.key(f"{explorer}\\RecentDocs", _t(88))
    h.value(f"{explorer}\\RecentDocs", "0", b.REG_BINARY, "clientes_2026.xlsx\x00".encode("utf-16-le") + b"\x00" * 8)
    h.value(f"{explorer}\\RecentDocs", "1", b.REG_BINARY, "nominas_septiembre.pdf\x00".encode("utf-16-le"))
    h.value(f"{explorer}\\RecentDocs", "MRUListEx", b.REG_BINARY, bytes.fromhex("0000000001000000ffffffff"))
    h.value(f"{explorer}\\TypedPaths", "url1", b.REG_SZ, "\\\\192.0.2.10\\finanzas")
    h.value(f"{explorer}\\WordWheelQuery", "0", b.REG_BINARY, "contraseñas\x00".encode("utf-16-le"))
    h.value(f"{explorer}\\WordWheelQuery", "MRUListEx", b.REG_BINARY, bytes.fromhex("00000000ffffffff"))
    h.key("Software\\Microsoft\\Windows\\CurrentVersion\\Run", _t(27))
    h.value("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", b.REG_SZ,
            "C:\\Users\\Public\\svchost.exe --silent")
    h.key("Software\\Microsoft\\Terminal Server Client\\Servers\\192.0.2.20", _t(65))
    h.value("Software\\Microsoft\\Terminal Server Client\\Servers\\192.0.2.20", "UsernameHint", b.REG_SZ,
            "CONTOSO\\administrador")
    h.key("Control Panel\\Desktop")
    h.key("Environment")
    h.save(path)


def _amcache_hive(path: Path) -> None:
    h = b.HiveBuilder(default_time=_t(-60 * 24 * 30))
    sha1 = hashlib.sha1(MALWARE).hexdigest()
    for key, path_value, digest, when in (
            ("0006a1b2c3d4e5f6", "c:\\users\\public\\svchost.exe", sha1, _t(26)),
            ("0006aaaaaaaaaaaa", "c:\\program files\\7-zip\\7zg.exe", "a" * 40, _t(81))):
        k = f"Root\\InventoryApplicationFile\\{key}"
        h.key(k, when)
        h.value(k, "LowerCaseLongPath", b.REG_SZ, path_value)
        h.value(k, "FileId", b.REG_SZ, "0000" + digest)
        h.value(k, "Name", b.REG_SZ, path_value.rsplit("\\", 1)[1])
    h.save(path)


# -- other artifacts ------------------------------------------------------------
def _links(base: Path) -> None:
    recent = base / "Recent"
    recent.mkdir(parents=True, exist_ok=True)
    (recent / "clientes_2026.xlsx.lnk").write_bytes(b.build_lnk(
        "E:\\clientes_2026.xlsx", _t(-60 * 24 * 10), _t(88), _t(92), size=184320, drive_type=2,
        serial=0x6A2F11C0, volume_label="KINGSTON", machine_id=HOST.lower(), mac="00:15:5d:01:02:03"))
    _touch(recent / "clientes_2026.xlsx.lnk", _t(92))
    (recent / "finanzas.lnk").write_bytes(b.build_lnk(
        "presupuesto_2027.docx", _t(-60 * 24 * 5), _t(70), _t(70), size=52000,
        network_share="\\\\192.0.2.10\\finanzas", machine_id="fs01"))
    _touch(recent / "finanzas.lnk", _t(70))
    startup = base / "Start Menu/Programs/Startup"
    startup.mkdir(parents=True, exist_ok=True)
    (startup / "OneDrive Sync.lnk").write_bytes(b.build_lnk(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", _t(-60 * 24 * 300), _t(-60 * 24 * 300),
        _t(28), size=450560, arguments="-w hidden -ep bypass -file C:\\Users\\Public\\sync.ps1",
        machine_id=HOST.lower()))
    _touch(startup / "OneDrive Sync.lnk", _t(28))


def _recycle_bin(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "$IR8K2QF.zip").write_bytes(b.build_i_file(f"C:\\Users\\{USER}\\Desktop\\clientes_2026.zip",
                                                         1_048_576, _t(135)))
    (folder / "$RR8K2QF.zip").write_bytes(b.build_zip({"clientes_2026.csv": b"id;nombre;iban\n"}))
    (folder / "$I0QW7LM.ps1").write_bytes(b.build_i_file("C:\\Users\\Public\\sync.ps1", 2048, _t(150)))
    for name, when in (("$IR8K2QF.zip", _t(135)), ("$RR8K2QF.zip", _t(130)), ("$I0QW7LM.ps1", _t(150))):
        _touch(folder / name, when)


def _browsers(appdata: Path) -> None:
    b.build_chrome_history(
        appdata / "Local/Google/Chrome/User Data/Default/History",
        visits=[("https://www.contoso.example/intranet", "Intranet", _t(-60 * 6), 0),
                ("https://mail.contoso.example/owa/", "Correo", _t(-60 * 5), 1),
                ("http://update-cdn.example/factura_septiembre.html", "Factura pendiente", _t(10), 0),
                ("https://pastebin.com/raw/Xk3vPq9z", "", _t(22), 1)],
        downloads=[("http://update-cdn.example/dl/Factura_0914.pdf.exe",
                    f"C:\\Users\\{USER}\\Downloads\\Factura_0914.pdf.exe", _t(12), 350_208)])
    b.build_firefox_places(
        appdata / "Roaming/Mozilla/Firefox/Profiles/k2x9f.default-release/places.sqlite",
        visits=[("https://www.wikipedia.org/", "Wikipedia", _t(-60 * 30), 2),
                ("https://transfer.sh/", "transfer.sh", _t(100), 2)],
        downloads=[("https://www.7-zip.org/a/7z2408-x64.exe", f"C:\\Users\\{USER}\\Downloads\\7z2408-x64.exe",
                    _t(78))])


def _files(c: Path) -> None:
    docs = c / f"Users/{USER}/Documents"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "informe_trimestral.pdf").write_bytes(b.build_pdf("Informe trimestral Q3"))
    (docs / "notas.txt").write_text(
        "Proveedor nuevo: pagos a la cuenta indicada por exfil@proton.example\n"
        "Servidor de actualización: http://update-cdn.example/dl/ (198.51.100.23)\n"
        "Clave persistencia: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\n",
        encoding="utf-8")
    pictures = c / f"Users/{USER}/Pictures"
    pictures.mkdir(parents=True, exist_ok=True)
    (pictures / "vacaciones.jpg").write_bytes(b.build_zip({"clientes.csv": b"id;nombre;iban\n1;ACME;ES00\n"}))
    (pictures / "logo.png").write_bytes(b.build_png())
    public = c / "Users/Public"
    public.mkdir(parents=True, exist_ok=True)
    (public / "svchost.exe").write_bytes(MALWARE)
    _touch(public / "svchost.exe", datetime(2019, 12, 7, 9, 10, tzinfo=timezone.utc))  # time-stomped
    _touch(docs / "notas.txt", _t(60))
    _touch(docs / "informe_trimestral.pdf", _t(-60 * 24 * 12))
    _touch(pictures / "vacaciones.jpg", _t(87))
    _touch(pictures / "logo.png", _t(-60 * 24 * 200))


def _mft(path: Path) -> None:
    ft = b.to_filetime
    old = ft(_t(-60 * 24 * 400))
    normal = (old, old, old, old)
    records: dict[int, bytes] = {
        0: b.build_mft_record(0, "$MFT", 5, si=normal, fn=normal, size=262144),
        5: b.build_mft_record(5, ".", 5, si=normal, fn=normal, directory=True, parent_sequence=5, sequence=5),
        64: b.build_mft_record(64, "Users", 5, si=normal, fn=normal, directory=True, parent_sequence=5),
        65: b.build_mft_record(65, "Public", 64, si=normal, fn=normal, directory=True),
        66: b.build_mft_record(66, USER, 64, si=normal, fn=normal, directory=True),
        67: b.build_mft_record(67, "Downloads", 66, si=normal, fn=normal, directory=True),
    }
    # svchost.exe: $SI back-dated to 2019 with whole seconds, $FN keeps the real creation time.
    stomped = ft(datetime(2019, 12, 7, 9, 10, 0, tzinfo=timezone.utc))
    real = ft(_t(25)) + 1234567
    records[70] = b.build_mft_record(70, "svchost.exe", 65, si=(stomped, stomped, real, real),
                                     fn=(real, real, real, real), size=len(MALWARE),
                                     zone_identifier="[ZoneTransfer]\r\nZoneId=3\r\n"
                                                     "HostUrl=http://update-cdn.example/dl/svchost.exe\r\n")
    dl = ft(_t(12)) + 4321
    records[71] = b.build_mft_record(71, "Factura_0914.pdf.exe", 67, si=(dl, dl, dl, dl), fn=(dl, dl, dl, dl),
                                     size=350208, zone_identifier="[ZoneTransfer]\r\nZoneId=3\r\n"
                                     "ReferrerUrl=http://update-cdn.example/factura_septiembre.html\r\n"
                                     "HostUrl=http://update-cdn.example/dl/Factura_0914.pdf.exe\r\n")
    gone = ft(_t(130)) + 777
    records[72] = b.build_mft_record(72, "clientes_2026.zip", 66, si=(gone, gone, gone, gone),
                                     fn=(gone, gone, gone, gone), size=1048576, in_use=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        for number in range(max(records) + 1):
            fh.write(records.get(number, b"\x00" * 1024))


def _disk_image(path: Path) -> None:
    rng = random.Random(1337)
    image = bytearray(512 * 1024)
    for pos in range(0, len(image), 4096):  # sprinkle some non-zero noise
        image[pos:pos + 64] = bytes(rng.randrange(0, 0xFE) for _ in range(64))
    thumb = b.build_jpeg(bytes(range(16, 80)))
    placements = (
        (8 * 1024, b.build_jpeg(bytes(range(1, 255)) * 8, thumbnail=thumb)),
        (40 * 1024, b.build_png(16, 16, (20, 120, 200))),
        (72 * 1024, b.GIF_1X1),
        (100 * 1024, b.build_pdf("Contrato confidencial")),
        (160 * 1024, b.build_zip({"clientes_2026.csv": b"id;nombre;iban\n1;ACME;ES00 0000\n"})),
        (220 * 1024, "Enviar a exfil@proton.example desde 198.51.100.23 via http://update-cdn.example/up"
                     .encode("utf-16-le")),
    )
    for offset, data in placements:
        image[offset:offset + len(data)] = data
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(image))


def _prefetch(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    vol = "\\DEVICE\\HARDDISKVOLUME3"
    entries = (
        ("EXCEL.EXE", 0x4A81B3C2, 57, _t(-60), [f"{vol}\\PROGRAM FILES\\MICROSOFT OFFICE\\ROOT\\OFFICE16\\EXCEL.EXE"]),
        ("SVCHOST.EXE", 0x6E0D1C17, 2, _t(26), [f"{vol}\\USERS\\PUBLIC\\SVCHOST.EXE",
                                                f"{vol}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"]),
        ("MIMIKATZ.EXE", 0x2C0F96A1, 1, _t(58), [f"{vol}\\USERS\\PUBLIC\\TOOLS\\MIMIKATZ.EXE",
                                                 f"{vol}\\WINDOWS\\SYSTEM32\\SAMLIB.DLL"]),
        ("RCLONE.EXE", 0x7D3E5A08, 1, _t(120), [f"{vol}\\USERS\\PUBLIC\\TOOLS\\RCLONE.EXE",
                                                f"{vol}\\USERS\\MARIA\\DESKTOP\\CLIENTES_2026.ZIP"]),
    )
    for exe, prefetch_hash, runs, when, files in entries:
        path = folder / f"{exe}-{prefetch_hash:08X}.pf"
        path.write_bytes(b.build_prefetch_v23(exe, prefetch_hash, runs, when, files, vol, 0x6A2F11C0))
        _touch(path, when)


def _usrclass(path: Path) -> None:
    h = b.HiveBuilder(default_time=_t(-60 * 24 * 30))
    h.key("Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags")
    this_pc = "20d04fe0-3aea-1069-a2d8-08002b30309d"
    network = "208d2c60-3aea-1069-a2d7-08002b30309d"
    folder = b.shell_file_entry
    tree = [
        (b.shell_root(this_pc), [
            (b.shell_volume("E:\\"), [(folder("clientes", _t(80), _t(80), _t(92), 41), None)]),
            (b.shell_volume("C:\\"), [(folder("Users", _t(-9e5), _t(-9e5), _t(20), 70), [
                (folder("Public", _t(-9e5), _t(-9e5), _t(25), 71), [(folder("Tools", _t(57), _t(57), _t(119), 72), None)]),
            ])]),
        ]),
        (b.shell_root(network, 0x58), [
            (b.shell_network("\\\\192.0.2.20\\C$"), None),
            (b.shell_network("\\\\192.0.2.10\\finanzas"), None),
        ]),
    ]
    b.add_shellbags(h, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", tree, _t(93))
    h.save(path)


# -- memory (Volatility 3 JSON outputs) --------------------------------------------
def _memory(folder: Path) -> None:
    """Outputs of ``vol -r json`` for a RAM capture taken at the end of the intrusion."""
    folder.mkdir(parents=True, exist_ok=True)
    boot, captured = _t(-600), _t(155)
    system32 = "C:\\Windows\\System32\\"
    # pid, ppid, name, created, exited, path, command line, threads, in pslist
    procs = [
        (4, 0, "System", boot, None, "", "", 160, True),
        (368, 4, "smss.exe", boot, None, "\\SystemRoot\\System32\\smss.exe", "\\SystemRoot\\System32\\smss.exe", 2,
         True),
        (476, 460, "csrss.exe", boot, None, system32 + "csrss.exe", "%SystemRoot%\\system32\\csrss.exe "
         "ObjectDirectory=\\Windows", 12, True),
        (552, 460, "wininit.exe", boot, None, system32 + "wininit.exe", "wininit.exe", 1, True),
        (636, 544, "winlogon.exe", boot, None, system32 + "winlogon.exe", "winlogon.exe", 5, True),
        (696, 552, "services.exe", boot, None, system32 + "services.exe", system32 + "services.exe", 7, True),
        (712, 552, "lsass.exe", boot, None, system32 + "lsass.exe", system32 + "lsass.exe", 9, True),
        (832, 696, "svchost.exe", boot, None, system32 + "svchost.exe", system32 + "svchost.exe -k DcomLaunch -p", 21,
         True),
        (904, 696, "svchost.exe", boot, None, system32 + "svchost.exe", system32 + "svchost.exe -k RPCSS -p", 11, True),
        (1204, 696, "svchost.exe", boot, None, system32 + "svchost.exe", system32 + "svchost.exe -k netsvcs -p", 48,
         True),
        (1688, 696, "spoolsv.exe", boot, None, system32 + "spoolsv.exe", system32 + "spoolsv.exe", 9, True),
        (2040, 696, "MsMpEng.exe", boot, None, "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24080"
         "\\MsMpEng.exe", '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24080\\MsMpEng.exe"', 31,
         True),
        (3964, 3940, "explorer.exe", _t(-540), None, "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", 74,
         True),
        (4410, 3964, "OneDrive.exe", _t(-539), None, f"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\"
         "OneDrive.exe", f'"C:\\Users\\{USER}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', 22,
         True),
        (5120, 3964, "EXCEL.EXE", _t(-20), None, "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
         f'"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Users\\{USER}\\Documents\\'
         'finanzas\\cierre.xlsx"', 18, True),
        (6012, 3964, "powershell.exe", _t(24), _t(25.5), "", "", 0, False),
        (6248, 6012, "svchost.exe", _t(26), None, "C:\\Users\\Public\\svchost.exe",
         "C:\\Users\\Public\\svchost.exe --silent", 6, True),
        (6400, 696, "wupd.exe", _t(42), None, "C:\\Windows\\Temp\\wupd.exe", "C:\\Windows\\Temp\\wupd.exe -k netsvcs",
         4, True),
        (6990, 6248, "cmd.exe", _t(57), None, system32 + "cmd.exe", "C:\\Windows\\system32\\cmd.exe", 1, True),
        (7012, 6990, "mimikatz.exe", _t(58), _t(59), "", "", 0, False),
        (7344, 6990, "rclone.exe", _t(120), _t(128), "", "", 0, False),
        (7660, 6248, "scvhost.exe", _t(131), None, "", "", 3, False),
    ]
    rows = []
    for pid, ppid, name, created, exited, path, cmd, threads, listed in procs:
        rows.append({"PID": pid, "PPID": ppid, "ImageFileName": name[:14], "Offset(V)": 0xFFFF_A000_0000_0000 + pid * 0x80,
                     "Threads": threads, "Handles": None if exited else 40 + threads * 7, "SessionId": 0 if pid < 3000
                     or name in ("wupd.exe",) else 1, "Wow64": False, "CreateTime": created.isoformat(),
                     "ExitTime": exited.isoformat() if exited else None, "File output": "Disabled", "__children": [],
                     "_path": path, "_cmd": cmd, "_listed": listed})

    def public(row: dict, *extra: str) -> dict:
        return {**{k: v for k, v in row.items() if not k.startswith("_") and k not in extra}, "__children": []}

    pslist = [public(r) for r in rows if r["_listed"]]
    psscan = [{**public(r), "Offset(V)": 0x1_2000_0000 + r["PID"] * 0x80} for r in rows]
    nodes = {r["PID"]: {**public(r, "File output"), "Audit": r["_path"].replace("C:", "\\Device\\HarddiskVolume3"),
                        "Cmd": r["_cmd"] or None, "Path": r["_path"] or None} for r in rows if r["_listed"]}
    tree = []
    for node in nodes.values():
        parent = nodes.get(node["PPID"])
        (parent["__children"] if parent else tree).append(node)
    cmdline = [{"PID": r["PID"], "Process": r["ImageFileName"], "Args": r["_cmd"] or
                f"Required memory at 0x{0x7FF0000 + r['PID']:x} is not valid (process exited?)", "__children": []}
               for r in rows if r["_listed"]]
    info = [{"Variable": k, "Value": v, "__children": []} for k, v in (
        ("Kernel Base", "0xf8015a600000"), ("Is64Bit", True), ("IsPAE", False), ("layer_name", "0 WindowsIntel32e"),
        ("NtSystemRoot", "C:\\Windows"), ("NtProductType", "NtProductWinNt"), ("NtMajorVersion", 10),
        ("NtMinorVersion", 0), ("NtBuildLab", "19041.1.amd64fre.vb_release.191206-1406"),
        ("SystemTime", captured.isoformat()), ("KeNumberProcessors", 4))]

    def conn(proto, local, lport, remote, rport, state, pid, owner, created):
        return {"Offset": 0xE000_0000 + pid * 16 + lport, "Proto": proto, "LocalAddr": local, "LocalPort": lport,
                "ForeignAddr": remote, "ForeignPort": rport, "State": state, "PID": pid, "Owner": owner,
                "Created": created.isoformat() if created else None, "__children": []}
    netscan = [
        conn("TCPv4", "0.0.0.0", 135, "0.0.0.0", 0, "LISTENING", 904, "svchost.exe", boot),
        conn("TCPv4", "0.0.0.0", 445, "0.0.0.0", 0, "LISTENING", 4, "System", boot),
        conn("TCPv4", "192.0.2.45", 49822, "203.0.113.80", 443, "ESTABLISHED", 4410, "OneDrive.exe", _t(140)),
        conn("TCPv4", "192.0.2.45", 49731, "198.51.100.23", 443, "ESTABLISHED", 6248, "svchost.exe", _t(26.5)),
        conn("TCPv4", "192.0.2.45", 49790, "198.51.100.23", 8443, "CLOSED", 7344, "rclone.exe", _t(121)),
        conn("UDPv4", "0.0.0.0", 5353, "*", 0, "", 1204, "svchost.exe", boot),
    ]
    mz = "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00"
    malfind = [
        {"PID": 3964, "Process": "explorer.exe", "Start VPN": 0x3A50000, "End VPN": 0x3A8FFFF, "Tag": "VadS",
         "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 64, "PrivateMemory": 1, "File output": "Disabled",
         "Notes": "MZ header", "Hexdump": mz, "Disasm": "0x3a50000:\tpop\tr10\n0x3a50002:\tnop", "__children": []},
        {"PID": 2040, "Process": "MsMpEng.exe", "Start VPN": 0x1F2D0000, "End VPN": 0x1F2D0FFF, "Tag": "VadS",
         "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1, "PrivateMemory": 1, "File output": "Disabled",
         "Notes": None, "Hexdump": "48 89 5c 24 08 57 48 83 ec 20 48 8b d9 e8 00 00", "Disasm": "", "__children": []},
    ]

    def svc(order, pid, start, state, name, display, binary, dll=None):
        return {"Offset": 0x2D0000 + order * 0x100, "Order": order, "PID": pid, "Start": start, "State": state,
                "Type": "SERVICE_WIN32_OWN_PROCESS", "Name": name, "Display": display, "Binary": binary,
                "Binary (Registry)": binary, "Dll": dll, "__children": []}
    svcscan = [
        svc(12, 1688, "SERVICE_AUTO_START", "SERVICE_RUNNING", "Spooler", "Print Spooler", system32 + "spoolsv.exe"),
        svc(40, 2040, "SERVICE_AUTO_START", "SERVICE_RUNNING", "WinDefend", "Microsoft Defender Antivirus Service",
            '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24080\\MsMpEng.exe"'),
        svc(77, 6400, "SERVICE_AUTO_START", "SERVICE_RUNNING", "WinUpdateSvc", "Windows Update Helper",
            "C:\\Windows\\Temp\\wupd.exe -k netsvcs"),
        svc(78, 1204, "SERVICE_AUTO_START", "SERVICE_RUNNING", "Schedule", "Task Scheduler",
            system32 + "svchost.exe -k netsvcs -p", system32 + "schedsvc.dll"),
    ]
    outputs = {"info": info, "pslist": pslist, "psscan": psscan, "pstree": tree, "cmdline": cmdline,
               "netscan": netscan, "malfind": malfind, "svcscan": svcscan}
    for plugin, data in outputs.items():
        (folder / f"{HOST}.windows.{plugin}.json").write_text(json.dumps(data, indent=2, sort_keys=True),
                                                             encoding="utf-8")
    (folder / "README.txt").write_text(
        f"vol -r json -f {HOST}.raw windows.<plugin>  (memoria capturada / memory captured {captured:%Y-%m-%d %H:%M} "
        "UTC)\n", encoding="utf-8")
