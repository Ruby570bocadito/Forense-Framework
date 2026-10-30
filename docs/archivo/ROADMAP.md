# Hoja de ruta de producto — Sabueso-Framework

Documento de planificación a medio y largo plazo (v0.4.0 → v1.0 y después). Complementa, no sustituye, a
`docs/agentes/ROADMAP.md`, que sigue siendo la cola operativa de tareas de los agentes: de aquí salen las tareas que
DIR va promoviendo a esa cola, con el formato `- [ ] (ID) slug — descripción — rutas`.

Base del diagnóstico: código en `a937ea3` (27 módulos = 21 Windows + 6 genéricos, ~17.600 líneas de producto,
~295 tests, esquema de caso v1, README es/en de ~660 líneas, CI en Linux/Windows con Python 3.10 y 3.12).

---

## Índice

1. [Diagnóstico del estado actual](#1-diagnóstico-del-estado-actual)
2. [Principios que guían la hoja de ruta](#2-principios-que-guían-la-hoja-de-ruta)
3. [Visión por versiones](#3-visión-por-versiones)
4. [Eje A — README y documentación](#eje-a--readme-y-documentación)
5. [Eje B — Calidad de código y arquitectura](#eje-b--calidad-de-código-y-arquitectura)
6. [Eje C — Nuevos artefactos de Windows](#eje-c--nuevos-artefactos-de-windows)
7. [Eje D — Profundizar los módulos existentes](#eje-d--profundizar-los-módulos-existentes)
8. [Eje E — Imágenes, sistemas de archivos y adquisición](#eje-e--imágenes-sistemas-de-archivos-y-adquisición)
9. [Eje F — Memoria RAM](#eje-f--memoria-ram)
10. [Eje G — Detección: Sigma, YARA y heurísticas](#eje-g--detección-sigma-yara-y-heurísticas)
11. [Eje H — Inteligencia de amenazas e indicadores](#eje-h--inteligencia-de-amenazas-e-indicadores)
12. [Eje I — Línea temporal, correlación y análisis](#eje-i--línea-temporal-correlación-y-análisis)
13. [Eje J — Linux, macOS y otras plataformas](#eje-j--linux-macos-y-otras-plataformas)
14. [Eje K — Interfaz web](#eje-k--interfaz-web)
15. [Eje L — Informes periciales](#eje-l--informes-periciales)
16. [Eje M — Automatización, API e integraciones](#eje-m--automatización-api-e-integraciones)
17. [Eje N — Rendimiento y escala](#eje-n--rendimiento-y-escala)
18. [Eje O — Seguridad y garantías forenses](#eje-o--seguridad-y-garantías-forenses)
19. [Eje P — Pruebas y aseguramiento de calidad](#eje-p--pruebas-y-aseguramiento-de-calidad)
20. [Eje Q — Empaquetado, distribución y releases](#eje-q--empaquetado-distribución-y-releases)
21. [Eje R — Internacionalización](#eje-r--internacionalización)
22. [Eje S — Comunidad y gobierno del proyecto](#eje-s--comunidad-y-gobierno-del-proyecto)
23. [Pulido transversal (checklist)](#pulido-transversal-checklist)
24. [Dependencias críticas entre tareas](#dependencias-críticas-entre-tareas)
25. [Riesgos](#riesgos)
26. [Métricas de éxito](#métricas-de-éxito)

Leyenda de cada tarea:

- **Prioridad**: P0 (bloquea la versión), P1 (debería entrar), P2 (deseable), P3 (exploratoria).
- **Esfuerzo**: S (< 1 sesión), M (1–2 sesiones), L (3–5 sesiones), XL (épica; dividir antes de empezar).
- **Zona**: el rol de `docs/agentes/OWNERSHIP.md` que la ejecuta (IMP-1, IMP-2, PUL, SEG, TEST, DIR).

---

## 1. Diagnóstico del estado actual

### Fortalezas (lo que hay que proteger)

- **Garantías forenses sólidas**: evidencia en solo lectura, hashes MD5/SHA-1/SHA-256, custodia encadenada por
  SHA-256, resultados verificables, evidencia derivada trazable, firma Ed25519 de informes.
- **Cobertura de Windows amplia**: EVTX con Sigma, registro (incluidos logs de transacciones y celdas borradas),
  $MFT/$UsnJrnl/$LogFile, Prefetch, SRUM, ShellBags, Jump Lists, LNK, papelera, navegadores, WMI, Defender,
  PSReadLine, Timeline, notificaciones, caché RDP, setupapi, memoria con Volatility 3.
- **Contenedores**: E01, raw/split, VHD/VHDX (incl. diferenciales), VMDK, QCOW2, VSS y BitLocker sin montar nada.
- **Flujo completo**: caso → evidencia → triaje → revisión → ATT&CK → STIX → informe HTML/PDF, por CLI, web o
  automatización (`auto`, `vigilar`, playbooks, webhooks).
- **Bilingüe de verdad**: datos en códigos neutros y textos en locales; el mismo caso se informa en es o en.
- **Disciplina de ingeniería**: parsers tolerantes a entradas hostiles, guardia ReDoS en Sigma, gate de tamaño
  (`read_capped`), auditoría de subprocesos/YAML, e2e por "personas", CI con instaladores y PDF real.

### Huecos detectados (lo que motiva esta hoja de ruta)

| Área | Hueco concreto |
|---|---|
| Documentación | `sabueso intel misp` (2b1fb2f) no aparece en la tabla CLI ni en el README; la "Hoja de ruta" del README aún lista MISP como pendiente; la fila de `logfile` no refleja la tabla de atributos abiertos (9267745); README de 660 líneas sin capturas, sin badges, sin documentación de referencia separada; no hay CHANGELOG, CONTRIBUTING ni SECURITY. |
| Releases | `__version__ = "0.4.0"` pero no hay etiquetas `v*` publicadas: el flujo `release` existe y nunca se ha disparado. |
| Arquitectura | `cli.py` (1.088 líneas) y `web/__init__.py` (775) concentran demasiado; los módulos se registran por import, sin descubrimiento de plugins de terceros; `SCHEMA_VERSION = 1` con migración ad hoc. |
| Calidad | Sin tipado estático comprobado (mypy/pyright), sin cobertura medida en CI, sin fuzzing sistemático de parsers. |
| Artefactos | Faltan BITS, Amcache completo (InventoryApplicationFile y compañía), $Secure/$SDS, ETL, WER, Office MRU/Trust Records, Outlook, OneDrive/Teams, IIS/Exchange, Hiberfil/Pagefile, cuentas Microsoft/Entra… |
| Plataformas | Solo Windows como sistema analizado (Linux/macOS en backlog desde hace tiempo). |
| Web | Servidor de desarrollo de Flask, HTTP Basic con una única contraseña, sin usuarios, roles ni bloqueo de concurrencia entre analistas. |
| Integraciones | Sin API REST documentada, sin exportación Timesketch/Plaso/ECS, sin TAXII, OpenCTI pendiente. |
| Escala | Un SQLite por caso y búsquedas `LIKE`; sin índice de texto completo ni procesamiento paralelo de módulos. |
| Coordinación | `docs/agentes/ROADMAP.md` lista como abiertas tareas ya entregadas (h-010-verificacion, web-duplicada-aviso, sigma-redos-revision, logfile-atributos, readbytes-gate, refs-rama-heredada, intel-misp-opencti). |

---

## 2. Principios que guían la hoja de ruta

1. **Fiabilidad antes que vistosidad.** Ninguna función nueva justifica debilitar la inmutabilidad de la evidencia,
   la custodia o la reproducibilidad. Cada módulo nuevo llega con muestra real con licencia o no llega.
2. **Indicios, no veredictos.** Toda detección nueva debe explicar por qué dispara, con qué confianza y qué la
   contradiría; la revisión del analista sigue siendo la fuente de verdad del informe.
3. **Sin red por defecto.** La herramienta funciona en laboratorios aislados; toda función que use red es explícita,
   desactivable y queda en custodia (destino, no credenciales).
4. **Bilingüe desde el primer commit.** Ningún texto visible sin clave en `es.json` y `en.json`.
5. **Una entrega = algo completo.** Código + locales + demo sintética honesta + tests + fila del README (vía PUL).
6. **Compatibilidad de casos.** Un caso creado con cualquier versión ≥ 0.4 se abre, verifica e informa con las
   siguientes (migraciones probadas, nunca destructivas).

---

## 3. Visión por versiones

| Versión | Tema | Contenido principal | Criterio de salida |
|---|---|---|---|
| **0.4.x** (inmediata) | *Puesta al día* | Sincronizar README/ROADMAP con lo entregado, CHANGELOG, primera release etiquetada | `v0.4.1` publicada con rueda, exe y Docker; README sin desfases |
| **0.5** | *Cimientos* | Refactor de CLI y web en paquetes, tipado, cobertura, migraciones versionadas, plugins por entry points, docs de referencia | mypy limpio en `core/` y `parsers/`; cobertura ≥ 85 % medida en CI; guía de desarrollo de módulos publicada |
| **0.6** | *Windows profundo* | BITS, Amcache completo, ETL/WER, Office/Outlook, OneDrive/Teams, $Secure, Hiberfil/Pagefile, parser CIM de WMI, carving fragmentado | 10+ artefactos nuevos con muestras reales y licencia documentada |
| **0.7** | *Interoperabilidad* | API REST, exportación Timesketch/Plaso/ECS/JSONL, OpenCTI y TAXII 2.1, Velociraptor/KAPE como fuentes, plugins de terceros | Un caso viaja ida y vuelta con Timesketch y MISP/OpenCTI en un e2e |
| **0.8** | *Equipo* | Multiusuario con cuentas y roles, servidor WSGI de producción, bloqueo optimista, auditoría de accesos, HTTPS integrado | 3 analistas trabajan en el mismo caso sin conflictos en un e2e |
| **0.9** | *Multiplataforma* | Linux (logs, auditd, journald, persistencia, bash history), macOS (Unified Logs, FSEvents, KnowledgeC, plists) | Triaje Linux y macOS con hallazgos y ATT&CK; demos sintéticas de ambos |
| **1.0** | *Estabilidad* | Congelación de esquema y API, documentación completa, auditoría de seguridad externa, rendimiento probado con casos de 100 GB | Garantía de compatibilidad publicada; benchmark reproducible en la documentación |
| **1.x+** | *Más allá* | Nube (M365/Entra, AWS, Azure), móviles (iOS/Android vía extracciones lógicas), asistencia al analista, colaboración entre organizaciones | Según demanda y muestras disponibles |

---

## Eje A — README y documentación

### A.1 Sincronización inmediata (0.4.x)

- **A1 · readme-intel-misp** — P0 · S · PUL — Añadir `sabueso intel misp EXPORT.json [-o SALIDA]` (`inteligencia`)
  a la tabla CLI, una subsección "Importar inteligencia de MISP" dentro de *MITRE ATT&CK, relato e indicadores*
  con un ejemplo completo (exportación → watchlist → `analizar ioc -o watchlist=` → correlación) y los tipos MISP
  admitidos. Es/en.
- **A2 · readme-hoja-de-ruta-sync** — P0 · S · PUL — En "Hoja de ruta" del README: MISP pasa a hecho, queda
  "OpenCTI/TAXII"; enlazar este documento para el detalle.
- **A3 · readme-logfile-atributos** — P1 · S · PUL — Ampliar la fila de `logfile` y la limitación de `$LogFile`:
  ahora se nombran también las operaciones de atributo (0x05–0x09, 0x0B) vía la tabla de atributos abiertos.
- **A4 · readme-readbytes-gate** — P2 · S · PUL — Bala en "Modelo de seguridad": tope central de tamaño por
  artefacto (256 MB por defecto) y que un artefacto gigante se reporta como error de análisis.
- **A5 · readme-ejemplo-modulo** — P2 · S · PUL — El ejemplo de "cómo crear un módulo" usa `bits`, que no existe
  y está bloqueado: cambiarlo por un ejemplo neutro (`example`) o por un módulo real recortado para no confundir.
- **A6 · roadmap-agentes-limpieza** — P0 · S · DIR — Marcar `[x]` en `docs/agentes/ROADMAP.md` lo ya entregado
  (h-010-verificacion, web-duplicada-aviso, sigma-redos-revision, logfile-atributos, readbytes-gate,
  refs-rama-heredada, intel-misp) y dividir intel en `intel-misp` (hecho) e `intel-opencti` (pendiente).

### A.2 Presentación del README (0.4.x – 0.5)

- **A7 · readme-badges** — P1 · S · PUL — Badges de CI, versión PyPI, licencia, Python soportado, imagen GHCR.
- **A8 · readme-capturas** — P1 · M · PUL+IMP-2 — Capturas (claro/oscuro) del resumen, línea temporal, ATT&CK y
  página de un informe, generadas automáticamente con Playwright sobre el caso demo (`scripts/screenshots.py`)
  para que no se queden viejas; GIF corto de `sabueso demo` → web.
- **A9 · readme-diagrama** — P2 · S · PUL — Diagrama del flujo (evidencia → extracción → módulos → hallazgos →
  revisión → informe/STIX) en SVG o Mermaid.
- **A10 · readme-adelgazar** — P1 · M · PUL — Dejar el README en ~250 líneas: qué es, por qué, instalación,
  inicio rápido, tabla de módulos resumida y enlaces; el detalle pasa a la documentación de referencia (A11).
- **A11 · readme-comparativa** — P3 · S · PUL — Tabla honesta frente a herramientas afines (Plaso, KAPE+EZTools,
  Autopsy, Velociraptor): qué hace cada una y cuándo usar Sabueso-Framework junto a ellas.

### A.3 Documentación de referencia (0.5)

- **A12 · docs-sitio** — P1 · L · PUL — Sitio con MkDocs Material (es/en con `mkdocs-static-i18n`) publicado en
  GitHub Pages desde CI. Secciones: Guía del analista, Referencia CLI, Referencia de módulos, Playbooks,
  Configuración, Modelo de seguridad, Formato del caso, Desarrollo.
- **A13 · docs-cli-autogenerada** — P1 · M · IMP-1+PUL — Referencia de la CLI generada desde argparse (es y en)
  para que nunca se desincronice; test que falla si cambia la CLI sin regenerar.
- **A14 · docs-modulos-autogenerada** — P1 · M · IMP-1+PUL — Página por módulo generada desde el registro:
  artefactos, opciones, tipos de registro, códigos de hallazgo con su severidad y técnica ATT&CK.
- **A15 · docs-hallazgos** — P1 · M · IMP-1 — Catálogo de todos los códigos de hallazgo con: qué significa, por qué
  dispara, falsos positivos habituales, cómo confirmarlo y referencia ATT&CK. Base para la guía del analista.
- **A16 · docs-formato-caso** — P2 · M · IMP-1 — Especificación del formato de caso (`sabueso.db`, tablas,
  custodia, carpetas) y garantías de compatibilidad, para que terceros puedan leerlo.
- **A17 · docs-guias** — P2 · L · PUL — Tutoriales paso a paso: "Mi primer caso", "Intrusión con RDP",
  "Ransomware", "Fuga de información por USB", "Análisis de memoria", "Playbook propio", "Trabajar con MISP".
- **A18 · docs-metodologia-pericial** — P2 · M · PUL — Guía de uso en peritaje judicial: ISO/IEC 27037, UNE 71506,
  RFC 3227, cómo anclar el hash de cabecera, qué adjuntar al dictamen.
- **A19 · docs-adr** — P2 · S · DIR — Carpeta `docs/adr/` con decisiones de arquitectura (SQLite por caso, sin red
  por defecto, códigos neutros, Ed25519…), para que los nuevos contribuidores entiendan el porqué.

---

## Eje B — Calidad de código y arquitectura

- **B1 · cli-paquete** — P1 · L · IMP-1 — Dividir `sabueso/cli.py` en `sabueso/cli/` (un archivo por grupo de
  órdenes: caso, evidencia, análisis, revisión, exportación, informe, automatización, utilidades) sin cambiar
  comportamiento; los e2e existentes son la red de seguridad.
- **B2 · web-blueprints** — P1 · L · IMP-2 — Dividir `sabueso/web/__init__.py` en blueprints (casos, evidencias,
  análisis, hallazgos, línea temporal, informes, API) con fábrica de app intacta.
- **B3 · tipado-estricto** — P1 · L · PUL — mypy (o pyright) en CI: primero `core/` y `parsers/` en modo estricto,
  después el resto; `py.typed` en el paquete.
- **B4 · cobertura-ci** — P1 · S · PUL — `pytest-cov` en CI con umbral (empezar en el valor actual y no bajar);
  informe de cobertura como artefacto de la ejecución.
- **B5 · migraciones-versionadas** — P0 (para 0.5) · M · IMP-1 — Sustituir `_migrate` por migraciones numeradas
  (`core/migrations/0002_*.py`), cada una con test que abre un caso de la versión anterior real (fixtures
  `tests/data/cases/v0.4/`), y registro en custodia de la migración aplicada.
- **B6 · plugins-entry-points** — P1 · M · IMP-1 — Descubrir módulos externos por `importlib.metadata`
  (`sabueso.modules` entry point) con aislamiento de errores: un plugin roto no tumba la herramienta; `doctor` los
  lista; los textos del plugin traen sus propios locales.
- **B7 · contrato-modulo-v2** — P2 · M · IMP-1 — Declarar en el módulo metadatos hoy implícitos: tipos de registro
  que produce, códigos de hallazgo con severidad y técnica ATT&CK por defecto, artefactos que consume; sirve a A14,
  A15 y a validaciones automáticas.
- **B8 · errores-unificados** — P2 · M · IMP-1 — Jerarquía de errores única (`core/errors.py`) con código de salida
  estable por tipo y mensaje localizado; documentar los códigos de salida.
- **B9 · logging-estructurado** — P2 · M · IMP-1 — `logging` con salida JSON opcional (`--log-json`) y nivel por
  módulo; identificador de análisis en cada línea para depurar casos grandes.
- **B10 · pre-commit** — P2 · S · PUL — `.pre-commit-config.yaml` con ruff, ruff-format, mypy y verificación de
  locales.
- **B11 · formato** — P2 · S · PUL — Adoptar `ruff format` en un único commit de formato (con `.git-blame-ignore-revs`).
- **B12 · deuda-heuristicas** — P2 · M · IMP-1 — Extraer listas de herramientas ofensivas, rutas sospechosas y
  dominios legítimos a datos versionados (`sabueso/data/*.yaml`) actualizables sin tocar código.

---

## Eje C — Nuevos artefactos de Windows

Cada tarea: módulo + registro + locales es/en + demo sintética honesta (si procede) + tests con muestra real y
licencia en `tests/data/README.md`. Sin muestra real, la tarea queda **bloqueada** (como BITS hoy).

### C.1 Ejecución y persistencia

- **C1 · artifact-bits** — P1 · M · IMP-1 — `qmgr.db` (ESE, Win10+) y `qmgr0.dat/qmgr1.dat` (legado): trabajos,
  URL, destino, estado, propietario; hallazgo T1197. *Desbloqueo*: generar la muestra en una VM propia y donarla
  con licencia CC0 documentando el procedimiento.
- **C2 · artifact-amcache-completo** — P1 · M · IMP-1 — Amcache moderno: `InventoryApplicationFile`,
  `InventoryApplication`, `InventoryDriverBinary`, `InventoryDevicePnp`, `InventoryApplicationShortcut`; drivers
  no firmados como hallazgo (T1014/T1543.003).
- **C3 · artifact-pca** — P1 · S · IMP-1 — Program Compatibility Assistant de Windows 11 22H2+
  (`C:\Windows\appcompat\pca\PcaAppLaunchDic.txt`, `PcaGeneralDb*.txt`): fuente de ejecución nueva para la vista
  de Ejecución.
- **C4 · artifact-services-drivers** — P2 · M · IMP-1 — Servicios y drivers con verificación de firma Authenticode
  de los binarios extraídos (sin red: catálogo local) y binarios en rutas de usuario.
- **C5 · artifact-com-hijack** — P2 · S · IMP-1 — Secuestro COM (`InprocServer32` en HKCU), `AppCertDlls`,
  `Netsh helpers`, `LSA packages`, `Print monitors`, `Active Setup`: persistencias poco cubiertas (T1546.*).
- **C6 · artifact-startup-completo** — P2 · S · IMP-1 — Unificar todas las persistencias en una vista
  "Autoruns" (como Sysinternals Autoruns) con fuente, usuario, fecha y estado.

### C.2 Actividad del usuario

- **C7 · artifact-office** — P1 · M · IMP-1 — Office MRU, Trust Records (macros habilitadas: T1204.002),
  Backstage, `OfficeFileCache`; hallazgo "documento con macros habilitado por el usuario".
- **C8 · artifact-outlook** — P2 · L · IMP-1 — PST/OST (con `libpff-python`): metadatos de correos, adjuntos con
  hash, reglas de reenvío (T1114.003); sin indexar cuerpos por defecto (privacidad).
- **C9 · artifact-onedrive** — P2 · M · IMP-1 — OneDrive (`SyncDiagnostics.log`, `*.odl`, `settings/*.dat`):
  archivos sincronizados y eliminados, cuentas; indicio de exfiltración.
- **C10 · artifact-teams-slack** — P3 · M · IMP-1 — Teams nuevo/clásico (LevelDB/IndexedDB), Slack: mensajes y
  archivos compartidos.
- **C11 · artifact-search-index** — P2 · L · IMP-1 — Windows Search (`Windows.edb`/`Windows.db` en Win11):
  archivos indexados que ya no existen, contenido parcial.
- **C12 · artifact-thumbcache** — P2 · M · IMP-1 — `thumbcache_*.db` e `IconCache.db`: miniaturas de imágenes ya
  borradas, extraídas como evidencia derivada.
- **C13 · artifact-ual** — P2 · M · IMP-1 — User Access Logging de Windows Server (`SystemIdentity.mdb`,
  `Current.mdb`): accesos de clientes por IP y usuario durante tres años.
- **C14 · artifact-mru-extra** — P3 · S · IMP-1 — OpenSaveMRU, LastVisitedMRU, WordWheelQuery, MountPoints2,
  MapNetworkDriveMRU, TypedURLs.

### C.3 Sistema y registros

- **C15 · artifact-etl** — P2 · L · IMP-1 — ETL relevantes (`WDI`, `LwtNetLog`, `ShutdownCKCS`, `DefenderApiLogger`)
  con un parser acotado y tolerante.
- **C16 · artifact-wer** — P1 · S · IMP-1 — Windows Error Reporting (`*.wer`, `ReportArchive`): fallos de
  herramientas ofensivas o de `lsass.exe` (indicio de volcado).
- **C17 · artifact-hiberfil-pagefile** — P2 · L · IMP-1 — `hiberfil.sys` (descompresión Xpress a raw para
  `memory`) y búsqueda de cadenas/IOC en `pagefile.sys`/`swapfile.sys`.
- **C18 · artifact-secure-sds** — P2 · M · IMP-1 — `$Secure:$SDS`: propietario y ACL de cada entrada del $MFT
  (quién creó el archivo).
- **C19 · artifact-iis-exchange** — P2 · M · IMP-1 — Logs de IIS (W3C), Exchange (HttpProxy, OWA), webshells en
  `inetpub` (T1505.003) con detecciones tipo ProxyLogon/ProxyShell.
- **C20 · artifact-firewall-rdp** — P2 · S · IMP-1 — `pfirewall.log`, reglas de firewall añadidas, `Terminal Server
  Client\Servers`, `RDP bitmap` ya existe: completar con `Default.rdp`.
- **C21 · artifact-cuentas-cloud** — P3 · M · IMP-1 — Cuentas Microsoft/Entra en el equipo (`CloudAP`, `AAD`
  Broker, tokens PRT presentes —sin extraerlos—), Windows Hello.
- **C22 · artifact-antivirus-terceros** — P3 · M · IMP-1 — Cuarentenas y logs de AV de terceros (Sophos,
  Symantec, ESET, Kaspersky, CrowdStrike sensor logs si accesibles).
- **C23 · artifact-scheduled-legacy** — P3 · S · IMP-1 — `SchedLgU.txt`, tareas `.job` (formato XP/2003).

---

## Eje D — Profundizar los módulos existentes

- **D1 · wmi-parser-cim** — P1 · XL · IMP-1 — Parser completo del repositorio CIM (`INDEX.BTR`, `MAPPING*.MAP`,
  `OBJECTS.DATA`): clases, instancias, consumidores, con fechas; mantener la búsqueda de cadenas como respaldo.
- **D2 · carving-fragmentado** — P2 · XL · IMP-1 — Carving de archivos no contiguos (bifragment gap carving para
  JPEG/ZIP/PDF) y nuevos tipos (DOCX/XLSX validados, SQLite, EVTX chunks, colmenas `regf`, PE).
- **D3 · evtx-carving** — P1 · M · IMP-1 — Recuperar registros EVTX del espacio no asignado y de `pagefile`
  (chunks `ElfChnk`), clave cuando el atacante borró los logs.
- **D4 · evtx-mas-detecciones** — P1 · M · IMP-1 — Logon types con mapa por cuenta, kerberos (4768/4769/4771
  con AS-REP roasting), cambios de política de auditoría (4719), RDP shadowing, PowerShell 800/4103, AppLocker,
  WinRM (T1021.006), creación de cuentas de máquina.
- **D5 · mft-avanzado** — P2 · M · IMP-1 — Detectar `$SI` con nanosegundos a cero, archivos residentes recuperables,
  ADS sospechosos más allá de Zone.Identifier, `$I30` slack (entradas de índice borradas).
- **D6 · usnjrnl-carving** — P2 · M · IMP-1 — Registros USN en espacio no asignado y en VSS.
- **D7 · registry-mas-claves** — P2 · M · IMP-1 — Tareas en `TaskCache` (cruce con `tasks`), Defender exclusions
  (T1562.001), `Terminal Server` config, WDigest `UseLogonCredential` (T1112), SAM: fechas de cambio de contraseña y
  hash de política.
- **D8 · browsers-extra** — P2 · M · IMP-1 — Cookies (solo metadatos), formularios autocompletados, extensiones
  instaladas con permisos peligrosos, sesiones, caché de Chrome/Firefox; Edge legacy (ESE).
- **D9 · srum-tablas** — P2 · S · IMP-1 — Resto de tablas SRUM (energía, notificaciones push, uso de red por perfil).
- **D10 · jumplist-tope** — P1 · S · IMP-1 — Aplicar el gate de tamaño a `parse_custom` del parser de Jump Lists
  (propuesta de IMP-1, fuera del alcance de readbytes-gate).
- **D11 · notifications-defusedxml** — P2 · S · SEG — Evaluar `defusedxml` para el XML de las notificaciones
  (nota abierta de SEG).
- **D12 · logfile-fechas** — P3 · M · IMP-1 — Datar operaciones del $LogFile cruzando LSN con `$UsnJrnl` y el $MFT
  (aproximación con intervalo de confianza explícito).
- **D13 · rdp-cache-mosaico** — P2 · M · IMP-1 — Reconstruir mosaicos de pantalla a partir de los tiles (como
  `bmc-tools` + `RdpCacheStitcher` asistido) para el informe.

---

## Eje E — Imágenes, sistemas de archivos y adquisición

- **E1 · fs-refs** — P2 · XL · IMP-1 — ReFS (lectura básica de metadatos) mediante librería con licencia
  compatible o parser propio acotado.
- **E2 · fs-linux** — P1 · L · IMP-1 — ext4 (incluido journal), XFS y Btrfs vía TSK/`libfsext`/`libfsxfs` para
  el eje J.
- **E3 · fs-apfs-hfs** — P2 · L · IMP-1 — APFS (`libfsapfs`, con FileVault si hay clave) y HFS+ para macOS.
- **E4 · cifrado-extra** — P2 · L · IMP-1 — LUKS (`libluksde`) y VeraCrypt/TrueCrypt (con contraseña o clave
  extraída de memoria); mismas reglas que BitLocker: claves nunca guardadas, huella en custodia.
- **E5 · formatos-extra** — P2 · M · IMP-1 — AFF4, VDI (VirtualBox), `.dmg`, imágenes lógicas AD1 (FTK) y L01.
- **E6 · lvm-raid** — P3 · L · IMP-1 — LVM, Storage Spaces y RAID por software.
- **E7 · recoleccion-perfiles** — P1 · M · IMP-1 — Perfiles de recolección configurables (YAML) compatibles con
  los *targets* de KAPE; recolección de memoria integrada (llamando a WinPmem si está presente) respetando el
  orden de volatilidad.
- **E8 · recoleccion-remota** — P3 · L · IMP-1 — Recolección vía SMB/WinRM sobre equipos del dominio con
  credenciales explícitas y custodia por equipo.
- **E9 · adquisicion-imagen** — P3 · L · IMP-1 — `sabueso adquirir` para crear E01/raw con verificación y
  metadatos (útil en Linux/sabueso en caliente), sin pretender sustituir a herramientas certificadas.
- **E10 · vss-diferencias** — P2 · M · IMP-1 — Vista de diferencias entre instantáneas (qué cambió entre VSS1 y
  el volumen actual) como hallazgos y en la línea temporal.

---

## Eje F — Memoria RAM

- **F1 · memoria-plugins** — P1 · M · IMP-1 — Más plugins de Volatility 3: `dlllist`, `handles`, `ldrmodules`
  (DLL desenlazadas), `hollowprocesses`, `ssdt`, `callbacks`, `driverirp`, `modscan`, `registry.hivelist` (y
  extracción de colmenas de memoria a `registry`), `filescan`/`dumpfiles` (evidencia derivada).
- **F2 · memoria-credenciales** — P2 · M · IMP-1 — Detección (no extracción) de material de credenciales expuesto:
  `hashdump`/`lsadump` solo como indicio de exposición, con advertencia legal en el informe.
- **F3 · memoria-yara** — P1 · S · IMP-1 — `vadyarascan`/`yarascan` con las reglas YARA del caso.
- **F4 · memoria-linux-mac** — P2 · L · IMP-1 — Volcados Linux y macOS (Volatility 3 + ISF) para el eje J.
- **F5 · memoria-memprocfs** — P3 · L · IMP-1 — Backend alternativo MemProcFS para análisis rápidos en Windows.
- **F6 · memoria-simbolos-offline** — P2 · S · IMP-1 — Empaquetar y verificar un almacén de símbolos ISF offline
  (`sabueso memoria simbolos descargar DIR`) para laboratorios aislados.
- **F7 · memoria-timeline** — P2 · M · IMP-1 — Eventos de memoria con marcas de tiempo (creación de procesos,
  conexiones) en la superlínea con su fuente.

---

## Eje G — Detección: Sigma, YARA y heurísticas

- **G1 · sigma-correlaciones** — P1 · L · IMP-1 — Reglas de correlación Sigma (`event_count`, `value_count`,
  `temporal`, `temporal_ordered`) de la especificación 2.0.
- **G2 · sigma-pipelines** — P1 · M · IMP-1 — Mapeo de campos por fuente (pipelines) para aplicar Sigma también a
  registros no EVTX (PSReadLine, tareas, servicios del registro, logs de IIS, Linux auditd).
- **G3 · sigma-cobertura** — P2 · S · IMP-1 — `sabueso sigma check` informa de qué campos/modificadores no se
  soportan por regla; objetivo: ≥ 95 % de las reglas Windows de SigmaHQ cargables.
- **G4 · sigma-reglas-propias** — P2 · M · IMP-1 — Ampliar las 15 reglas integradas a ~50 de alto valor y bajo
  ruido, cada una con test positivo y negativo sobre EVTX real.
- **G5 · yara-integradas** — P2 · M · IMP-1 — Conjunto pequeño de reglas YARA integradas y curadas (webshells,
  herramientas ofensivas comunes, Cobalt Strike beacons) con licencia compatible.
- **G6 · scoring-confianza** — P1 · M · IMP-1 — Puntuación de confianza por hallazgo (fuentes que lo respaldan,
  corroboración cruzada) además de la severidad; orden por riesgo en la web y en el informe.
- **G7 · supresiones** — P1 · M · IMP-1+IMP-2 — Listas de supresión por organización (software legítimo, rutas de
  agentes EDR) aplicables a todos los casos y registradas en custodia.
- **G8 · detecciones-cruzadas** — P2 · L · IMP-1 — Hallazgos que solo existen combinando fuentes (ejecución en
  Prefetch + borrado en USN + ausencia en EVTX = antiforense; USB conectado + LNK a la unidad + archivos grandes
  enviados en SRUM = posible exfiltración).
- **G9 · lolbas** — P2 · S · IMP-1 — Catálogo LOLBAS/LOLDrivers (datos versionados) para marcar abuso de binarios
  legítimos y drivers vulnerables.
- **G10 · hayabusa-chainsaw-compat** — P3 · S · IMP-1 — Importar resultados de Hayabusa/Chainsaw como hallazgos
  externos con su procedencia.

---

## Eje H — Inteligencia de amenazas e indicadores

- **H1 · intel-opencti** — P1 · M · IMP-1 — Importar indicadores desde exportaciones STIX de OpenCTI (bundle) a
  watchlist; misma filosofía que MISP: sin red por defecto.
- **H2 · intel-taxii** — P2 · M · IMP-1 — Cliente TAXII 2.1 opcional (red explícita, credenciales por variable de
  entorno, nunca en el caso) para descargar colecciones a un directorio de inteligencia.
- **H3 · intel-misp-push** — P2 · M · IMP-1 — Exportar los IOC del caso como evento MISP (JSON) y, opcionalmente,
  publicarlo vía API con confirmación explícita; custodia registra el destino.
- **H4 · intel-hashlists** — P2 · S · IMP-1 — Soporte de NSRL (RDS moderno en SQLite) para descartar archivos
  conocidos y de listas de hashes en formatos comunes (CSV de VirusTotal, `hashdeep`).
- **H5 · intel-enriquecimiento** — P3 · M · IMP-1 — Enriquecimiento opcional y explícito (VirusTotal, AbuseIPDB,
  GreyNoise) con caché local; desactivado por defecto y nunca enviando archivos, solo hashes/IP si el analista lo
  autoriza.
- **H6 · stix-completo** — P2 · M · IMP-1 — STIX 2.1 con `sighting`, `observed-data`, relaciones con técnicas y
  `report` del caso; validación contra el esquema oficial en tests.
- **H7 · intel-watchlist-gestion** — P3 · M · IMP-2 — Página web para gestionar listas de inteligencia del espacio
  de trabajo (origen, fecha, número de indicadores, caducidad).

---

## Eje I — Línea temporal, correlación y análisis

- **I1 · timeline-fts** — P1 · M · IMP-1 — Índice de texto completo (SQLite FTS5) para búsqueda en eventos,
  registros y hallazgos; sintaxis de consulta documentada (campo:valor, rangos, booleanos).
- **I2 · timeline-pivotes** — P1 · M · IMP-2 — Pivotar desde cualquier valor (usuario, ruta, hash, IP, PID) a todo
  lo relacionado en el caso con un clic.
- **I3 · timeline-ventanas** — P2 · M · IMP-2 — "¿Qué pasó ±5 minutos alrededor de este evento?" con agrupación
  por fuente.
- **I4 · timeline-skew** — P2 · M · IMP-1 — Corrección de desfase horario por evidencia (reloj adelantado) declarada
  por el analista y registrada en custodia; detección de cambios de hora del sistema (4616).
- **I5 · grafo-entidades** — P2 · L · IMP-2 — Grafo de entidades (usuarios, equipos, procesos, archivos, IP) y sus
  relaciones, navegable en la web (sin dependencias externas pesadas; SVG o librería ligera embebida).
- **I6 · movimiento-lateral** — P2 · L · IMP-1 — Reconstrucción de movimiento lateral entre casos del espacio
  (RDP/SMB/WinRM/PsExec por origen-destino-cuenta-hora) como diagrama en el informe.
- **I7 · correlacion-avanzada** — P2 · M · IMP-1 — Correlación entre casos por hash de archivo, nombre de tarea/
  servicio, mutex, dominio, certificado; puntuación de similitud entre casos.
- **I8 · anotaciones** — P2 · M · IMP-2 — Etiquetas libres y comentarios en eventos y registros (no solo
  hallazgos), en el historial de solo inserción.
- **I9 · hipotesis** — P3 · M · IMP-2 — Registro de hipótesis del analista con eventos a favor/en contra, que
  alimenta las conclusiones.

---

## Eje J — Linux, macOS y otras plataformas

Épica XL: dividir en tareas M/L antes de empezar; cada plataforma con su propio perfil de triaje, demo y
detecciones ATT&CK (matrices Linux y macOS).

### J.1 Linux (0.9)

- **J1 · linux-perfil-triaje** — P1 · M · IMP-1 — Perfil de extracción Linux (`/etc`, `/var/log`, `/home/*/.*history`,
  `/root`, crontabs, systemd, `~/.ssh`, `/tmp`, `/dev/shm`) y compatibilidad con UAC (Unix-like Artifacts Collector).
- **J2 · linux-logs** — P1 · L · IMP-1 — `auth.log`/`secure`, `syslog`, `journald` (formato binario),
  `wtmp/btmp/lastlog`, `auditd` (con Sigma vía G2).
- **J3 · linux-persistencia** — P1 · M · IMP-1 — cron, systemd units/timers, `rc.local`, `ld.so.preload`, módulos
  del kernel, `authorized_keys`, PAM, `.bashrc`/`profile`, sudoers.
- **J4 · linux-ejecucion** — P2 · M · IMP-1 — Historial de shells, `auditd` execve, paquetes instalados
  (dpkg/rpm), binarios SUID nuevos; integrarlos en la vista de Ejecución.
- **J5 · linux-web-servidores** — P2 · M · IMP-1 — Logs de Apache/Nginx, webshells, contenedores Docker
  (`/var/lib/docker`: imágenes, contenedores y sus logs).

### J.2 macOS (0.9)

- **J6 · macos-unified-logs** — P1 · L · IMP-1 — Unified Logs (`tracev3`) con parser acotado o vía `log show`
  exportado.
- **J7 · macos-fsevents-knowledgec** — P1 · M · IMP-1 — FSEvents, KnowledgeC, Biome, `Quarantine Events`.
- **J8 · macos-persistencia** — P1 · M · IMP-1 — LaunchAgents/Daemons, Login Items (BTM), perfiles, extensiones
  de kernel/sistema, TCC.db (permisos concedidos).
- **J9 · macos-actividad** — P2 · M · IMP-1 — Safari, Spotlight, Recent Items, plists de aplicaciones,
  `.zsh_history`.

### J.3 Más allá (1.x)

- **J10 · cloud-m365** — P2 · L · IMP-1 — Importar Unified Audit Log de M365 y logs de inicio de sesión de Entra
  ID (exportaciones JSON/CSV): BEC, reglas de buzón, consentimientos OAuth sospechosos.
- **J11 · cloud-aws-azure-gcp** — P3 · L · IMP-1 — CloudTrail, Azure Activity Log, GCP Audit Logs (exportaciones).
- **J12 · movil** — P3 · XL · IMP-1 — Extracciones lógicas iOS (copias de iTunes/Finder) y Android (ADB backup,
  extracciones lógicas): SMS, llamadas, ubicaciones, apps; requiere análisis legal previo.

---

## Eje K — Interfaz web

### K.1 Producción y equipo (0.8)

- **K1 · web-wsgi** — P0 (para 0.8) · M · IMP-2+PUL — Servidor de producción (waitress en Windows, gunicorn en
  Linux) por defecto en `sabueso web`; el servidor de desarrollo solo con `--dev`. Actualizar Docker.
- **K2 · web-usuarios** — P1 · L · IMP-2 — Cuentas locales con contraseña (hash argon2/scrypt), sesión con cookie
  segura y caducidad; el analista de la custodia es el usuario autenticado, no un campo libre.
- **K3 · web-roles** — P1 · M · IMP-2 — Roles: lector, analista, responsable (puede cerrar caso, firmar informe),
  administrador; permisos por caso.
- **K4 · web-sso** — P3 · L · IMP-2 — OIDC/SAML opcional para organizaciones (Entra ID, Keycloak).
- **K5 · web-concurrencia** — P1 · M · IMP-2+IMP-1 — Bloqueo optimista en revisiones y conclusiones (versión
  esperada), aviso de "otro analista modificó esto"; SQLite WAL ya ayuda, pero hay que probarlo con escrituras
  concurrentes.
- **K6 · web-https** — P2 · S · IMP-2 — `--tls-cert/--tls-key` para HTTPS sin proxy en equipos pequeños.
- **K7 · web-auditoria-accesos** — P2 · M · IMP-2 — Registro de quién consultó qué (accesos de lectura) separado de
  la custodia, exportable; útil en casos con datos personales.
- **K8 · web-rate-limit** — P2 · S · SEG — Límite de intentos de autenticación y bloqueo temporal.

### K.2 Experiencia de uso (0.5 – 0.8)

- **K9 · web-subida-archivos** — P1 · M · IMP-2 — Subida de evidencias por navegador con reanudación por trozos y
  hash en streaming (hoy se registra por ruta); límite configurable.
- **K10 · web-progreso** — P1 · M · IMP-2 — Progreso real de los jobs (archivos procesados / total, módulo actual)
  con Server-Sent Events, cancelación de jobs y cola visible.
- **K11 · web-vista-impresa-hallazgos** — P1 · S · IMP-2 — Vista imprimible de hallazgos análoga a la de la línea
  temporal, anclada a custodia (tarea ya en la cola de agentes).
- **K12 · web-atajos-teclado** — P2 · S · IMP-2 — Navegación por teclado en hallazgos (j/k, c = confirmar, f =
  falso positivo, n = nota) para revisiones masivas rápidas.
- **K13 · web-comparar-analisis** — P2 · M · IMP-2 — Comparar dos ejecuciones del mismo módulo (opciones distintas,
  versión distinta) y ver diferencias de resultados.
- **K14 · web-dashboard-espacio** — P2 · M · IMP-2 — Panel del espacio de trabajo: casos abiertos, estado,
  hallazgos críticos pendientes de revisión, último acceso.
- **K15 · web-estado-caso** — P2 · S · IMP-2+IMP-1 — Ciclo de vida del caso (abierto, en revisión, cerrado,
  archivado); cerrado = solo lectura y custodia lo registra.
- **K16 · web-visor-artefactos** — P2 · L · IMP-2 — Visores integrados: hex con resaltado, registro navegable por
  claves, EVTX como XML, imágenes de carving y tiles RDP en galería.
- **K17 · web-pwa-offline** — P3 · S · IMP-2 — Todos los recursos locales (ya se cumple); comprobar que no hay
  ninguna petición externa con un test de CSP estricto.
- **K18 · web-accesibilidad-aa** — P1 · M · IMP-2 — Auditoría WCAG 2.1 AA completa (contraste, foco, lectores de
  pantalla en tablas y gráficos) con axe-core en un e2e.
- **K19 · web-responsive** — P3 · S · IMP-2 — Lectura cómoda en tablet para revisiones en reunión.

---

## Eje L — Informes periciales

- **L1 · informe-plantillas** — P1 · M · IMP-2 — Plantillas seleccionables (pericial completo, ejecutivo de 2
  páginas, técnico para el SOC, anexo de IOC) y plantillas propias de la organización (logo, colores, cláusulas)
  sin tocar código.
- **L2 · informe-docx** — P2 · M · IMP-2 — Exportar a DOCX editable para dictámenes que el perito completa en Word,
  manteniendo hash y custodia del DOCX generado.
- **L3 · informe-pdfa** — P1 · M · IMP-2 — PDF/A-2b para archivo a largo plazo y firma PAdES (además de la `.sig`
  desacoplada), compatible con validadores (eIDAS); estudiar firma con certificado cualificado (PKCS#11/DNIe).
- **L4 · informe-sello-tiempo** — P2 · M · IMP-2 — Sello de tiempo RFC 3161 opcional del hash del informe y del hash
  de cabecera de la custodia (TSA configurable), para anclar la cadena sin depender de un correo.
- **L5 · informe-anexos** — P2 · M · IMP-2 — Anexos automáticos: lista de archivos extraídos con hash, tabla de
  evidencias derivadas, glosario de artefactos, metodología por módulo usado.
- **L6 · informe-secciones-elegibles** — P2 · S · IMP-2 — Elegir qué secciones incluir y con qué nivel de detalle
  (máximo de filas, solo hallazgos confirmados…), registrado en custodia.
- **L7 · informe-redaccion** — P2 · M · IMP-2 — Anonimización/redacción de datos personales (nombres de usuario,
  correos, IP internas) para informes que se comparten fuera (RGPD).
- **L8 · informe-verificador** — P2 · S · IMP-2 — `sabueso verificar-informe INFORME --sig --pub` independiente del
  caso, para que un tercero (juzgado, cliente) verifique sin tener el caso.
- **L9 · informe-graficos** — P3 · M · IMP-2 — Nuevos gráficos: mapa de calor de actividad por hora/día, cronología
  de fases ATT&CK tipo Gantt, flujo de movimiento lateral.

---

## Eje M — Automatización, API e integraciones

- **M1 · api-rest** — P1 · L · IMP-2 — API REST versionada (`/api/v1`) con tokens por usuario: casos, evidencias,
  análisis, hallazgos, revisiones, informes; especificación OpenAPI publicada en la documentación.
- **M2 · cliente-python** — P2 · M · IMP-2 — Cliente Python mínimo (`sabueso.client`) y ejemplos de notebooks
  (Jupyter) para análisis ad hoc sobre un caso.
- **M3 · export-timesketch** — P1 · M · IMP-1 — Exportar la línea temporal en formato JSONL/CSV de Timesketch (y
  subida opcional con su API).
- **M4 · export-plaso** — P2 · M · IMP-1 — Importar un almacén Plaso (`.plaso`) o su salida `psort` como fuente de
  eventos adicional del caso.
- **M5 · export-ecs-siem** — P2 · M · IMP-1 — Exportación en Elastic Common Schema / OCSF para ingesta en SIEM
  (Elastic, Splunk, Sentinel).
- **M6 · velociraptor** — P2 · M · IMP-1 — Registrar como evidencia una recolección de Velociraptor (ZIP de
  *offline collector*) con sus metadatos, y artefacto VQL que la produce.
- **M7 · eztools-import** — P3 · M · IMP-1 — Importar CSV de herramientas de Eric Zimmerman (MFTECmd, PECmd,
  EvtxECmd…) como resultados externos con procedencia, para equipos que ya las usan.
- **M8 · playbooks-condicionales** — P2 · M · IMP-1 — Pasos condicionales en playbooks (`if: findings.critical > 0`)
  y paso `notify` explícito; validación de esquema del YAML con mensajes localizados.
- **M9 · vigilar-servicio** — P2 · M · IMP-1+PUL — Instalar `vigilar` como servicio de Windows / unidad systemd
  (`sabueso vigilar --instalar-servicio`).
- **M10 · notificaciones-ricas** — P3 · S · IMP-1 — Correo SMTP, plantillas de mensaje y notificación de
  hallazgos críticos en cuanto aparecen (no solo al final).
- **M11 · ticketing** — P3 · M · IMP-1 — Crear incidencias en TheHive/Jira/ServiceNow con el resumen del caso (red
  explícita, credenciales por entorno).
- **M12 · mcp-server** — P3 · M · IMP-2 — Servidor MCP de solo lectura sobre un caso para que asistentes puedan
  consultar hallazgos y línea temporal con control del analista (nunca escriben en custodia sin confirmación).

---

## Eje N — Rendimiento y escala

- **N1 · benchmark** — P1 · M · TEST+PUL — Banco de pruebas reproducible (imagen de 20–100 GB generada o pública,
  p. ej. retos DFIR con licencia abierta) con tiempos por módulo publicados en la documentación y vigilados en CI
  nocturna.
- **N2 · paralelismo-modulos** — P1 · M · IMP-1 — Ejecutar módulos del triaje en paralelo (procesos) con
  escrituras serializadas a SQLite; opción `-j N`.
- **N3 · streaming-parsers** — P2 · M · IMP-1 — Parsers por streaming en `$MFT`, `$UsnJrnl` y EVTX grandes para
  memoria acotada; inserciones por lotes con `executemany`.
- **N4 · extraccion-incremental** — P2 · M · IMP-1 — Reanudar una extracción/triaje interrumpido sin rehacer lo
  ya hecho (con verificación de hash de lo existente).
- **N5 · indices-sqlite** — P1 · S · IMP-1 — Revisar índices de `events`, `records`, `findings` con `EXPLAIN QUERY
  PLAN` sobre el caso del benchmark; `ANALYZE` tras el triaje.
- **N6 · web-paginacion-cursor** — P2 · S · IMP-2 — Paginación por cursor (keyset) en línea temporal con millones de
  eventos.
- **N7 · cache-presentacion** — P3 · S · IMP-2 — Caché de gráficos y resúmenes invalidada por el hash de cabecera de
  la custodia (mismo patrón que la correlación).
- **N8 · limites-configurables** — P2 · S · IMP-1 — Exponer el tope de `read_capped` y otros límites en la
  configuración con valores por defecto seguros.

---

## Eje O — Seguridad y garantías forenses

- **O1 · disk-path-containment** — P1 · S · SEG — Contención explícita (`resolve` + `parents`) para rutas
  relativas en `disk_path` (nota abierta de SEG).
- **O2 · fuzzing-parsers** — P1 · L · SEG+TEST — Fuzzing con `atheris`/Hypothesis de todos los parsers (regf, lnk,
  shellitems, mft, usnjrnl, logfile, jumplist, evtx wrapper, srum, defender, recyclebin) en CI nocturna con
  corpus guardado.
- **O3 · sandbox-parsers** — P2 · L · SEG+IMP-1 — Ejecutar parsers de terceros (libyal, pytsk3) en subproceso con
  límites de memoria/tiempo, para que un crash nativo no tumbe el análisis.
- **O4 · actualizacion-verificada** — P1 · M · SEG+PUL — `sabueso update` verifica la firma/atestación de la release
  (Sigstore, atestaciones de GitHub) antes de instalar; hoy es "self-update sin pin de hash" aceptado.
- **O5 · sbom-firma-release** — P1 · M · PUL — SBOM CycloneDX, atestaciones de procedencia SLSA y firma Sigstore de
  rueda, exe e imagen Docker en el flujo `release`.
- **O6 · pdf-sin-no-sandbox** — P3 · M · SEG+IMP-2 — Evaluar imprimir el PDF sin `--no-sandbox` donde el sistema lo
  permita (usuario sin privilegios), dejando la excepción documentada solo en contenedores.
- **O7 · cifrado-caso** — P2 · L · IMP-1+SEG — Cifrado en reposo opcional del caso (SQLCipher o contenedor cifrado)
  para casos con datos sensibles en portátiles.
- **O8 · custodia-anclaje** — P2 · M · IMP-1 — Anclaje periódico del hash de cabecera (RFC 3161, véase L4) y
  exportación del "acta de custodia" firmada.
- **O9 · auditoria-externa** — P1 (para 1.0) · L · DIR — Auditoría de seguridad externa antes de 1.0 y política de
  divulgación responsable (S3).
- **O10 · validacion-herramienta** — P1 (para 1.0) · L · TEST — Plan de validación forense de la herramienta
  (resultados conocidos sobre imágenes de referencia NIST CFReDS / retos públicos), publicado para respaldar su uso
  pericial.

---

## Eje P — Pruebas y aseguramiento de calidad

- **P1 · muestras-reales** — P0 (continua) · M · DIR+TEST — Programa de obtención de muestras reales con licencia
  (VM propias documentadas, CFReDS, retos con licencia abierta) para desbloquear C1 y el resto del eje C.
- **P2 · casos-legados** — P1 · S · TEST — Fixtures de casos creados con versiones anteriores (0.3, 0.4) para probar
  migraciones (B5).
- **P3 · e2e-web-navegador** — P1 · M · TEST — E2E con Playwright de los flujos web clave (alta, triaje, revisión
  masiva, informe, firma) en CI.
- **P4 · personas-r6** — P1 · M · TEST — Ronda "Operador" y "Entorno adverso" ya planificada en la cola de agentes.
- **P5 · golden-files** — P2 · M · TEST — Salidas de referencia del demo (hallazgos, línea temporal, STIX) para
  detectar cambios de comportamiento no intencionados; actualización explícita.
- **P6 · ci-macos** — P2 · S · PUL — Añadir `macos-latest` a la matriz de CI y Python 3.13/3.14.
- **P7 · tests-mutacion** — P3 · M · TEST — Pruebas de mutación (mutmut) en `core/custody.py`, `core/hashing.py` y
  `report/signing.py`: el código que sostiene las garantías.
- **P8 · ci-nocturna** — P2 · S · PUL — Flujo nocturno con fuzzing (O2), benchmark (N1) y descarga real de Sigma.

---

## Eje Q — Empaquetado, distribución y releases

- **Q1 · primera-release** — P0 · S · PUL — Etiquetar `v0.4.1` (tras A1–A6) y comprobar que el flujo `release`
  produce rueda, sdist, exe y Docker; corregir lo que falle.
- **Q2 · changelog** — P0 · S · PUL — `CHANGELOG.md` (Keep a Changelog) reconstruido desde el historial, y
  generación de notas de release a partir de Conventional Commits.
- **Q3 · pypi** — P1 · S · PUL — Publicar en PyPI con *trusted publishing*; `pipx install sabueso-framework` como vía
  recomendada en el README.
- **Q4 · winget-scoop-brew** — P2 · M · PUL — Manifiestos para winget, Scoop y Homebrew.
- **Q5 · instalador-msi** — P3 · M · PUL — Instalador MSI firmado para despliegues corporativos (GPO/Intune).
- **Q6 · docker-slim** — P2 · S · PUL — Imagen Docker multi-arquitectura (amd64/arm64), usuario no root, tamaño
  reducido y variante con Volatility.
- **Q7 · live-usb** — P3 · L · PUL — Imagen/ISO o paquete portable para USB de respuesta a incidentes con todo
  preinstalado y símbolos offline.
- **Q8 · versionado-semantico** — P1 · S · DIR — Política de versiones (SemVer), qué se considera API pública (CLI,
  formato de caso, API REST, contrato de módulo) y periodo de soporte.

---

## Eje R — Internacionalización

- **R1 · i18n-plural-formato** — P2 · M · IMP-1 — Plurales y formato de fechas/números por idioma (Babel o mínimo
  propio) en lugar de textos fijos.
- **R2 · idioma-portugues** — P2 · M · PUL — Tercer idioma (pt-BR/pt-PT: comunidad DFIR lusófona) validando que la
  arquitectura de locales escala; los tests de i18n pasan a exigir paridad con N idiomas.
- **R3 · traduccion-comunitaria** — P3 · S · PUL — Flujo para contribuciones de traducciones (Weblate o PR con
  validación automática de claves).
- **R4 · zonas-horarias-presentacion** — P2 · S · IMP-2 — Mostrar la línea temporal en UTC o en la zona horaria de
  la evidencia, a elección, con la zona siempre visible.

---

## Eje S — Comunidad y gobierno del proyecto

- **S1 · contributing** — P1 · S · PUL — `CONTRIBUTING.md` (es/en): entorno, estilo, cómo crear un módulo, cómo
  aportar muestras con licencia, Conventional Commits, checklist de PR.
- **S2 · plantillas-github** — P1 · S · PUL — Plantillas de issue (bug, nuevo artefacto, falso positivo de
  detección) y de pull request.
- **S3 · security-md** — P1 · S · SEG — `SECURITY.md` con canal de divulgación responsable y versiones soportadas.
- **S4 · codigo-conducta** — P2 · S · PUL — `CODE_OF_CONDUCT.md`.
- **S5 · discussions** — P3 · S · DIR — GitHub Discussions para preguntas y compartir playbooks/reglas.
- **S6 · galeria-playbooks** — P3 · M · PUL — Repositorio o carpeta de playbooks y listas de supresión aportados por
  la comunidad, validados en CI.
- **S7 · citacion** — P3 · S · PUL — `CITATION.cff` para uso académico.

---

## Pulido transversal (checklist)

Elementos pequeños que mejoran la percepción de calidad; se pueden ir colando en tareas que ya tocan esos archivos.

- [ ] Todos los mensajes de error indican **qué hacer a continuación** (comando sugerido), no solo qué falló.
- [ ] `--help` de cada orden con un ejemplo real al final (es/en).
- [ ] Autocompletado de shell (bash/zsh/PowerShell) generado desde argparse.
- [ ] Salida de la CLI con colores accesibles y `--no-color`/`NO_COLOR` respetado; `--json` en todas las órdenes de
      consulta.
- [ ] Barra de progreso en extracción, hashing y triaje (con ETA) en la CLI.
- [ ] `sabueso doctor` sugiere el comando exacto para arreglar cada problema.
- [ ] Estados vacíos de la web con explicación y acción ("Aún no hay análisis: lanza el triaje").
- [ ] Coherencia terminológica es/en revisada (glosario único: hallazgo/finding, evidencia derivada/derived
      evidence, custodia/custody).
- [ ] Favicon, título de pestaña con el caso, y `<meta>` correctos en la web.
- [ ] Informe: numeración de hallazgos estable entre versiones del informe para poder citarlos.
- [ ] Fechas siempre con zona explícita (`Z` o desfase) en CLI, web, CSV e informe.
- [ ] Nombres de archivo de exportaciones con caso, tipo y fecha (`2026-017_findings_20261025T1200Z.csv`).
- [ ] Revisar que ningún texto visible queda fuera de locales (test que busca literales en plantillas).
- [ ] El demo cubre todos los módulos (incluidos los nuevos) y su texto describe cada hallazgo esperado.

---

## Dependencias críticas entre tareas

```
A1–A6 (sincronizar docs) ──► Q2 (changelog) ──► Q1 (primera release) ──► Q3 (PyPI)
B5 (migraciones) ──► cualquier cambio de esquema (K2 usuarios, K15 estado del caso, I8 anotaciones, O7 cifrado)
B1/B2 (refactor CLI/web) ──► A13 (CLI autogenerada), M1 (API REST)
B7 (contrato de módulo) ──► A14/A15 (docs de módulos y hallazgos), B6 (plugins)
P1 (muestras reales) ──► C1 BITS y el resto del eje C
E2 (ext4/XFS) ──► J1–J5 (Linux)      E3 (APFS) ──► J6–J9 (macOS)
G2 (pipelines Sigma) ──► J2 (auditd con Sigma), C19 (IIS)
K1 (WSGI) ──► K2 (usuarios) ──► K3 (roles) ──► K4 (SSO), M1 (tokens de API)
N1 (benchmark) ──► N2/N3/N5 (optimizaciones medibles)
O2 (fuzzing) y O10 (validación) ──► 1.0
```

## Riesgos

| Riesgo | Mitigación |
|---|---|
| Falta de muestras reales con licencia bloquea artefactos | P1 como programa continuo; VM propias con procedimiento documentado; no aceptar sintéticos "deshonestos" |
| El crecimiento de módulos degrada el rendimiento del triaje | N1 antes de 0.6; N2 paralelismo; presupuesto de tiempo por módulo vigilado en CI |
| Multiusuario rompe la sencillez del "un analista, un portátil" | Modo local actual sigue siendo el por defecto; multiusuario se activa explícitamente |
| Divergencia README es/en | Docs autogeneradas (A13, A14) y test de paridad de secciones entre ambos README |
| Dependencias nativas (libyal, pytsk3) sin ruedas para nuevas versiones de Python | CI con la versión más nueva en modo "permitido fallar" para detectarlo pronto; O3 aísla crashes |
| Uso pericial cuestionado en juicio | O10 (validación publicada), A18 (metodología), L3/L4 (PDF/A, sellos de tiempo) |
| Funciones con red rompen el principio de "sin red" | Toda red opcional, explícita, registrada en custodia y apagada en tests |

## Métricas de éxito

- **Fiabilidad**: 0 hallazgos CRÍTICO/ALTO abiertos en cada release; fuzzing sin crashes nuevos durante 30 días.
- **Cobertura forense**: nº de artefactos con muestra real (hoy 27 módulos; objetivo 40 en 0.6 y 60 en 1.0).
- **Calidad**: cobertura de tests ≥ 85 %; mypy estricto en `core/` y `parsers/`.
- **Rendimiento**: triaje de una imagen de 100 GB por debajo de un umbral publicado en el benchmark (N1).
- **Adopción**: descargas de PyPI/GHCR, estrellas, issues de la comunidad con plantilla de "nuevo artefacto".
- **Documentación**: 100 % de módulos y códigos de hallazgo documentados automáticamente; README es/en sin desfases
  detectados por test.
