# ROADMAP — coordinación de agentes

Único escritor: DIR. Formato de tarea: `- [ ] (ID destino) slug — descripción en una línea — rutas`.
Las tareas van priorizadas de arriba abajo; se marca `[x]` cuando está hecha y verificada.
Lo entregado y verificado vive al final, en "Entregado (histórico)"; la lista activa queda limpia.

Fase actual: **fiabilidad del resultado forense** (artefactos del motor, confianza en el informe) antes de funciones vistosas.
Base: "Hoja de ruta" y "Limitaciones conocidas" del README contrastadas con el código real (commit 20fe3f3).
Corrección detectada: la correlación entre casos YA está implementada (commit 7b647b8, `forense/core/correlation.py` y página web
`/correlation`); en la hoja de ruta del README solo queda pendiente la importación MISP/OpenCTI (petición a PUL en `estado/DIR.md`).
Tabla de módulos verificada contra el código: 27 módulos = 21 de Windows + 6 genéricos, coincide con el README (PUL, a36a780).
Revisión DIR del 2026-10-23 (vespertina, sobre 18a0619): estados contrastados con el código (h-010 en cli.py:939, guardia sigma
en engine.py, 21+6 módulos, refs-rama-heredada aún en update.py:26); `ruff check forense tests` limpio y `python -m pytest -q`
= 368 passed, 1 skipped. Sin claims activos.

## ALTA

(ninguna: build verde, sin hallazgos CRÍTICO/ALTO abiertos)

## Tareas priorizadas

- [ ] (TEST) h-010-verificacion — verificar y cerrar H-010 (fix 2254b95: `informe --firmar/--sign`): repro literal del hallazgo con claves Ed25519, .sig válido, verificación OK, manipulación detectada, entrada de custodia; e2e de regresión y "close: H-010" — tests/e2e/, docs/agentes/hallazgos/
- [ ] (IMP-2) web-duplicada-aviso — residual de H-005: la subida web (POST /c/<slug>/evidence) ignora ev.duplicate_of; el flash del job debe avisar del gemelo en el idioma de sesión (locales es/en) — forense/web/, forense/locales/, tests/
- [ ] (SEG) sigma-redos-revision — revisar la guardia ReDoS entregada por IMP-1 (65dd311): formas hostiles cubiertas, presupuesto de ramificación, evasiones (lookarounds, clases cuantificadas, anidamientos); dar sigma-redos por verificada o devolverla — forense/sigma/, tests/
- [ ] (IMP-1) logfile-atributos — ampliar $LogFile: reconstruir la tabla de atributos abiertos (0x1C/0x1D) para nombrar operaciones contextuales — forense/parsers/, forense/modules/, forense/locales/, tests/
- [ ] (SEG) disk-path-containment — contención explícita (resolve + parents) para rutas relativas en disk_path (bajo; fix mínimo con test de regresión) — transversal (claim previo)
- [ ] (IMP-1) readbytes-gate — gate central de tamaño para el patrón read_bytes() común de los módulos (evidencias que provoquen consumo desmedido de memoria/disco) — forense/modules/, forense/core/, tests/
- [ ] (IMP-2) vista-impresa-hallazgos — vista imprimible de hallazgos análoga a la de la línea temporal, anclada a custodia (export_created + sha256) — forense/web/, forense/locales/, tests/
- [ ] (TEST) personas-r6 — ronda con personas aún sin cubrir: Operador (doctor, config, vigilar --una-vez, update --check, Docker/instaladores) y Entorno adverso (PDF sin Edge/Chrome, sin Volatility, sin red, carpeta de casos de solo lectura; verificar exit 2 al manipular una copia) — tests/e2e/, docs/agentes/hallazgos/
- [ ] (IMP-1) artifact-bits — módulo BITS (qmgr.db): trabajos, URLs, estado y destino, hallazgo con severidad y técnica ATT&CK T1197; BLOQUEADA: sin muestra real en tests/data (qmgr.db es ESE y no se sintetiza con honestidad); reactivar cuando entre muestra con origen y licencia — forense/modules/, forense/locales/, forense/demo/, tests/
- [ ] (IMP-1) refs-rama-heredada — quitar la ref de fallback a la rama heredada en REFS (`claude/inspiring-cray-xn35zk`, línea 26) y dejar solo main — forense/update.py
- [ ] (IMP-1) intel-misp-opencti — importación de inteligencia desde MISP (IOCs → lista de vigilancia de `ioc` y correlación); OpenCTI después; sesión dedicada completa, no fraccionar — forense/core/, forense/locales/, tests/

## Dependencias entre tareas

- h-010-verificacion cierra la cola de hallazgos; web-duplicada-aviso (residual H-005) no la bloquea.
- sigma-redos solo se da por cerrada tras sigma-redos-revision de SEG.
- personas-r6 rinde más tras h-010-verificacion y sigma-redos-revision (no lanzar TEST mientras el programa se reconstruye).
- PUL (readme-sign-doc) cuando IMP-1 no esté a mitad de módulo: README y modules/ cambian juntos.
- artifact-bits permanece bloqueada por falta de muestra; no sustituirla por sintéticos no honestos.

## Backlog (largo plazo)

- (IMP-1) wmi-parser-cim — parser CIM completo del repositorio WMI (hoy por búsqueda de cadenas).
- (IMP-1) carving-fragmentado — carving de archivos no contiguos.
- (IMP-1) sistemas-no-windows — Linux y macOS como sistemas analizados.
- (IMP-1) ampliar-logfile — reconstrucción de atributos abiertos 0x1C/0x1D (promovida a logfile-atributos).

## Entregado (histórico)

- [x] (PUL) readme-hoja-de-ruta — retirar "Correlación entre casos" de la hoja de ruta de ambos README (ya implementada: 7b647b8) — README.md, README.en.md
- [x] (PUL) readme-firma-mft-limitaciones — retirar "Firma digital de informes" de la Hoja de ruta (5be9c5a) y la limitación de $ATTRIBUTE_LIST de Limitaciones conocidas (cf72bfa), es/en — README.md, README.en.md
- [x] (PUL) readme-arbol-comandos — árbol de "Arquitectura", comandos de instalación probados y tabla de módulos contrastada — README.md, README.en.md
- [x] (PUL) readme-modulos-rdp-notifications — filas de notifications y rdp_cache, árbol y demo actualizados (a36a780; 27 módulos = 21+6 verificados) — README.md, README.en.md
- [x] (PUL) readme-h010-firmar-export-sync — `informe --firmar/--sign` en la tabla CLI, párrafo de firma web+CLI, destinos es/en de `exportar` (H-009) y bala de la guardia ReDoS Sigma (1ea8dac) — README.md, README.en.md
- [x] (IMP-1) mft-attribute-list — atributos de registros de extensión ($ATTRIBUTE_LIST) combinados en $MFT (cf72bfa) — forense/parsers/mft.py, tests/
- [x] (IMP-1) artifact-logfile — soporte básico de $LogFile NTFS — forense/parsers/, forense/modules/, forense/locales/, tests/
- [x] (IMP-1) artifact-notifications — módulo de notificaciones de Windows (wpndatabase.db / NotificationStore) (740b11c; TEST ronda 4) — forense/modules/, forense/locales/, forense/demo/, tests/
- [x] (IMP-1) artifact-rdp-cache — artefacto RDP Bitmap Cache, tiles como BMP (a487698; TEST ronda 4) — forense/modules/, forense/locales/, forense/demo/, tests/
- [x] (IMP-1) h-005-evidencia-duplicada — aviso de contenido duplicado en `evidencia agregar` (1f94986; verificado y cerrado por TEST) — forense/core/, forense/cli.py, forense/locales/, tests/
- [x] (IMP-1) h-006-conclusiones-archivo — errores localizados de `conclusiones --archivo` (0606ea2; verificado y cerrado por TEST) — forense/cli.py, forense/locales/, tests/
- [x] (IMP-1) h-009-exportar-alias — `exportar` acepta los términos es/en de su propia ayuda (8383161; verificado y cerrado por TEST) — forense/cli.py, forense/locales/, tests/
- [x] (IMP-1) h-010-informe-firmar — `informe --firmar/--sign` con el mismo camino de firma que la web (2254b95; PENDIENTE verificación TEST → h-010-verificacion) — forense/cli.py, forense/locales/, tests/
- [x] (IMP-1) sigma-redos — guardia estructural ReDoS en patrones `|re` de Sigma antes de compilar (65dd311; PENDIENTE revisión SEG → sigma-redos-revision) — forense/sigma/, tests/
- [x] (IMP-2) report-signing — firma digital de informes: Ed25519, `.sig` desacoplada + verificación, clave por variable de entorno, hash anclado a custodia (5be9c5a) — forense/report/, forense/locales/, tests/
- [x] (IMP-2) web-rendimiento — paginación y rendimiento con casos grandes — forense/web/, tests/
- [x] (IMP-2) web-accessibility — enlace de salto, aria-current, roles de avisos, thead/scope; tema claro/oscuro intacto (verificada por TEST en HTML servido) — forense/web/templates/, forense/locales/, tests/
- [x] (IMP-2) reports-hash-display — SHA-256 y estado de firma de cada informe en la página de informes (verificada por TEST) — forense/web/, tests/
- [x] (IMP-2) web-revision-masiva — revisión masiva de hallazgos en la web (90d4996; revisada por SEG, sesión 3) — forense/web/, tests/
- [x] (IMP-2) timeline-export-html — exportación de la línea temporal como HTML imprimible autónomo, anclada a custodia (bfea922; e2e de TEST con navegador falso) — forense/web/, tests/
- [x] (IMP-2) web-filtros-guardados — filtros guardados por caso en hallazgos y línea temporal (e7962a7; revisado SEG sesión 6, verificado TEST ronda 5) — forense/web/, forense/locales/, tests/
- [x] (SEG) auditoria-extraccion — path traversal y nombres hostiles al extraer de imágenes, con regresión — transversal
- [x] (SEG) auditoria-subprocesos-yaml — subprocesos sin shell y YAML solo con safe_load — transversal
- [x] (SEG) pip-audit — dependencias auditadas y vulnerabilidades corregidas — transversal
- [x] (TEST) personas-r1 — primera ronda (analista nuevo, perito veterano, despistado, evidencia hostil); 9 hallazgos, batería e2e inicial — tests/e2e/, docs/agentes/hallazgos/
