# ROADMAP — coordinación de agentes

Único escritor: DIR. Formato de tarea: `- [ ] (ID destino) <código>-<slug> — descripción en una línea — rutas`.
El prefijo `<código>` remite a la ficha de la tarea en `docs/ROADMAP.md` (hoja de ruta de producto: alcance,
prioridad, dependencias y criterio de la versión); léela antes de empezar. Las tareas heredadas de la cola anterior
sin ficha mantienen su slug. Las tareas van priorizadas de arriba abajo; se marca `[x]` cuando está hecha y verificada.
Lo entregado y verificado vive al final, en "Entregado (histórico)"; la lista activa queda limpia.

Versión en curso: **0.4.x "Puesta al día"** (docs/ROADMAP.md §3). Criterio de salida: `v0.4.1` publicada con rueda,
exe y Docker; README sin desfases.
Revisión DIR del 2026-10-25 (sobre 7178cd8, primera sesión con el roadmap de producto en main): estados contrastados
con git log y código; sin claims activos, hallazgos a cero, build verde (última suite declarada: 369 passed, 1 skipped).
Promovidas las tareas 0.4.x del producto (A1–A5, A7, Q2, Q1) e intel dividida en intel-misp (hecha) e intel-opencti.

## ALTA

(ninguna: build verde, sin hallazgos CRÍTICO/ALTO abiertos)

## Tareas priorizadas

- [ ] (PUL) a1-readme-intel-misp — `forense intel misp EXPORT.json` en la tabla CLI y subsección "Importar inteligencia de MISP" con ejemplo completo (exportación → watchlist → `analizar ioc -o watchlist=` → correlación) y tipos MISP admitidos, es/en — README.md, README.en.md
- [ ] (PUL) a2-readme-hoja-de-ruta-sync — "Hoja de ruta" del README: MISP pasa a hecho, queda "OpenCTI/TAXII"; enlazar docs/ROADMAP.md para el detalle — README.md, README.en.md
- [ ] (PUL) a3-readme-logfile-atributos — ampliar la fila de `logfile` y la limitación de $LogFile: también se nombran las operaciones de atributo (0x05–0x09, 0x0B) vía la tabla de atributos abiertos — README.md, README.en.md
- [ ] (PUL) a7-readme-badges — badges de CI, versión PyPI, licencia, Python soportado e imagen GHCR — README.md, README.en.md
- [ ] (PUL) a4-readme-readbytes-gate — bala en "Modelo de seguridad": tope central de tamaño por artefacto (256 MB por defecto) y artefacto gigante reportado como error de análisis — README.md, README.en.md
- [ ] (PUL) a5-readme-ejemplo-modulo — el ejemplo de "cómo crear un módulo" usa `bits` (inexistente y bloqueado): cambiarlo por un ejemplo neutro o un módulo real recortado — README.md, README.en.md
- [ ] (PUL) q2-changelog — CHANGELOG.md (Keep a Changelog) reconstruido desde el historial y notas de release generadas desde Conventional Commits — CHANGELOG.md, .github/workflows/
- [ ] (PUL) q1-primera-release — etiquetar v0.4.1 (tras A1–A6 y Q2) y comprobar que el flujo `release` produce rueda, sdist, exe y Docker; corregir lo que falle — pyproject.toml, .github/workflows/, install/, packaging/
- [ ] (SEG) disk-path-containment — contención explícita (resolve + parents) para rutas relativas en disk_path (bajo; fix mínimo con test de regresión) — transversal (claim previo)
- [ ] (IMP-2) vista-impresa-hallazgos — vista imprimible de hallazgos análoga a la de la línea temporal, anclada a custodia (export_created + sha256) — forense/web/, forense/locales/, tests/
- [ ] (TEST) personas-r6 — ronda con personas aún sin cubrir: Operador (doctor, config, vigilar --una-vez, update --check, Docker/instaladores) y Entorno adverso (PDF sin Edge/Chrome, sin Volatility, sin red, carpeta de casos de solo lectura; verificar exit 2 al manipular una copia) — tests/e2e/, docs/agentes/hallazgos/
- [ ] (IMP-1) intel-opencti — colecciones OpenCTI → watchlist de `ioc` (2ª mitad de la tarea de inteligencia; sesión dedicada completa, no fraccionar) — forense/core/, forense/locales/, tests/
- [ ] (IMP-1) artifact-bits — módulo BITS (qmgr.db): trabajos, URLs, estado y destino, hallazgo con severidad y técnica ATT&CK T1197; BLOQUEADA: sin muestra real en tests/data (desbloqueo: P1 · muestras-reales del roadmap de producto) — forense/modules/, forense/locales/, forense/demo/, tests/

## Dependencias entre tareas

- A1–A5 y a7 tocan ambos README (misma ruta): PUL los ejecuta en una sola sesión ordenada, un claim cada vez, no en paralelo.
- q2-changelog solo cuando A1–A6 estén cerradas (A6 lo está desde hoy); q1-primera-release solo tras q2 y sin claims de código activos.
- La verificación TEST de la tanda IMP-1/IMP-2 (intel-misp, logfile-atributos, readbytes-gate, refs-rama-heredada, web-duplicada-aviso) conviene antes de q1: el CHANGELOG y la release documentan lo verificado.
- personas-r6 rinde tras un ciclo completo de IMP (no lanzar TEST mientras el programa se reconstruye).
- intel-opencti tras la verificación de intel-misp; sesión dedicada.
- artifact-bits permanece BLOQUEADA sin muestra real de qmgr.db; no sustituirla por sintéticos no honestos (principio §2.1 del roadmap de producto).

## Backlog (largo plazo)

- (IMP-1) wmi-parser-cim — parser CIM completo del repositorio WMI (hoy por búsqueda de cadenas); en el roadmap de producto entra en 0.6.
- (IMP-1) carving-fragmentado — carving de archivos no contiguos (0.6).
- (IMP-1) sistemas-no-windows — Linux y macOS como sistemas analizados (eje J, 0.9).
- (PUL) readme-capturas/diagrama/adelgazar — A8/A9/A10 (0.4.x–0.5), cuando el README se estabilice tras A1–A5.

## Entregado (histórico)

- [x] (DIR) a6-roadmap-agentes-limpieza — cola contrastada con estados y git log; 7 entregas pasadas a histórico; intel dividida en intel-misp (hecha) e intel-opencti (en cola); slugs con prefijo de ficha del roadmap de producto (2026-10-25, tras 7178cd8) — docs/agentes/ROADMAP.md
- [x] (TEST) h-010-verificacion — H-010 cerrado: repro literal del fix 2254b95 (`informe --firmar/--sign`) con claves Ed25519, .sig desacoplado, custodia report_signed, manipulación detectada y error localizado sin clave; "close: H-010" (5bcb5fc) — tests/e2e/, docs/agentes/hallazgos/
- [x] (SEG) sigma-redos-revision — guardia ReDoS revisada por SEG (sesión 7: formas hostiles cubiertas, presupuesto de ramificación, trade-off conservador documentado) y verificada por TEST (8/8 hostiles, 7/7 seguros, 5bcb5fc); una re-auditoría adversarial de SEG quedó reclamada el mismo día (1a3aeb7) — forense/sigma/, tests/
- [x] (IMP-2) web-duplicada-aviso — el job de la subida web avisa del gemelo duplicado con su SHA-256, es/en (9a9e803; PENDIENTE verificación TEST) — forense/web/, forense/locales/, tests/
- [x] (IMP-1) logfile-atributos — operaciones de nivel de atributo (0x05–0x09, 0x0B) nombradas vía la tabla de atributos abiertos (9267745; PENDIENTE verificación TEST) — forense/parsers/, forense/modules/, forense/locales/, tests/
- [x] (IMP-1) readbytes-gate — read_capped() como gate central del patrón read_bytes; adoptado por psreadline, defender, lnk, tasks, recyclebin, rdp_cache y setupapi (0221fdc; PENDIENTE verificación TEST) — forense/modules/, forense/core/, tests/
- [x] (IMP-1) refs-rama-heredada — REFS = ("main",): retirada la ref de fallback a la rama heredada en update.py (14305d5; PENDIENTE verificación TEST) — forense/update.py
- [x] (IMP-1) intel-misp-opencti — `forense intel misp` convierte exportaciones MISP en watchlist de `ioc` conectada a la correlación (2b1fb2f; PENDIENTE verificación TEST; la mitad OpenCTI continúa en intel-opencti) — forense/core/, forense/locales/, tests/
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
- [x] (IMP-1) h-010-informe-firmar — `informe --firmar/--sign` con el mismo camino de firma que la web (2254b95; verificado y cerrado por TEST, 5bcb5fc) — forense/cli.py, forense/locales/, tests/
- [x] (IMP-1) sigma-redos — guardia estructural ReDoS en patrones `|re` de Sigma antes de compilar (65dd311; revisada por SEG sesión 7 y verificada por TEST, 5bcb5fc) — forense/sigma/, tests/
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
