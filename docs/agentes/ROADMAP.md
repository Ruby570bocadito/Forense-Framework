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
Revisión DIR del 2026-10-25 (2ª, petición del operador): promovidas a8 (capturas y vídeos de uso generados con
Playwright) y a9 (diagrama de flujo), repartidas entre IMP-2 (generación en scripts/ y docs/assets/) y PUL (README);
a1–a5, vista-impresa-hallazgos y disk-path-containment pasan a histórico; sigma-redos devuelta por SEG (sesión 8,
8 familias de evasión) → ALTA sigma-redos-v2; web-progreso (K10) e intel-opencti añadidas como en curso.

## ALTA

- [ ] (IMP-1) sigma-redos-v2 — la guardia ReDoS de 65dd311 es evadible: 8 familias con re.search congelado >4 s
  ((a?){25}X, (a{0,2}){15}X, (.?){25}X, ((a?){5}){5}X, a?×30+X, ([\w]{0,3}){12}X; repros completos en estado/SEG.md
  sesión 8). Dos fallos de modelo: el presupuesto multiplica por la ventana del repetidor UNA vez (la ambigüedad se
  eleva B^iteraciones) y los átomos adyacentes cuantificados sin grupo no se comprueban. Fix sugerido por SEG:
  presupuesto de ambigüedad global Σ log2(ways) con recursión en grupos cuantificados; el test del paquete builtin
  (15 reglas, 0 errores) es la red contra falsos positivos — forense/sigma/, tests/

  IMP-1 la coge en cuanto libere intel-opencti; mientras tanto, no importar packs Sigma de dudosa procedencia (SEG).

## Tareas priorizadas

- [ ] (PUL) a7-readme-badges — badges de CI, versión PyPI, licencia, Python soportado e imagen GHCR — README.md, README.en.md
- [ ] (IMP-2) a8-capturas-script — capturas profesionales del programa con Playwright sobre el caso demo (`scripts/screenshots.py` reproducible): resumen, línea temporal, ATT&CK y página de informe en claro/oscuro, más vídeos de uso (GIF corto de `forense demo` → web y de una sesión CLI de triaje → informe); salida en docs/assets/ con peso contenido (GIF corto o mp4/webm ligero) — scripts/, docs/assets/, tests/
- [ ] (PUL) a8-readme-visual — presentación profesional del README con los assets de docs/assets/ (capturas de portada en claro/oscuro y sección "Vistazo" con los vídeos de uso), es/en sincronizados; tras a8-capturas-script — README.md, README.en.md
- [ ] (PUL) a9-readme-diagrama — diagrama del flujo (evidencia → extracción → módulos → hallazgos → revisión → informe/STIX) en SVG en docs/assets/ y embebido en ambos README — README.md, README.en.md, docs/assets/
- [ ] (PUL) q2-changelog — CHANGELOG.md (Keep a Changelog) reconstruido desde el historial y notas de release generadas desde Conventional Commits — CHANGELOG.md, .github/workflows/
- [ ] (PUL) q1-primera-release — etiquetar v0.4.1 (tras A1–A6 y Q2) y comprobar que el flujo `release` produce rueda, sdist, exe y Docker; corregir lo que falle — pyproject.toml, .github/workflows/, install/, packaging/
- [ ] (IMP-2) k10-web-progreso — progreso real de los jobs (archivos procesados/total, módulo actual) con Server-Sent Events, cancelación de jobs y cola visible (EN CURSO, claim IMP-2 2026-10-25 12:20 UTC) — forense/web/, forense/locales/, tests/
- [ ] (TEST) personas-r6 — ronda con personas aún sin cubrir: Operador (doctor, config, vigilar --una-vez, update --check, Docker/instaladores) y Entorno adverso (PDF sin Edge/Chrome, sin Volatility, sin red, carpeta de casos de solo lectura; verificar exit 2 al manipular una copia) — tests/e2e/, docs/agentes/hallazgos/
- [ ] (IMP-1) artifact-bits — módulo BITS (qmgr.db): trabajos, URLs, estado y destino, hallazgo con severidad y técnica ATT&CK T1197; BLOQUEADA: sin muestra real en tests/data (desbloqueo: P1 · muestras-reales del roadmap de producto) — forense/modules/, forense/locales/, forense/demo/, tests/

## Dependencias entre tareas

- a8-readme-visual y a9-readme-diagrama dependen de a8-capturas-script (assets en docs/assets/); no bloquean q1, pero si entran antes de la release, mejor portada para v0.4.1.
- sigma-redos-v2 (ALTA) es la siguiente de IMP-1 (intel-opencti ya entregada); hasta su fix, no importar packs Sigma de dudosa procedencia (consejo de SEG).
- q2-changelog solo cuando A1–A6 estén cerradas (lo están); q1-primera-release solo tras q2 y sin claims de código activos.
- La verificación TEST de la tanda entregada (a1–a5, vista-impresa-hallazgos, disk-path-containment, intel-misp, logfile-atributos, readbytes-gate, refs-rama-heredada, web-duplicada-aviso) conviene antes de q1: el CHANGELOG y la release documentan lo verificado; añadir sigma-redos-v2 cuando IMP-1 la entregue.
- personas-r6 rinde tras un ciclo completo de IMP (no lanzar TEST mientras el programa se reconstruye).
- web-progreso tiene claim activo (IMP-2): no reclamar.
- artifact-bits permanece BLOQUEADA sin muestra real de qmgr.db; no sustituirla por sintéticos no honestos (principio §2.1 del roadmap de producto).

## Backlog (largo plazo)

- (IMP-1) wmi-parser-cim — parser CIM completo del repositorio WMI (hoy por búsqueda de cadenas); en el roadmap de producto entra en 0.6.
- (IMP-1) carving-fragmentado — carving de archivos no contiguos (0.6).
- (IMP-1) sistemas-no-windows — Linux y macOS como sistemas analizados (eje J, 0.9).
- (PUL) readme-adelgazar — A10 (0.5): dejar el README en ~250 líneas cuando exista la documentación de referencia (A12); capturas, vídeos y diagrama ya habrán entrado con a8/a9.

## Entregado (histórico)

- [x] (IMP-1) intel-opencti — importación de bundles STIX de OpenCTI en watchlists de `ioc` (ad00865; PENDIENTE verificación TEST) — forense/core/, forense/locales/, tests/
- [x] (PUL) a1-readme-intel-misp — `forense intel misp` en la tabla CLI y subsección "Importar inteligencia de MISP" con ejemplo completo y tipos admitidos, es/en (14cd5c6; PENDIENTE verificación TEST) — README.md, README.en.md
- [x] (PUL) a2-readme-hoja-de-ruta-sync — hoja de ruta del README: MISP pasa a hecho, queda OpenCTI/TAXII, enlace a docs/ROADMAP.md (83eb8ad; PENDIENTE verificación TEST) — README.md, README.en.md
- [x] (PUL) a3-readme-logfile-atributos — fila de logfile y limitación de $LogFile ampliadas con las operaciones de atributo (4ac3a4f; PENDIENTE verificación TEST) — README.md, README.en.md
- [x] (PUL) a4-readme-readbytes-gate — bala de consumo acotado (256 MB por defecto, artefacto gigante como error de análisis) en "Modelo de seguridad" (45e99a2; PENDIENTE verificación TEST) — README.md, README.en.md
- [x] (PUL) a5-readme-ejemplo-modulo — ejemplo de módulo neutro en lugar del bits bloqueado (70af8f0; PENDIENTE verificación TEST) — README.md, README.en.md
- [x] (SEG) disk-path-containment — las rutas relativas de disk_path se resuelven y quedan contenidas en la raíz del caso (resolve + parents, symlink incluido); error.evidence_path_escapes es/en (e53919f; PENDIENTE verificación TEST) — forense/core/, forense/locales/, tests/
- [x] (IMP-2) vista-impresa-hallazgos — exportación de hallazgos como HTML imprimible autónomo con filtros y custodia export_created + SHA-256 (de9adc2; PENDIENTE verificación TEST) — forense/report/, forense/web/, forense/locales/, tests/
- [x] (DIR) a6-roadmap-agentes-limpieza — cola contrastada con estados y git log; 7 entregas pasadas a histórico; intel dividida en intel-misp (hecha) e intel-opencti (en cola); slugs con prefijo de ficha del roadmap de producto (2026-10-25, tras 7178cd8) — docs/agentes/ROADMAP.md
- [x] (TEST) h-010-verificacion — H-010 cerrado: repro literal del fix 2254b95 (`informe --firmar/--sign`) con claves Ed25519, .sig desacoplado, custodia report_signed, manipulación detectada y error localizado sin clave; "close: H-010" (5bcb5fc) — tests/e2e/, docs/agentes/hallazgos/
- [x] (SEG) sigma-redos-revision — guardia ReDoS revisada por SEG (sesión 7) y verificada por TEST (8/8 hostiles, 7/7 seguros, 5bcb5fc); la re-auditoría adversarial de SEG (sesión 8, 1a3aeb7) la DEVOLVIÓ con 8 familias de evasión → ALTA sigma-redos-v2 — forense/sigma/, tests/
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
