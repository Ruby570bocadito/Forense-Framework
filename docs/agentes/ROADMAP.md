# ROADMAP — coordinación de agentes

Único escritor: DIR. Formato de tarea: `- [ ] (ID destino) slug — descripción en una línea — rutas`.
Las tareas van priorizadas de arriba abajo; se marca `[x]` cuando está hecha y verificada.

Fase actual: **fiabilidad del resultado forense** (artefactos del motor, confianza en el informe) antes de funciones vistosas.
Base: "Hoja de ruta" y "Limitaciones conocidas" del README contrastadas con el código real (commit 20fe3f3).
Corrección detectada: la correlación entre casos YA está implementada (commit 7b647b8, `forense/core/correlation.py` y página web
`/correlation`); en la hoja de ruta del README solo queda pendiente la importación MISP/OpenCTI (petición a PUL en `estado/DIR.md`).
Tabla de módulos verificada contra el código: 18 de Windows + 6 genéricos, coincide con el README.
Revisión DIR del 2026-10-23: entregas del primer ciclo verificadas con `ruff check forense tests` limpio y `python -m pytest -q`
= 278 passed, 1 skipped sobre b278129 (venv refrescado por la entrada de `cryptography`, ver estado de IMP-1).

## ALTA

(ninguna: build verde, sin hallazgos CRÍTICO/ALTO abiertos)

## Tareas priorizadas

- [x] (PUL) readme-hoja-de-ruta — retirar "Correlación entre casos" de la hoja de ruta de ambos README (ya implementada: 7b647b8); la línea queda solo con MISP/OpenCTI — README.md, README.en.md
- [ ] (PUL) readme-firma-mft-limitaciones — retirar "Firma digital de informes" de la Hoja de ruta (implementada: 5be9c5a) y la limitación de $ATTRIBUTE_LIST de Limitaciones conocidas (resuelta: cf72bfa), es/en — README.md, README.en.md
- [x] (IMP-1) mft-attribute-list — combinar atributos de registros de extensión ($ATTRIBUTE_LIST) en $MFT (limitación conocida del README) — forense/parsers/mft.py, tests/
- [ ] (IMP-1) artifact-bits — módulo BITS (qmgr.db): trabajos, URLs, estado y destino, hallazgo con severidad y técnica ATT&CK T1197; entrega completa (módulo + registro + locales es/en + artefacto en demo + tests con caso corrupto) — forense/modules/, forense/locales/, forense/demo/, tests/
- [x] (IMP-2) report-signing — firma digital de informes: Ed25519, firma desacoplada `.sig` + verificación, clave por variable de entorno, hash anclado a la cadena de custodia — forense/report/, forense/locales/, tests/
- [x] (IMP-2) web-rendimiento — paginación y rendimiento con casos grandes (listas de hallazgos, eventos y búsqueda de caso) — forense/web/, tests/
- [ ] (IMP-2) web-accessibility — accesibilidad base de la interfaz: enlace de salto, aria-current, roles de avisos, thead/scope en tablas; mantener tema claro/oscuro — forense/web/templates/, forense/web/static/, forense/locales/, tests/
- [ ] (IMP-1) artifact-logfile — soporte básico de $LogFile NTFS (operaciones de registro de interés forense; limitación conocida) — forense/parsers/, forense/modules/, forense/locales/, tests/
- [ ] (IMP-1) artifact-rdp-cache — artefacto RDP Bitmap Cache (bCache*.bin, Tile_*.bmp): actividad RDP histórica; entrega completa — forense/modules/, forense/locales/, forense/demo/, tests/
- [ ] (IMP-1) artifact-notifications — módulo de notificaciones de Windows (wpndatabase.db / NotificationStore): apps emisoras, títulos y cuerpos; entrega completa — forense/modules/, forense/locales/, forense/demo/, tests/
- [ ] (IMP-2) reports-hash-display — mostrar SHA-256 y estado de firma de cada informe en la página de informes — forense/web/, tests/
- [ ] (IMP-1) intel-misp-opencti — importación de inteligencia desde MISP (IOCs → lista de vigilancia de `ioc` y correlación); OpenCTI después — forense/core/, forense/locales/, tests/
- [ ] (IMP-1) refs-rama-heredada — quitar la ref de fallback a la rama heredada en REFS (`claude/inspiring-cray-xn35zk`, línea 26) y dejar solo main — forense/update.py
- [ ] (IMP-1) sigma-redos — validar/limitar los patrones de las reglas Sigma del operador antes de compilar regex (ReDoS de reglas hostiles) — forense/sigma/, tests/
- [ ] (PUL) readme-arbol-comandos — verificar árbol de "Arquitectura" contra el árbol real, probar los comandos de instalación (manual, Docker, `forense demo`) y contrastar la tabla de módulos — README.md, README.en.md
- [x] (SEG) auditoria-extraccion — revisar path traversal y nombres hostiles al extraer de imágenes (`..`, rutas absolutas, enlaces simbólicos) con test de regresión; fixes mínimos — transversal (claim previo)
- [x] (SEG) auditoria-subprocesos-yaml — revisar subprocesos (Volatility, PDF) sin shell y con argumentos controlados, y YAML solo con safe_load (config, Sigma) — transversal (claim previo)
- [x] (SEG) pip-audit — ejecutar pip-audit sobre las dependencias y corregir lo vulnerable — transversal, fixes mínimos
- [ ] (TEST) personas-r1 — primera ronda de personas (analista nuevo, perito veterano, despistado, evidencia hostil) sobre la demo y el README — tests/e2e/, docs/agentes/hallazgos/

## Dependencias entre tareas

- report-signing (IMP-2) precede a la exposición CLI `--sign` (IMP-1, forense/cli.py).
- reports-hash-display (IMP-2) tiene mejor valor tras report-signing.
- personas-r1 (TEST) rinde más tras el primer ciclo de IMP/SEG; no lanzar TEST mientras el programa se reconstruye.

## Backlog (largo plazo)

- (IMP-1) wmi-parser-cim — parser CIM completo del repositorio WMI (hoy por búsqueda de cadenas).
- (IMP-1) carving-fragmentado — carving de archivos no contiguos.
- (IMP-1) sistemas-no-windows — Linux y macOS como sistemas analizados.
