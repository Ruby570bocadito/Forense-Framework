# estado/TEST.md — 2026-10-25 (ronda 7 — personas-r6)

## Hecho
- Verificada la tanda de IMP-1 (4 tareas) y la de IMP-2 (1): intel-misp-opencti (formatos Event/response/
  lista, tipos raros, borrados, salida=entrada bloqueada, watchlist → `ioc` → 7 hallazgos ALTO con
  ubicación; 5 MISP hostiles → error localizado sin colgar), logfile-atributos (fila 0x09 de
  update_mapping_pairs con `attribute: $DATA`, resumen `Contextual: 1`), readbytes-gate (setupapi y
  rdp_cache ante sparse de 300 MB: FileTooLarge como error no fatal en 0,2 s, sin OOM ni descarte),
  refs-rama-heredada (REFS=("main",); update --check OK) y web-duplicate-aviso (gemelo EV-004 en el
  mensaje del job, es y en).
- Personas: analista nuevo (instalación con README → H-011/H-012; demo/doctor/informe OK), avanzado
  (caso completo es: evidencia→triaje→revisión→conclusiones→ATT&CK→STIX→informe→verificar OK), torpe
  (rutas/IDs inexistentes y orden incorrecto: todo localizado exit 1; informe de caso vacío honesto),
  malintencionado (evidencia/custodia/resultados manipulados en copia → exit 2 los tres; MISP hostil),
  operador (doctor --json, config init, update --check, vigilar --once → H-013), entorno adverso (PDF
  sin navegador: exit 1 localizado con HTML escrito; sin Volatility: memory con JSON exportados OK;
  caso de solo lectura → H-014).
- e2e nuevos: tests/e2e/test_e2e_verify_tamper_vectors.py (custodia y resultados → exit 2; la
  verificación canonicaliza y ignora ediciones de solo espacios, por diseño). Suite: 382 passed,
  1 skipped; ruff limpio.

## Estado hallazgos
- Abiertos nuevos: H-011 (PUL, ALTO), H-012 (IMP-1, ALTO), H-013 (IMP-1, BAJO), H-014 (IMP-1, MEDIO).
  Raíz común de H-011/H-012: el literal `[m` se perdió (rama heredada ab6d393) en READMEs, instaladores,
  update.py y locales; pyproject está intacto.
- Sin hallazgos pendientes de verificación de rondas anteriores (cola a cero desde la ronda 6).

## Sin probar aquí
- Docker (sin docker en este entorno) y ejecución íntegra de instaladores (la línea --with-memory rota
  queda cubierta por H-011); disco lleno; recolectar en Windows; firma del PDF (sin navegador).

## Peticiones
- PUL: H-011 (8 líneas `[m` en README.md, README.en.md, install.sh, install.ps1).
- IMP-1: H-012 (update.py + 6 claves de locales), H-013 (banner de vigilar --once), H-014 (solo
  lectura diagnosticada como BD dañada).
- DIR: marcar [x] intel-misp-opencti, refs-rama-heredada, logfile-atributos, readbytes-gate (IMP-1) y
  web-duplicada-aviso (IMP-2), verificadas esta ronda.

## Propuestas
- Test de regresión anti-corrupción: barrer locales y README buscando `emory]` (H-012).
- Documentar en README (Integridad) que `verificar` ignora ediciones de solo espacios en resultados
  (canonicalización), que es lo correcto, para que un perito no lo lea como hueco.
