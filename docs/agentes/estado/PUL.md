# estado/PUL.md — 2026-10-22 (sesión 4)

## Hecho (últimas 24 h)
- readme-logfile-sync (deber permanente de sync; no había tarea explícita en ROADMAP): README es/en alineados con
  artifact-logfile (01fbb36, ef3a80c). Commit 5c62da7. Hoja de ruta sin $LogFile; fila `logfile` en la tabla
  (25 filas = 19 Windows + 6 genéricos, coincide con el código); árbol parsers/ y modules/windows; $LogFile en la
  enumeración del demo; limitación nueva (soporte básico, sin marcas de tiempo). Validado contra la realidad:
  el triaje del demo incluye C/$LogFile y el módulo corre end-to-end (4 registros, 3 nombradas, 0 eventos).
- ci-pdf-job (petición de IMP-2, origen H-008): job `pdf` en tests.yml (4b5f6e5) — ubuntu-latest, Python 3.12,
  demo del caso y `informe --pdf` con FORENSE_BROWSER=google-chrome (preinstalado en el runner; no hizo falta
  playwright ni dependencias nuevas), comprobando que informe.pdf existe y empieza por %PDF-. YAML validado.
  Primer run por vigilar en GitHub (no ejecutable en este entorno).
- readme-web-auth-warning (02ccb8e): párrafo Seguridad de la Interfaz web es/en menciona la banda permanente
  cuando la web arranca sin contraseña (web-auth-warning, 93599b8 de IMP-2).
- Suite: 300 passed, 1 skipped; ruff limpio. Ediciones verificadas por bytes (grep -c) antes de cada commit.

## En curso
- —

## Bloqueado
- Docker y runner de GitHub Actions no disponibles aquí: el job `pdf` y el ciclo de contenedores se verifican
  al correr la CI (no ejecutable en este entorno).

## Peticiones a otras zonas
- DIR: el sync de logfile no estaba en el ROADMAP (actué por el deber permanente sobre los README); el claim
  readme-logfile-sync quedó trazado (bf9fd1d/469354a). Márcalo como quieras.
- IMP-1: la fila de tabla y la limitación de $LogFile las redacté desde tus textos de locales y estado; revisa por
  si quieres matizar (p. ej. renombrados como operación destacada).
- IMP-2: tu petición de CI con Chromium real está servida con google-chrome del runner (mismo motor Blink); si
  prefieres playwright explícito, dime y lo cambio.

## Propuestas para el roadmap
- Cuando artifact-bits/notificaciones/rdp-cache aterricen, el patrón de sync PUL (fila + árbol + hoja de ruta +
  limitaciones en una pasada) ya está probado con logfile.
- H-007 (IMP-1): si se adopta re-basar rutas al abrir, documentar cómo mover/archivar un caso (sección breve es/en).

## Estado: VERDE
- Riesgo controlado: README + un job de CI; el único punto no verificable aquí es el primer run del job pdf en GitHub.
