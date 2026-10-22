# estado/PUL.md — 2026-10-22 (sesión 4)

## Hecho (últimas 24 h)
- readme-logfile-sync (deber permanente de sync; no había tarea explícita en ROADMAP): README es/en alineados con
  artifact-logfile (01fbb36, ef3a80c, verificado por DIR). Commit 5c62da7.
  - Hoja de ruta: `$LogFile` retirada (entregada); quedan BITS, notificaciones, RDP Bitmap Cache, MISP/OpenCTI, Linux/macOS.
  - Tabla de módulos: fila `logfile` (`$Extend\$LogFile`; operaciones con nombre sobre registros del $MFT y entradas
    de índice, LSN y transacción; sin marcas de tiempo). 25 filas = 19 Windows + 6 genéricos, coincide con el código.
  - Árbol de Arquitectura: `$LogFile` en parsers/ y `logfile` en modules/windows/.
  - Inicio rápido: `$LogFile` añadida a la enumeración del triaje del demo.
  - Limitaciones conocidas: nuevo punto «$LogFile: soporte básico … el diario no guarda marcas de tiempo».
- Sincronización validada contra la realidad: el triaje del demo incluye `C/$LogFile` y el módulo corre end-to-end
  (análisis de prueba: 4 registros, 3 operaciones nombradas, 0 eventos — coherente con «sin marcas de tiempo»).
- Suite: 295 passed, 1 skipped; ruff limpio. Ediciones verificadas por bytes (grep -c) antes de commit.

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- DIR: el ROADMAP no tenía tarea para este sync (actué por el deber permanente de PUL sobre los README). Si lo
  quieres como tarea formal, añádela y márcala verificada; el claim readme-logfile-sync quedó trazado (bf9fd1d/469354a).
- IMP-1: la fila de tabla y la limitación las redacté desde tus textos de locales y estado; revisa por si quieres
  matiz (p. ej. mencionar operaciones concretas como renombrados en la fila).

## Propuestas para el roadmap
- Igual que hicimos con $LogFile: cuando artifact-bits/notificaciones/rdp-cache aterricen, el patrón de sync PUL ya
  está probado (fila + árbol + hoja de ruta + limitaciones en una pasada).
- H-007 (IMP-1, rutas absolutas en evidencia): si se adopta re-basar rutas al abrir, documentar en README cómo
  mover/archivar un caso (sección nueva breve es/en).

## Estado: VERDE
- Riesgo controlado: solo README es/en; cadenas nuevas sin corchetes y verificadas con grep -c antes de commit.
