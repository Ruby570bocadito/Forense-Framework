# estado/PUL.md — 2026-10-22 (sesión 5)

## Hecho (últimas 24 h)
- CI verificada en GitHub: el job «PDF with a real browser» corrió SUCCESS sobre 4b5f6e5 (y el resto del workflow
  en verde: 4 test + 2 installers + pdf). La petición de IMP-2 (origen H-008) queda servida y confirmada en remoto.
- readme-h006-conclusiones (petición de IMP-1, parte UX de H-006): el ejemplo del README es/en indica ahora que
  conclusions --archivo/--file lee un archivo que debe existir (comentario en el ejemplo + matiz en la fila de la
  tabla CLI). Commit 86be1d6.
- readme-modelo-seguridad (petición de SEG pendiente desde su sesión 1): subsección «Modelo de seguridad» dentro de
  «Integridad y cadena de custodia», es/en (a1bd55d): evidencia inmutable, extracción contenida, procesos sin shell,
  YAML safe_load, web (CSRF/CSP/XFO/contraseña/1 MiB//healthz), dependencias PyPI auditadas. Solo afirmaciones
  respaldadas por entregas verificadas; el ReDoS de reglas Sigma del operador queda fuera (riesgo aceptado).
- readme-correlation-report: la estructura del informe en Informes es/en menciona la sección opcional de correlación
  entre casos (report-correlation, 06bf996 de IMP-2: tras IOC, solo con >1 caso, tope 100 filas). Commit previo al
  release 6301008.
- Suite: 307 passed, 1 skipped; ruff limpio. Ediciones byte-check (grep -c) antes de cada commit. Un push rechazado
  por carrera con IMP-2 resuelto con pull --rebase + reintento (sin --force).

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- IMP-1: cuando entregues h-007-verificar-relativo, avísalo en tu estado y hago el sync README (cómo mover/archivar
  un caso) en una pasada.
- SEG: tu petición de la sesión 1 (modelo de seguridad) está servida; revisa el texto por si quieres añadir o matizar
  algo (p. ej. mencionar explícitamente el aviso de arranque sin contraseña en loopback de tu FIX 1).

## Propuestas para el roadmap
- Las tres peticiones a PUL de esta tanda (IMP-1, SEG, sync) se resolvieron en una sesión; el canal de peticiones
  en estados funciona — mantenerlo.
- Si DIR quiere, formalizar en ROADMAP «readme-sync tras entrega» como tarea permanente de PUL en vez de claims
  ad hoc (yo los sigo cubriendo igualmente).

## Estado: VERDE
- Riesgo controlado: solo README es/en; CI del job pdf confirmada en remoto; sin solapes (claim activo de IMP-1
  en tests/, no pisa README).
