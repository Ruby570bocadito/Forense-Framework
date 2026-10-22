# estado/TEST.md — 2026-10-23 (ronda 5)

## Hecho
- H-005 verificado y CERRADO (fix 1f94986 de IMP-1): repro literal del hallazgo — el 2º registro
  del mismo EVTX avisa por stderr «Aviso: contenido idéntico a EV-001 (SHA-256 …); el registro
  continúa» en el idioma de sesión (-L es verificado; en locale C el aviso sale en inglés, que es
  el comportamiento conocido, no parte de H-005). Exit 0 en todos los casos, stdout limpio para
  consumo automático, `evidencia listar` muestra las 3 gemelas, y también avisa con directorios
  duplicados y con copia renombrada (mismo contenido, otra ruta). El primer registro de un caso
  jamás avisa (sin falsos positivos). Residual para IMP-1/IMP-2: la subida web
  (POST /c/<slug>/evidence) ignora `ev.duplicate_of` — el flash solo dice «Evidencia EV-00X
  registrada»; no bloquea el cierre (el hallazgo era del CLI del perito veterano).
- web-filtros-guardados (IMP-2) verificado por HTTP real: barra oculta en página limpia; guardar
  exige CSRF; query forjada (cookie=stolen&q=<script> en findings, evilloot=1 en timeline) queda
  recortada a la allowlist de cada página; nombre hostil `"><script>alert(1)</script>` renderiza
  escapado en el chip; el chip aplica (GET 200) y su borrado vacía el JSON; tope de 20 con aviso
  localizado («Up to 20 saved filters» en/Máximo en es); <case>/ui/saved_filters.json sin tocar
  la custodia (0 filas nuevas); saved_filters.json dañado degrada a «sin chips» con página 200.
  Regresión: tests/e2e/test_e2e_saved_filters.py (2 tests, servidor real con contraseña).
- Nota técnica del e2e: el flash viaja en la cookie de sesión que refresca el 302; hay que
  REEMPLAZAR (no acumular) los cookies de misma clave — werkzeug se queda con el primer valor
  duplicado, así que mezclar cookies viejas y nuevas silencia los flashes.
- Re-confirmados abiertos: H-006 (errno crudo, exit 1 correcto — IMP-1 la acaba de reclamar),
  H-009 (argparse rechaza «hallazgos» con -L es), H-010 (--sign sigue ausente de informe --help).
- Suite: 344 passed, 1 skipped; ruff limpio. 1 e2e nuevo esta ronda (10 ficheros e2e).

## Estado hallazgos
- Cerrados esta ronda: H-005. Abiertos: H-006, H-009, H-010 (todos IMP-1, en su cola).

## Sin probar
- Job pdf de CI (GitHub), Docker, recolectar (Windows admin), memoria real con Volatility,
  disco lleno, muestras reales de wpndatabase/qmgr.db/Cache*.bin.

## Peticiones
- IMP-1: H-006/009/010 cuando puedas (H-006 ya reclamada). Residual de H-005: que la subida web
  muestre el gemelo duplicado (1 línea con ev.duplicate_of en el mensaje del job).
- IMP-2: filtros guardados — verificado todo; solo el residual de arriba toca tu superficie web.
- PUL: pendientes README de notifications/rdp_cache y documentar mover/archivar caso (H-007).
- DIR: el token sigue pendiente de rotación por el operador.
