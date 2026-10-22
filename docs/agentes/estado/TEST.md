# estado/TEST.md — 2026-10-23 (ronda 4)

## Hecho
- H-007 verificado y CERRADO (fix dfe9cde de IMP-1): e2e tests/e2e/test_e2e_verify_copia.py —
  copia con cp -r del caso entero se verifica contra sí misma; manipular un fichero DENTRO de
  la copia da exit 2 con [FAIL]; el original sigue en exit 0; copia movida a otra ruta sigue
  resolviendo su evidencia. Lo pide IMP-1 en su estado.
- Módulos nuevos verificados sobre demo fresca: notifications (4 registros, 4 eventos) y
  rdp_cache (4 registros, hallazgo LOW "Historic RDP activity", 4 tiles extraídos como BMP con
  cabecera BM válida en analyses/0009_rdp_cache/).
- timeline-export-html (IMP-2) verificado de extremo a extremo por HTTP real: POST con CSRF
  escribe en exports/ anclado a custodia (export_created con sha256 que coincide), documento
  autónomo (doctype, sin src/href externos, sin JS), y un comando hostil de histórico
  PowerShell (`<script>alert(1)</script> =cmd...`) llega ESCAPADO al export. Regresión:
  tests/e2e/test_e2e_timeline_html.py (servidor real en puerto efímero con contraseña).
- Nota técnica del e2e: el CSRF vive en la sesión; hay que reutilizar la MISMA cookie de la
  GET que renderizó el token en el POST (mi primer intento falló con 400 por mezclar sesiones).
- Re-confirmados abiertos: H-005 (duplicada sin aviso), H-006 (errno crudo en conclusiones
  --archivo), H-009 (argparse en inglés con -L es), H-010 (--sign sigue ausente de informe
  --help). Coincide con la cola declarada por IMP-1.
- Suite: 334 passed, 1 skipped; ruff limpio. 2 e2e nuevos esta ronda (9 ficheros e2e).

## Estado hallazgos
- Cerrados esta ronda: H-007. Abiertos: H-005, H-006, H-009, H-010 (todos IMP-1, en su cola).

## Sin probar
- Job pdf de CI (GitHub), Docker, recolectar (Windows admin), memoria real con Volatility,
  disco lleno, wpndatabase/Cache*.bin reales (el demo sintetiza bien, sin muestra real de
  referencia en tests/data para notificaciones/rdp).

## Peticiones
- IMP-1: H-005/006/009/010 cuando puedas; h-002 guardas vistas (bien).
- IMP-2: h-008 ya lo cerré en la ronda 3 (12a5c8b); tu estado quedó anticuado.
- PUL: faltan README de notifications/rdp_cache (petición de IMP-1) y documentar cómo mover/
  archivar un caso (parte documental de H-007).
- DIR: recordatorio — los claims se liberan al empujar (claims/ está vacío, correcto); el
  token sigue pendiente de rotación por el operador (a SEG le fue rechazado).
