# estado/TEST.md — 2026-10-23 (ronda 3)

## Hecho
- Conflicto H-002 resuelto con evidencia independiente de la vista (od -c + conteos Python):
  las 6 claves de locales, update.py:82 y ambos READMEs contienen `[memory]` correcto y hay
  0 bytes ESC en las fuentes. La "corrupción" es la capa de visualización de los agentes
  (reproducida en vivo: printf de `[memory]` imprime `emory]`). El cierre de
  H-001/H-002/H-003 era correcto; el claim h-002-volatility-pista (IMP-1) persigue una
  ilusión y NO debe aplicarse: "corregir" esos textos los corrompería de verdad.
- H-008 verificado y CERRADO: sin navegador, error localizado limpio (exit 1); navegador que
  no produce PDF, pdf_failed limpio; navegador falso que escribe %PDF, exit 0 con
  report_pdf_generated en custodia y verificar en verde. e2e: tests/e2e/test_e2e_pdf.py.
- H-004 actualizado (sigue ABIERTO): el repro de urandom ya no dispara 6/6 muestras
  (lookbehind `(?<![\w.-])` en _TOOLS de psreadline), pero el bypass del predicado para
  archivos sueltos sigue fabricando 2 hallazgos ALTO desde prosa ("cme was used by the
  attacker" en un notas.txt). Nuevo repro en el hallazgo; e2e de la mitad arreglada:
  tests/e2e/test_e2e_find_files_suelto.py.
- Petición de SEG (evidencia hostil) servida como e2e: tests/e2e/test_e2e_hostil_texto.py —
  descripción con <script>/fórmulas y nota hostil: informe HTML las escapa (texto, nunca
  atributo; &#34;) y el CSV neutraliza celdas de fórmula con prefijo ' (core/utils._csv_value;
  la web usa la misma ruta core/exports).
- Entregas nuevas verificadas: aviso sin contraseña también en loopback (stderr; silencio con
  contraseña), 413 con cuerpo de 2 MiB, banda HTML de no-auth en la página del caso, 45
  for=/id= en analyses sin ninguno roto (web-labels-analyses).
- Persona Entorno adverso (nueva, de la ronda 1): caso solo lectura, TMPDIR no escribible,
  HOME=/no/existe y evidencia borrada bajo el caso: todo falla limpio, sin tracebacks, exits
  coherentes (tempfile hace el fallback estándar a /tmp). Re-confirmados abiertos H-005
  (duplicada sin aviso), H-006 (error crudo de conclusiones --archivo; exit 1 correcto) y
  H-009 (exportar con término es; argparse en inglés).

## Estado hallazgos
- Cerrados esta ronda: H-008. Abiertos: H-004 (con repro de prosa), H-005, H-006, H-007,
  H-009, H-010 (--sign sigue ausente de informe --help).

## Sin probar
- Job pdf de CI (primer run en GitHub), Docker, recolectar (Windows admin), memoria real,
  disco lleno.

## Peticiones
- IMP-1: NO aplicar el claim h-002-volatility-pista; verificar con od -c o conteos antes de
  editar (fenómeno ya documentado por PUL). H-004 (prosa), H-005/006/007/009/010 abiertos.
- DIR: al revisar claims de contenido, exigir evidencia por bytes (od -c / grep -c), no por
  captura de la vista.
