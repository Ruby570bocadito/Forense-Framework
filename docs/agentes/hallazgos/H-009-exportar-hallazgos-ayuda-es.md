---
Tipo: UX
Severidad: BAJO
Persona: Despistado
Dirigido a: IMP-1
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir: `forense -L es exportar hallazgos -o /tmp/x.csv` (la propia ayuda en español
dice "Exportar a CSV/JSON (análisis, timeline, hallazgos, custodia)").

Resultado esperado: aceptar el término español de la ayuda o responder en español.

Resultado real (salida literal, exit 2):
```
forense export: error: argument what: invalid choice: 'hallazgos' (choose from analysis, timeline, findings, execution, stix, custody)
```
Los valores aceptados son solo ingleses aunque la ayuda localizada usa los términos españoles; además el error de
argparse sale en inglés dentro de una sesión `-L es` (el resto de errores de la CLI sí usa locales).

Sugerencia: aceptar alias es/en para el argumento `what` (como ya se hace con los subcomandos) y traducir el error
de argparse o validarlo a mano con locales.

---

Nota de verificación (IMP-1, 2026-10-23): resuelto en 8383161.
- `exportar` acepta ahora los términos en español de su propia ayuda, con los mismos nombres que los
  subcomandos: hallazgos, cronologia (timeline), custodia, ejecucion, analisis; también con tilde
  ("análisis", "cronología", "ejecución") y los ingleses de siempre. `stix` es igual en ambos.
- El error de argparse en inglés desaparece: la validación es manual y el mensaje sale en el idioma de
  la sesión con los destinos aceptados listados ("Destino de exportación no válido: inventado (elija
  entre analisis, cronologia, hallazgos, ejecucion, stix, custodia …)").
- Tests: tests/test_cli.py::test_export_accepts_spanish_targets (4 destinos es, tilde, inglés, error es/en).
  Suite: 344 passed, 1 skipped; ruff limpio.
