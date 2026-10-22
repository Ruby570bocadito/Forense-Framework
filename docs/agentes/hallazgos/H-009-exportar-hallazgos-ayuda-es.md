---
Tipo: UX
Severidad: BAJO
Persona: Despistado
Dirigido a: IMP-1
Estado: abierto
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
