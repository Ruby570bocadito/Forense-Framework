---
Tipo: mejora
Severidad: BAJO
Persona: Perito veterano
Dirigido a: IMP-1
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir: con claves Ed25519 generadas (`openssl genpkey -algorithm ed25519 -out perito.pem` y `openssl pkey -in perito.pem -pubout -out perito.pub.pem`), definir `FORENSE_SIGN_KEY` y `FORENSE_SIGN_PUB` y ejecutar `forense -c ./caso informe`. La misma operación desde la web (página Informes con la casilla de firma) sí firma. Nota: el informe de esta verificación se firmó vía web y el flujo completo funciona (`.sig` creado, verificación OK, manipulación detectada, custodia con huella).

Resultado esperado: que la CLI ofrezca el mismo camino que la web — una opción explícita tipo `--firmar/--sign` en `informe` (y en el PDF) — o, si la firma sigue siendo solo de la web, que la CLI avise de que la clave definida no se va a usar.

Resultado real: el informe se genera sin `.sig` y sin ningún aviso (salida literal):
```
Report written: /ruta/caso/reports/report_20261022T175613Z_en.html
```
`ls caso/reports/*.sig` no devuelve nada. En el código, `generate_report(sign=False)` por defecto; la web pasa `sign=on` por su casilla, pero `forense informe --help` no expone ninguna opción de firma. La tarea report-signing del ROADMAP preveía explícitamente la exposición CLI `--sign` (IMP-1, forense/cli.py) como paso posterior.

Sugerencia: añadir `--firmar/--sign` a `informe` (y al PDF) que active `generate_report(sign=True)`; alternativa mínima: advertir por locales cuando `FORENSE_SIGN_KEY` esté definida y la firma no se solicite.

---

Nota de verificación (IMP-1, 2026-10-23): resuelto en 2254b95 (dependencia report-signing de ROADMAP cumplida).
- `forense informe --firmar` (alias `--sign`, ayuda localizada es/en) activa generate_report(sign=True) y,
  con --pdf, html_to_pdf(sign=True): mismo camino que la casilla de la web. El `.sig` queda junto al informe
  y la custodia registra report_signed con huella SHA-256 y fingerprint de la clave publica; la clave
  privada no se persiste (FORENSE_SIGN_KEY).
- Mensaje "Informe firmado: {sig}" por cada fichero firmado (HTML y PDF); sin --firmar no hay .sig ni aviso,
  incluso con la clave definida.
- Tests: tests/test_cli.py::test_report_sign_option (.sig valido, verificacion OK, manipulacion detectada,
  entrada de custodia) y test_report_without_sign_makes_no_sig. Suite: 346 passed, 1 skipped; ruff limpio.
