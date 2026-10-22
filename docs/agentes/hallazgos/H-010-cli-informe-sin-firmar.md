---
Tipo: mejora
Severidad: BAJO
Persona: Perito veterano
Dirigido a: IMP-1
Estado: abierto
---

Pasos para reproducir: con claves Ed25519 generadas (`openssl genpkey -algorithm ed25519 -out perito.pem` y `openssl pkey -in perito.pem -pubout -out perito.pub.pem`), definir `FORENSE_SIGN_KEY` y `FORENSE_SIGN_PUB` y ejecutar `forense -c ./caso informe`. La misma operación desde la web (página Informes con la casilla de firma) sí firma. Nota: el informe de esta verificación se firmó vía web y el flujo completo funciona (`.sig` creado, verificación OK, manipulación detectada, custodia con huella).

Resultado esperado: que la CLI ofrezca el mismo camino que la web — una opción explícita tipo `--firmar/--sign` en `informe` (y en el PDF) — o, si la firma sigue siendo solo de la web, que la CLI avise de que la clave definida no se va a usar.

Resultado real: el informe se genera sin `.sig` y sin ningún aviso (salida literal):
```
Report written: /ruta/caso/reports/report_20261022T175613Z_en.html
```
`ls caso/reports/*.sig` no devuelve nada. En el código, `generate_report(sign=False)` por defecto; la web pasa `sign=on` por su casilla, pero `forense informe --help` no expone ninguna opción de firma. La tarea report-signing del ROADMAP preveía explícitamente la exposición CLI `--sign` (IMP-1, forense/cli.py) como paso posterior.

Sugerencia: añadir `--firmar/--sign` a `informe` (y al PDF) que active `generate_report(sign=True)`; alternativa mínima: advertir por locales cuando `FORENSE_SIGN_KEY` esté definida y la firma no se solicite.
