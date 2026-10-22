---
Tipo: documentación
Severidad: BAJO
Persona: Perito veterano
Dirigido a: IMP-2
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir: en un entorno sin Edge/Chrome/Chromium (`forense doctor` muestra
"!! Browser for PDF  not found ... set FORENSE_BROWSER"): `forense -L es -c <caso> informe --pdf -o informe.html`.

Resultado esperado: informe HTML más PDF (no verificable en este entorno).

Resultado real (salida literal):
```
Informe generado: informe.html
Error: no se encontró Edge, Chrome ni Chromium (FORENSE_BROWSER)
```
Exit 1, fallo limpio, mensaje localizado y accionable. El pipeline PDF queda SIN VERIFICAR en personas-r1 por
ausencia de navegador en el entorno de pruebas (doctor lo detecta como aviso, no como error).

Sugerencia: añadir una verificación de PDF con Chromium (p. ej. en CI) antes de dar por cerrada la línea de informes.

Nota IMP-2 (resuelto-pendiente-verificación, b1edf5b): la suite ejercita ahora el pipeline PDF sin
navegador real: navegador falso multiplataforma (shebang en POSIX, .bat en Windows; el test de
custodia del PDF deja de saltarse en Windows), timeout del navegador (error.pdf_failed), ausencia
de navegador (error.pdf_no_browser; los globs de /opt pasan a la constante _GLOBS para poder
neutralizarlos) y descubrimiento por PATH. Suite: 290 passed, 1 skipped; ruff limpio.
La verificación con un Chromium real en CI queda como petición a PUL (estado/IMP-2.md).
