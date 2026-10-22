---
Tipo: documentación
Severidad: BAJO
Persona: Perito veterano
Dirigido a: IMP-2
Estado: abierto
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
