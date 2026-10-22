# estado/TEST.md — 2026-10-22 (sesión personas-r1)

## Hecho (últimas 24 h)
- Claim personas-r1 ejecutado completo. Nota: H-001..H-006 ya existían de una ronda TEST anterior; esta ronda no los duplica y añade H-007..H-009. Abiertos por destinatario: IMP-1 6 (H-002, H-004, H-005, H-006, H-007, H-009), PUL 2 (H-001, H-003), IMP-2 1 (H-008).
- Analista nuevo: venv desde cero con solo el README; el comando literal de instalación sigue fallando (H-001 vivo); con el extra correcto instala limpio y `doctor` da 20 OK (solo falta navegador para PDF).
- Perito veterano: caso completo sobre la demo (nuevo, evidencia agregar --copiar, triaje, analizar, revisar, conclusiones, informe HTML, verificar); `verificar` exit 2 al manipular el hash de una evidencia en COPIA del caso; custodia, mitre, exportar y cronologia OK.
- Despistado: caso inexistente (error limpio, exit 1), evidencia repetida en silencio (H-005 vivo), rutas con espacios/ñ/&, SIGINT a mitad de triaje (sin traceback, análisis queda "failed", custodia íntegra), flags en distinta posición.
- Evidencia hostil: EVTX y colmena truncados, nombres con comillas/;/&/ñ, `<script>alert(1)</script>` en ImagePath de servicio: triaje sin tracebacks y payload ESCAPADO en informe HTML y web (sin XSS).
- e2e nueva: tests/e2e/test_e2e_cli.py, 5 tests subprocess sobre demo en tmp_path (flujo perito completo, verificar exit 2 en copia, caso inexistente, truncados tolerados, ruta con espacios/tildes). 5 passed en ~4 s; suite completa 291 passed, 1 skipped; ruff limpio.

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- IMP-1: H-007 es el hallazgo de mayor impacto forense de la ronda: `verificar` sobre una copia del caso valida las rutas absolutas del ORIGINAL (una copia manipulada da OK, y un caso movido da FAIL). Valorar rutas relativas al caso.
- IMP-2: H-008, verificar el pipeline PDF en un entorno con Chromium (aquí no hay navegador; el fallo sin navegador es limpio y accionable).
- PUL: H-001 y H-003 reproducidos hoy tal cual (README e instaladores con el extra corrupto).

## Propuestas para el roadmap
- Ampliar la batería e2e con imagen VHD/QCOW2 de tests/data y correlación entre casos (pendiente ya de la ronda anterior).
- Añadir en e2e un test de XSS con payload en registro (hoy verificado a mano) si se toca plantillas del informe o la web.

## Sin probar (motivo)
- recolectar (requiere Windows como administrador); Docker e instaladores del README (sin docker ni Windows en el entorno; lógica replicada en H-003); PDF real (sin navegador, H-008); memoria con Volatility contra volcado real (solo JSON sintéticos de la demo); descarga real de Sigma (sin red por normativa); instalador con extra de memoria instalado pero Volatility no ejecutado.
