# estado/TEST.md — 2026-10-23

## Hecho (últimas 24 h)
- Instalación desde cero en Linux/Py3.12 siguiendo solo el README: falla el comando literal del README (H-001) y doctor/memoria muestran pistas corruptas (H-002); con `.[dev]` instala completo con ruedas, sin errores.
- Personas ejecutadas (5): analista nuevo (instalación, doctor, demo, web), perito veterano (caso completo con E01 real: agregar, imagen --verificar --triaje, revisar, conclusiones, informe, verificar), despistado (caso inexistente, rutas con espacios/tildes/ñ, -L en ambas posiciones, new sin -i), evidencia hostil (evtx/SRUM truncados, colmena y $MFT de bytes aleatorios, nombre con comillas/;/ñ, HTML+JS en contenido) y operador (doctor, config, update --check, vigilar --una-vez).
- 6 hallazgos abiertos: H-001, H-003 (PUL), H-002, H-004, H-005, H-006 (IMP-1).

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- SEG: la web sin FORENSE_WEB_PASSWORD abre sin autenticación en 127.0.0.1 (probado: / 200, /login 404); cabeceras y cookie de sesión correctas. Revisar si hay que avisar en el arranque.
- PUL: el ejemplo de `conclusiones --archivo` del README (línea 228) no indica que el archivo debe existir antes (detalle en H-006).

## Propuestas para el roadmap
- Añadir a TEST: caso con imagen VHD/QCOW2 de tests/data (solo probé E01) y correlación entre casos con la demo.

## Flujo y comprobaciones positivas
- Robustez hostil: 6 evidencias corruptas/basura por triaje sin un solo traceback; custodia íntegra (verificar exit 0).
- `verificar` sale 0 sano y 2 con custodia manipulada en copia ([FAIL] Cadena de custodia), como documenta el README.
- Sin XSS: URLs del módulo ioc se cortan en `<`, 0 `<script>`/`<img onerror>` crudos en informe HTML y web.
- PDF sin navegador falla con mensaje claro y accionable; vigilar --una-vez genera caso + informe + CSV + STIX.

## Sin probar (motivo)
- recolectar (requiere Windows como administrador); Docker e instaladores completos (sin docker en el entorno; lógica réplica en H-003); memoria real (sin Volatility); entornos sin red (no simulables aquí); imagen VHD/QCOW2 y correlación entre casos (quedan para la próxima ronda).
