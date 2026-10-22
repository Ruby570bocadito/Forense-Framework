# estado/PUL.md — 2026-10-22 (sesión 3)

## Hecho (últimas 24 h)
- readme-arbol-comandos (tarea de DIR): árbol de «Arquitectura» contrastado contra el árbol real y ajustado en es/en:
  core/ gana correlación e indicadores STIX, report/ gana PDF y firma Ed25519 (respaldado en código:
  core/correlation.py, core/stix.py, report/pdf.py, report/signing.py). Commit 276c913.
- Tabla de módulos: 24 filas = 18 de Windows + 6 genéricos, coincide con forense/modules/ (sesión previa + revisión DIR).
- Comandos probados en este entorno: pip install -e ".[dev]" (refrescado), forense doctor (19 OK, 0 errores),
  forense demo (61 hallazgos, 237 eventos; coherente con los registros de extensión MFT nuevos).
- CI verificada contra lo que promete «Desarrollo»: tests.yml (ubuntu+windows, Python 3.10/3.12, demo con verify+report,
  instaladores install/uninstall) y release.yml (etiqueta v*, imagen en ghcr.io). bash -n de install.sh OK.
- Docker no ejecutable aquí: Dockerfile y docker-compose.yml verificados textualmente (8765, FORENSE_WEB_PASSWORD,
  /cases, /evidence:ro, WITH_MEMORY) y el Dockerfile además por bytes (od -c).
- Suite: 283 passed, 1 skipped; ruff limpio.

## En curso
- —

## Bloqueado
- Docker no está disponible en este entorno: el ciclo completo de contenedores (build/run) no es verificable aquí.

## Peticiones a otras zonas
- DIR: sin respuesta aún a la difusión del maquillado de corchetes+m en la capa de visualización (sesión 2). Hoy volvió
  a ocurrir en MI terminal: rg mostraba el Dockerfile como ".emory]" y od -c probó que el disco contiene ".[memory]".
  El repo sigue limpio; ningún «arreglo» fue necesario. La regla (grep -c / od -c antes de editar) evita que cualquier
  agente introduzca el daño real.
- IMP-1: cuando entregues artifact-logfile, avisa en tu estado y sincronizamos en una pasada: árbol de Arquitectura,
  tabla de módulos, Hoja de ruta y Limitaciones (es/en).

## Propuestas para el roadmap
- Tras artifact-bits/logfile/rdp-cache/notifications, una pasada PUL única de README (tabla + hoja de ruta + limitaciones)
  es más barata que cuatro sincronizaciones sueltas.

## Estado: VERDE
- Riesgo controlado: solo documentación tocada; las cadenas nuevas no contienen corchetes y se verificaron con grep -c.
