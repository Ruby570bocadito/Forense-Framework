# estado/PUL.md — 2026-10-23

## Hecho (últimas 24 h)
- readme-hoja-de-ruta: retirada «Correlación entre casos» de la Hoja de ruta en README.md y README.en.md (queda solo la importación MISP/OpenCTI), como pedía DIR.
- readme-arbol-comandos: árbol de «Arquitectura» contrastado con el código en ambos README. Corregido: módulo `defender` en modules/windows/, parser Defender y recuperación de celdas borradas en parsers/; añadidos los módulos raíz que faltaban (automation, notify, update, doctor, i18n, charts, presentation). La tabla de módulos coincide con el registro real (18 de Windows + 6 genéricos).
- Instaladores: eliminado el fallback a `claude/inspiring-cray-xn35zk` en install/install.sh e install/install.ps1 (main es la predeterminada y contiene todo). Sintaxis verificada con bash -n.
- Comandos del README probados en Linux (Python 3.x): `pip install -e ".[dev]"`, `python -m pytest -q` (270 passed, 1 skipped), `ruff check forense tests` (limpio), `forense doctor` (19 OK, 0 errores), `forense demo` (61 hallazgos, 236 eventos, exit 0).
- Escaneo de secretos con gitleaks 8.30.1 (binario oficial de su releases) sobre árbol e historial completo (24 commits): 0 hallazgos. Completa el escaneo por patrones que hizo DIR.
- sesion cerrada: claim readme-sync liberado; 3 commits (1ab1954, a4e1a10, 915e0a6 rebased a e73091f).

## En curso
- —

## Bloqueado
- Docker no está disponible en este entorno: los comandos `docker compose up` / `docker run` del README no se han podido ejecutar aquí (la CI sí los prueba). Pendiente de verificar por TEST u operador.

## Peticiones a otras zonas
- IMP-1: `forense/update.py` (línea 26, REFS) mantiene `claude/inspiring-cray-xn35zk` como referencia alternativa; con main predeterminada y completa es un resto de la migración de rama. Quitarlo con cambio mínimo (instaladores ya limpiados en mi zona).

## Propuestas para el roadmap
- Ninguna nueva: el ROADMAP de DIR ya cubre lo detectado.

## Estado: VERDE
- Riesgos: ninguno añadido. Nota: los README dicen lo mismo en es/en tras los cambios (secciones homologadas 1:1).
