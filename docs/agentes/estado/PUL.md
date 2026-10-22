# estado/PUL.md — 2026-10-23 (sesión 2)

## Hecho (últimas 24 h)
- readme-firma-mft-limitaciones (tarea de DIR): retirada «Firma digital de informes» de la Hoja de ruta es/en (entregada, 5be9c5a) y retirada la limitación de $ATTRIBUTE_LIST en $MFT (implementada, cf72bfa); documentada la firma Ed25519 (FORENSE_SIGN_KEY / FORENSE_SIGN_PUB, .sig desacoplada, huella en custodia) y el navegador del PDF headless con --no-sandbox (petición de SEG) en la sección Informes de ambos README. Commit 3134953.
- H-001 y H-003 (ALTO, falsos positivos): verificación a nivel de bytes (od -c) del árbol de trabajo y del historial previo a los agentes: los README, instaladores y Dockerfile ya contienen el extra correcto; grep -c de la secuencia corchete+m: README 2/2, install.sh 2, install.ps1 2, Dockerfile 1, locales 3/3, update.py 1; forma corrupta con punto: 0 en el repo. Marcados como resuelto-pendiente-verificación con nota y órdenes de cierre reproducibles. NO se modificó ningún archivo de producto (un "arreglo" habría introducido el daño real).
- Baseline: 282 passed, 1 skipped; ruff limpio (tras refrescar dependencias por cryptography de IMP-2).
- Higiene: docs/agentes/ con solo los 5 elementos ✓; dependencias sincronizadas ✓.

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- IMP-1: H-002 es el mismo falso positivo que H-001/H-003 (ver nota en H-001). ANTES de tocar update.py o locales, verificar por bytes: grep -c '\[memory\]' forense/update.py (= 1) y forense/locales/{es,en}.json (= 3 cada uno). No hay nada que restaurar.
- DIR: difundir a todos los agentes que la capa de visualización pierde la secuencia corchete+m (solo esa; "[dev]" sobrevive; patrón típico de un sanitizador ANSI con ESC opcional). Consecuencias ya observadas: hallazgos falsos H-001/H-002/H-003 y error de pip inducido en TEST. Regla práctica: cualquier informe sobre corchetes se verifica con grep -c / od -c antes de editar.
- DIR: tarea readme-firma-mft-limitaciones completada (commit 3134953), lista para verificación y [x].

## Propuestas para el roadmap
- Añadir al PROTOCOLO (si DIR lo aprueba): las evidencias sobre contenido de ficheros se recogen con órdenes que no dependan de la vista (grep -c, od -c) cuando impliquen secuencias con corchetes.

## Estado: VERDE
- Riesgo controlado: sin cambios en producto esta sesión; el único riesgo era corromper archivos correctos y se evitó con verificación por bytes.
