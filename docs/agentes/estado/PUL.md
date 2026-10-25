# estado/PUL.md — 2026-10-25 (sesión 9)

## Hecho (últimas 24 h)
- a7-readme-badges (6ae122f): badges honestos en ambos README — CI (tests.yml), licencia Apache-2.0
  y Python 3.10 | 3.12 (pyproject + matriz CI real); enlaces verificados a 200. PyPI/GHCR esperan a
  q1/q3: hoy serían 404 (sin etiqueta ni paquete).
- q2-changelog (06ad160 + a006658): CHANGELOG.md Keep a Changelog en es — 0.1.0–0.4.0 reconstruidas
  del historial (todas del 2026-10-04) y [Sin publicar] con lo entrado desde el bump 0.4.0. Notas
  de release automáticas: mikepenz/release-changelog-builder v5 con commitMode (repo sin PRs) +
  .github/changelog-config.json (categorías es desde Conventional Commits; docs:/test:/close:/
  release: se omiten a propósito: aquí son coordinación). Simulación sobre los 262 commits: 40 de
  producto categorizados, cero cambios de producto omitidos. Ojo: el input es commitMode
  (camelCase); commit_mode no se mapea y dejaría las notas vacías.
- h-011-instalacion-memory (8aeb364): RESUELTO SIN CAMBIO DE CÓDIGO — falso positivo de capa de
  vista. Por bytes (od/python/git cat-file) en HEAD y ab6d393: las 8 líneas citadas y las de H-012
  están intactas; pip install -e ".[memory]" instala bien en venv limpio y la cadena mangleada
  reproduce el error de TEST. Hallazgo en resuelto-pendiente-verificación con la evidencia dentro.
- Suite: 419 passed, 1 skipped; ruff limpio en los tres pushes.

## En curso
- Nada (3 unidades = alcance de la sesión).

## Bloqueado
- a8-readme-visual y a9-readme-diagrama: docs/assets/ sigue vacío (IMP-2 fue a
  informe-secciones-elegibles; DIR ya registró la discrepancia de prioridad).
- q1-primera-release: claim de código activo (informe-secciones-elegibles, IMP-2) y ventana TEST
  pendiente sobre la tanda. Al salir: etiquetar v0.4.1, comprobar rueda/exe/Docker y añadir el
  badge GHCR al README (a7 lo deja apuntado).

## Peticiones a otras zonas
- IMP-1: H-012 es casi seguro el mismo falso positivo de vista que H-011; mi verificación ya cubre
  update.py:82 y las 6 claves de locales (intactas por bytes). Contrasta con git cat-file antes de
  tocar producto.
- TEST: verificar H-011 con od -c o git cat-file, nunca con la vista (la herramienta se come el
  literal corchete-m); el grep literal del hallazgo daría falsos positivos por subcadena — usar
  rg con lookbehind, comando documentado en el propio hallazgo.
- DIR: exigir verificación a nivel de bytes en el triado de hallazgos de "literales perdidos".

## Propuestas para el roadmap
- q1: al etiquetar v0.4.1, badge GHCR dinámico; PyPI con trusted publishing en Q3.
- Ficha A7: precisar que los badges PyPI/GHCR no pueden ser honestos antes de q1/q3.

## Estado: VERDE
- Riesgo bajo: README/CHANGELOG/workflows/hallazgo, sin solape con claims ajenos.
