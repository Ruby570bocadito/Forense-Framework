# estado/PUL.md — 2026-10-25 (sesión 8)

## Hecho (últimas 24 h)
- Tanda 0.4.x del roadmap de producto, es/en, una sola sesión con claims secuenciales (5 tareas, tope):
  - a1-readme-intel-misp (14cd5c6): `forense intel misp EXPORT.json [-o SALIDA]` en la tabla CLI; subsección
    «Importar inteligencia de MISP» con ejemplo probado de verdad (export → watchlist → `analizar ioc`) y tipos
    admitidos; el árbol menciona intel en core/.
  - a2-readme-hoja-de-ruta-sync (83eb8ad): MISP pasa a hecha, queda OpenCTI/TAXII; enlace a
    docs/ROADMAP.md; BITS «falta muestra real con licencia».
  - a3-readme-logfile-atributos (4ac3a4f): fila `logfile` y limitación $LogFile con operaciones de atributo
    (0x05–0x09, 0x0B) vía tabla de atributos abiertos; retirado «soporte básico».
  - a4-readme-readbytes-gate (45e99a2): bala «Consumo acotado» en Modelo de seguridad.
  - a5-readme-ejemplo-modulo (70af8f0): ejemplo neutro `example` (adiós `bits`, inexistente y bloqueada) con
    read_capped y ctx.error reales (API verificada contra base.py/utils.py); bloques python validados con ast.
- Suite local: 387 passed, 1 skipped; ruff limpio (creció con tests de SEG/IMP entrados durante la sesión).
- Zona verificada: .agent-tmp/ en .gitignore; pyproject (dev/memory) y workflows (tests, release) coherentes.

## En curso
- Nada (5 tareas = alcance de la sesión).

## Bloqueado
- a7-readme-badges: PyPI sin publicar (Q3) y sin releases (Q1): badges de PyPI/GHCR serían 404. Honestos solo
  tras q1 (imagen GHCR) o q3. Ver Propuestas.

## Peticiones a otras zonas
- DIR: marcar [x] a1–a5; con eso q2-changelog queda desbloqueada. (Mis claims a1/a2 usan slug sin prefijo:
  los reclamé antes de tu reordenación; los commits de cierre ya citan el prefijo correcto.)
- TEST: subsección MISP y ejemplo de módulo nuevos en el README — material fresco para la persona «documentación».

## Propuestas para el roadmap
- a4: la ficha decía «256 MB por defecto»; el código real tiene tope por tipo de artefacto (64 KB `$I` → 256 MB
  contenedores grandes). Documenté el código; un único default sería cambio de IMP-1.
- a7 junto a q1: al etiquetar v0.4.1, la release produce imagen GHCR y badge CI honesto; PyPI espera a Q3.
- Próxima ventana PUL: q2-changelog → (TEST verifica la tanda IMP) → q1-primera-release + a7.

## Estado: VERDE
- Riesgo bajo: solo README es/en + claims/estado; claims activos de IMP-1 (intel-opencti) e IMP-2 (web-progreso),
  sin solape con mi zona.
