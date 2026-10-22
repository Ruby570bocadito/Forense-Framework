# estado/DIR.md — 2026-10-23

## Hecho (últimas 24 h)
- Verificadas las ramas: main = claude/inspiring-cray-xn35zk (ambas en 20fe3f3); main ya es la rama predeterminada en GitHub. Sin merge necesario.
- Creados PROTOCOLO.md, OWNERSHIP.md, ROADMAP.md y carpetas claims/, estado/ y hallazgos/ (.gitkeep); añadida `.agent-tmp/` a .gitignore.
- ROADMAP inicial: "Hoja de ruta" y "Limitaciones conocidas" del README contrastadas con el código (módulos existentes, correlación ya implementada, BITS/$LogFile/notificaciones/RDP Bitmap Cache/MISP ausentes).
- Escaneo de secretos por patrones de alto señal en árbol e historial completo: sin secretos reales (solo un ejemplo documental de webhook y un test con ruta ficticia). gitleaks/trufflehog no disponibles en esta sesión; repetir con herramienta cuando sea posible.
- Resuelto conflicto de bootstrap: había una segunda instancia DIR en paralelo (0652c83). PROTOCOLO y OWNERSHIP eran idénticos (se quedó la versión con formato estándar); ROADMAP fusionado conservando las tareas de ambas (detalle de core/correlation.py, firma Ed25519, pip-audit + entrega completa de módulo, auditorías SEG, web-rendimiento). Sin --force, sin descartar trabajo ajeno.
- Escaneo repetido con gitleaks 8.30.1 sobre árbol e historial completo (24 commits): 0 hallazgos. Cierra el pendiente de la sesión anterior.
- Entorno verificado (Python 3.12, venv): `pip install -e ".[dev]"` ok, `ruff check forense tests` limpio, `python -m pytest -q` = 270 passed, 1 skipped (~11 s).
- Tercera instancia DIR detectada antes de pushear (bootstrap duplicado): abortada y descartada sin tocar el origen; su única aportación útil se fusiona aquí (ref heredada en forense/update.py).

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- PUL: README.md y README.en.md listan "Correlación entre casos" en la Hoja de ruta, pero está implementada y documentada (`forense correlacionar`, commit 7b647b8, core/correlation.py). Corregir la línea para dejar solo MISP/OpenCTI. Ver tarea readme-hoja-de-ruta (primera del ROADMAP).

## Propuestas para el roadmap
- Volcadas en ROADMAP.md (fase actual + backlog). Próxima revisión de DIR tras ~3 sesiones de IMP/SEG.

## Estado: VERDE
- Riesgos: al menos tres instancias DIR lanzadas a la vez (riesgo de pisarse de nuevo: lanzar una sola por rol); el escaneo de secretos ya está confirmado con gitleaks (0 hallazgos).
- Decisiones: main como rama de trabajo (ya predeterminada); orden IMP-1 = $ATTRIBUTE_LIST → BITS → notificaciones (fiabilidad del parser primero, entrega completa de módulo después).
