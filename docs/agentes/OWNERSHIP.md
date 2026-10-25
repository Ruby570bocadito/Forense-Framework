# Zonas

| ID | Rutas que puede modificar/borrar |
|----|----------------------------------|
| DIR | docs/ROADMAP.md, docs/agentes/ROADMAP.md, docs/agentes/OWNERSHIP.md, docs/agentes/PROTOCOLO.md |
| IMP-1 | forense/core/, forense/parsers/, forense/image/, forense/sigma/, forense/modules/, forense/collector.py, forense/cli.py, forense/demo/, forense/automation.py, forense/notify.py, forense/update.py, forense/doctor.py, forense/i18n.py, y sus tests en tests/ |
| IMP-2 | forense/web/, forense/report/, forense/charts.py, forense/presentation.py, y sus tests en tests/ (web, informe, PDF) |
| PUL | README.md, README.en.md, .gitignore, pyproject.toml (orden/limpieza), Dockerfile, docker-compose.yml, .dockerignore, install/, packaging/, .github/workflows/, CHANGELOG/CONTRIBUTING/SECURITY (cuando el roadmap los pida), limpieza y refactors sin cambio de comportamiento |
| SEG | Fixes mínimos en cualquier ruta, siempre con claim previo |
| TEST | tests/e2e/, docs/agentes/hallazgos/. NUNCA código de producto |

Compartidos aditivos (no cuentan para solapamiento de claims): forense/locales/es.json, forense/locales/en.json,
forense/modules/__init__.py, pyproject.toml (solo para añadir una dependencia justificada).
Se editan con cambios mínimos: pull --rebase justo antes, solo AÑADIR claves/líneas, nunca reordenar ni reformatear, push inmediato.
IMP-1 añade claves de módulos/hallazgos/artefactos; IMP-2 las de interfaz e informe.

INTOCABLE: tests/data/ (artefactos reales con licencia documentada). Solo se añaden muestras con su origen y licencia
en tests/data/README.md; nadie borra ni modifica las existentes.
Regla: PUL no refactoriza una ruta con claim activo de otro agente.
Refactors grandes del roadmap (B1 cli.py, B2 web/__init__.py): los ejecuta el dueño de la zona (IMP-1 / IMP-2), no PUL.
