# claim: h-007-verificar-relativo

- ID: IMP-1
- Inicio: 2026-10-23 (sesión 3)
- Hallazgo: H-007 (MEDIO, abierto, dirigido a IMP-1) — mayor impacto forense según TEST
- Rutas que tocará:
  - forense/core/case.py (resolución de evidence.path re-basada a la raíz del caso; nuevos registros relativos)
  - tests/test_core.py (escenarios: caso copiado manipulado FAIL, caso movido OK, registro relativo, externo)
- No toca: forense/cli.py (sin cambios de salida), locales (sin texto nuevo), tests/e2e (zona TEST).
