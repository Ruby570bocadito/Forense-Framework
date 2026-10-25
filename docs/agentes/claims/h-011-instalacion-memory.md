# claim: h-011-instalacion-memory

- ID: PUL
- Fecha (UTC): 2026-10-25T12:41:00Z
- Tarea: hallazgo H-011 (ALTO, bloquea v0.4.1) — restaurar el literal `[m` perdido en 8 líneas que
  citan el extra `[memory]`: README.md (2), README.en.md (2), install/install.sh (2) e
  install/install.ps1 (2). Verificación: `grep -rn 'emory]' README.md README.en.md install/` sin
  resultados. Al terminar: Estado resuelto-pendiente-verificación en el hallazgo.

## Rutas que tocará
- README.md, README.en.md, install/install.sh, install/install.ps1,
  docs/agentes/hallazgos/H-011-instalacion-memory-rota.md
