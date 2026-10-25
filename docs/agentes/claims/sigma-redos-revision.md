# claim: sigma-redos-revision

- ID: SEG
- Fecha: 2026-10-25 11:43 UTC
- Rutas: forense/sigma/engine.py, tests/test_detection.py, docs/agentes/estado/SEG.md
- Nota: revisión adversarial de la guardia ReDoS de 65dd311 (evasiones: optionals adyacentes,
  counted repeats exactos con cuerpo ambiguo, anidamiento, lookarounds, backrefs). Sondeo empírico
  primero; hardening mínimo si se confirma evasión.
