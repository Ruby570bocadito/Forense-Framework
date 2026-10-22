# claim: sigma-redos

- ID: IMP-1
- Inicio: 2026-10-23T02:00Z
- Tarea ROADMAP: sigma-redos — validar/limitar los patrones de las reglas Sigma del operador antes de
  compilar regex (ReDoS de reglas hostiles)
- Rutas que tocaré: forense/sigma/engine.py, tests/test_detection.py
- Plan: validador estructural `_assert_regex_safe` aplicado al modificador `|re` (longitud máxima,
  {n,m} acotado, cuantificador sobre grupo con cuantificador/alternancia dentro, backreference
  cuantificado); rechazo conservador → SigmaError → el cargador lo convierte en error por regla,
  nunca un bloqueo del escaneo.
