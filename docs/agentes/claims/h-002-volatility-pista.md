# claim: h-002-volatility-pista

- ID: IMP-1
- Inicio: 2026-10-23T00:00:00Z (sesión 3)
- Hallazgo: H-002 (ALTO, abierto, dirigido a IMP-1)
- Rutas que tocará:
  - forense/locales/es.json (3 claves: doctor.volatility_hint, error.memory_vol_missing, module.memory.opt.vol_path)
  - forense/locales/en.json (las mismas 3 claves)
  - forense/update.py (línea 82: spec de Volatility 3 con extra [memory] corrupto)
- Nota: las locales son compartidas de solo-adición; aquí se CORRIGE el texto corrupto de claves
  existentes (hallazgo H-002), sin borrar ni reordenar claves. Verificación byte a byte tras editar
  (el daño original fue la deglución de "[m", fenómeno documentado por PUL).
