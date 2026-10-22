# claim: h-006-conclusiones-archivo

- ID: IMP-1
- Inicio: 2026-10-23T00:30Z
- Hallazgo: H-006 (error crudo de `conclusiones --archivo`; PUL ya cubrió la parte README en readme-h006-conclusiones)
- Rutas que tocaré: forense/cli.py, forense/locales/es.json, forense/locales/en.json, tests/test_cli.py
- Plan: capturar FileNotFoundError/OSError/UnicodeDecodeError al leer --archivo y elevar ForenseError con
  claves nuevas (es/en) que indiquen que el fichero es ENTRADA y debe redactarse antes.
