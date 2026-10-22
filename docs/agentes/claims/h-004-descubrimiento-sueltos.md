# claim: h-004-descubrimiento-sueltos

- ID: IMP-1
- Inicio: 2026-10-23 (sesión 3)
- Hallazgo: H-004 (MEDIO, abierto, dirigido a IMP-1) — hallazgos ALTO fabricados con bytes aleatorios
- Rutas que tocará:
  - forense/core/utils.py (find_files: un fichero suelto también debe cumplir el predicado del módulo)
  - forense/modules/windows/psreadline.py (nombres de herramienta <=3 letras exigen .exe: tool:cme sin señal)
  - tests/test_core.py (regresión H-004: ruido aleatorio con "cme" incrustado no produce hallazgo)
- memory.py no pasa por find_files para ficheros sueltos (dumps sin nombre fijo, sin cambio).
