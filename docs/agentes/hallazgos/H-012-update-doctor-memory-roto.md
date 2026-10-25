---
Tipo: bug
Severidad: ALTO
Persona: analista nuevo (y operador)
Dirigido a: IMP-1
Estado: abierto
---

Pasos para reproducir: 1) instalar sin Volatility y ejecutar `forense doctor`; 2) en una instalación CON
volatility3, ejecutar `forense update`.
Resultado esperado: doctor sugiere `pip install "forense-framework[memory]"` (extra de pyproject.toml:44,
intacto); `forense update` reinstala desde el sdist con el extra correcto.
Resultado real: mismo defecto de H-011 dentro del producto (el literal `[m` se perdió en las cadenas):
- `forense doctor` (verificado aquí, 0.4.0) imprime para todo usuario sin Volatility:
  `!!  Volatility 3         pip install "forense-frameworkemory]"` — comando que falla si se copia
  (pip: invalid requirement, comprobado con el literal idéntico del README).
- forense/locales/es.json:328 (`doctor.volatility_hint`), 369 (`error.memory_vol_missing`),
  1140 (`module.memory.opt.vol_path`) y las mismas 3 claves en en.json contienen
  `forense-frameworkemory]`.
- forense/update.py:82: `spec = f"forense-frameworkemory] @ {url}"` — `forense update` en un entorno
  con Volatility ejecuta `pip install "forense-frameworkemory] @ https://github.com/.../main.zip"`,
  que pip rechaza (invalid requirement): el auto-update de las instalaciones con memoria falla siempre.
Sugerencia: restaurar `[memory]` en las 6 claves de locales y en update.py:82; añadir un test que
recorra locales es/en buscando `emory]` (o que compare la pista de doctor con el extra de pyproject).
