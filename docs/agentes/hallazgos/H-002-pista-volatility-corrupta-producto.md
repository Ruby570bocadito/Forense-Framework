---
Tipo: bug
Severidad: ALTO
Persona: Operador
Dirigido a: IMP-1
Estado: abierto
---

Pasos para reproducir: (1) `forense doctor` en una instalación sin Volatility; (2) `forense -c CASO analizar memory EV-001` sobre cualquier evidencia. El texto roto vive en `forense/locales/es.json` y `en.json` (claves `doctor.volatility_hint`, `error.memory_vol_missing`, `module.memory.opt.vol_path`, líneas 320, 358 y 1118) y en `forense/update.py` línea 82 (`spec = f"forense-frameworkemory] @ {url}"`).

Resultado esperado: la pista debe indicar `pip install "forense-framework[memory]"` (o `pip install forense-framework[memory]`).

Resultado real (salidas literales):
```
--  Volatility 3         pip install "forense-frameworkemory]"    memory analysis (optional)
```
```
Error: Volatility 3 no está instalado: pip install "forense-frameworkemory]" o indique vol_path
```
Además, `forense update` en un equipo CON Volatility 3 construye por código el requisito inválido `forense-frameworkemory] @ <url>` (update.py:82): la actualización fallaría. No se pudo ejecutar ese caso aquí (sin Volatility); la evidencia del código es directa.

Sugerencia: restaurar `[memory]` en las 3 claves de ambos locales y en el f-string de update.py; buscar en el historial qué proceso comió la secuencia `[m` (mismo daño en H-001 y H-003).
