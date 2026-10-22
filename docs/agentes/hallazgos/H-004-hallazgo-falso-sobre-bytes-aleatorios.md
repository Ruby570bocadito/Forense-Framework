---
Tipo: bug
Severidad: MEDIO
Persona: Evidencia hostil
Dirigido a: IMP-1
Estado: abierto
---

Pasos para reproducir: (1) crear un archivo cualquiera con bytes aleatorios: `python3 -c "import os; open('.agent-tmp/SYSTEM-basura','wb').write(os.urandom(200_000))"`; (2) caso nuevo y `forense -c CASO evidencia agregar .agent-tmp/SYSTEM-basura -d "x"`; (3) `forense -c CASO triaje EV-001`; (4) `forense -c CASO hallazgos`. Causa raíz: `find_files` (`forense/core/utils.py` líneas 157-163) acepta SIEMPRE un target que es archivo ("A file target is always accepted"), saltándose el predicado de `discover()` de cada módulo; la heurística `psreadline` decodifica el binario como texto y la regla `tool:cme` hace coincidencia de subcadena de 3 letras.

Resultado esperado: un módulo solo debe analizar archivos que cumplan su predicado de descubrimiento (o que el tipo del artefacto suelto lo justifique); bytes aleatorios no deben producir hallazgos.

Resultado real (registro literal en forense.db del caso, read-only):
```
id: 1  evidence_id: EV-003  severity: high  code: psreadline.suspicious_command
params: {"command":"hL+<\u001590\t...", "line":1747, "rules":"tool:cme", "user":"-"}
```
Un hallazgo ALTO de "Comando de PowerShell sospechoso" fabricado con ruido aleatorio (la subcadena `cme` aparece en 200 KB de azar). Infla el triaje de evidencias hostiles y resta credibilidad al informe.

Sugerencia: que `find_files` aplique el predicado también a archivos sueltos (según el nombre) o filtre módulos por tipo de artefacto; y exigir señal adicional a reglas de herramientas cortas (`cme`) antes de severidad ALTO.

---

Verificación TEST 2026-10-23 (ronda 3): el repro original (200 KB de urandom) ya no dispara
6/6 muestras — el regex `_TOOLS` de `psreadline` exige ahora `(?<![\w.-])` antes del nombre
de herramienta, así que la subcadena incrustada en ruido no cuenta (regresión en
`tests/e2e/test_e2e_find_files_suelto.py`). PERO la causa raíz sigue y el repro se simplifica
a prosa legible: archivo suelto `notas.txt` con las líneas

```
cme was used by the attacker on 2026-09-14
nmap scan followed
```

`forense -c CASO triaje EV-001` fabrica DOS hallazgos ALTO (`psreadline.suspicious_command`,
`rules: tool:cme` y `tool:nmap`) desde texto en claro que no es un histórico de PowerShell:
basta que la línea EMPIECE por el nombre de la herramienta. Sigue abierto, dirigido a IMP-1;
la sugerencia original (predicado también para archivos sueltos, o señal adicional antes de
ALTO) resuelve ambos repros.
