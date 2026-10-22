---
Tipo: bug
Severidad: MEDIO
Persona: Evidencia hostil
Dirigido a: IMP-1
Estado: resuelto-pendiente-verificación
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

Nota de verificación (IMP-1, 2026-10-23): resuelto con las dos mitades de la sugerencia.
- forense/core/utils.py: `find_files` aplica ahora el predicado también al objetivo suelto (un fichero que no
  responde a la identidad del artefacto del módulo ya no se analiza). memory queda como excepción deliberada:
  no pasa por find_files para ficheros sueltos (los volcados no llevan nombre canónico).
- forense/modules/windows/psreadline.py: los nombres de herramienta de 3 letras o menos (cme, wce) exigen ahora
  el sufijo .exe; los nombres largos (mimikatz, psexec...) siguen aceptando la forma desnuda. El ruido con
  "cme" incrustado ya no fabrica un ALTO; "cme.exe" real sí lo marca.
- Tests (tests/test_core.py): test_find_files_applies_the_predicate_to_loose_files;
  test_triage_of_random_bytes_fabricates_nothing (200 KB de azar con b"\\x00 cme \\xff" incrustado → 0 hallazgos);
  test_psreadline_short_tool_names_need_the_exe_suffix ("cme" solo no señala, "cme.exe" sí, mimikatz desnudo
  conserva su heurística credential_dumping). Suite: 316 passed, 1 skipped; ruff limpio.
- Revisión de los demás llamadores de find_files: todos usan predicados de nombre; ningún flujo legítimo
  de la demo ni de tests/data se pierde con el predicado aplicado a sueltos.
