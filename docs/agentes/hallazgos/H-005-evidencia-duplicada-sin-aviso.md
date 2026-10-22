---
Tipo: mejora
Severidad: BAJO
Persona: Perito veterano
Dirigido a: IMP-1
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir: `forense -c CASO evidencia agregar tests/data/Security_short_selected.evtx -d "Repetida"` dos veces sobre el mismo caso (la primera ya registrada como EV-001) y luego `forense -c CASO evidencia listar`.

Resultado esperado: al menos un aviso visible del tipo "hash idéntico al de EV-001" en el momento de registrar (registrar dos veces puede ser legítimo, pero el perito debe saberlo en el acto, no descubrirlo comparando hashes a mano).

Resultado real: el registro continúa en silencio y `evidencia listar` muestra dos evidencias con el mismo SHA-256 (`50c87926d2dfed9776906ffbcc77e61577940910a71fb1c1871860a4e2213456`):
```
EV-001  archivo  1  68.0 KiB  50c87926d2dfed97…  Log de Security (muestra)
EV-004  archivo  1  68.0 KiB  50c87926d2dfed97…  Repetida
```
Sin ningún mensaje de coincidencia. Exit 0.

Sugerencia: tras calcular el hash, comparar con las evidencias existentes y emitir "Aviso: contenido idéntico a EV-001 (SHA-256 …)" sin bloquear el registro.

---

Nota de verificación (IMP-1, 2026-10-23): resuelto en 1f94986.
- Core: `Case.find_duplicate(hashes)` devuelve la primera evidencia registrada con la misma SHA-256;
  `add_evidence` la consulta antes del INSERT y expone el gemelo en `Evidence.duplicate_of`
  (transitorio, no se persiste: `evidencia listar` sigue igual).
- CLI: `evidencia agregar` emite por stderr, en el idioma de la sesión, "Aviso: contenido idéntico a
  EV-001 (SHA-256 …); el registro continúa, puede ser legítimo." Exit 0, registro no bloqueado,
  stdout se queda limpio para consumo automático. Aplica a ficheros y a directorios (mismo
  manifiesto de árbol).
- Tests: test_core.py (gemelo de fichero, gemelo con --copiar, directorio, find_duplicate sin
  SHA-256/vacío) y test_cli.py (aviso es/en por stderr, ausente de stdout). Suite: 336 passed,
  1 skipped; ruff limpio.
