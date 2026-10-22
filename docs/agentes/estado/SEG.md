# SEG — informe vivo

## Hecho (últimas 24 h)
- Tareas del ROADMAP dirigidas a SEG, las tres completadas:
  - auditoria-extraccion: `safe_name` + `_target` (contención por commonpath, colisiones `~N`, nombres reservados,
    límite 200 B), profundidad máx. 64 y tamaño máx. 4 GiB; no hay forma de salir del destino con `..` ni separadores.
    Tests de regresión ya existentes en tests/test_hardening.py (safe_name, extractor targets, evidencia que contiene
    el caso). Sin fixes que aplicar.
  - auditoria-subprocesos-yaml: todo YAML con safe_load/safe_load_all (config, playbooks, Sigma); subprocess solo con
    listas de argumentos y sin shell (collector, volatility, pdf, update); VOLATILE_COMMANDS constantes. Sin fixes.
  - pip-audit: sin vulnerabilidades conocidas en el entorno dev. Gates: ruff limpio; suite 270 passed, 1 skipped.
- Auditoría amplia adicional: CSRF global en Flask (hmac.compare_digest), Basic auth opcional, cabeceras + CSP,
  descargas con send_from_directory, `_back` sin open-redirect, case_dir con slug + contención, SVG de charts escapado,
  único `|safe` estático, CSV con neutralización de fórmulas y test, ReadOnlySqlite (copia temporal, mode=ro),
  custodia encadenada por SHA-256 con verificación, claves BitLocker kind="secret" enmascaradas (PBKDF2 por caso) y
  custodia guarda solo el host del webhook (nunca la URL). Escaneo de secretos árbol+historial: limpio (coincide con DIR).
- Rebase sobre 0f9e5dc: mi bootstrap de protocolo (hecho en paralelo con DIR) entró en conflicto; resuelto tomando la
  versión canónica de DIR y conservando solo este estado. Sin --force; ficheros de DIR intactos (diff 0).

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- ReDoS potencial al compilar regex de reglas Sigma del operador: las reglas vienen de la carpeta de intel del analista
  (no de la evidencia); riesgo bajo. Propuesta volcada a Propuestas para el roadmap.
- PDF con --no-sandbox (necesario como root/contenedor; el HTML impreso es autocontenido y sin scripts): aceptado.
- SESSION_COOKIE_SECURE sin fijar: deliberado en HTTP local/LAN con contraseña; activar si se publica tras proxy TLS.
- update.py instala el archivo de la rama sin pin de hash: diseño de self-update por HTTPS al repo propio; aceptado.

## Peticiones a otras zonas
- PUL: documentar en README es/en el modelo de seguridad (web 127.0.0.1 con contraseña opcional, CSRF, cabeceras,
  --no-sandbox del PDF) cuando toque esas secciones. Sin urgencia.

## Propuestas para el roadmap
- (IMP-1) Validar/limitar patrones Sigma antes de compilar regex (ReDoS de reglas hostiles).
- (TEST) e2e "evidencia hostil": HTML en valores de registro comprobando el escapado del informe y export CSV en hoja de cálculo.
- (DIR) Marcar en ROADMAP auditoria-extraccion, auditoria-subprocesos-yaml y pip-audit como hechas y verificadas.
