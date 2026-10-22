# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 2: revisión del código nuevo entrado tras mi primera auditoría (20fe3f3..b278129) y parsers no cubiertos.
- report-signing (3e1671f): signing.py e integración web/CLI completos. Clave privada solo por entorno (nunca en el
  caso), custodia con hechos públicos (huella, hashes), b64 validado, ruta web de verificación con contención +
  sufijo + CSRF, cryptography>=42 declarada y justificada en el commit. Sin hallazgos.
- web-rendimiento (93074ef): paginación con cota de página (1..1e6) y corte seguro. Sin hallazgos.
- mft-attribute-list (cf72bfa): parse_attribute_list acotado (length>=26 garantiza avance: sin bucle infinito),
  merge con verificación de secuencia y de $ATTRIBUTE_LIST (un registro base reutilizado no adopta nada). Sin hallazgos.
- Bucles de todos los parsers revisados: acotados (visited/seen, profundidad máxima, avance garantizado).
  regf walk con visited+_MAX_DEPTH; PathResolver con seen+cota 255; evtx con max_consecutive_errors; usnjrnl,
  regf_log (anillo con máscara), regf_deleted, lnk y shellitems avanzan siempre. Sin hallazgos.
- i18n (plantilla solo del paquete, params como valores), stix (UUIDv5 determinista), mask_secret (PBKDF2 200k con
  sal por caso), hashing en streaming: correctos. Gates: ruff limpio; pytest verde al cierre.

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- Sin cambios respecto a la sesión 1: ReDoS de reglas Sigma de operador (bajo, intel del analista), --no-sandbox del
  PDF (aceptado), SESSION_COOKIE_SECURE (deliberado en HTTP local/LAN), self-update sin pin de hash (aceptado).

## Peticiones a otras zonas
- PUL: pendiente la de la sesión 1 (documentar el modelo de seguridad en README es/en). Sin urgencia.
- IMP-1: find_embedded_lnks es O(cabeceras × rebanado) en blobs con muchas cabeceras LNK; es rendimiento, no seguridad.

## Propuestas para el roadmap
- (DIR) Marcar en ROADMAP auditoria-extraccion, auditoria-subprocesos-yaml y pip-audit (hechas y verificadas, sesión 1).
- (IMP-1) Validar/limitar patrones Sigma antes de compilar regex (se mantiene de la sesión 1).
- (TEST) e2e "evidencia hostil": escapado del informe con HTML en valores de registro y export CSV en hoja de cálculo.
