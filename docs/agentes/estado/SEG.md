# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 8 sobre 10cf6aa (tras traer DIR el roadmap de producto, 7178cd8).
- sigma-redos-revision: DEVUELTA a IMP-1. La guardia de 65dd311 es evadible: 8 familias de patrones
  la atraviesan y congelan re.search (>4 s con tamaños minúsculos, exponencial). Dos fallos de
  modelo: (1) `_body_paths` multiplica por la ventana del repetidor UNA vez, pero la ambigüedad
  se eleva B^iteraciones: `(a?){25}X`, `(a{0,2}){15}X`, `(.?){25}X` (congela con entrada genérica),
  `((a?){5}){5}X` (anidamiento compuesto); (2) átomos adyacentes cuantificados sin grupo nunca se
  comprueban: `a?`×30+`X`, `([\w]{0,3}){12}X`. Bien cubierto: lookarounds (`(?=a+(a+)+)` se
  rechaza), backrefs cuantificados, longitud ≤1024, repeats >1000. Sin falsos positivos hoy:
  el paquete builtin (15 reglas) carga con 0 errores. Fix sugerido: presupuesto de ambigüedad
  global Σ log2(ways) con recursión en grupos cuantificados (expansión de repeticiones), no por
  grupo aislado; su test de paquete builtin sirve de red contra falsos positivos.
- disk-path-containment: CORREGIDO (e53919f). La rama relativa de `disk_path` resuelve y exige
  contención (resolve + parents) en la raíz resuelta del caso; un symlink plantado dentro también
  se bloquea. `error.evidence_path_escapes` nueva en es/en (2 claves aditivas); regresión en
  test_core.py (traversal, normalización con intermedios inexistentes, symlink; sin symlink en nt).
- Revisado lo entrado desde mi sesión 7 (1b3d74f..a937ea3): intel-misp-opencti (sin red por
  diseño, tope 256 MB, allowlist de tipos, salida no puede pisar la entrada) limpio;
  readbytes-gate mantiene el patrón `except (OSError, ValueError)`; logfile-atributos con bucles
  acotados por longitud; web-duplicate-aviso sin superficie nueva. Sin hallazgos nuevos.
- Escaneo de secretos (árbol + pickaxe del historial): limpio, sin ghp_/AKIA/clave privada.
- Gates: ruff limpio; pytest 381 passed, 1 skipped (los e2e exigen `forense` en el PATH del venv).

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- Guardia ReDoS Sigma: DEVUELTA (ver arriba); mientras tanto, una regla hostil congelaría el
  scan: importar solo packs de confianza hasta el fix de IMP-1.
- Sin cambios: --no-sandbox del PDF (aceptado), SESSION_COOKIE_SECURE (deliberado), self-update
  sin pin de hash (aceptado), notifications ET.fromstring (bajo; defusedxml si se mantiene 3.10).

## Peticiones a otras zonas
- IMP-1: sigma-redos v2 con presupuesto de ambigüedad global (repros arriba); es la única vía
  real: re no tiene timeout y los jobs web corren en hilos (signal.alarm no aplica).

## Propuestas para el roadmap
- (TEST) e2e "evidencia hostil" en el informe (HTML en valores) y CSV exportado (se mantiene).
- (IMP-2) contención equivalente si la web llega a servir ficheros por ruta relativa.
