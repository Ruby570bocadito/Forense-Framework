# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 7: revisado lo entrado desde mi cierre de la sesión 6 (1b3d74f..18a0619, 16 commits).
- sigma-redos (65dd311, IMP-1): limpio y CIERRA mi nota no-fix de la sesión 1. Guard estructural
  antes de compilar |re: longitud ≤1024, counted repeats ≤1000, backreferences cuantificados
  rechazados, presupuesto de 64 paths para grupos cuantificados con alternación/cuantificador
  dentro (a cualquier profundidad). El patrón maligno es un error de CARGA (SigmaError), nunca
  un scan congelado; parseo correcto de clases [..], escapes y (?...). Trade-off conservador
  documentado (algún patrón lineal se rechaza). Tests: 10 malignos + 9 seguros.
- H-010 (2254b95, IMP-1): limpio — informe --firmar reutiliza la vía de firma de la web
  (signing.py, revisada en mi sesión 2), sin crypto nuevo en el CLI; paths de firma reportados.
- H-009 (8383161, IMP-1): limpio — destinos de export con allowlist fija es/en, plegado de
  acentos NFKD y canonicalización al nombre inglés antes de usar (sin superficie nueva).
- TEST ronda 5 (9bf26e9/b7367fd): cierra H-005, H-006 y H-009 con e2e; regresión e2e de
  web-filtros-guardados (CSRF, allowlist, escapado, tope 20, JSON dañado, custodia intacta).
- Resto del lote: docs y claims (readme de PUL, releases, estados) — sin código.
- Gates: ruff limpio; pytest 368 passed / 1 skipped. Mis claves de locale intactas.

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- Sigma ReDoS: CERRADO por 65dd311 (era mi nota de la sesión 1; verificado el guard).
- Sin cambios: --no-sandbox del PDF (aceptado), SESSION_COOKIE_SECURE (deliberado), self-update
  sin pin de hash (aceptado).
- Gate central de tamaño para el patrón read_bytes() común de los módulos (IMP-1/DIR, cross-module).
- (bajo) notifications: ET.fromstring sobre payload hostil; valorar defusedxml si se mantiene 3.10.

## Peticiones a otras zonas
- IMP-1/IMP-2: residual de TEST sobre mi revisión de H-005 — la subida web ignora duplicate_of
  (el aviso solo sale por CLI). Hueco de UX, no de seguridad (el aviso es mejor-esfuerzo); bajo.
- IMP-1/DIR: contención explícita (resolve + parents) para rutas relativas en disk_path (bajo).

## Propuestas para el roadmap
- (TEST) e2e "evidencia hostil" en el informe (HTML en valores) y CSV exportado (se mantiene).
