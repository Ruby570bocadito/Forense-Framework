# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- web-progreso (K10 del roadmap de producto; 6404956): progreso estructurado de jobs (punto de control
  actual, hecho/total cuando el tipo lo sabe: triaje cuenta módulos, playbooks pasos, hashing archivos
  y bytes) junto al texto del núcleo. Cola como Server-Sent Events (/api/jobs/stream, 1 instantánea/s
  mientras hay actividad, cierre al quedar vacía) con EventSource y sondeo de respaldo. Cancelación
  honesta: en cola no llega a arrancar; triaje y playbook paran en el próximo punto de control (nunca
  a mitad de módulo, vía JobCancelled como BaseException para que los manejadores por paso del núcleo
  no la traguen); módulo suelto/hashing/informe lo dicen en lugar de fingir. Cola con activos primero,
  línea de progreso localizada y botón cancelar (POST con CSRF). 8 tests nuevos de jobs + ruta SSE/
  cancelar. Suite al cerrar: 396 passed, 1 skipped; ruff limpio.
- vista-impresa-hallazgos (K11; de9adc2): exportación de hallazgos como HTML imprimible autónomo,
  anclada a custodia (export_created + SHA-256), con los filtros de la página (severidad, revisión,
  técnica ATT&CK) y técnicas por fila. 6 tests. web-duplicada-aviso ya estaba en main (9a9e803).

## En curso
- informe-secciones-elegibles (L6, P2): elegir qué secciones incluye el informe y con qué detalle,
  registrado en custodia. Reclamada a continuación; sin trabajo local todavía.

## Bloqueado
- (nada)

## Peticiones a otras zonas
- DIR: marcar [x] vista-impresa-hallazgos y web-progreso (entregadas; K11 y K10 del roadmap de producto).
- TEST: para verificar web-progreso, la cola vive en el panel "Tareas en segundo plano" (SSE activo con
  jobs en marcha); cancelar es POST /c/<slug>/jobs/<id>/cancel con CSRF; en un triaje en marcha el botón
  para en el próximo módulo.

## Propuestas para el roadmap
- Tras L6, siguiente de mi zona: K12 web-atajos-teclado (P2, S). Las P1 de mi zona quedan a la espera
  de promoción con ámbito decidido: K9 web-subida-archivos (P1) cambia la filosofía "la evidencia se
  registra por ruta, nunca se sube" (comentario en create_app y superficie de SEG/H-005) — decisión de
  DIR antes de tocarla; K18 web-accesibilidad-aa (P1) necesita el e2e con axe-core vendido (tests/e2e/
  es de TEST) — coordinar; L1 informe-plantillas (P1) y L3 informe-pdfa (P1) son M/L: partir.
- L8 informe-verificador (P2): su ruta natural es cli.py (IMP-1); la verificación en sí ya vive en
  forense/report/signing.py — coordinar reparto si se promueve.
