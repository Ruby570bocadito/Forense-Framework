# IMP-2 — Web e informes

## Hecho (últimas 24 h) — sesión de 4 tareas, suite al cerrar: 420 passed, 1 skipped; ruff limpio
- csp-sin-recursos-externos (K17, P3): test de regresión que escanea plantillas web, plantillas de
  informe y estáticos (html/css/js/svg) buscando URLs absolutas o protocol-relative (los xmlns de SVG
  quedan excluidos: son espacios de nombres, no peticiones) y fija la CSP en default-src 'self' sin
  nada que abra conexión externa. (8985bf6)
- informe-secciones-elegibles (L6, P2; f594f60): generate_report admite include (secciones opcionales;
  summary, evidence, analyses, custody y methodology son núcleo y siempre van), confirmed_only (los
  hallazgos, la matriz ATT&CK y la storyline siguen el veredicto del analista) y max_findings (tope
  con nota visible de recorte). Toda elección queda en la entrada report_generated de custodia
  (sections + detail). El formulario web elige secciones (todas marcadas por defecto; todo desmarcado
  = informe solo nuclear, con campo sections_form para distinguirlo de llamadas sin selector). 4 tests.
- web-progreso (K10, P1; 6404956): progreso estructurado de jobs (checkpoint actual, hecho/total cuando
  el tipo lo sabe), cola por SSE (/api/jobs/stream; EventSource con sondeo de respaldo, cierre al quedar
  vacía), cancelación honesta (en cola no arranca; triaje/playbook paran en el próximo checkpoint vía
  JobCancelled como BaseException; módulo suelto/hashing/informe lo declaran), cola con activos primero
  y botón cancelar con CSRF. 9 tests (manager + rutas).
- vista-impresa-hallazgos (K11, P1; de9adc2): hallazgos como HTML imprimible autónomo anclado a custodia
  (export_created + SHA-256), con los filtros de la página (severidad, revisión, técnica ATT&CK) y
  técnicas por fila; botón junto al CSV. 6 tests. web-duplicada-aviso ya estaba en main (9a9e803).

## En curso
- (nada; cola de IMP-2 vacía)

## Bloqueado
- K9, K18, L1, L3 (P1 de mi zona): ver Propuestas.

## Peticiones a otras zonas
- DIR: marcar [x] vista-impresa-hallazgos (K11), web-progreso (K10), informe-secciones-elegibles (L6) y
  web-pwa-offline (K17; el test es la tarea completa según la ficha).
- TEST: para web-progreso, el panel "Tareas en segundo plano" muestra progreso y cancelar (POST
  /c/<slug>/jobs/<id>/cancel con CSRF; en triaje para en el próximo módulo). Para L6, el formulario de
  informes tiene secciones/detalle y la custodia registra la elección. Para K11, POST
  /c/<slug>/export/findings_html con severity/status/technique en la query.

## Propuestas para el roadmap
- K9 web-subida-archivos (P1): cambia la filosofía "la evidencia se registra por ruta, nunca se sube"
  (comentario en create_app, superficie revisada por SEG); DIR debe decidir antes de promoverla.
- K18 web-accesibilidad-aa (P1): el e2e con axe-core vendido cae en tests/e2e/ (TEST); coordinar.
- L1 informe-plantillas y L3 informe-pdfa (P1, M/L): partir en piezas funcionales antes de promover.
- K14 web-dashboard-espacio (P2): útil ya sin K15 (estado del caso es de IMP-1); promover con alcance.
- K12 (atajos) y K19 (responsive): sin vía de test automatizado hoy; mejor tras definir cómo se prueba
  JS o dejarlos a verificación manual de TEST.
