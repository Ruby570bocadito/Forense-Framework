# estado/DIR.md — 2026-10-25 (2ª revisión del día, petición del operador, sobre 64505a8)

## Hecho (últimas 24 h)
- Sesión 1 (sobre 7178cd8): docs/ROADMAP.md traído a main; PROTOCOLO (ficha de tarea en el ciclo + reglas §6) y
  OWNERSHIP al día; A6 con 7 entregas a histórico; promovidas las 0.4.x del producto (a1–a5, a7, q2, q1).
- Entre sesiones, los agentes entregaron 7 tareas: a1–a5 (PUL, README es/en), vista-impresa-hallazgos (IMP-2,
  de9adc2) y disk-path-containment (SEG, e53919f). Todas marcadas [x] en histórico, pendientes de verificación TEST.
- Petición del operador ("readme con vídeos de uso e imágenes más profesional") promovida como a8 y a9 del roadmap:
  a8-capturas-script (IMP-2: Playwright sobre el caso demo, capturas claro/oscuro + GIF/vídeos de uso en
  scripts/screenshots.py → docs/assets/) y a8-readme-visual + a9-readme-diagrama (PUL: portada, sección "Vistazo"
  y diagrama de flujo embebidos, es/en). OWNERSHIP: scripts/ y docs/assets/ asignados a IMP-2.
- sigma-redos-revision de SEG (sesión 8) DEVOLVIÓ la guardia de 65dd311 con 8 familias de evasión (repro incluido):
  promovida como ALTA sigma-redos-v2 para IMP-1, con el fix sugerido (presupuesto de ambigüedad global) y la red
  antifalsos-positivos (paquete builtin). La re-auditoría "duplicada" de la mañana encontró algo real.
- k10-web-progreso (IMP-2, claim activo) e intel-opencti (IMP-1, claim activo) añadidas a la cola como EN CURSO.

## En curso
- Nada directo; vigilando claims de IMP-1 e IMP-2.

## Bloqueado
- artifact-bits: sin muestra real de qmgr.db (desbloqueo: P1 · muestras-reales, programa continuo DIR+TEST).

## Peticiones a otras zonas
- IMP-1: al liberar intel-opencti, sigma-redos-v2 (ALTA) es la siguiente; mientras, sin packs Sigma no confiables.
- IMP-2: a8-capturas-script cuando cierres web-progreso; el operador quiere README con vídeo y capturas de calidad.
- PUL: a7 badges ya; a8-readme-visual y a9-readme-diagrama en cuanto IMP-2 deje assets en docs/assets/.
- TEST: la tanda de verificación ha crecido (a1–a5, vista-impresa, disk-path, intel-misp, logfile-atributos,
  readbytes-gate, refs-rama-heredada, web-duplicada-aviso); ventana TEST antes de q1, por favor.

## Propuestas para el roadmap
- Siguientes de IMP-2 a la espera: K9 web-subida-archivos, K18 web-accesibilidad-aa, L1 informe-plantillas, L3 informe-pdfa.
- Tras q1 (v0.4.1): versión en curso pasa a 0.5 (B5 migraciones antes de cualquier cambio de esquema; B1/B2 antes de A13/M1).

## Estado: AMARILLO
- Versión en curso: 0.4.x "Puesta al día". Criterio de salida: v0.4.1 con rueda, exe y Docker; README sin desfases.
- Riesgos: sigma-redos evadible hasta sigma-redos-v2 (mitigación: no importar packs no confiables); cola de
  verificación TEST creciendo más rápido que TEST; token de despliegue sigue pendiente de rotación por el operador.
- Decisiones: orden IMP-2 = web-progreso → a8-capturas-script; IMP-1 = intel-opencti → sigma-redos-v2; PUL = a7 →
  a8-readme-visual/a9 cuando haya assets; ventana TEST antes de q1.
