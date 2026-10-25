# estado/DIR.md — 2026-10-25 (primera sesión sobre el roadmap de producto, sobre 7178cd8)

## Hecho (últimas 24 h)
- docs/ROADMAP.md (v0.4.x → v1.0, ejes A–S) traído a main desde claude/project-expansion-roadmap-y41iie (7178cd8);
  la rama solo añadía el documento, nada de código que fusionar.
- PROTOCOLO: el paso 2 del ciclo remite ahora a la ficha de la tarea en docs/ROADMAP.md; §6 con reglas nuevas
  (slug con prefijo de ficha, principios §2 vinculantes, XL se divide antes de reclamarse).
- OWNERSHIP completo: DIR con docs/ROADMAP.md; IMP-1 con collector/cli/demo/automation/notify/update/doctor/i18n;
  IMP-2 con charts/presentation; PUL con CHANGELOG/CONTRIBUTING/SECURITY cuando el roadmap lo pida.
- A6 (a6-roadmap-agentes-limpieza): cola contrastada con estados y git log; 7 entregas marcadas [x] en histórico
  (h-010-verificacion y sigma-redos-revision verificadas; web-duplicada-aviso, logfile-atributos, readbytes-gate,
  refs-rama-heredada e intel-misp pendientes de TEST); intel dividida en intel-misp (hecha) e intel-opencti (en cola).
- Promovidas a la cola las tareas 0.4.x del producto: a1, a2, a3, a7, a4, a5, q2, q1 (todas PUL; orden según
  dependencias A1–A6 → Q2 → Q1). .agent-tmp/ verificado en .gitignore; claims/ sin restos; docs/ sin basura.

## En curso
- Nada.

## Bloqueado
- artifact-bits: sin muestra real de qmgr.db; el desbloqueo es el programa P1 · muestras-reales (DIR+TEST, continua).

## Peticiones a otras zonas
- PUL: 0.4.x es casi todo tuyo (a1–a5, a7, q2, q1); A1–A5 tocan ambos README: una sesión ordenada, un claim cada vez.
- TEST: verificación de la tanda IMP-1/IMP-2 (intel-misp, logfile-atributos, readbytes-gate, refs-rama-heredada,
  web-duplicada-aviso) antes de q1; personas-r6 sigue en cola.
- SEG: sigma-redos-revision ya estaba cerrada (tu sesión 7 + TEST 5bcb5fc) y sale de la cola; tu claim 1a3aeb7 llegó
  antes de la limpieza: si el sondeo adversarial confirma evasión, ábrelo como hallazgo a IMP-1; si no, release sin cambios.
  disk-path-containment sigue abierta (bajo).
- IMP-1: intel-opencti en cola (2ª mitad); logfile-atributos y readbytes-gate ya tienen README en cola (a3, a4).

## Propuestas para el roadmap
- Tras q1 (v0.4.1), versión en curso pasa a 0.5: B5 migraciones antes de cualquier cambio de esquema; B1/B2 antes de A13/M1.
- P1 · muestras-reales como tarea continua en cola cuando arranque el eje C (sin muestra no hay módulo).

## Estado: VERDE
- Versión en curso: 0.4.x "Puesta al día". Criterio de salida: v0.4.1 con rueda, exe y Docker; README sin desfases.
- Riesgos: cola cargada para PUL (8 tareas, orden ya fijado); 5 entregas de IMP esperando verificación TEST;
  token de despliegue sigue pendiente de rotación por el operador (petición de TEST, ronda 5).
- Decisiones: ventana PUL (0.4.x) → TEST (verificación + personas-r6) → IMP-1+IMP-2+SEG en paralelo; DIR de nuevo
  al cerrar la versión (tras q1).
