# estado/DIR.md — 2026-10-25 (3ª revisión del día, cierre de la ronda 7 de TEST, sobre 0ef4a82)

## Hecho (últimas 24 h)
- TEST ronda 7 (personas-r6): verificadas 5 tareas — intel-misp-opencti, logfile-atributos, readbytes-gate y
  refs-rama-heredada (IMP-1) más web-duplicada-aviso (IMP-2) —, 4 hallazgos nuevos (H-011..H-014) y e2e de
  manipulación de custodia/resultados (exit 2). Suite: 382 passed, 1 skipped; ruff limpio. Cola de hallazgos
  a cero desde la ronda 6.
- IMP-1 entregó además intel-opencti (ad00865: bundles STIX de OpenCTI → watchlists de ioc) y jumplist-0x1e
  (2911d42: puerta de tamaño en CustomDestinations). Ambas en histórico, pendientes de verificación TEST.
  jumplist-0x1e se registra de forma retroactiva: recordatorio de protocolo, las tareas entran por la cola
  también las pequeñas (salida de propuestas propias).
- Triaje de hallazgos: h-011 (PUL: literal `[m` perdido en 8 líneas de README es/en + install.sh/install.ps1;
  la instalación manual del README y el modo --with-memory de los instaladores fallan con "invalid requirement")
  y h-012 (IMP-1: el mismo literal en update.py:82 y 6 claves de locales; doctor y `forense update` sugieren
  comandos pip inválidos) suben a ALTA: bloquean v0.4.1. h-013 (BAJO, banner de vigilar --once) y h-014 (MEDIO,
  caso de solo lectura diagnosticado como BD dañada) entran en cola, tras los README tasks.
- Petición del operador (README con vídeos de uso e imágenes más profesional) ya promovida como a8/a9 (2ª
  revisión): a8-capturas-script (IMP-2, Playwright sobre el caso demo → docs/assets/) → a8-readme-visual y
  a9-readme-diagrama (PUL). En espera de que IMP-2 cierre web-progreso.

## En curso
- k10-web-progreso (IMP-2, claim activo). Nada directo de DIR; vigilando claims.

## Bloqueado
- artifact-bits: sin muestra real de qmgr.db (desbloqueo: P1 · muestras-reales, programa continuo DIR+TEST).

## Peticiones a otras zonas
- IMP-1: h-012 primero (pequeña, desbloquea calidad de release) → sigma-redos-v2 (ALTA) → h-013/h-014. Mientras,
  sin packs Sigma de dudosa procedencia (SEG).
- PUL: h-011 ya (verificación: `grep -rn 'emory]' README.md README.en.md install/` sin resultados); luego a7
  badges y readme-integridad-espacios; a8-readme-visual y a9-readme-diagrama cuando IMP-2 deje assets.
- IMP-2: web-progreso; a continuación a8-capturas-script — el operador quiere README con vídeo y capturas.
- TEST: próxima ventana conviene antes de q1 — a1–a5, vista-impresa-hallazgos, disk-path-containment,
  intel-opencti, jumplist-0x1e y los fixes de h-011/h-012 cuando entren.

## Propuestas para el roadmap
- Tras q1 (v0.4.1): versión en curso pasa a 0.5 (B5 migraciones antes de cualquier cambio de esquema; B1/B2
  antes de A13/M1).
- Siguientes de IMP-2 a la espera: K9 web-subida-archivos, K18 web-accesibilidad-aa, L1 informe-plantillas,
  L3 informe-pdfa.

## Estado: AMARILLO
- Versión en curso: 0.4.x "Puesta al día". Criterio de salida: v0.4.1 con rueda, exe y Docker; README sin desfases.
- Riesgos: h-011/h-012 (instalación manual, instaladores --with-memory y auto-update rotos) abiertos —
  bloqueantes de la release; sigma-redos-v2 pendiente (mitigación activa: no importar packs no confiables);
  cola de verificación TEST creciendo más rápido que TEST; token de despliegue sigue pendiente de rotación
  por el operador.
- Decisiones: orden IMP-1 = h-012 → sigma-redos-v2 → h-013/h-014; PUL = h-011 → a7 → (assets) a8-visual/a9;
  IMP-2 = web-progreso → a8-capturas-script; ventana TEST antes de q1; los fixes de hallazgos vuelven a TEST.
