# estado/TEST.md — 2026-10-23 (ronda 6)

## Hecho
- H-010 verificado y CERRADO (fix 2254b95 de IMP-1): `informe --firmar/--sign` existe en la ayuda
  y firma como la web — con claves Ed25519 de openssl y FORENSE_SIGN_KEY/PUB el CLI escribe el
  .sig desacoplado junto al HTML, la custodia registra report_signed, el informe intacto verifica
  True, el mismo fichero manipulado («Forense»→«Forged») verifica False, y sin clave definida el
  CLI responde «No hay clave de firma: define FORENSE_SIGN_KEY…» (exit 1), sin traceback.
  Sin probar: la firma del PDF (este entorno no tiene navegador; el camino HTML es el mismo
  call-through `sign=args.sign` que IMP-1 cubre con test_cli).
- sigma-redos (65dd311, tarea del ROADMAP de DIR) verificado: la guarda estructural rechaza 8/8
  patrones hostiles ((a+)+, (?:a|aa)+, (a?)+, (a|b)*, backref cuantificado, {2,100000},
  (a{1,3})+) y compila 7/7 seguros (incluida una IP-like bajo el presupuesto de ramas). Por CLI
  real, una regla Sigma hostil en -o sigma_rules= se convierte en error de carga en 0.25 s
  («Errores no fatales: 1», el barrido termina; sin cuelgue) y la regla buena sigue aplicando
  (15 reglas, sin errores). Sus 3 tests de módulo pasan.
- Suite: 368 passed, 1 skipped; ruff limpio.

## Estado hallazgos
- Cerrados esta ronda: H-010. Abiertos: NINGUNO — la cola de hallazgos de IMP-1 está a cero.
  docs/agentes/hallazgos/ queda con .gitkeep.

## Sin probar
- Firma PDF vía CLI (sin navegador aquí), job pdf de CI, Docker, recolectar (Windows admin),
  memoria real con Volatility, disco lleno, muestras reales de wpndatabase/qmgr.db/Cache*.bin.

## Peticiones
- IMP-1: cola a cero, enhorabuena — 10/10 hallazgos resueltos y verificados desde la ronda 1.
  Residual pendiente de H-005: que la subida web muestre el gemelo duplicado (ev.duplicate_of).
- IMP-2: residual de H-005 toca tu superficie web (mensaje del job de subida).
- DIR: si aparecen tareas nuevas del ROADMAP (o auditorías SEG), verifico en la siguiente ronda;
  el token sigue pendiente de rotación por el operador.
