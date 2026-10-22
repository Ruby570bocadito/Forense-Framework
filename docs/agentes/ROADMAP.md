# ROADMAP

Fase actual: **fiabilidad del resultado forense** (artefactos del motor, confianza en el informe) antes de funciones vistosas.

Base: "Hoja de ruta" y "Limitaciones conocidas" del README contrastadas con el código real (commit 20fe3f3).
Corrección detectada: la correlación entre casos YA está implementada (commit 7b647b8, `forense/core/correlation.py`
y página web `/correlation`); en la hoja de ruta del README solo queda pendiente la importación MISP/OpenCTI
(petición a PUL en `estado/DIR.md`).

## ALTA
(ninguna: build verde, sin hallazgos CRÍTICO/ALTO abiertos)

## Tareas priorizadas

- [ ] (IMP-2) report-signing — firma digital de informes: Ed25519, firma desacoplada `.sig` + verificación, clave por variable de entorno, registro en custodia — forense/report/, forense/web/, locales, tests
- [ ] (IMP-1) mft-attribute-list — combinar atributos de registros de extensión ($ATTRIBUTE_LIST) en $MFT (limitación conocida del README) — forense/parsers/, forense/modules/, tests
- [ ] (IMP-1) artifact-bits — artefacto BITS (qmgr.db) con hallazgo y técnica ATT&CK — forense/modules/, forense/parsers/, forense/demo/, locales
- [ ] (IMP-2) web-accessibility — accesibilidad base de la interfaz: enlace de salto, aria-current, roles de avisos, thead/scope en tablas — forense/web/templates/, forense/web/static/, locales, tests
- [ ] (IMP-1) artifact-logfile — soporte básico de $LogFile (limitación conocida) — forense/parsers/, forense/modules/
- [ ] (IMP-1) artifact-rdp-cache — artefacto RDP Bitmap Cache — forense/modules/, forense/demo/, locales
- [ ] (IMP-1) artifact-notifications — artefacto de notificaciones de Windows — forense/modules/, forense/demo/, locales
- [ ] (IMP-2) reports-hash-display — mostrar SHA-256 y estado de firma de cada informe en la página de informes — forense/web/, tests
- [ ] (IMP-1) intel-misp-opencti — importación de inteligencia desde MISP/OpenCTI (hoja de ruta del README) — forense/core/, forense/modules/
- [ ] (PUL) readme-hoja-de-ruta — retirar "correlación entre casos" de la hoja de ruta (ya hecha, 7b647b8) y sincronizar README.en.md — README.md, README.en.md
- [ ] (PUL) readme-arbol-comandos — verificar árbol de "Arquitectura" contra el árbol real y probar los comandos de instalación — README.md, README.en.md
- [ ] (SEG) pip-audit — ejecutar pip-audit sobre las dependencias y corregir lo vulnerable — transversal, fixes mínimos
- [ ] (TEST) personas-r1 — primera ronda de personas (analista nuevo, perito veterano, despistado, evidencia hostil) sobre la demo — tests/e2e/, docs/agentes/hallazgos/

## Dependencias entre tareas
- report-signing (IMP-2) precede a la exposición CLI `--sign` (IMP-1, forense/cli.py).
- reports-hash-display (IMP-2) tiene mejor valor tras report-signing.
