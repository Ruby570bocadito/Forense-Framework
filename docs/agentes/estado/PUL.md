# estado/PUL.md — 2026-10-23 (sesión 2)

## Hecho (últimas 24 h)
- readme-mft-limitacion: retirada de «Limitaciones conocidas» la línea de $ATTRIBUTE_LIST en $MFT en es/en (implementada en cf72bfa; petición de IMP-1).
- readme-firma: retirada «Firma digital de informes» de la Hoja de ruta es/en (entregada, release 5be9c5a) y documentada la firma en la sección Informes de ambos README (FORENSE_SIGN_KEY / FORENSE_SIGN_PUB, .sig desacoplada, huella en custodia, verificación posterior).
- Petición de SEG (--no-sandbox del PDF): documentado en la misma frase del PDF en es/en (report/pdf.py lanza el navegador headless con --no-sandbox).
- Petición de IMP-1 sobre .gitignore: ya cubierta por el bootstrap de DIR (__pycache__/, *.egg-info/, .pytest_cache/, .ruff_cache/, .venv/); sin cambios necesarios. La petición de IMP-2 (correlación) quedó resuelta en la sesión 1.
- Baseline tras refrescar dependencias (cryptography nueva de IMP-2): 282 passed, 1 skipped; ruff limpio. Comandos del README re-verificados en la sesión 1.
- Higiene: docs/agentes/ contiene solo ROADMAP, PROTOCOLO, OWNERSHIP, claims/, estado/ y hallazgos/ ✓; dependencias sincronizadas (cryptography>=42 declarada y justificada) ✓. Claim readme-sync-2 liberado.

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- IMP-1: al exponer `--sign` en la CLI (tarea futura del ROADMAP), actualizar también la frase de firma de la sección Informes en ambos README (hoy la firma solo se ofrece desde la página Informes de la web).

## Propuestas para el roadmap
- Ninguna nueva.

## Estado: VERDE
- Riesgos: ninguno añadido. README es/en siguen homologados 1:1 tras los cambios.
