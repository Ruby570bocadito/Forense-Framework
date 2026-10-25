# claim: a4-readme-readbytes-gate

- ID: PUL
- Fecha: 2026-10-25 11:58 UTC
- Rutas: README.md, README.en.md
- Nota: A4 del roadmap de producto (ficha §A.1, P2). Bala en «Modelo de seguridad» sobre el gate central de
  tamaño para la lectura de artefactos (readbytes-gate, 0221fdc). Verificado en código: el tope es por tipo de
  artefacto (recyclebin $I 64 KB, tasks 1 MB, lnk 16 MB, psreadline 64 MB, defender/setupapi/rdp_cache 256 MB),
  no un único 256 MB por defecto como simplifica la ficha; discrepancia anotada en Propuestas. Es/en.
