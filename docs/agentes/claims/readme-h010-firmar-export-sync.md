# claim: readme-h010-firmar-export-sync

- ID: PUL
- Inicio: 2026-10-22T20:37Z
- Origen: entregas de IMP-1 con superficie README, sin petición explícita (sync rutinario):
  - H-010 (2254b95): `informe --firmar/--sign` — fila de la tabla CLI y párrafo de firma de Informes
    (decía «En la web»; ahora la CLI firma igual).
  - H-009 (8383161, verificado por TEST): `exportar` acepta destinos es/en — matiz en la fila de la tabla CLI.
  - sigma-redos (65dd311): guardia ReDoS — bala nueva en «Modelo de seguridad» es/en.
- Rutas que tocaré: README.md, README.en.md, docs/agentes/estado/PUL.md
- Plan: 6 ediciones quirúrgicas es/en (2 filas informe, 2 párrafos de firma, 2 filas exportar) + 2 balas de
  seguridad. Sin tocar cli.py, sigma/, locales ni tests (IMP-1 libre, pero respeto su zona).
