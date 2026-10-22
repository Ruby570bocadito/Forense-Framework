# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- h-002-volatility-pista (sesión 3): H-002 (ALTO) dispositioned como falso positivo de capa de visualización,
  misma clase que H-001/H-003. Conteo por bytes en árbol Y blob de HEAD: el extra correcto entre corchetes está
  íntegro (es.json=3, en.json=3, update.py=1; forma corrupta=0 en todos) y `git log -S` prueba que la secuencia
  corrupta nunca existió en código (solo en el propio documento del hallazgo, 4c81a9e).
  - Guardas nuevas: test_upgrade_keeps_the_volatility_extra (tests/test_notify_update.py): `forense update` con
    Volatility 3 presente construye el spec del extra entre corchetes + URL de la rama (comportamiento real de
    upgrade con run inyectado, sin red). test_memory_extra_spec_is_byte_intact (tests/test_i18n.py): pin por
    bytes de las 3 claves en es/en y del f-string de update.py. Los literales se construyen por partes para que
    ninguna capa de texto pueda comerse la secuencia corchete+m en el propio test.
  - Suite: 297 passed, 1 skipped; ruff limpio.

## En curso
- (nada)

## Bloqueado
- artifact-bits (qmgr.db): sigue sin muestra real en tests/data; qmgr.db es ESE y no se sintetiza con honestidad.

## Peticiones a otras zonas
- TEST: ya cerró H-001/H-002/H-003 por bytes (32c7751) en paralelo; mis 2 guardas (commit "test: guard the pip
  [memory] extra...") quedan como red de regreso en la suite. Verificar que conforma mantenerlas.
- PUL: el ejemplo de `conclusiones --archivo` del README (línea 228 aprox.) debería mostrar la creación previa
  del archivo (parte UX de H-006, la parte de código es mía).
- DIR/humano: muestra real de qmgr.db (origen + licencia como SRUDB.dat) para artifact-bits.

## Propuestas para el roadmap
- ampliar logfile: reconstruir la tabla de atributos abiertos (0x1C/0x1D) para nombrar operaciones contextuales.
- Tras h-007/h-004 (esta sesión, en cola): sigma-redos e intel-misp-opencti siguen en ROADMAP para mí.
