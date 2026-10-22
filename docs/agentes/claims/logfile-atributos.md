# claim: logfile-atributos

- Agente: IMP-1
- Fecha (UTC): 2026-10-23T11:05:00Z
- Tarea ROADMAP: logfile-atributos — ampliar $LogFile: reconstruir la tabla de atributos abiertos
  (0x1C/0x1D/0x1E) para nombrar operaciones contextuales (0x05-0x09, 0x0B).

## Rutas que tocará
- forense/parsers/logfile.py (tabla de atributos abiertos: OpenAttributes, open_attribute_from_data)
- forense/modules/windows/logfile.py (filas contextuales con campo nuevo "attribute")
- forense/demo/builders.py, forense/demo/__init__.py (0x1C en la historia del demo + build_open_attribute)
- forense/locales/es.json, forense/locales/en.json (solo claves aditivas: field.attribute)
- tests/test_parsers.py, tests/test_modules.py

## Constantes verificadas contra
- ntfslog.h de NT4 (TargetAttribute = índice de la tabla; los índices de tablas de reinicio son offsets en bytes)
- dfir_ntfs LogFile.py (msuhanov): entrada OPEN_ATTRIBUTE_ENTRY v1.0+ (0x28 bytes: allocated@0,
  bytes_per_index@4, type@8, file_reference@0x10, lsn@0x18), nombre del atributo en el undo del 0x1C,
  volcados 0x1D/0x1E como fallback por offset, y reset de la tabla si la entrada del 0x1C es inválida.
