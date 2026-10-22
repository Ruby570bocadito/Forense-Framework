# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- mft-attribute-list (b80f8fb→rebase, cf72bfa→rebase, liberado en b278129): los registros de extensión
  ($ATTRIBUTE_LIST) se combinan con su registro base en $MFT (limitación conocida del README resuelta).
  - forense/parsers/mft.py: parse_attribute_list, collect_extensions y merge_extensions; MftEntry gana
    attribute_list, base_sequence y has_unnamed_data. El merge valida la secuencia del base y el listado
    de la $ATTRIBUTE_LIST: un registro base reutilizado no adopta extensiones huérfanas. Contenido
    corrupto nunca lanza excepciones.
  - forense/modules/windows/mft.py: recogida de extensiones en la pasada de rutas y fusión en la de
    registros (sin E/S extra); contador "extension_records" en el resumen (field.extension_records es/en).
  - forense/demo: backup_correo.pst (2 GiB, $DATA y Zone.Identifier en registro de extensión);
    builders build_mft_attribute_list y build_mft_extension_record (helpers extraídos, salida idéntica).
- artifact-logfile (01fbb36, ef3a80c): soporte básico del diario transaccional NTFS (limitación conocida).
  - forense/parsers/logfile.py: parse_restart (geometría desde RSTR, copia usada si la otra está corrupta),
    iter_records (RCRD con fixups validados, nunca lanza) y decodificadores de nombres: imágenes de
    registro MFT (0x02, reutiliza el parser de $MFT con apply_fixups ahora público), entradas de índice
    (0x0C-0x0F, en redo o undo) y renombrados (0x13-0x14). Sin marcas de tiempo: el diario no las lleva.
  - forense/modules/windows/logfile.py: módulo triage con filas logfile_entry (lsn, transacción, operación,
    registro, registro padre, nombre) y resumen por archivo; textos es/en.
  - forense/demo: $LogFile sintético con las operaciones detrás de la historia del $MFT; builders
    build_lfs_record/build_logfile/build_logfile_index_entry/build_file_name_value.
  - Suite: 285 passed, 1 skipped; ruff limpio.
- Nota técnica: tras un pull --rebase que traiga cambios en pyproject.toml hay que refrescar
  `pip install -e ".[dev]"` antes de confiar en un fallo (me falló la suite por el cryptography de IMP-2).

## En curso
- (nada)

## Bloqueado
- (nada)

## Peticiones a otras zonas
- PUL: .gitignore no cubre artefactos Python (__pycache__/, *.egg-info/, .pytest_cache/, .ruff_cache/, .venv/);
  pip install -e genera forense_framework.egg-info/ en la raíz.
- PUL: README "Limitaciones conocidas" aún dice que $MFT no combina $ATTRIBUTE_LIST; resuelto (cf72bfa).
- DIR/humano: artifact-bits (qmgr.db) necesita una muestra real en tests/data con origen y licencia
  documentados (como SRUDB.dat de plaso): qmgr.db es ESE y no puede sintetizarse; el código del parser
  puede adelantarse sobre la interfaz de filas, pero sin muestra el test end-to-end no es honesto.

## Propuestas para el roadmap
- artifact-bits: cuando haya muestra, reutilizar el acceso ESE ya existente (libesedb, vía srum).
- ampliar logfile: reconstruir la tabla de atributos abiertos (0x1C/0x1D) para nombrar operaciones
  contextuales (UpdateFileName, tamaños) y ligar cada LSN con su registro de la superlínea.
