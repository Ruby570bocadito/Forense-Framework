# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- mft-attribute-list (b80f8fb, cf72bfa): los registros de extensión ($ATTRIBUTE_LIST) se combinan con su
  registro base en $MFT (limitación conocida del README resuelta).
  - forense/parsers/mft.py: parse_attribute_list, collect_extensions y merge_extensions; MftEntry gana
    attribute_list, base_sequence y has_unnamed_data. El merge valida la secuencia del base y el listado
    de la $ATTRIBUTE_LIST: un registro base reutilizado por otro archivo no adopta extensiones huérfanas.
    Contenido corrupto o truncado nunca lanza excepciones.
  - forense/modules/windows/mft.py: recogida de extensiones en la pasada de rutas y fusión en la de
    registros (sin E/S extra); contador "extension_records" en el resumen (field.extension_records es/en).
  - forense/demo: backup_correo.pst (2 GiB, $DATA y Zone.Identifier en registro de extensión, registros
    90-91); builders nuevos build_mft_attribute_list y build_mft_extension_record (helpers extraídos con
    salida byte-idéntica; build_mft_record gana attribute_list/omit_data).
  - Tests: fusión, rechazo de huérfanos y contenido corrupto en test_parsers.py; PST del demo en
    test_mft_module. Suite: 278 passed, 1 skipped; ruff limpio.
- Nota técnica: tras un pull --rebase que traiga cambios en pyproject.toml hay que refrescar
  `pip install -e ".[dev]"` antes de confiar en un fallo (me falló la suite por el cryptography de IMP-2).

## En curso
- (nada)

## Bloqueado
- (nada)

## Peticiones a otras zonas
- PUL: .gitignore no cubre artefactos Python (__pycache__/, *.egg-info/, .pytest_cache/, .ruff_cache/, .venv/);
  pip install -e genera forense_framework.egg-info/ en la raíz.
- PUL: README "Limitaciones conocidas" aún dice que $MFT no combina $ATTRIBUTE_LIST; ya está resuelto (cf72bfa).

## Propuestas para el roadmap
- artifact-bits: qmgr.db es una base ESE; conviene reutilizar el acceso ESE ya existente (libesedb, vía srum).
- artifact-logfile: delimitar el alcance a la reconstrucción básica de rangos de $MFT (evita prometer más).
