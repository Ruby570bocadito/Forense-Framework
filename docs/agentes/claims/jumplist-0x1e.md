Claim: jumplist-0x1e
ID: IMP-1
Fecha: 2026-10-25 12:10 UTC
Rutas: forense/parsers/jumplist.py, tests/test_artifacts.py
Nota: propuesta propia del estado (sesión 5): tope de tamaño para el read_bytes completo de
parse_custom (customDestinations), fuera del alcance de readbytes-gate (que cubría módulos/core).
