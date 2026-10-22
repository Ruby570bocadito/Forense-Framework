# claim: readbytes-gate

- Agente: IMP-1
- Fecha (UTC): 2026-10-23T12:10:00Z
- Tarea ROADMAP: readbytes-gate — gate central de tamaño para el patrón read_bytes() común de los
  módulos (evidencias que provoquen consumo desmedido de memoria/disco).

## Rutas que tocará
- forense/core/utils.py (FileTooLarge + read_capped)
- forense/modules/windows/psreadline.py, lnk.py, tasks.py, defender.py, rdp_cache.py, setupapi.py,
  recyclebin.py (adopción del gate; rdp_cache y setupapi ganan un tope que no tenían)
- tests/test_core.py, tests/test_modules.py (ficheros sparse: nunca se materializan en disco)

## Semántica
- read_capped(path, limit) → bytes o FileTooLarge (subclase de ValueError, así los except
  (OSError, ValueError) existentes siguen funcionando); OSError se propaga tal cual.
- Los módulos conservan su comportamiento: error visible (psreadline, defender, setupapi, rdp_cache)
  o salto silencioso (lnk, tasks, recyclebin).
