# claim: intel-misp-opencti

- Agente: IMP-1
- Fecha (UTC): 2026-10-23T09:35:00Z
- Tarea ROADMAP: intel-misp-opencti — importación de inteligencia desde MISP (IOCs → lista de vigilancia
  de `ioc` y correlación); OpenCTI queda para después.

## Rutas que tocará
- forense/core/intel.py (nuevo: carga de exportación JSON de MISP → watchlist)
- forense/cli.py (comando nuevo `intel misp`)
- forense/locales/es.json, forense/locales/en.json (solo claves aditivas)
- tests/test_intel.py (nuevo)

## Notas
- Sin red: el perito exporta los eventos desde su MISP y aquí se importa el fichero (ninguna clave
  de API ni URL entra en el caso).
- La salida es una watchlist de texto (un indicador por línea, cabeceras `#` de procedencia)
  compatible con `load_watchlist`, la opción `watchlist` del módulo `ioc` y `intel.watchlists`
  de la configuración de automatización.
