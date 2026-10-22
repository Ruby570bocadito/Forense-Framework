# claim: seg-web-open-notice

- Agente: SEG
- Fecha: 2026-10-23
- Tarea: atender la petición de TEST (estado/TEST.md): la web sin FORENSE_WEB_PASSWORD abre sin
  autenticación en 127.0.0.1 sin ningún aviso en el arranque. Añadir aviso de arranque (stderr)
  cuando no hay contraseña también en loopback, conservando el aviso fuerte de red expuesta;
  claves es/en + tests de regresión.
- Rutas: forense/cli.py, forense/locales/es.json, forense/locales/en.json, tests/ (compartidos
  es/en permitidos por protocolo), docs/agentes/estado/SEG.md
- Duración estimada: sesión única
