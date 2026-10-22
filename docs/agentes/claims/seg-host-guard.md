# claim: seg-host-guard

- Agente: SEG
- Fecha: 2026-10-23
- Tarea: endurecer la web contra DNS rebinding cuando no hay contraseña (propuesta SEG de la
  sesión 3, entregada como fix mínimo): before_request rechaza con 403 todo Host que no sea
  loopback (localhost/127.0.0.1/::1) o una IP literal; /healthz queda exento (sonda sin datos);
  con contraseña no se aplica (Basic no se re-envía entre orígenes). Claves es/en + tests.
- Rutas: forense/web/__init__.py, forense/locales/es.json, forense/locales/en.json,
  tests/test_hardening.py, docs/agentes/estado/SEG.md (es/en compartidos permitidos)
- Duración estimada: sesión única
