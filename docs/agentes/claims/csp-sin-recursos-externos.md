# claim: csp-sin-recursos-externos

- ID: IMP-2
- Fecha (UTC): 2026-10-25T13:40:00Z
- Tarea ROADMAP: web-pwa-offline (K17 del roadmap de producto, P3) — todos los recursos locales (ya se
  cumple); comprobar que no hay ninguna petición externa con un test de CSP estricto.

## Rutas que tocará
- tests/test_web.py (test de regresión: sin http(s):// ni URLs protocol-relative en plantillas web y de
  informe, ni en static; CSP con default-src 'self' sin huecos de connect-src externos)
