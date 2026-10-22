# claim: web-auth-warning (IMP-2)

- ID: IMP-2
- Inicio: 2026-10-22T18:05:23Z
- Rutas: forense/web/__init__.py, forense/web/templates/base.html, forense/locales/{es,en}.json, tests/test_web.py

Aviso visible en la interfaz cuando arranca sin contraseña (PASSWORD no configurada): banda
permanente en base.html con el texto es/en y referencia a FORENSE_WEB_PASSWORD. Complementa el
aviso CLI (solo bind no-loopback) y responde a la petición de TEST dirigida a SEG; SEG puede
vetar. El aviso de arranque en cli.py queda como sugerencia a IMP-1.
