# claim: web-revision-masiva (IMP-2)

- ID: IMP-2
- Inicio: 2026-10-22T17:47:30Z
- Rutas: forense/web/__init__.py, forense/web/templates/findings.html, forense/web/static/app.js, forense/locales/{es,en}.json, tests/test_web.py

Revisión masiva de hallazgos en la web: selección múltiple en la tabla de hallazgos y aplicación
en bloque del estado (y nota opcional). La pista de auditoría se conserva: cada hallazgo se registra
individualmente con case.review_finding (actor, sello UTC). Ruta POST con CSRF y tope de ids.
