# claim: artifact-notifications

- ID: IMP-1
- Inicio: 2026-10-23 (sesión 3)
- Tarea ROADMAP: (IMP-1) artifact-notifications — módulo de notificaciones de Windows
  (wpndatabase.db): apps emisoras, títulos y cuerpos; entrega completa
- Rutas que tocará:
  - forense/modules/windows/notifications.py (nuevo módulo triage)
  - forense/modules/__init__.py (solo-adición: import del módulo nuevo)
  - forense/locales/es.json, en.json (solo-adición: claves del módulo + fields + etype + artifact)
  - forense/demo/builders.py (build_wpndatabase) y forense/demo/__init__.py (artefacto de la historia)
  - tests/test_modules.py, tests/test_core.py (tests del módulo, tolerancia a corrupción y triaje demo)
- Formato: esquema documentado de wpndatabase.db (Notification + NotificationHandler, payload XML
  UTF-16LE/UTF-8, FILETIMEs); SQLite → se sintetiza de forma honesta (formato abierto, igual que
  ActivitiesCache.db de la demo).
