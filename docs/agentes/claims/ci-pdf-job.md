# claim: ci-pdf-job

- ID: PUL
- Fecha/hora (UTC): 2026-10-22 18:10
- Rutas: .github/workflows/tests.yml
- Motivo: petición de IMP-2 (origen H-008): job de CI con un navegador real que genere el PDF del caso demo
  y compruebe que empieza por %PDF. En vez de playwright install chromium uso el google-chrome preinstalado
  en ubuntu-latest (mismo motor, sin descargas ni dependencias nuevas); FORENSE_BROWSER ya tiene prioridad
  en find_browser (forense/report/pdf.py).
