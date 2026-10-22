# claim: h-010-informe-firmar

- ID: IMP-1
- Inicio: 2026-10-23T01:30Z
- Hallazgo: H-010 (la CLI no expone la firma que ya ofrece la web; dependencia report-signing cumplida)
- Rutas que tocaré: forense/cli.py, forense/locales/es.json, forense/locales/en.json, tests/test_cli.py
- Plan: opción `--firmar/--sign` en `informe` que activa generate_report(sign=True) y html_to_pdf(sign=True),
  con mensaje por informe firmado; la clave sigue sin persistirse (FORENSE_SIGN_KEY, errores ya localizados).
