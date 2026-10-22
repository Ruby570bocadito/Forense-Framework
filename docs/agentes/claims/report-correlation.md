# claim: report-correlation (IMP-2)

- ID: IMP-2
- Inicio: 2026-10-22T18:13:26Z
- Rutas: forense/report/__init__.py, forense/report/templates/report.html, forense/locales/{es,en}.json, tests/test_report.py

Sección de correlación entre casos en el informe HTML: observables compartidos con otros casos del
mismo espacio de trabajo (focus en el caso del informe), reutilizando core/correlation.py y sus claves
correlation.*. Solo cuando hay >1 caso; nunca bloquea el informe si otro caso está dañado; tope de 100
filas con nota de truncado. La coincidencia con fases actuales: confianza en el informe.
