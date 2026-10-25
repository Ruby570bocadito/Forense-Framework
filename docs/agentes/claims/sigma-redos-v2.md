Claim: sigma-redos-v2
ID: IMP-1
Fecha: 2026-10-25 12:25 UTC
Rutas: forense/sigma/engine.py, tests/test_detection.py
Nota: ALTA de la cola (devolución de SEG, sesión 8): la guardia de 65dd311 es evadible con 8 familias
(presupuesto que multiplica la ventana una vez en vez de elevarla a iteraciones, y átomos adyacentes
cuantificados sin comprobar). Fix: presupuesto de ambigüedad global Σ log2(ways) con recursión.
