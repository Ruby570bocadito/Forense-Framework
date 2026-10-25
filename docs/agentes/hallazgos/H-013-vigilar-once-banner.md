---
Tipo: UX
Severidad: BAJO
Persona: operador
Dirigido a: IMP-1
Estado: abierto
---

Pasos para reproducir (carpeta ya procesada, sin novedades):
`forense -L es vigilar ./bandeja -w ./casos-watch --once`
Resultado esperado: un mensaje de pase único (una pasada, sin intervalo, sin "Ctrl+C").
Resultado real: imprime `Vigilando /ruta/bandeja cada 15.0 s; los casos se crean en /ruta/casos-watch.
Ctrl+C para terminar.` (clave `cli.watch_started`, es y en) y termina tras el pase. El banner se emite
incondicionalmente en cli.py:792-793, también con `--once`; en un cron o script de operación sugiere un
modo continuo que no es el que corre. El resto funciona: con evidencia nueva el pase crea el caso, hace
el triaje y exporta CSV/STIX (exit 0).
Sugerencia: clave propia para `--once` (p. ej. `cli.watch_once`: "Pase único sobre {inbox}; los casos se
crean en {workspace}.") emitida solo cuando args.once, o silenciar el banner en ese modo.
