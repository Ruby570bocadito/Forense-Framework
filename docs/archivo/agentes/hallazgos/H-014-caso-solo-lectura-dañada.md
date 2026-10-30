---
Tipo: bug
Severidad: MEDIO
Persona: entorno adverso
Dirigido a: IMP-1
Estado: abierto
---

Pasos para reproducir: `cp -r CASO copia_ro && chmod -R a-w copia_ro` (equivalente a montar la carpeta
de casos de solo lectura, habitual en laboratorios y compartidos de evidencia) y ejecutar cualquier
orden, incluidas las de lectura: `forense -L es -c copia_ro info`, `... hallazgos`, `... verificar`,
`... informe`.
Resultado esperado: las órdenes de lectura funcionan sin escribir y las de escritura dan un error
localizado claro de permisos ("la carpeta del caso es de solo lectura…").
Resultado real (las cuatro órdenes, exit 1): `Error: la base de datos del caso está dañada o no es de
Forense (attempt to write a readonly database)` — diagnóstico engañoso: la base es válida; el problema
es de permisos. Un operador con un compartido de solo lectura concluiría que el caso está corrupto.
La apertura del caso escribe algo de forma incondicional y el handler mapea cualquier
sqlite3.OperationalError a la clave `error.case_database` (es.json:336).
Sugerencia: distinguir el error "readonly database" con una clave propia (p. ej. `error.case_readonly`)
y no escribir al abrir en las órdenes de lectura.
