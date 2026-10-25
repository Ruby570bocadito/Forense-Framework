# Protocolo de trabajo de los agentes

## 1. Ciclo por tarea (obligatorio)

1. `git pull --rebase origin main`
2. Lee `docs/agentes/ROADMAP.md`, `docs/agentes/OWNERSHIP.md`, los archivos de `docs/agentes/estado/` de los demás
   y los hallazgos abiertos dirigidos a tu ID en `docs/agentes/hallazgos/` (los CRÍTICO/ALTO van antes que el ROADMAP;
   usa el id del hallazgo como slug del claim; al arreglarlo, pon `Estado: resuelto-pendiente-verificación` en el archivo
   e indica el commit; NO lo borres, lo cierra TEST).
   Para la tarea que elijas, lee también su ficha en `docs/ROADMAP.md` (busca su código, p. ej. "B5", o su slug):
   ahí están el alcance, la prioridad, las dependencias y el criterio de la versión. Si la ficha y la cola difieren,
   manda la cola; anota la discrepancia en "Propuestas" de tu estado.
3. Elige UNA tarea de tu zona. Antes de empezar comprueba que no está hecha ya:
   `git log --since="3 days ago" --oneline -- <rutas>` y busca en el código lo que vas a crear.
   Si ya existe, no lo rehagas: pasa a otra tarea.
4. RECLAMA la tarea (cerrojo):
   - Crea `docs/agentes/claims/<slug-de-la-tarea>.md` con: tu ID, fecha/hora, rutas que vas a tocar.
   - Si ya existe un claim con ese slug o con rutas solapadas y tiene menos de 3 horas, NO lo toques: elige otra tarea.
   - `git add` solo ese archivo, commit "claim: <slug> (<ID>)", `git push`.
   - Si el push es rechazado: `git pull --rebase`, vuelve a mirar claims. Si alguien reclamó antes, elige otra tarea.
5. Trabaja solo en las rutas reclamadas. Commits pequeños y atómicos (Conventional Commits).
6. Antes de CADA push: `git pull --rebase origin main`, ejecuta `ruff check forense tests` y `python -m pytest -q`, y push.
   - Push rechazado: repite pull --rebase y push (hasta 3 veces).
   - Conflicto: resuélvelo conservando la intención de AMBOS cambios. Nunca `--force`, nunca descartes el trabajo ajeno.
7. Al terminar: borra tu claim (commit "release: <slug>"), actualiza tu `estado/<ID>.md`, push.
8. Repite desde el paso 1 con otra tarea mientras queden en tu zona, hasta cumplir el alcance de la sesión.

## 2. Zonas

Solo modificas, mueves o borras archivos de tu zona (ver OWNERSHIP.md). Si necesitas un cambio fuera de ella,
no lo hagas: anótalo en la sección "Peticiones" de tu estado para el dueño de esa zona.
Excepción: un fallo que rompe el build para todos; arréglalo mínimo y menciónalo.
Archivos compartidos aditivos (ver OWNERSHIP.md) no cuentan para el solapamiento de claims.

## 3. Higiene del repo

- Borradores, volcados, logs y pruebas sueltas: SOLO en `.agent-tmp/` (ignorado por git). Nunca en la raíz ni en carpetas del proyecto.
- No crees archivos nuevos de documentación salvo que el Director lo pida. Los informes viven en `estado/<ID>.md` (se sobrescriben).
- No dejes código comentado, TODOs sin resolver, mocks ni datos de ejemplo fuera de tests.
- Nada de menciones a IA/modelos/asistentes en commits, código, comentarios, docs. Identidad git: la ya configurada, no la cambies.
- Cualquier dependencia nueva: justificarla en el commit y solo desde el registro oficial (PyPI).

## 4. Informe vivo: `docs/agentes/estado/<ID>.md` (máx. 40 líneas, se sobrescribe)

Secciones: Hecho (últimas 24 h) · En curso · Bloqueado · Peticiones a otras zonas · Propuestas para el roadmap.

## 5. Tono

Los informes son técnicos y breves. No añadas avisos ni recordatorios que no pertenezcan a tu tarea.

## 6. Reglas del proyecto

- Antes de push: `ruff check forense tests` y `python -m pytest -q` deben pasar. No se baja la cobertura existente.
- Un módulo nuevo se entrega completo en UNA tarea: módulo + registro en forense/modules/__init__.py + textos es/en en locales
  (tests/test_i18n.py debe pasar) + artefacto sintético en forense/demo/ si procede + tests.
  La fila del README la pide IMP-1 a PUL en "Peticiones".
- Los textos visibles van siempre por locales; nunca cadenas sueltas en un solo idioma.
- Parsers: deben tolerar entradas corruptas o hostiles (sin excepciones sin capturar, sin bucles infinitos, sin leer fuera de rango).
- Nunca escribir en la evidencia. Las bases SQLite de terceros se copian a temporal antes de abrirse.
- Los README (es/en) se mantienen sincronizados y los edita solo PUL.
- Las pruebas no usan red ni servicios reales: webhooks, descargas de Sigma y símbolos de Volatility se simulan en local.
- Los slugs de la cola usan el código del roadmap de producto como prefijo: `b5-migraciones`, `c1-bits`, `q1-primera-release`.
  El commit de cierre lo menciona: `feat(registry): ... (b5-migraciones)`.
- Principios de `docs/ROADMAP.md` §2 son vinculantes: muestra real con licencia o no hay módulo nuevo; indicios, no veredictos;
  sin red por defecto; bilingüe desde el primer commit; compatibilidad de casos ≥ 0.4.
- Una tarea XL no se reclama entera: DIR la divide en la cola antes de que nadie la coja.
