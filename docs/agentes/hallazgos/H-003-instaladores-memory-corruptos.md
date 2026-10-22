---
Tipo: bug
Severidad: ALTO
Persona: Analista nuevo
Dirigido a: PUL
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir: misma corrupción `[m` que H-001/H-002 pero en instaladores y Docker (zona PUL). (1) `install/install.sh` línea 83: `PACKAGE="$SOURCE"; [ "$MEMORY" = 1 ] && PACKAGE="${SOURCE}emory]"`. (2) `install/install.ps1` líneas 121-122: `$Source + "emory]"` y `"forense-frameworkemory] @ " + $Source`. (3) `Dockerfile` línea 27: `RUN if [ "$WITH_MEMORY" = "1" ]; then pip install ".emory]"; ...`. Reproducción mínima de la lógica del sh (sin instalar nada):
```
$ SOURCE="forense-framework"; MEMORY=1; PACKAGE="${SOURCE}emory]"; echo "$PACKAGE"
forense-frameworkemory]
```

Resultado esperado: con `--with-memory` / `-WithMemory` / `WITH_MEMORY=1` el requisito debe ser `forense-framework[memory]` / `.[memory]`.

Resultado real: los tres generan un requisito pip inválido, por lo que el instalador con memoria y el build Docker `WITH_MEMORY=1` fallan. No se pudo ejecutar el instalador completo en este entorno (sin Docker y sin objetivo Windows); la lectura del código y la réplica de la lógica sh son la evidencia, y el mismo patrón se confirmó en ejecución real en H-002.

Sugerencia: restaurar `[memory]` en las tres ubicaciones; revisar si algún procesado de texto (no git) fue el origen, porque `install/` y `Dockerfile` se dañaron a la vez que README y locales.

---

Nota de verificación (PUL, 2026-10-23): igual que H-001: el daño no existe en el repositorio, se verificó por bytes.
- grep -c '\[memory\]' sobre el árbol de trabajo: install/install.sh = 2 (líneas 83 y 85, ambas ramas del if), install/install.ps1 = 2 (líneas 121 y 122), Dockerfile = 1 (línea 27). Forma corrupta con punto: 0 en todo el repo fuera de docs/agentes/hallazgos.
- bash -n install/install.sh: sintaxis correcta. La réplica sh del hallazgo produce la cadena corrupta solo porque la cadena de partida ya estaba maquillada por la vista del agente.
- Los commits que introdujeron estas líneas (ab6d393 y anteriores, previos a los agentes) ya contienen el extra correcto: el daño nunca estuvo en git.
- NO restaurar nada en install/ ni Dockerfile: cualquier "arreglo" introduciría el daño real. Docker no es ejecutable en este entorno; el build WITH_MEMORY=1 queda para la CI.
