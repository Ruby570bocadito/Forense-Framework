---
Tipo: documentación
Severidad: ALTO
Persona: analista nuevo
Dirigido a: PUL
Estado: resuelto-pendiente-verificación (sin cambio de código: falso positivo de capa de vista)
---

## Resolución PUL (2026-10-25, sesión 9)

Verificación a nivel de bytes del repo: las 8 líneas citadas (README.md 106 y 335, README.en.md 106
y 332, install/install.sh 83 y 85, install/install.ps1 121 y 122) contienen el texto correcto,
tanto en el árbol de trabajo como en los objetos git de HEAD (94c5453) y de ab6d393, el commit donde
se situaba el origen. Cero líneas corruptas reales. También intactos pyproject.toml (extra
memory = ["volatility3>=2.7"]) y, para H-012, forense/update.py y las 6 claves de locales.

Prueba funcional en venv limpio (.agent-tmp/venv-h011):
- pip install -e ".[memory]" (la orden literal del README): CORRECTA — instala forense-framework 0.4.0.
- pip install -e ".emory]" (la cadena tal y como la muestra la herramienta): falla con EXACTAMENTE
  el error citado arriba. Esa cadena no existe en ninguna línea del repo.

Causa raíz: la capa de presentación de las herramientas de agente se come el literal corchete-m en
ciertos contextos (bloques de código de README, líneas de shell); el propio texto de este hallazgo
y de la cola de DIR lo muestran vacío entre tildes invertidas. TEST reprodujo el error pegando en
el shell la cadena tal y como la mostraba la vista, no la del repo. Recomendación: ante cualquier
hallazgo de "literal perdido", contrastar siempre con od -c, git cat-file blob o
python text.count() antes de triar; y el comando de verificación literal grep 'emory]' daría
falsos positivos porque toda línea con el extra contiene esa subcadena (usar lookbehind:
rg '(?<!\[m)emory\]' README.md README.en.md install/ — cero resultados).

Commit de esta resolución: ver docs/agentes/estado/PUL.md (sesión 9).

---

Pasos para reproducir: seguir el README al pie de la letra (instalación manual, opción 5, README.md:102 /
README.en.md:102): `python -m venv .venv && . .venv/bin/activate && pip install -e ".emory]"`.
Resultado esperado: `pip install -e ".[memory]"` (el extra existe en pyproject.toml:44, intacto).
Resultado real: `ERROR: .emory] is not a valid editable requirement. It should either be a path to a local
project or a VCS URL (...)` — el analista nuevo se queda atascado en el primer paso, en ambos idiomas.
El literal `[m` desapareció en 8 líneas de 4 ficheros (todas las que citan el extra `[memory]`;
el mismo defecto en producto es H-012): README.md:102 y 330, README.en.md:102 y 327,
install/install.sh:83 y 85 (`PACKAGE="${SOURCE}emory]"` y `"forense-frameworkemory] @ "`) y
install/install.ps1:121 y 122. Consecuencia extra: `sh install/install.sh --with-memory` y
`install.ps1 -WithMemory` construyen un spec pip inválido, así que el modo con memoria de ambos
instaladores está roto. La corrupción está desde ab6d393 (2026-10-04, rama heredada); los
`[Memory](#memory)` con mayúscula sobrevivieron, por lo que la limpieza fue exactamente `[m`.
Sugerencia: restaurar `[m` en esas 8 líneas y verificar con `grep -rn 'emory]' README.md README.en.md
install/` sin resultados; `packaging/` está limpio.
