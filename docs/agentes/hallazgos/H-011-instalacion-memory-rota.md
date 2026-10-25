---
Tipo: documentación
Severidad: ALTO
Persona: analista nuevo
Dirigido a: PUL
Estado: abierto
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
