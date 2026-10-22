---
Tipo: documentación
Severidad: ALTO
Persona: Analista nuevo
Dirigido a: PUL
Estado: abierto
---

Pasos para reproducir: seguir SOLO el README (sección "Instalación", opción "5. Manual con pip"), README.md línea 102 y línea 328 (igual en README.en.md líneas 102 y 325): `python -m venv .venv && . .venv/bin/activate` y luego el comando literal que aparece: `pip install -e ".emory]"`.

Resultado esperado: el comando del README instala el paquete (con el extra correcto, `.[memory]` para Volatility o `.[dev]` para desarrollo).

Resultado real: pip rechaza el requisito corrupto (salida literal):
```
ERROR: .emory] is not a valid editable requirement. It should either be a path to a local project or a VCS URL (beginning with bzr+http, bzr+https, bzr+ssh, bzr+sftp, bzr+ftp, bzr+lp, bzr+file, git+http, git+https, git+ssh, git+git, hg+file, hg+http, hg+https, hg+ssh, hg+static-http, svn+ssh, svn+http, svn+https, svn+svn, svn+file).
```
En `pyproject.toml` los extras reales son `dev` y `memory`. La corrupción (`[m` desaparecido) afecta a las 2 apariciones por idioma.

Sugerencia: restaurar `pip install -e ".[memory]"` (línea 102, comentario "sin [memory] no se instala Volatility 3") y la mención de la línea 328/325; sincronizar ambos idiomas.
