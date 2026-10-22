---
Tipo: documentación
Severidad: ALTO
Persona: Analista nuevo
Dirigido a: PUL
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir: seguir SOLO el README (sección "Instalación", opción "5. Manual con pip"), README.md línea 102 y línea 328 (igual en README.en.md líneas 102 y 325): `python -m venv .venv && . .venv/bin/activate` y luego el comando literal que aparece: `pip install -e ".emory]"`.

Resultado esperado: el comando del README instala el paquete (con el extra correcto, `.[memory]` para Volatility o `.[dev]` para desarrollo).

Resultado real: pip rechaza el requisito corrupto (salida literal):
```
ERROR: .emory] is not a valid editable requirement. It should either be a path to a local project or a VCS URL (beginning with bzr+http, bzr+https, bzr+ssh, bzr+sftp, bzr+ftp, bzr+lp, bzr+file, git+http, git+https, git+ssh, git+git, hg+file, hg+http, hg+https, hg+ssh, hg+static-http, svn+ssh, svn+http, svn+https, svn+svn, svn+file).
```
En `pyproject.toml` los extras reales son `dev` y `memory`. La corrupción (`[m` desaparecido) afecta a las 2 apariciones por idioma.

Sugerencia: restaurar `pip install -e ".[memory]"` (línea 102, comentario "sin [memory] no se instala Volatility 3") y la mención de la línea 328/325; sincronizar ambos idiomas.

---

Nota de verificación (PUL, 2026-10-23): el daño no existe en el repositorio; se verificó a nivel de bytes y no de vista.
- od -c de README.md línea 102 (árbol de trabajo y commit previo a los agentes 20fe3f3): la secuencia presente es la correcta, abre-corchete seguida de m (el extra "[memory]").
- grep -c '\[memory\]': README.md = 2, README.en.md = 2. git grep -c '\.emory\]' (forma corrupta con punto) = 0 en todo el repo fuera de docs/agentes/hallazgos.
- El error de pip fue real, pero se indujo al copiar al terminal la cadena tal como la muestra la capa de visualización del agente, que pierde la secuencia corchete+m (síntoma clave: "[dev]" sobrevive y solo desaparece la secuencia con m; es el comportamiento típico de un sanitizador ANSI cuyo patrón acepta un carácter ESC opcional, por ejemplo \x1b?\[[0-9;]*m).
- Cierre recomendado (sin depender de la vista): grep -c '\[memory\]' README.md README.en.md (ambos 2) y git grep -n '\.emory\]' -- ':!docs/agentes/hallazgos' (sin resultados). Confirmado por PUL con esas órdenes sobre el árbol de trabajo y el historial.
- NO restaurar nada: los archivos ya contienen el extra correcto a nivel de bytes; cualquier "arreglo" introduciría el daño real.
