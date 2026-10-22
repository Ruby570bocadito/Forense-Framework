---
Tipo: UX
Severidad: BAJO
Persona: Perito veterano
Dirigido a: IMP-1
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir: en un caso sin conclusiones previas, ejecutar exactamente el ejemplo del README.md línea 228: `forense -c ./2026-017 conclusiones --archivo conclusiones.md` sin crear antes ese archivo. (Verificado: con un archivo existente el comando funciona, "Conclusiones guardadas (versión 1, SHA-256 …)", así que `--archivo` es ENTRADA.)

Resultado esperado: un mensaje claro en el idioma de la interfaz, del tipo "El archivo conclusiones.md no existe: redáctelo primero (su contenido se registra como conclusiones)" o una ayuda que diga que el archivo debe existir.

Resultado real (salida literal):
```
Error: [Errno 2] No such file or directory: 'conclusiones.md'
```
Error Python crudo, sin contexto y en inglés dentro de una sesión `-L es`; la ayuda (`--text TEXT | --file FILE`) tampoco aclara que el archivo es de lectura. El ejemplo del README no menciona que hay que crearlo antes.

Sugerencia: capturar FileNotFoundError en cli.py y traducir el mensaje por locales; pedir a PUL que el ejemplo del README (línea 228) muestre la creación previa del archivo.

---

Nota de verificación (IMP-1, 2026-10-23): resuelto en 0606ea2 (parte CLI; el ejemplo del README lo cubrió
PUL en readme-h006-conclusiones).
- `conclusiones --archivo` ya no deja escapar el error de Python: FileNotFoundError → "El archivo {file} no
  existe: redáctelo primero (su contenido se registra como conclusiones); también puede usar --texto." en el
  idioma de la sesión, exit 1 limpio; otros fallos de lectura (directorio, permisos, binario no UTF-8) →
  "No se puede leer {file}: {error}".
- Ayuda de las opciones traducida y aclarada: --archivo "Fichero cuyo contenido se registra como
  conclusiones (debe existir; es de lectura)" y --texto.
- Tests: tests/test_cli.py::test_conclusions_file_errors_are_localized (es/en, binario, sin traceback).
  Suite: 343 passed, 1 skipped; ruff limpio.
