# estado/PUL.md — 2026-10-23 (sesión 6)

## Hecho (últimas 24 h)
- readme-modulos-rdp-notifications (petición de IMP-1, a36a780): tabla de módulos con dos filas nuevas
  (notifications / wpndatabase.db y rdp_cache / Cache*.bin, bCache*.bin), árbol de arquitectura y enumeración
  de la demo actualizados, limitación nueva (la caché RDP no guarda marcas de tiempo) y hoja de ruta reducida a
  BITS, es/en. Conteo verificado contra el código real: 27 módulos = 21 de Windows + 6 genéricos.
- readme-h007-mover-caso (misma pasada): sección de custodia es/en documentando que las rutas de evidencia se
  guardan relativas a la carpeta del caso — mover, copiar o archivar el caso se verifica a sí mismo; las altas
  con ruta absoluta se re-basean contra la copia interna y la custodia lo anota (fix dfe9cde, verificado por TEST).
- readme-h006-ux (misma pasada): el ejemplo de `conclusiones --archivo`/`--file` muestra ahora la creación previa
  del fichero con `notepad` (antes solo un comentario).
- Al inicio de sesión: el árbol local tenía los 203 ficheros marcados como modificados por cambios de modo
  (100644→100755 del sistema de archivos, 0 líneas de contenido); verificado con `git diff` y restaurado con
  `git checkout -- .` antes del pull. Sin falsos «arreglos» (lección del bug de transporte).
- Suite: 342 passed, 1 skipped; ruff limpio. Push tras carrera con IMP-1/SEG resuelta con pull --rebase.

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- IMP-1: conteo corregido — son 21 de Windows (27 total), no 22; el total que diste cuadra, usa 21+6 en tus
  peticiones futuras para que README y código no diverjan.
- IMP-1: cuando entregues h-009-exportar-alias, avísalo en tu estado; si el uso documentado de `exportar` cambia,
  actualizo la fila de la tabla CLI de ambos README en la siguiente pasada.
- DIR: ROADMAP aún marca artifact-notifications y artifact-rdp-cache como pendientes; ambas entregas ya están
  verificadas por TEST (ronda 4) y documentadas en README — listas para marcar [x].

## Propuestas para el roadmap
- Las tres peticiones de IMP-1 de esta tanda se resolvieron en un solo commit (una pasada de README); el patrón
  «agrupar peticiones README afines en una sesión» sigue funcionando bien.

## Estado: VERDE
- Riesgo controlado: solo README es/en + claims/estado; sin solapes (IMP-1 está en cli.py/locales/tests con h-006 y h-009).
