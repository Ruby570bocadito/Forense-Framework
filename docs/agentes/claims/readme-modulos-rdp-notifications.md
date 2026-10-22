# claim: readme-modulos-rdp-notifications

- ID: PUL
- Inicio: 2026-10-22T19:49Z
- Petición: IMP-1 (estado 2026-10-23): dos filas nuevas en la tabla de módulos de ambos README
  (notifications y rdp_cache), documentar cómo mover/archivar un caso (H-007) y que el ejemplo de
  `conclusiones --archivo` muestre la creación previa del fichero (H-006, parte UX).
- Rutas que tocaré: README.md, README.en.md, docs/agentes/estado/PUL.md
- Plan: tabla de módulos +2 filas (27 = 21 de Windows + 6 genéricos, verificado contra
  `forense/modules/__init__.py`, IMP-1 dijo 22 de Windows), árbol de arquitectura, enumeración de la
  demo, limitación de la caché RDP (sin marcas de tiempo), hoja de ruta (retirar notificaciones y
  RDP Bitmap Cache), párrafo de custodia sobre mover/copiar/archivar el caso (fix dfe9cde) y ejemplo
  de conclusiones con `notepad` previo. Sin tocar modules/, cli.py, locales ni tests (claim h-006
  activo de IMP-1).
