# Qué sigue en Sabueso

Una página, en orden. Lo terminado se borra de aquí (queda en el historial de git y en el CHANGELOG).
El plan largo original, por ejes y versiones, está archivado en [docs/archivo/ROADMAP.md](docs/archivo/ROADMAP.md).

**Rumbo:** ser la herramienta forense de Windows para **peritos hispanohablantes**: hallazgos que se pueden
defender ante un juez, custodia verificable e informe pericial en español. Cada mejora se valida con casos reales
([docs/VALIDACION.md](docs/VALIDACION.md)) antes de darla por buena.

## Ahora — imagen y difusión

Que quien llegue al repositorio entienda en 10 segundos qué es, lo vea funcionar y pueda probarlo.

- [x] Mascota («Sabu», un sabueso con collar y placa-escudo) y banner del README.
- [x] Demostraciones animadas: la CLI de punta a punta y un recorrido por la web.
- [x] README profesional (qué es, por qué, pruébalo en un minuto, cómo trabaja, vistazo, validación, cuándo usar otra herramienta) y la referencia completa en `docs/MANUAL.md`.
- [ ] Publicar en PyPI (`pipx install sabueso-framework`): configurar *trusted publishing* en pypi.org.
- [ ] Imagen de vista previa social del repositorio (Settings → Social preview) con el banner.
- [ ] `CONTRIBUTING.md`, `SECURITY.md` y plantillas de *issues* (fallo, artefacto nuevo, falso positivo).
- [ ] Web de documentación (GitHub Pages) con la guía del perito paso a paso.
- [ ] Publicar la validación: un artículo con las cifras de `docs/VALIDACION.md`.

## Siguiente — v0.5 «Perito»: lo que la validación con casos reales dejó pendiente

- [ ] Registros `.evt` de Windows XP: ya se extraen, falta el analizador.
- [ ] Configuración de clientes de correo, noticias e IRC (Outlook Express, Forté Agent, mIRC).
- [ ] Validar con una imagen moderna (Windows 10/11) con preguntas oficiales: SRUM, Amcache, EVTX, navegadores.
- [ ] Rendimiento de Sigma con SigmaHQ (~150 eventos/s de creación de procesos): índice de cadenas común a todas
      las reglas.
- [x] Portada del informe pericial con solicitante, juzgado y número de procedimiento.
- [ ] Lista de comprobación del perito antes de entregar (evidencias verificadas, hallazgos revisados, conclusiones, firma).
- [ ] Anexo de hashes de todos los archivos citados en los hallazgos.

## Después

- Partir `cli.py` (~1.100 líneas) y `web/__init__.py` (~880) en paquetes; tipado con mypy en `core/` y `parsers/`.
- Módulos de terceros por *entry points* (plugins).
- Varios analistas a la vez: usuarios, roles y bloqueo entre analistas en la web.
- Linux y macOS como sistemas analizados (solo cuando Windows esté redondo).

## Cómo comprobar un cambio

```bash
python -m pytest -q                       # tests (más de 470)
ruff check sabueso tests scripts          # estilo
python scripts/validar_evtx.py RUTA/EVTX-ATTACK-SAMPLES --sigma RUTA/sigma   # detección con ataques reales
```
