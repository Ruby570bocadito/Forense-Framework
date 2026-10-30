# Qué sigue en Sabueso

Una página, en orden. Lo terminado se borra de aquí (queda en el historial de git y en el CHANGELOG).
El plan largo original, por ejes y versiones, está archivado en [docs/archivo/ROADMAP.md](docs/archivo/ROADMAP.md).

**Rumbo:** ser la herramienta forense de Windows para **peritos hispanohablantes**: hallazgos que se pueden
defender ante un juez, custodia verificable e informe pericial en español. Cada mejora se valida con casos reales
([docs/VALIDACION.md](docs/VALIDACION.md)) antes de darla por buena.

## Ahora — difusión de la v0.4.1 (publicada el 2026-10-30)

- [ ] Publicar en PyPI (`pipx install sabueso-framework`).

## Siguiente — v0.5 «Perito»: lo que la validación con casos reales dejó pendiente

- [ ] Registros `.evt` de Windows XP: ya se extraen, falta el analizador.
- [ ] Configuración de clientes de correo, noticias e IRC (Outlook Express, Forté Agent, mIRC).
- [ ] Validar con una imagen moderna (Windows 10/11) con preguntas oficiales: SRUM, Amcache, EVTX, navegadores.
- [ ] Rendimiento de Sigma con SigmaHQ (~150 eventos/s de creación de procesos): índice de cadenas común a todas
      las reglas.
- [ ] Plantilla de informe pericial: campos de solicitante, juzgado y número de procedimiento en la portada.

## Después

- Partir `cli.py` (~1.100 líneas) y `web/__init__.py` (~880) en paquetes; tipado con mypy en `core/` y `parsers/`.
- Módulos de terceros por *entry points* (plugins).
- Varios analistas a la vez: usuarios, roles y bloqueo entre analistas en la web.
- Linux y macOS como sistemas analizados (solo cuando Windows esté redondo).

## Cómo comprobar un cambio

```bash
python -m pytest -q                       # tests (458 en la última ejecución)
ruff check sabueso tests scripts          # estilo
python scripts/validar_evtx.py RUTA/EVTX-ATTACK-SAMPLES --sigma RUTA/sigma   # detección con ataques reales
```
