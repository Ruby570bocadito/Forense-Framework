# Forense-Framework

**Framework de análisis forense digital centrado en Windows**, con gestión de casos, cadena de custodia verificable,
módulos de análisis de artefactos, superlínea temporal, interfaz web y CLI, e informes periciales en **español e inglés**.

> 🇬🇧 English version: [README.en.md](README.en.md)

```
forense demo ./laboratorio          # crea un escenario de intrusión ficticio y lo analiza
forense web -w ./laboratorio        # ábrelo en http://127.0.0.1:8765
```

---

## Índice

1. [Principios](#principios)
2. [Instalación](#instalación)
3. [Inicio rápido](#inicio-rápido)
4. [Flujo de trabajo con la CLI](#flujo-de-trabajo-con-la-cli)
5. [Interfaz web](#interfaz-web)
6. [Módulos de análisis](#módulos-de-análisis)
7. [Qué evidencias analizar](#qué-evidencias-analizar)
8. [Integridad y cadena de custodia](#integridad-y-cadena-de-custodia)
9. [Arquitectura y cómo crear un módulo](#arquitectura-y-cómo-crear-un-módulo)
10. [Limitaciones conocidas](#limitaciones-conocidas)
11. [Hoja de ruta](#hoja-de-ruta)
12. [Desarrollo](#desarrollo)

## Principios

| Principio | Cómo se cumple |
|---|---|
| **La evidencia nunca se modifica** | Todo se abre en solo lectura. Con `--copiar` se trabaja sobre una copia verificada por hash y marcada como de solo lectura. Las bases de datos SQLite (navegadores) se copian a una carpeta temporal antes de abrirlas. |
| **Identificación por hash** | Cada evidencia se registra con MD5, SHA-1 y SHA-256. Para un directorio se calcula el hash de un manifiesto ordenado de todos sus archivos, así que cualquier alta, baja, cambio de nombre o modificación lo altera. |
| **Cadena de custodia a prueba de manipulación** | Cada acción (alta de evidencia, verificación, análisis, exportación, informe, borrado) queda en un registro encadenado por SHA-256. Si se altera una entrada, se rompe la cadena. |
| **Resultados verificables** | Cada análisis guarda el SHA-256 de todos sus resultados. `forense verificar` recalcula hashes de evidencias, custodia y resultados. |
| **Reproducibilidad** | Se registra qué módulo se ejecutó, con qué opciones, sobre qué evidencia, quién lo hizo y cuándo (UTC). |
| **Hallazgos ≠ conclusiones** | Las detecciones son indicios con la regla que los disparó; el analista debe confirmarlos con los registros originales. |

Referencias metodológicas: RFC 3227, ISO/IEC 27037, ISO/IEC 27042 y UNE 71506.

## Instalación

Requisitos: **Python 3.10 o superior** (Windows, Linux o macOS). Dependencias: `evtx` (parser de EVTX en Rust con
binarios precompilados) y `Flask`.

**Windows (PowerShell):**

```powershell
git clone https://github.com/Ruby570bocadito/Forense-Framework.git
cd Forense-Framework
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
forense --version
```

**Linux / macOS:**

```bash
git clone https://github.com/Ruby570bocadito/Forense-Framework.git
cd Forense-Framework
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

El idioma se elige con `-L es|en` (en cualquier posición), con la variable `FORENSE_LANG` o, si no hay ninguna de las
dos, según la configuración regional del sistema.

## Inicio rápido

```bash
forense demo ./laboratorio -a "Tu nombre"
```

Genera un escenario **ficticio** (equipo `WS-CONTAB01` comprometido): colmenas del registro, `$MFT`, accesos directos,
papelera, historial de Chrome/Firefox, una imagen raw para carving, una lista de hashes maliciosos y una lista de IOC.
Después crea el caso `laboratorio/case_demo`, registra las evidencias, lanza el triaje y genera unos 27 hallazgos:
un depurador IFEO en `sethc.exe`, timestomping, persistencia en `Run`, un servicio en `C:\Windows\Temp`, la descarga
de un `.pdf.exe`, el uso de un USB, borrado de archivos…

```bash
forense -c laboratorio/case_demo hallazgos
forense -c laboratorio/case_demo cronologia --desde 2026-09-14T02:00 --hasta 2026-09-14T05:00
forense -c laboratorio/case_demo informe
forense web -w laboratorio
```

## Flujo de trabajo con la CLI

Todas las órdenes tienen nombre en inglés y alias en español.

| Español | English | Para qué sirve |
|---|---|---|
| `forense nuevo DIR -n NOMBRE -i INVESTIGADOR [-r REFERENCIA] [-o ORGANIZACIÓN]` | `new` | Crear un caso |
| `forense -c CASO info` | `info` | Resumen del caso |
| `forense -c CASO evidencia agregar RUTA [--copiar] [-d DESCRIPCIÓN]` | `evidence add [--copy]` | Registrar una evidencia (calcula los hashes) |
| `forense -c CASO evidencia listar` / `verificar [ID]` | `evidence list` / `verify` | Listar evidencias o verificar su integridad |
| `forense modulos` | `modules` | Módulos disponibles y sus opciones |
| `forense -c CASO triaje EV-001` | `triage` | Ejecutar todos los módulos que encuentren artefactos |
| `forense -c CASO analizar MÓDULO EV-001 [-o clave=valor]` | `analyze` | Ejecutar un módulo concreto (`todas` = todas las evidencias) |
| `forense -c CASO analisis` / `mostrar N [--artefacto X]` | `analyses` / `show` | Ver los análisis y sus registros |
| `forense -c CASO hallazgos [--severidad high]` | `findings` | Hallazgos ordenados por severidad |
| `forense -c CASO cronologia [--desde] [--hasta] [--buscar] [--fuente]` | `timeline` | Superlínea temporal |
| `forense -c CASO exportar {analysis N,timeline,findings,custody} -o ARCHIVO` | `export` | CSV (compatible con Excel) o JSON |
| `forense -c CASO custodia [--verificar]` | `custody` | Cadena de custodia |
| `forense -c CASO verificar` | `verify` | Verificación completa (sale con código 2 si algo falla) |
| `forense -c CASO informe [--verificar] [-L en]` | `report` | Informe HTML autocontenido |
| `forense web [-w ESPACIO] [--puerto 8765] [--clave X]` | `web` | Interfaz web |

Opciones comunes: `-c/--caso` (o la variable `FORENSE_CASE`), `-a/--analista` (quién figura en la custodia) y
`-L/--idioma`.

Ejemplo completo (PowerShell):

```powershell
forense nuevo ./2026-017 -n "Intrusión servidor de ficheros" -i "R. García" -r "EXP-2026/017"
forense -c ./2026-017 evidencia agregar D:\KAPE\FS01 --copiar -d "Triaje KAPE de FS01"
forense -c ./2026-017 triaje EV-001
forense -c ./2026-017 analizar hashset EV-001 -o hash_list=C:\intel\malware_sha256.txt
forense -c ./2026-017 analizar ioc EV-001 -o watchlist=C:\intel\iocs.txt
forense -c ./2026-017 hallazgos --severidad medium
forense -c ./2026-017 informe --verificar
```

## Interfaz web

```bash
forense web -w ./casos            # http://127.0.0.1:8765
```

- **Espacio de trabajo**: lista de casos y alta de casos nuevos.
- **Resumen**: indicadores, hallazgos relevantes, evidencias y triaje con un clic.
- **Evidencias**: alta por ruta (el hash se calcula en segundo plano), hashes y verificación de integridad.
- **Análisis**: formulario por módulo con sus opciones, triaje automático, resultados paginados con búsqueda por
  artefacto y exportación a CSV.
- **Hallazgos**, **Línea temporal** (filtros por fecha, texto, origen y severidad), **Cadena de custodia** e **Informes**
  (en el idioma que elijas).
- Selector **ES/EN** y campo **Analista**: el nombre se registra en cada acción de la custodia.

Seguridad: escucha solo en `127.0.0.1` por defecto, todos los formularios llevan token CSRF, envía cabeceras de
seguridad (CSP, `X-Frame-Options`) y admite contraseña con `--clave` (HTTP Basic). Si la expones en red, ponla detrás de
HTTPS.

## Módulos de análisis

| Módulo | Artefactos | Qué detecta |
|---|---|---|
| `evtx` | `*.evtx` (Security, System, PowerShell, Sysmon, Defender, RDP, TaskScheduler, WMI, BITS) | Fuerza bruta y **acceso tras fuerza bruta**, borrado de logs (1102/104), altas de usuario y en grupos privilegiados, servicios (7045/4697) y tareas creadas, comandos sospechosos (4688/Sysmon 1), PowerShell malicioso (4104), detecciones y desactivación de Defender, persistencia WMI, RDP desde IP pública |
| `registry` | SYSTEM, SOFTWARE, SAM, NTUSER.DAT, Amcache.hve | Equipo, zona horaria, red, **USB** (primera/última conexión), servicios, **ShimCache**, **BAM**, SO e instalación, programas instalados, perfiles de red, **Run/RunOnce**, Winlogon, **IFEO**, AppInit_DLLs, cuentas SAM, **UserAssist**, RecentDocs, RunMRU, TypedPaths, búsquedas, destinos RDP, Amcache con SHA-1 |
| `lnk` | `*.lnk`, `*.customDestinations-ms` | Archivos abiertos, rutas de red, **unidades extraíbles** (serie y etiqueta del volumen), equipo y **MAC** de origen, persistencia en la carpeta Inicio, argumentos sospechosos |
| `recyclebin` | `$Recycle.Bin\<SID>\$I*` | Ruta original, tamaño, fecha de borrado, usuario y si el contenido (`$R`) es recuperable |
| `browsers` | Chrome, Edge, Brave, Opera (`History`), Firefox (`places.sqlite`) | Historial, descargas, **ejecutables descargados**, servicios de intercambio y paste |
| `mft` | `$MFT` | Línea temporal $SI/$FN, entradas borradas, rutas completas, **Zone.Identifier** (URL de descarga), **timestomping** |
| `inventory` | Cualquier carpeta | Metadatos, hashes, tipo real por firma, **archivos camuflados**, línea temporal y *bodyfile* compatible con Sleuth Kit (`mactime`) |
| `ioc` | Cualquier archivo | Cadenas ASCII/UTF-16, URL, IP, correos, claves de registro y lista de vigilancia (`-o watchlist=`) |
| `hashset` | Cualquier carpeta | Coincidencias con listas de hashes MD5/SHA-1/SHA-256 (`-o hash_list=`) |
| `carving` | Imagen raw / espacio no asignado | Recupera JPEG, PNG, GIF, PDF y ZIP validando su estructura interna |

Los seis primeros y `inventory` se ejecutan en el **triaje** si encuentran artefactos. Severidades: crítico, alto,
medio, bajo e informativo.

## Qué evidencias analizar

El framework trabaja sobre **archivos y carpetas**:

- **Recolecciones de triaje** con [KAPE](https://www.kroll.com/kape) (target `KapeTriage`), Velociraptor o CyLR: se
  registra la carpeta completa.
- **Imágenes montadas en solo lectura** (Arsenal Image Mounter, `ewfmount`, FTK Imager → *Mount image*): se registra
  la unidad o carpeta montada.
- **Artefactos sueltos**: un `.evtx`, una colmena, un `$MFT` exportado con FTK Imager, una imagen `dd` para carving…

Al ser una recolección completa, la evidencia de directorio admite todos los módulos a la vez mediante `triaje`.

## Integridad y cadena de custodia

```
custody(seq, timestamp, action, actor, details, prev_hash, hash)
hash = SHA-256(JSON canónico de {seq, timestamp, action, actor, details, prev_hash})
```

- `forense -c CASO custodia --verificar` detecta entradas modificadas, borradas o reordenadas.
- El **hash de cabecera** (el de la última entrada) aparece en el informe y en `custodia`. Anótalo fuera del caso (en el
  acta, un correo o el expediente) para anclar la cadena: así ni siquiera quien reescriba la base de datos entera podrá
  ocultar la manipulación.
- Cada informe y cada exportación registran su propio SHA-256 en la cadena.

Estructura de un caso:

```
caso/
├── forense.db     SQLite (WAL): caso, evidencias, custodia, resultados, eventos y hallazgos
├── evidence/      copias de trabajo verificadas (--copiar), en solo lectura
├── analyses/      archivos generados (carving, bodyfile, strings…)
├── reports/       informes HTML
└── exports/       exportaciones CSV/JSON
```

## Arquitectura y cómo crear un módulo

```
forense/
├── core/        caso (SQLite), custodia, hashing, firmas, heurísticas, exportaciones
├── parsers/     parsers autónomos: regf, lnk, $I, $MFT, ShimCache, EVTX
├── modules/     windows/ (evtx, registry, lnk, recyclebin, browsers, mft) y generic/ (inventory, ioc, hashset, carving)
├── report/      informe HTML (Jinja2)
├── web/         interfaz Flask (plantillas, estáticos, tareas en segundo plano)
├── demo/        escenario de demostración y generadores de artefactos sintéticos
├── locales/     es.json / en.json
└── cli.py
```

Los datos se guardan con códigos neutros (`evtx.log_cleared`, `usb_device`, `program_executed`…) y se traducen al
mostrarlos, por lo que el mismo caso se puede revisar o informar en cualquiera de los dos idiomas.

Un módulo nuevo:

```python
from forense.core.utils import find_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register


@register
class PrefetchModule(Module):
    name = "prefetch"
    category = "windows"
    triage = True
    options = (Option("max_files", 1000, "int"),)

    def discover(self, target):
        return find_files(target, lambda p: p.suffix.lower() == ".pf")

    def analyze(self, ctx: AnalysisContext) -> None:
        for path in self.discover(ctx.target)[: ctx.options["max_files"]]:
            rel = relative_name(path, ctx.target)
            ...
            ctx.record("prefetch", {"file": rel, "executable": exe, "run_count": runs})
            ctx.event(last_run, "program_executed", f"Prefetch: {exe}", rel)
            if sospechoso:
                ctx.finding("prefetch.suspicious", "high", last_run, executable=exe)
        ctx.summary["files"] = n
```

Después se importa en `forense/modules/__init__.py` y se añaden sus textos a `locales/es.json` y `locales/en.json`
(`module.prefetch.title`, `.description`, `.opt.*`, `finding.prefetch.suspicious.title/.description`,
`artifact.prefetch`). Los tests de `tests/test_i18n.py` avisan si falta alguna traducción.

## Limitaciones conocidas

- **Colmenas con cambios pendientes**: los registros de transacciones (`.LOG1`/`.LOG2`) no se aplican. Se avisa con un
  hallazgo para que sepas que pueden faltar datos recientes.
- **Imágenes de disco**: no lee E01 ni sistemas de archivos NTFS/ext4 dentro de una imagen. Hay que montarla o exportar
  los artefactos; con imágenes raw solo funciona el carving.
- **$MFT**: no combina los atributos de los registros de extensión (`$ATTRIBUTE_LIST`) de archivos muy fragmentados.
- **Carving**: solo recupera archivos contiguos (no fragmentados). Un PDF termina en su primer `%%EOF`.
- **Fechas en hora local**: las de los perfiles de red (`NetworkList`) se muestran como hora local del sistema, sin
  convertir.
- **Heurísticas**: las reglas de detección son indicios para priorizar el trabajo, no veredictos.
- La interfaz web usa el servidor integrado de Flask, pensado para uso local por un analista o un equipo pequeño.

## Hoja de ruta

- Prefetch (incluida la descompresión Xpress Huffman de Windows 10/11), SRUM, ShellBags y Jump Lists automáticas
- Imágenes E01/VMDK y sistemas de archivos NTFS sin montar
- Aplicación de los logs de transacciones del registro y recuperación de claves borradas
- Reglas YARA y Sigma sobre EVTX
- Memoria RAM (integración con Volatility 3)
- Firma digital de informes y exportación a PDF
- Linux y macOS como sistemas analizados

## Desarrollo

```bash
pip install -e ".[dev]"
python -m pytest -q        # tests (EVTX reales en tests/data; el resto se genera de forma sintética)
ruff check forense tests   # estilo
```

La CI ejecuta los tests en Linux y Windows con Python 3.10 y 3.12, además de una prueba completa con el escenario de
demostración.
