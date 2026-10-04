# Forense-Framework

**Framework de análisis forense digital centrado en Windows**: gestión de casos, cadena de custodia verificable,
imágenes de disco (E01, raw, VHD/VHDX, VMDK, QCOW2) con instantáneas VSS y BitLocker, recolección en vivo, más de 20
módulos de artefactos de Windows y memoria RAM, reglas Sigma y YARA, superlínea temporal, vista de ejecución de
programas, **mapa MITRE ATT&CK con relato del incidente**, indicadores en **STIX 2.1**, análisis **automatizado**
(de la evidencia al informe con una orden, o soltando la evidencia en una carpeta), revisión del analista, interfaz
web con panel gráfico y CLI, e informes periciales en HTML y **PDF** en **español e inglés**.

> 🇬🇧 English version: [README.en.md](README.en.md)

```
forense demo ./laboratorio          # crea un escenario de intrusión ficticio y lo analiza
forense web -w ./laboratorio        # ábrelo en http://127.0.0.1:8765
```

---

## Índice

1. [Principios](#principios)
2. [Instalación](#instalación)
3. [Configuración](#configuración)
4. [Inicio rápido](#inicio-rápido)
5. [Flujo de trabajo con la CLI](#flujo-de-trabajo-con-la-cli)
6. [Automatización](#automatización)
7. [Imágenes de disco y recolección en vivo](#imágenes-de-disco-y-recolección-en-vivo)
8. [Memoria RAM](#memoria-ram)
9. [Ejecución de programas](#ejecución-de-programas)
10. [Revisión del analista](#revisión-del-analista)
11. [MITRE ATT&CK, relato e indicadores](#mitre-attck-relato-e-indicadores)
12. [Informes](#informes)
13. [Interfaz web](#interfaz-web)
14. [Módulos de análisis](#módulos-de-análisis)
15. [Reglas Sigma y YARA](#reglas-sigma-y-yara)
16. [Integridad y cadena de custodia](#integridad-y-cadena-de-custodia)
17. [Arquitectura y cómo crear un módulo](#arquitectura-y-cómo-crear-un-módulo)
18. [Limitaciones conocidas](#limitaciones-conocidas)
19. [Hoja de ruta](#hoja-de-ruta)
20. [Desarrollo](#desarrollo)
21. [Licencia](#licencia)

## Principios

| Principio | Cómo se cumple |
|---|---|
| **La evidencia nunca se modifica** | Todo se abre en solo lectura. Con `--copiar` se trabaja sobre una copia verificada por hash y marcada como de solo lectura. Las imágenes de disco se leen sin montarlas. Las bases de datos SQLite (navegadores) se copian a una carpeta temporal antes de abrirlas. |
| **Identificación por hash** | Cada evidencia se registra con MD5, SHA-1 y SHA-256. Para un directorio se calcula el hash de un manifiesto ordenado de todos sus archivos, así que cualquier alta, baja, cambio de nombre o modificación lo altera. |
| **Cadena de custodia a prueba de manipulación** | Cada acción (alta de evidencia, evidencia derivada, verificación, análisis, revisión, exportación, informe, borrado) queda en un registro encadenado por SHA-256. Si se altera una entrada, se rompe la cadena. |
| **Resultados verificables** | Cada análisis guarda el SHA-256 de todos sus resultados. `forense verificar` recalcula hashes de evidencias, custodia y resultados. |
| **Trazabilidad de lo derivado** | Lo que se extrae de una imagen se registra como evidencia derivada, con su propio hash y enlazada a la imagen y al análisis que la produjo. |
| **Reproducibilidad** | Se registra qué módulo se ejecutó, con qué opciones, sobre qué evidencia, quién lo hizo y cuándo (UTC). Las salidas de herramientas externas (Volatility) se guardan íntegras. |
| **Hallazgos ≠ conclusiones** | Las detecciones son indicios con la regla que los disparó. El analista los confirma o descarta, y las conclusiones del informe las redacta él. |

Referencias metodológicas: RFC 3227, ISO/IEC 27037, ISO/IEC 27042 y UNE 71506.

## Instalación

Elija la opción que mejor le encaje. En todas, `forense doctor` comprueba después que todo funciona.

**1. Instalador para Windows** (sin permisos de administrador). Crea un entorno aislado en `%LOCALAPPDATA%\Forense`,
añade `forense` al PATH, crea la carpeta de casos `Documentos\Forense`, la configuración y un acceso directo en el
menú Inicio que abre la interfaz web:

```powershell
irm https://raw.githubusercontent.com/Ruby570bocadito/Forense-Framework/main/install/install.ps1 | iex
# o desde una copia del repositorio:
powershell -ExecutionPolicy Bypass -File install\install.ps1 -WithMemory     # -WithMemory añade Volatility 3
```

Opciones: `-Workspace D:\Casos`, `-InstallPython` (instala Python 3.12 con winget si falta), `-NoShortcut`,
`-Uninstall` (no toca los casos).

**2. Instalador para Linux y macOS** (en `~/.local/share/forense`, enlaza `~/.local/bin/forense`):

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/Forense-Framework/main/install/install.sh | sh
sh install/install.sh --with-memory --workspace ~/Casos     # desde una copia del repositorio
```

**3. Ejecutable para Windows sin Python**: descargue `forense-<versión>-windows-x64.zip` de
[Releases](https://github.com/Ruby570bocadito/Forense-Framework/releases), descomprímalo y ejecute
`forense\forense.exe`. Útil en equipos de laboratorio aislados (se puede llevar en un USB). Para memoria RAM necesita
además Python con `volatility3` o la ruta de `vol.exe` (`-o vol_path=`).

**4. Docker** (interfaz web, CLI y PDF con Chromium incluido):

```bash
docker compose up -d                       # http://127.0.0.1:8765, contraseña en FORENSE_WEB_PASSWORD
docker run --rm -v "$PWD/casos:/cases" -v "/ruta/evidencias:/evidence:ro" ghcr.io/ruby570bocadito/forense-framework \
       auto /evidence/portatil.E01 --new /cases/portatil
```

Las evidencias se montan en solo lectura (`:ro`). `docker build --build-arg WITH_MEMORY=1 .` incluye Volatility 3.

**5. Manual con pip** (Python 3.10 o superior):

```bash
git clone https://github.com/Ruby570bocadito/Forense-Framework.git
cd Forense-Framework
python -m venv .venv && . .venv/bin/activate      # Windows: py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[memory]"                         # sin [memory] no se instala Volatility 3
forense doctor
```

Todas las dependencias tienen binarios precompilados para Windows, Linux y macOS: `evtx` (EVTX), `Flask` (web e
informes), `PyYAML` (Sigma, configuración), `olefile` (Jump Lists), `libscca-python` (Prefetch), `libesedb-python`
(SRUM), `libewf-python` (E01), `libvhdi-python`, `libvmdk-python` y `libqcow-python` (discos virtuales),
`libvshadow-python` (VSS), `libbde-python` (BitLocker), `pytsk3` (NTFS, The Sleuth Kit) y `yara-x` (YARA). Los PDF
usan Microsoft Edge (presente en todo Windows 10/11), Chrome o Chromium; otro navegador se indica con
`FORENSE_BROWSER`.

`forense doctor` (`diagnostico`) lista cada componente con su versión y para qué sirve, avisa de lo que falta
(Volatility, navegador para PDF, listas de inteligencia que no existen, carpeta de casos sin permiso de escritura…) y
termina con error si falta algo imprescindible; `--json` da el resultado para scripts.

El idioma se elige con `-L es|en` (en cualquier posición), con la variable `FORENSE_LANG`, en la configuración o, si no
hay ninguna, según la configuración regional del sistema.

## Configuración

`forense config init` crea un archivo comentado (`%APPDATA%\Forense\config.yaml` en Windows,
`~/.config/forense/config.yaml` en Linux/macOS, o el de `FORENSE_CONFIG` / `--config`). Las opciones de la línea de
órdenes siempre tienen prioridad.

```yaml
analyst: "R. García"            # nombre por defecto en la cadena de custodia
language: es
organization: "CERT Ejemplo"
workspace: 'D:\Casos'           # carpeta de casos de la web, forense auto y forense watch
intel:
  hash_lists: ['D:\intel\malware_sha256.txt']
  watchlists: ['D:\intel\iocs.txt']
  yara_rules: ['D:\intel\yara']
  sigma_rules: 'D:\intel\sigma'  # forense sigma download D:\intel\sigma
  sigma_min_level: medium
image: {vss: true}               # extraer también de las instantáneas de volumen
memory: {symbols: 'D:\symbols', offline: false}
report: {languages: [es, en], pdf: true}
automation: {playbook: full}
web: {host: 127.0.0.1, port: 8765}
```

`forense config show` muestra la configuración efectiva y `forense config path` dónde está.

## Inicio rápido

```bash
forense demo ./laboratorio -a "Tu nombre"
```

Genera un escenario **ficticio**: el equipo `WS-CONTAB01` comprometido. Incluye una recolección de triaje (colmenas,
`$MFT`, `$UsnJrnl`, Prefetch, ShellBags, tareas programadas, repositorio WMI, historial de PowerShell, línea de tiempo
de Windows, `setupapi`, accesos directos, papelera, historial de Chrome/Firefox…), una imagen raw para carving, la
memoria RAM del equipo (salidas de Volatility 3), una lista de hashes maliciosos, una lista de IOC y una regla YARA.
Después crea el caso `laboratorio/case_demo`, registra las tres evidencias, lanza el triaje y los módulos de
inteligencia, y genera más de 50 hallazgos. Entre ellos, un depurador IFEO en `sethc.exe`, timestomping, persistencia
en `Run`, en una tarea oculta y en una suscripción WMI, un servicio en `C:\Windows\Temp`, ejecución de mimikatz y
rclone (y su borrado según el diario USN), un `svchost.exe` falso con conexión al exterior, un proceso oculto, código
inyectado en `explorer.exe`, un comando codificado en el portapapeles, un USB, archivos borrados y, recuperados
del espacio libre del registro, el servicio de PsExec y un valor `Run` que el atacante eliminó.

```bash
forense -c laboratorio/case_demo hallazgos
forense -c laboratorio/case_demo cronologia --desde 2026-09-14T02:00 --hasta 2026-09-14T05:00
forense -c laboratorio/case_demo mitre --resumen        # tácticas ATT&CK y borrador del relato
forense -c laboratorio/case_demo informe --pdf
forense web -w laboratorio --abrir
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
| `forense -c CASO triaje EV-001` | `triage` | Ejecutar todos los módulos que encuentren artefactos (si es una imagen, primero extrae) |
| `forense -c CASO imagen EV-001 [--verificar] [--vss] [--bitlocker-recuperacion -] [-p PATRÓN] [--todo] [--triaje]` | `image` | Extraer los artefactos de una imagen como evidencia derivada |
| `forense recolectar DESTINO [--origen \\.\C:] [--volatil] [--agregar-al-caso]` | `collect` | Recolección en vivo en Windows |
| `forense -c CASO analizar MÓDULO EV-001 [-o clave=valor]` | `analyze` | Ejecutar un módulo concreto (`todas` = todas las evidencias) |
| `forense -c CASO analisis` / `mostrar N [--artefacto X]` | `analyses` / `show` | Ver los análisis y sus registros |
| `forense -c CASO hallazgos [--severidad high] [--estado confirmado]` | `findings` | Hallazgos ordenados por severidad, con su estado de revisión |
| `forense -c CASO revisar N confirmado\|falso_positivo\|pendiente [-n NOTA]` | `review` | Revisar un hallazgo |
| `forense -c CASO destacar N [-n NOTA] [--quitar]` | `bookmark` | Marcar un evento de la línea temporal |
| `forense -c CASO conclusiones [--texto T \| --archivo F]` | `conclusions` | Ver o redactar las conclusiones (versionadas) |
| `forense -c CASO cronologia [--desde] [--hasta] [--buscar] [--fuente] [--destacados]` | `timeline` | Superlínea temporal |
| `forense -c CASO ejecucion [--buscar X] [--sospechosos]` | `execution` | Programas ejecutados según todas las fuentes |
| `forense -c CASO exportar {analysis N,timeline,findings,execution,stix,custody} -o ARCHIVO` | `export` | CSV (compatible con Excel), JSON o STIX 2.1 |
| `forense -c CASO mitre [--resumen]` | `attack` | Técnicas MITRE ATT&CK observadas o borrador del relato del incidente |
| `forense -c CASO custodia [--verificar]` | `custody` | Cadena de custodia |
| `forense -c CASO verificar` | `verify` | Verificación completa (sale con código 2 si algo falla) |
| `forense -c CASO informe [--verificar] [--pdf] [-L en]` | `report` | Informe HTML autocontenido (y PDF) |
| `forense auto EVIDENCIA… [--nuevo DIR] [-p PLAYBOOK]` | `auto` | De la evidencia al informe con una orden |
| `forense vigilar CARPETA [-w ESPACIO] [--una-vez]` | `watch` | Procesar automáticamente lo que se deje en una carpeta |
| `forense config [show\|init\|path]` | `config` | Configuración |
| `forense doctor` | `diagnostico` | Comprobar la instalación |
| `forense sigma check RUTA` / `sigma download DIR` | `sigma` | Validar reglas Sigma o descargar las de SigmaHQ |
| `forense web [-w ESPACIO] [--puerto 8765] [--clave X] [--abrir]` | `web` | Interfaz web |

Opciones comunes: `-c/--caso` (o la variable `FORENSE_CASE`), `-a/--analista` (quién figura en la custodia; por
defecto el de la configuración), `-L/--idioma` y `--config ARCHIVO`. En `cronologia`, `--hasta 2026-09-14` incluye el
día completo.

Ejemplo completo (PowerShell):

```powershell
forense nuevo ./2026-017 -n "Intrusión servidor de ficheros" -i "R. García" -r "EXP-2026/017"
forense -c ./2026-017 evidencia agregar E:\adquisiciones\FS01.E01 -d "Disco de FS01 (FTK Imager)"
forense -c ./2026-017 imagen EV-001 --verificar --triaje
forense -c ./2026-017 evidencia agregar E:\adquisiciones\FS01.mem -d "Memoria RAM de FS01"
forense -c ./2026-017 analizar memory EV-003
forense -c ./2026-017 analizar hashset EV-002 -o hash_list=C:\intel\malware_sha256.txt
forense -c ./2026-017 analizar yara EV-002 -o rules=C:\intel\yara
forense -c ./2026-017 hallazgos --severidad medium
forense -c ./2026-017 revisar 12 confirmado -n "Coincide con el 4688 del controlador de dominio"
forense -c ./2026-017 conclusiones --archivo conclusiones.md
forense -c ./2026-017 informe --verificar
```

## Automatización

`forense auto` registra la evidencia (en un caso existente con `-c`, en uno nuevo con `--nuevo`, o en la carpeta de
casos de la configuración), ejecuta un **playbook** y deja el informe y las exportaciones listos:

```powershell
forense auto E:\adquisiciones\PC-042.E01 --nuevo D:\Casos\PC-042 -i "R. García"
forense -c D:\Casos\2026-017 auto E:\adquisiciones\FS01.mem          # añadir al caso y analizar
```

| Playbook | Pasos |
|---|---|
| `triage` | triaje (las imágenes se extraen primero; la memoria va a Volatility) → informe |
| `quick` | registro, Prefetch, EVTX, tareas, PowerShell y `$MFT` → informe |
| `full` (por defecto) | triaje → inteligencia de la configuración (hashes, IOC, YARA, Sigma) → informe → exportaciones (hallazgos, línea temporal, ejecución y STIX) |

Un playbook propio es un YAML con `steps:`; cada paso es `triage`, `memory`, `intel`, `modules` (con opciones por
módulo), `report` (idiomas, PDF) o `export`:

```yaml
steps:
  - triage
  - modules: {evtx: {sigma_rules: 'D:\intel\sigma', sigma_min_level: high}}
  - intel
  - report: {languages: [es, en], pdf: true}
  - export: [findings, stix]
```

**Carpeta vigilada**: `forense vigilar D:\Entrada -w D:\Casos` crea un caso por cada archivo o carpeta que se deje en
`D:\Entrada` y lo procesa con el playbook. Espera a que la copia termine (tamaño y fecha estables entre dos
comprobaciones), ignora `.part`/`.tmp`, recuerda lo procesado en `D:\Casos\.forense-watch.json` y un elemento que
falle no detiene a los demás. `--una-vez` procesa lo que haya y termina (útil en una tarea programada).

En la web, el botón **Automático** de cada evidencia ejecuta el playbook en segundo plano.

## Imágenes de disco y recolección en vivo

### Imágenes

Formatos: **E01/Ex01** (EnCase, FTK Imager, ewfacquire), **raw/dd**, **raw dividido** (`.001`, `.002`…), **VHD y
VHDX** fijos, dinámicos y diferenciales (el disco padre se busca en la misma carpeta), **VMDK** y **QCOW2**. Se leen
las particiones MBR/GPT y los sistemas de archivos con The Sleuth Kit, **sin montar nada**, así que se obtienen
también los archivos bloqueados (`$MFT`, colmenas, SRUM, EVTX) y los flujos alternativos como `$UsnJrnl:$J`.

```bash
forense -c CASO evidencia agregar portatil.E01
forense -c CASO imagen EV-001 --verificar      # comprueba los MD5/SHA-1 de adquisición y extrae
forense -c CASO triaje EV-002                  # EV-002 = artefactos extraídos (evidencia derivada)
```

- `--verificar` recalcula los hashes del medio y los compara con los guardados en el E01; si no coinciden se genera un
  hallazgo crítico.
- Por defecto se extrae el **perfil de triaje de Windows** (colmenas y sus `.LOG`, `$MFT`, EVTX, SRUM, tareas, Prefetch,
  Amcache, `setupapi`, NTUSER/UsrClass, Recent, Inicio, historial de PowerShell y navegadores, `$Recycle.Bin`,
  ejecutables en carpetas temporales). Con `-p "Users/*/Desktop/**"` se añaden patrones y con `--todo` se extrae todo.
- Cada volumen NTFS se guarda en `C/`, `D/`… conservando las fechas de modificación, y cada archivo extraído queda
  registrado con su ruta original, tamaño, MD5, SHA-256, fechas MACB y número de entrada MFT.
- `triaje` sobre una imagen hace la extracción automáticamente.
- **Instantáneas de volumen (VSS)**: se listan siempre (con su fecha de creación, también en la línea temporal). Con
  `--vss` se extrae además el perfil de triaje de cada instantánea, guardando solo los archivos que difieren del
  volumen actual (`C_vss1/`, `C_vss2/`…): versiones anteriores de colmenas, EVTX borrados o herramientas eliminadas.
- **BitLocker** (también BitLocker To Go): se descifra con la contraseña de recuperación de 48 dígitos
  (`--bitlocker-recuperacion -` la pide sin mostrarla), la contraseña o la clave de inicio `.BEK`. Las claves **no se
  guardan** en el caso: la custodia registra solo una huella SHA-256 que permite demostrar qué clave se usó. Un
  volumen que no se puede descifrar genera un hallazgo explicando qué falta.

### Recolección en vivo

En un Windows en funcionamiento (como administrador), `recolectar` lee el **volumen en bruto** (`\\.\C:`) con The
Sleuth Kit para copiar los artefactos bloqueados, sin depender de VSS ni de herramientas externas:

```powershell
forense recolectar E:\recoleccion_PC01 --volatil
forense -c E:\caso recolectar E:\recoleccion_PC01 --agregar-al-caso --copiar
```

- Copia el mismo perfil de triaje a `DESTINO\C\…` y escribe `manifest.csv` (ruta, tamaño, SHA-256, MD5, fechas y
  entrada MFT de cada archivo) y `collection.json` (equipo, usuario, herramienta, inicio y fin, SHA-256 del manifiesto
  y errores).
- `--volatil` guarda además procesos, servicios, conexiones (`netstat -anob`), configuración de red, caché DNS, ARP,
  rutas, sesiones, recursos compartidos, tareas programadas y `systeminfo`.
- `--origen` acepta otro volumen o una imagen. Para memoria RAM utiliza una herramienta específica (WinPmem, DumpIt,
  Magnet RAM Capture) **antes** de la recolección de disco, siguiendo el orden de volatilidad.

## Memoria RAM

El módulo `memory` analiza volcados de memoria de Windows con **Volatility 3**: `info`, `pslist`, `psscan`, `pstree`,
`cmdline`, `netscan`, `malfind` y `svcscan`.

```bash
pip install -e ".[memory]"
forense -c CASO evidencia agregar PC01.raw
forense -c CASO analizar memory EV-003                       # descarga los símbolos de Microsoft si hace falta
forense -c CASO analizar memory EV-003 -o symbols=D:\symbols -o offline=si -o plugins=pslist,psscan,netscan
```

- Volatility se ejecuta como proceso aparte y su salida JSON se guarda íntegra en la carpeta del análisis.
- Si ya ejecutaste Volatility (`vol -r json -f mem.raw windows.pslist > pslist.json`), registra la carpeta con los JSON
  y se **importarán** directamente (el nombre de archivo debe contener el del plugin).
- Detecta: **procesos ocultos** (en `psscan` y no en `pslist`), **padres anómalos** de procesos del sistema
  (`lsass.exe`, `services.exe`, `svchost.exe`…), instancias duplicadas, intérpretes lanzados por Office o por servicios
  (WMI, IIS, SQL Server), **suplantación** (`svchost.exe` fuera de `System32`) y nombres parecidos (`scvhost.exe`),
  herramientas ofensivas y de acceso remoto (también con el nombre truncado a 15 caracteres), líneas de comandos
  sospechosas, **conexiones externas** de intérpretes o procesos en ubicaciones sospechosas, **código inyectado**
  (`malfind`, más grave con cabecera PE y menos en procesos con JIT) y servicios sospechosos.

## Ejecución de programas

`forense -c CASO ejecucion` (y la página **Ejecución** de la web) reúne en una fila por programa todo lo que dicen
Prefetch, Amcache, ShimCache, BAM, UserAssist, SRUM, la línea de tiempo de Windows, los eventos 4688/Sysmon 1, RunMRU y
la memoria. Cada fuente escribe las rutas a su manera (`\VOLUME{…}\USERS\…`, `\Device\HarddiskVolume3\…`,
`%ProgramFiles%`, GUID de carpetas conocidas…); se normalizan para unirlas y obtener primera y última ejecución, número
de ejecuciones, usuarios, SHA-1, líneas de comandos y las fuentes que lo respaldan. Se marcan las herramientas
ofensivas o de acceso remoto, los nombres que imitan binarios del sistema (`scvhost.exe`) y las ubicaciones
sospechosas. ShimCache y Amcache prueban presencia, no ejecución, y así se trata. La tabla también se exporta
(`exportar execution`) y aparece en el informe.

## Revisión del analista

Los hallazgos son indicios. Cada uno se puede marcar como **confirmado**, **falso positivo** o **pendiente** con una
nota, y los eventos clave de la línea temporal se pueden **destacar**. Todo queda en un historial de solo inserción y en
la cadena de custodia, con quién y cuándo.

Las **conclusiones** del caso las redacta el analista (texto libre, versionado). El informe las incluye junto con los
hallazgos agrupados por estado de revisión y los eventos destacados.

## MITRE ATT&CK, relato e indicadores

Cada hallazgo se relaciona con técnicas de **MITRE ATT&CK** por su tipo (persistencia en `Run` → T1547.001, timestomping
→ T1070.006…), por las reglas que lo dispararon (PowerShell codificado, `ExecutionPolicy Bypass`…), por las
herramientas que nombra (mimikatz → T1003, rclone → T1567.002, AnyDesk → T1219) y por las etiquetas de las reglas
Sigma. Con eso:

- `forense mitre` y la página **ATT&CK** muestran la matriz de tácticas y técnicas observadas, con la primera vez que
  aparecen y los hallazgos que las respaldan (enlazados). Los hallazgos de gravedad baja o descartados no cuentan; los
  confirmados, siempre.
- **Relato del incidente**: la secuencia de fases en orden de la cadena de ataque y un **borrador** de narración
  (`mitre --resumen`, o el botón de la página ATT&CK que lo lleva a las conclusiones) que el analista revisa y completa.
- **Indicadores de compromiso**: `exportar stix` genera un paquete **STIX 2.1** con los hashes, IP, dominios, URL y
  correos de los hallazgos (listas de hashes, YARA, listas de vigilancia, conexiones de memoria, descargas) y de los
  programas marcados, más las técnicas ATT&CK, listo para MISP, OpenCTI o un SIEM. Los dominios legítimos (descargas de
  7-zip.org, por ejemplo) no se incluyen.

## Informes

`forense informe` genera un HTML autocontenido (sin scripts ni recursos externos) y `--pdf` también el PDF, ambos con
su SHA-256 en la cadena de custodia. Estructura:

1. Portada con los datos del caso y aviso de confidencialidad, e índice.
2. **Resumen ejecutivo**: cifras clave, periodo del incidente, gráficos de hallazgos por gravedad y de actividad,
   hallazgos principales y la secuencia del incidente por tácticas ATT&CK.
3. Conclusiones del analista (versionadas, con su hash).
4. Técnicas ATT&CK observadas e indicadores de compromiso.
5. Evidencias con hashes e integridad, hallazgos por estado de revisión (con sus técnicas), eventos destacados,
   ejecución de programas, cronología, análisis realizados (opciones y hash de resultados), cadena de custodia completa
   y metodología.

El PDF sale en A4 con el ID del caso y «página x / y» en el pie, sin cortar filas entre páginas. En la web, la página
**Informes** genera cualquiera de los dos en el idioma que elija.

## Interfaz web

```bash
forense web -w ./casos            # http://127.0.0.1:8765
```

- **Espacio de trabajo**: lista de casos y alta de casos nuevos.
- **Resumen**: cifras clave, gráfico de actividad del periodo del incidente con los hallazgos en su momento (cada barra
  lleva a la línea temporal de ese intervalo), hallazgos por gravedad, hallazgos principales, técnicas por táctica
  ATT&CK, y evidencias con botones **Automático** (playbook completo) y **Triaje**. Los gráficos tienen vista de tabla,
  descripciones emergentes y siguen el tema claro u oscuro del sistema.
- **ATT&CK**: matriz de técnicas observadas, secuencia del incidente y borrador del relato.
- **Evidencias**: alta por ruta (el hash se calcula en segundo plano), hashes, origen de las evidencias derivadas y
  verificación de integridad.
- **Análisis**: formulario por módulo con sus opciones, triaje automático, resultados paginados con búsqueda por
  artefacto y exportación a CSV.
- **Hallazgos** con revisión (confirmar, descartar, nota), **Línea temporal** (filtros por fecha, texto, origen,
  severidad y destacados), **Conclusiones**, **Cadena de custodia** e **Informes** (en el idioma que elijas).
- Selector **ES/EN** y campo **Analista**: el nombre se registra en cada acción de la custodia.

Seguridad: escucha solo en `127.0.0.1` por defecto, todos los formularios llevan token CSRF, envía cabeceras de
seguridad (CSP, `X-Frame-Options`) y admite contraseña con `--clave` o `FORENSE_WEB_PASSWORD` (HTTP Basic). Si la
expones en red, ponla detrás de HTTPS. `--abrir` abre el navegador al arrancar; `/healthz` responde sin contraseña para
las comprobaciones de estado de contenedores.

## Módulos de análisis

| Módulo | Artefactos | Qué detecta |
|---|---|---|
| `evtx` | `*.evtx` (Security, System, PowerShell, Sysmon, Defender, RDP, TaskScheduler, WMI, BITS) | Fuerza bruta y **acceso tras fuerza bruta**, borrado de logs (1102/104), altas de usuario y en grupos privilegiados, servicios (7045/4697) y tareas creadas, comandos sospechosos (4688/Sysmon 1), PowerShell malicioso (4104), detecciones y desactivación de Defender, persistencia WMI, RDP desde IP pública y **reglas Sigma** |
| `registry` | SYSTEM, SOFTWARE, SAM, NTUSER.DAT, Amcache.hve | Equipo, zona horaria, red, **USB** (primera/última conexión), servicios, **ShimCache**, **BAM**, SO e instalación, programas instalados, perfiles de red, **Run/RunOnce**, Winlogon, **IFEO**, AppInit_DLLs, cuentas SAM, **UserAssist**, RecentDocs, RunMRU, TypedPaths, búsquedas, destinos RDP, Amcache con SHA-1, **claves y valores borrados** (servicios, tareas, IFEO y comandos eliminados) |
| `prefetch` | `*.pf` (XP a Windows 11, incluido el formato comprimido) | Ejecución de programas: nº de ejecuciones, últimas 8 fechas, volumen y archivos cargados; herramientas ofensivas y ejecución desde ubicaciones sospechosas |
| `srum` | `SRUDB.dat` | Bytes enviados y recibidos por aplicación y usuario, conexiones, uso de CPU/disco; **posible exfiltración** |
| `shellbags` | `UsrClass.dat`, `NTUSER.DAT` | Carpetas exploradas, también en USB, red y carpetas ya borradas |
| `jumplists` | `*.automaticDestinations-ms`, `*.customDestinations-ms` | Archivos abiertos por aplicación, conexiones RDP, unidades extraíbles, argumentos sospechosos |
| `lnk` | `*.lnk` | Archivos abiertos, rutas de red, **unidades extraíbles** (serie y etiqueta), equipo y **MAC** de origen, persistencia en la carpeta Inicio |
| `recyclebin` | `$Recycle.Bin\<SID>\$I*` | Ruta original, tamaño, fecha de borrado, usuario y si el contenido (`$R`) es recuperable |
| `browsers` | Chrome, Edge, Brave, Opera (`History`), Firefox (`places.sqlite`) | Historial, descargas, **ejecutables descargados**, servicios de intercambio y paste |
| `mft` | `$MFT` | Línea temporal $SI/$FN, entradas borradas, rutas completas, **Zone.Identifier** (URL de descarga), **timestomping** |
| `usnjrnl` | `$Extend\$UsnJrnl:$J` | Creación, borrado y renombrado de archivos con rutas completas (usando el `$MFT`); herramientas ofensivas, ejecutables creados y borrados, borrado de Prefetch y EVTX, **renombrado masivo (ransomware)** y borrado masivo |
| `tasks` | `Windows\System32\Tasks` | Tareas programadas: autor, desencadenadores, cuenta, acciones; **tareas ocultas**, con intérpretes o en ubicaciones sospechosas, como SYSTEM |
| `wmi` | `wbem\Repository\OBJECTS.DATA` | **Persistencia WMI** (filtro + consumidor CommandLine/ActiveScript), también suscripciones borradas |
| `psreadline` | `ConsoleHost_history.txt` | Comandos de PowerShell de cada usuario: descargas, ejecución codificada, desactivación de Defender, herramientas ofensivas |
| `wintimeline` | `ActivitiesCache.db` | Aplicaciones y documentos usados, tiempo en primer plano e **historial del portapapeles** |
| `setupapi` | `setupapi.dev.log` | Primera conexión de USB y dispositivos portátiles (fabricante, modelo, número de serie), convertida a UTC |
| `memory` | Volcado de memoria o salidas JSON de Volatility 3 | Ver [Memoria RAM](#memoria-ram) |
| `image` | E01/Ex01, raw, VHD/VHDX, VMDK, QCOW2 | Ver [Imágenes de disco](#imágenes-de-disco-y-recolección-en-vivo) |
| `inventory` | Cualquier carpeta | Metadatos, hashes, tipo real por firma, **archivos camuflados**, línea temporal y *bodyfile* compatible con Sleuth Kit (`mactime`) |
| `ioc` | Cualquier archivo | Cadenas ASCII/UTF-16, URL, IP, correos, claves de registro y lista de vigilancia (`-o watchlist=`) |
| `hashset` | Cualquier carpeta | Coincidencias con listas de hashes MD5/SHA-1/SHA-256 (`-o hash_list=`) |
| `yara` | Cualquier carpeta | Coincidencias con reglas YARA (`-o rules=`), con la severidad que indique la regla |
| `carving` | Imagen raw / espacio no asignado | Recupera JPEG, PNG, GIF, PDF y ZIP validando su estructura interna |

Los módulos de Windows y `inventory` se ejecutan en el **triaje** si encuentran artefactos (`memory` no, porque puede
tardar). Severidades: crítico, alto, medio, bajo e informativo.

Qué se puede registrar como evidencia:

- **Imágenes de disco** (E01, raw, VHD/VHDX, VMDK, QCOW2) y **volcados de memoria**.
- **Recolecciones de triaje**: la de `forense recolectar`, [KAPE](https://www.kroll.com/kape) (target `KapeTriage`),
  Velociraptor o CyLR. Se registra la carpeta completa.
- **Imágenes montadas en solo lectura** (Arsenal Image Mounter, `ewfmount`).
- **Artefactos sueltos**: un `.evtx`, una colmena, un `$MFT`, un `SRUDB.dat`, una carpeta de Prefetch…

## Reglas Sigma y YARA

**Sigma**: el módulo `evtx` aplica 15 reglas integradas (Office que lanza una shell, acceso a LSASS, Kerberoasting,
DCSync, PsExec, pass-the-hash, borrado de instantáneas…) y las que le indiques:

```bash
forense sigma download ./sigma                 # reglas Windows de SigmaHQ
forense sigma check ./sigma                    # cuántas son compatibles
forense -c CASO analizar evtx EV-001 -o sigma_rules=./sigma -o sigma_min_level=high
```

El motor admite selecciones, palabras clave, comodines, los modificadores habituales (`contains`, `startswith`,
`endswith`, `all`, `re`, `windash`, `cidr`, `base64`, `base64offset`, `wide`, `exists`, comparaciones, `fieldref`) y
condiciones (`and`, `or`, `not`, paréntesis, `1 of`, `all of`, `them`). `process_creation` se evalúa sobre Sysmon 1
y sobre el 4688 de Security.

**YARA** (motor YARA-X): `forense -c CASO analizar yara EV-002 -o rules=C:\intel\yara`. La severidad del hallazgo se
toma del metadato `severity` de la regla.

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
- Las evidencias derivadas registran de qué evidencia y de qué análisis proceden.

Estructura de un caso:

```
caso/
├── forense.db     SQLite (WAL): caso, evidencias, custodia, resultados, eventos, hallazgos y revisiones
├── evidence/      copias de trabajo verificadas (--copiar), en solo lectura
├── analyses/      archivos generados (artefactos extraídos, salidas de Volatility, carving, bodyfile…)
├── reports/       informes HTML y PDF
└── exports/       exportaciones CSV/JSON/STIX
```

## Arquitectura y cómo crear un módulo

```
forense/
├── core/        caso (SQLite), revisión, custodia, hashing, firmas, heurísticas, zona horaria, ejecución, exportaciones
├── parsers/     regf (+ logs de transacciones), lnk, $I, $MFT, $UsnJrnl, ShimCache, EVTX, SRUM, shell items,
│                Jump Lists, Volatility
├── image/       contenedores (libewf, libvhdi, libvmdk, libqcow), BitLocker, VSS, The Sleuth Kit y extractor
├── sigma/       motor Sigma y reglas integradas
├── modules/     windows/ (evtx, registry, prefetch, srum, shellbags, jumplists, lnk, recyclebin, browsers, mft,
│                usnjrnl, tasks, wmi, psreadline, wintimeline, setupapi, memory)
│                generic/ (image, inventory, ioc, hashset, yara, carving)
├── collector.py recolección en vivo
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
class BitsModule(Module):
    name = "bits"
    category = "windows"
    triage = True
    options = (Option("max_files", 1000, "int"),)

    def discover(self, target):
        return find_files(target, lambda p: p.name.lower() == "qmgr.db")

    def analyze(self, ctx: AnalysisContext) -> None:
        for path in self.discover(ctx.target)[: ctx.options["max_files"]]:
            rel = relative_name(path, ctx.target)
            ...
            ctx.record("bits_job", {"file": rel, "url": url, "destination": dest})
            ctx.event(created, "bits_job", f"BITS: {url} → {dest}", rel)
            if sospechoso:
                ctx.finding("bits.suspicious_job", "high", created, url=url)
        ctx.summary["jobs"] = n
```

Después se importa en `forense/modules/__init__.py` y se añaden sus textos a `locales/es.json` y `locales/en.json`
(`module.bits.title`, `.description`, `.opt.*`, `finding.bits.suspicious_job.title/.description`,
`artifact.bits_job`, `etype.bits_job`). Los tests de `tests/test_i18n.py` avisan si falta alguna traducción.

## Limitaciones conocidas

- **Colmenas con cambios pendientes**: se recuperan en memoria aplicando sus logs de transacciones (`.LOG`, `.LOG1`,
  `.LOG2`, formatos antiguo y nuevo, validando los hashes Marvin32); si no se recogieron los logs, un hallazgo avisa
  de que pueden faltar datos recientes. Las **claves y valores borrados** se recuperan del espacio libre de la colmena
  (y de celdas que quedaron sin enlazar), con su ruta completa o parcial; sus datos son indicios, porque la celda de
  datos pudo reutilizarse después del borrado.
- **Imágenes**: no se leen volúmenes cifrados con otros sistemas (VeraCrypt, LUKS), ni sistemas de archivos que The
  Sleuth Kit no admite (ReFS, APFS).
- **Recolección en vivo**: el volumen se lee mientras el sistema funciona, por lo que un archivo que cambie durante la
  copia puede quedar incoherente (el hash registrado es el de lo copiado).
- **Memoria**: Volatility necesita los símbolos de la versión exacta de Windows (se descargan de Microsoft o se indican
  con `-o symbols=`). Solo se analizan volcados de Windows.
- **$MFT**: no combina los atributos de los registros de extensión (`$ATTRIBUTE_LIST`) de archivos muy fragmentados.
- **Carving**: solo recupera archivos contiguos (no fragmentados). Un PDF termina en su primer `%%EOF`.
- **Fechas en hora local** (perfiles de red, `setupapi`): se convierten a UTC con las reglas de zona horaria de la
  colmena SYSTEM de la propia evidencia (incluido el horario de verano); sin ella se dejan como hora local.
- **WMI**: el repositorio se analiza por búsqueda de cadenas (como PyWMIPersistenceFinder), no con un parser completo
  del formato CIM.
- **Heurísticas**: las reglas de detección son indicios para priorizar el trabajo, no veredictos.
- La interfaz web usa el servidor integrado de Flask, pensado para uso local por un analista o un equipo pequeño.

## Hoja de ruta

- Más artefactos: BITS (`qmgr.db`), `$LogFile`, notificaciones, RDP Bitmap Cache, Microsoft Defender (MPLog)
- Firma digital de informes
- Correlación entre casos e importación de inteligencia desde MISP/OpenCTI
- Linux y macOS como sistemas analizados

## Desarrollo

```bash
pip install -e ".[dev]"
python -m pytest -q        # tests (artefactos reales en tests/data; el resto se genera de forma sintética)
ruff check forense tests   # estilo
```

La CI ejecuta los tests en Linux y Windows con Python 3.10 y 3.12, una prueba completa con el escenario de
demostración y los dos instaladores (instalar, ejecutar y desinstalar). Al publicar una etiqueta `v*`, el flujo
`release` construye la rueda y el sdist, el ejecutable de Windows (PyInstaller, `packaging/forense.spec`, probado con
la demo y un PDF) y la imagen Docker en GitHub Container Registry, y los adjunta a la versión. El origen y la licencia de los datos de prueba están en [tests/data/README.md](tests/data/README.md).

## Licencia

[Apache License 2.0](LICENSE). Las dependencias conservan sus licencias: libewf, libscca y libesedb (LGPL-3.0+),
The Sleuth Kit (IPL-1.0 / CPL-1.0) y pytsk3 (Apache-2.0), YARA-X (BSD-3-Clause), evtx (MIT/Apache-2.0), Flask (BSD-3-Clause).
Volatility 3 es opcional, se ejecuta como proceso aparte y se distribuye bajo la Volatility Software License.
