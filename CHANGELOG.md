# CHANGELOG

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/) y el versionado
sigue [Versionado Semántico](https://semver.org/lang/es/). Las notas de las releases publicadas en
GitHub se generan automáticamente a partir de Conventional Commits (`.github/changelog-config.json`,
flujo `release`).

## [Sin publicar]

### Añadido
- Personalidad de Sabueso (`docs/IDENTIDAD.md`): portada al ejecutar `sabueso` sin orden, lema en la web y pie con la
  versión.
- Guía de **siguiente paso** en cada caso: la CLI termina `nuevo`, `info`, `evidencia agregar`, `triaje`, `imagen`,
  `revisar` y `conclusiones` con lo que toca hacer y la orden exacta; la web lo muestra como tarjeta en el resumen y
  como columna en la lista de casos.
- Papelera de Windows XP (`RECYCLER\<SID>\INFO2`) y extracción de su contenido (`D<unidad><n>`).
- Registro: tarjetas de red, concesiones DHCP y último usuario y dominio de Winlogon.
- Herramientas de anonimato (Anonymizer) con gravedad baja y técnica T1090.
- `sabueso doctor` recomienda las reglas de SigmaHQ si no hay ninguna configurada.
- Capturas de la interfaz en el README.

### Cambiado
- Acciones de GitHub en sus versiones con Node 24.
- La interfaz web abre el puerto antes de anunciarse; si está ocupado o reservado por Windows, lo explica y propone
  otro en lugar de mostrar `WinError 10013`.

## [0.4.1] - 2026-10-30

### Cambiado
- El proyecto pasa a llamarse **Sabueso-Framework**: orden `sabueso`, paquete `sabueso-framework`, variables
  `SABUESO_*` y logo con huella. Los casos (`forense.db`), la configuración y las variables `FORENSE_*` anteriores
  siguen funcionando (ad887c2).
- La interfaz web se sirve con waitress, un servidor WSGI de producción, en lugar del de desarrollo de Flask.
- El plan vigente es `TODO.md`; la documentación de los agentes y la hoja de ruta extensa pasan a `docs/archivo/`.

### Añadido
- Informe pericial (`informe --pericial [--objeto]`, también en la web): objeto y alcance, declaración del perito
  del art. 335.2 LEC y referencia a UNE 71506. Todos los informes incluyen ahora una sección de **limitaciones**
  generada a partir del propio caso, y cada hallazgo muestra el archivo del que procede.
- Exportación para Timesketch (`exportar timesketch`, JSONL) con la línea temporal, los hallazgos etiquetados y
  los eventos destacados.
- Validación con casos reales públicos (`docs/VALIDACION.md`, `scripts/validar_evtx.py`): 261 ataques de
  EVTX-ATTACK-SAMPLES, 599 registros de Hayabusa y el disco del NIST «Hacking Case».
- Alerta de herramienta ofensiva instalada y reconocimiento de Cain & Abel, Ethereal/Wireshark, NetStumbler,
  Look@LAN y 123WASP, con sus técnicas ATT&CK (T1040, T1046, T1555).
- Perfil de triaje para Windows XP (`Documents and Settings`, `RECYCLER`, `.evt`).

### Rendimiento
- Reglas Sigma: carga de SigmaHQ de 27 s a 3,7 s (caché en memoria y cargador YAML en C) y evaluación indexada por
  EventID con prefiltro de cadenas obligatorias: 599 registros de 265 s a 108 s con resultados idénticos.

### Corregido
- La línea temporal de un disco extraído mezclaba la fecha de extracción con las del incidente (240 eventos
  falsos en el caso NIST): se usan las fechas MACB originales de la imagen.
- Falsos positivos vistos en datos reales: la clave IFEO de ejemplo de Windows XP, archivos descomprimidos por el
  Explorador marcados como timestomping, `.LOG` del registro como archivos camuflados e `iexplore.exe` (y otros
  binarios legítimos) como imitación de un binario del sistema.
- Las técnicas de reglas Sigma ausentes de la tabla ATT&CK interna ya aparecen en su táctica.
- Los tests renombraban el `sabueso.exe` del entorno al simular `sabueso update` y lo dejaban sin lanzador.
- Los tests fallaban en un Windows configurado en español.

Incluye además lo desarrollado desde la 0.4.0 hasta el 2026-10-25:

#### Añadido
- Inteligencia de amenazas: `forense intel misp` importa exportaciones MISP a las watchlists de
  `ioc` (2b1fb2f) y se admiten bundles STIX de OpenCTI (ad00865), conectadas a la correlación.
- Firma digital de informes: Ed25519 con `.sig` desacoplada y anclada a la custodia (3e1671f),
  también desde la CLI con `informe --firmar/--sign` (2254b95).
- Correlación entre casos de indicadores, dispositivos USB, direcciones IP, equipos y cuentas
  (7b647b8), con sección propia en el informe (06bf996).
- Módulos de artefactos nuevos: Microsoft Defender, MPLog e historial de detecciones (1362bbc);
  notificaciones de Windows, wpndatabase.db (740b11c); caché de bits del RDP con tiles como BMP
  (a487698); y $LogFile de NTFS con las operaciones de nivel de atributo (a426940, 9267745).
- Registro: recuperación de claves y valores borrados (dcc5d10) y $MFT fusiona los atributos de los
  registros de extensión ($ATTRIBUTE_LIST) (cf72bfa).
- Búsqueda en todo el caso y gráfico de actividad en la línea temporal (20fe3f3).
- Web: revisión masiva de hallazgos (90d4996), filtros guardados por caso (e7962a7), paginación de
  hallazgos y ejecución para casos grandes (93074ef), SHA-256 y estado de firma de cada informe en
  la página de informes (be0cbba), accesibilidad básica (0a89a82) y asociación explícita de
  etiquetas en los análisis (9f88327).
- Exportaciones imprimibles y autónomas de la línea temporal (bfea922) y de los hallazgos
  (de9adc2), ambas ancladas a la custodia.
- Notificaciones webhook tras la automatización y tras `forense update` (1bab974).
- Gate central `read_capped()` para las lecturas de los módulos (0221fdc) y tope adicional para la
  lectura íntegra de contenedores customDestinations (2911d42).

#### Corregido
- Las rutas relativas de `disk_path` quedan contenidas en la carpeta del caso (f5281b5).
- Las rutas de evidencia se re-referen a la carpeta del caso para que las copias se verifiquen a sí
  mismas (dfe9cde).
- Aviso de contenido duplicado al agregar evidencia por CLI (1f94986) y al subirla por web
  (9a9e803).
- Errores localizados cuando `conclusiones --archivo` apunta a un fichero inexistente o ilegible
  (0606ea2); `exportar` acepta los términos en español de su propia ayuda (8383161).
- El descubrimiento de módulos aplica sus predicados a archivos sueltos y los nombres cortos de
  herramientas resuelven el `.exe` correcto (ac01ed1).
- Web endurecida: rechazo de hosts con DNS rebinding cuando corre sin contraseña (ad1a361), tope
  del tamaño del cuerpo de las peticiones (423bd07) y aviso de arranque sin contraseña también en
  loopback (d9865d2).
- Retirada la referencia a la rama de desarrollo heredada en `forense update` (14305d5) y en los
  instaladores (58bf1e6).

#### Seguridad
- Guardia estructural ReDoS en los patrones `|re` de Sigma antes de compilarlos (65dd311).

#### Documentación
- README es/en sincronizados con el código: inteligencia MISP/OpenCTI, $LogFile y sus operaciones
  de atributo, firma de informes, consumo acotado, ejemplo de módulo neutro, hoja de ruta ligada a
  docs/ROADMAP.md y badges de CI, licencia y Python (14cd5c6, 83eb8ad, 4ac3a4f, 45e99a2, 70af8f0,
  6ae122f).
- Este CHANGELOG y las notas de release automáticas a partir de Conventional Commits.

## [0.4.0] - 2026-10-04

### Añadido
- Instalación fácil: instaladores Windows y Linux con desinstalación (`install/`), diagnóstico del
  entorno con `forense doctor`, imagen Docker con docker-compose y ejecutable standalone de Windows
  (PyInstaller) con prueba de humo (ab6d393).

## [0.3.0] - 2026-10-04

### Añadido
- Nuevos artefactos de Windows: tareas programadas, PSReadLine, Windows Timeline, setupapi, WMI y
  $UsnJrnl (632a757).
- El registro de Windows reproduce los registros de transacciones de hives sucias (1941efa).
- Imágenes: VHD/VHDX dinámicos, diferenciales y con padre, VMDK, QCOW2, instantáneas VSS y
  volúmenes BitLocker (5c8d315).
- Vista de ejecución de programas que correlaciona todas las fuentes de ejecución (bdb9ee8).

## [0.2.0] - 2026-10-04

### Añadido
- Análisis de memoria con Volatility 3 (eb7258a).
- Imágenes de disco (E01, raw) y recolección en vivo (edd75f1).
- Motor Sigma para EVTX y módulo YARA (c060432).
- Artefactos de Windows: Prefetch, SRUM, ShellBags y Jump Lists (6df4f14).
- Flujo del analista: revisión de hallazgos, eventos destacados y conclusiones (d20ac58).
- Documentación bilingüe y licencia Apache-2.0 (aaaaf01).

### Corregido
- Parseo de fechas con fracción de segundo y zona horaria (daa0600).

## [0.1.0] - 2026-10-04

### Añadido
- Framework forense inicial para Windows: casos con cadena de custodia verificable por SHA-256,
  gestión de evidencia, artefactos de Registro de Windows y ShimCache, $MFT, EVTX, LNK, Papelera de
  reciclaje y navegadores, línea temporal, heurísticas de detección, exportaciones CSV/JSON
  ancladas a custodia, CLI bilingüe `forense` e interfaz web con informes HTML en español e inglés
  (df6a194, c5140a8).

[Sin publicar]: https://github.com/Ruby570bocadito/Forense-Framework/compare/v0.4.1...HEAD
