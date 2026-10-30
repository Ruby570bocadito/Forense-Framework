# Validación con casos reales

Sabueso se valida contra evidencias **públicas con respuesta conocida**: registros de ataques reales clasificados
por técnica y un disco completo con preguntas oficiales. Este documento recoge el método, las cifras y lo que se
corrigió gracias a ellas, para que cualquiera pueda repetirlo.

Última ejecución: 2026-10-30, Sabueso 0.4.0 + correcciones de esta validación, Windows 11, Python 3.12.

## Datos usados

| Conjunto | Origen | Licencia | Tamaño | Qué aporta |
|---|---|---|---|---|
| EVTX-ATTACK-SAMPLES | [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | GPL-3.0 | 278 EVTX, ~6 MB | Cada archivo reproduce un ataque real y está en la carpeta de su táctica ATT&CK: respuesta conocida por archivo |
| hayabusa-sample-evtx | [github.com/Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | sin licencia declarada | 599 EVTX, ~9 MB | Volumen y variedad (APT, Sysmon, PowerShell) para robustez y rendimiento |
| NIST CFReDS «Hacking Case» | [cfreds-archive.nist.gov/Hacking_Case.html](https://cfreds-archive.nist.gov/Hacking_Case.html) | dominio público (NIST) | E01 en 2 partes, 1,04 GB (disco de 4,6 GB) | Portátil Windows XP abandonado con 31 preguntas oficiales |
| Reglas SigmaHQ | `sabueso sigma download` ([github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)) | DRL 1.1 | 2.425 reglas de Windows | Detección comunitaria frente a las 15 reglas integradas |

Ninguno se incluye en el repositorio: se descargan aparte. Las pruebas automáticas (`tests/test_validation_regressions.py`)
reproducen con datos sintéticos cada fallo encontrado.

## 1. Registros de eventos de ataques reales (EVTX-ATTACK-SAMPLES)

```bash
python scripts/validar_evtx.py RUTA/EVTX-ATTACK-SAMPLES --csv base.csv
python scripts/validar_evtx.py RUTA/EVTX-ATTACK-SAMPLES --sigma RUTA/sigma --csv sigmahq.csv
```

*Detectado* = al menos un hallazgo de gravedad media o superior. *Táctica OK* = algún hallazgo se asocia a la táctica
ATT&CK de la carpeta del ataque (criterio estricto: un movimiento lateral también deja rastros de ejecución).

| Táctica | Archivos | Detectados (integradas) | Detectados (+ SigmaHQ) | Táctica OK (+ SigmaHQ) |
|---|---:|---:|---:|---:|
| command-and-control | 6 | 1 (17 %) | 4 (67 %) | 2 (33 %) |
| credential-access | 39 | 18 (46 %) | 29 (74 %) | 18 (46 %) |
| defense-evasion | 36 | 6 (17 %) | 24 (67 %) | 10 (28 %) |
| discovery | 11 | 4 (36 %) | 5 (45 %) | 1 (9 %) |
| execution | 34 | 8 (24 %) | 27 (79 %) | 16 (47 %) |
| lateral-movement | 47 | 12 (26 %) | 29 (62 %) | 10 (21 %) |
| persistence | 22 | 4 (18 %) | 17 (77 %) | 11 (50 %) |
| privilege-escalation | 66 | 10 (15 %) | 59 (89 %) | 45 (68 %) |
| **Total** | **261** | **63 (24 %)** | **194 (74 %)** | **113 (43 %)** |

Errores de lectura: **0 de 261** en ambos casos.

**Conclusión práctica:** las 15 reglas integradas son una base mínima; para analizar registros de eventos hay que
usar las de SigmaHQ (`sabueso sigma download DIR` y `intel.sigma_rules` en la configuración).

## 2. Robustez y rendimiento (hayabusa-sample-evtx)

`sabueso analizar evtx` sobre los 599 archivos con las reglas de SigmaHQ: 26.197 eventos, 2.888 hallazgos,
**sin ningún fallo de lectura**.

| Medida | Antes | Después |
|---|---:|---:|
| Carga de las 2.405 reglas de SigmaHQ | 27 s | 3,7 s (0,15 s si no han cambiado) |
| `many-events-security.evtx` (13.223 eventos, 8.346 de creación de procesos) | 147 s | ~60 s |
| Los 599 archivos | 265 s | 108 s |
| Validación completa del apartado 1 con SigmaHQ | ~2 h (estimado) | 56 s |

Los resultados antes y después de la optimización son **idénticos** (mismos 26.197 eventos y 2.888 hallazgos).
Con solo las reglas integradas, el mismo registro se analiza en 1,3 s.

## 3. Disco completo: NIST «Hacking Case» (Windows XP)

```bash
sabueso auto "4Dell Latitude CPi.E01" --nuevo nist-hacking -p full
```

13 segundos para la imagen completa. Resultado frente a las preguntas oficiales (segunda ronda, tras las mejoras de la v0.5):

| # | Pregunta | Sabueso | Dónde |
|---|---|---|---|
| 1 | Hash de la imagen | ⚠️ MD5 guardado en el E01 (`aee4fcd9…959a`); `imagen --verificar` lo recalcula | `image_info` |
| 2 | Sistema operativo | ✅ Microsoft Windows XP | `os_info` |
| 3 | Fecha de instalación | ✅ 2004-08-19 22:48:27 UTC | `os_info` |
| 4 | Zona horaria | ✅ Central Standard Time | `system_info` |
| 5 | Propietario registrado | ✅ Greg Schardt | `os_info` |
| 6 | Nombre del equipo | ✅ N-1A9ODN6ZXK4LQ | `system_info` |
| 7 | Dominio principal | ✅ N-1A9ODN6ZXK4LQ (Winlogon) | `os_info` |
| 8 | Último apagado | ✅ 2004-08-27 15:46:33 UTC | `system_info` |
| 9 | Número de cuentas | ✅ 5 | `user_account` |
| 10–11 | Usuario habitual / último en iniciar sesión | ✅ Mr. Evil (15 inicios, último 2004-08-27 15:08:23 UTC; también en Winlogon) | `user_account`, `os_info` |
| 12 | Archivo que liga a G. Schardt con Mr. Evil | ❌ requiere buscar en el contenido de archivos de programa | — |
| 13 | Tarjetas de red | ✅ Xircom CardBus Ethernet 100 + Modem 56 y Compaq WL110 Wireless LAN, con sus concesiones DHCP | `network_card`, `network_interface` |
| 14–15 | IP, MAC y fabricante | ⚠️ MAC 00:10:a4:93:3e:09 en los accesos directos (prefijo de Xircom); la IP solo está en un archivo de Look@LAN | `shell_link` |
| 16 | 6 programas de hacking | ✅ los 6 marcados: Cain & Abel, Ethereal, Look@LAN, Network Stumbler y 123 Write All Stored Passwords (gravedad media) y Anonymizer (baja) | hallazgos |
| 17–20 | Correo, servidor de noticias, grupos | ⚠️ Forté Agent y Outlook Express identificados; su configuración no se analiza | `installed_program`, ejecución |
| 21–22 | Configuración y canales de mIRC | ⚠️ se ve el acceso a `mIRC\channels\channels.txt`; no se lee su contenido | `shell_link` |
| 23–27 | Captura de Ethereal y correo web | ❌ fuera del perfil de triaje | — |
| 28–29 | Ejecutables en la papelera | ✅ 4 (lalsetup250, NetStumbler, WinPcap y Ethereal) y su contenido sigue en `RECYCLER` (`Dc1.exe`…): no están realmente borrados | `deleted_file` |
| 30 | Archivos borrados según el sistema de archivos | ✅ 3 entradas borradas en `$MFT` | análisis `mft` |
| 31 | Antivirus | ❌ no es un antivirus (YARA y listas de hashes sí) | — |

**Resumen:** de las 31 preguntas, **15 con respuesta completa, 9 parciales y 7 sin respuesta** (en la primera ronda: 11, 10 y 10). Lo que falta es, sobre todo,
el **contenido de archivos de aplicaciones** (mIRC, Agent, Outlook Express, capturas de red), que hoy no forma parte
del triaje.

## Fallos encontrados y corregidos

| Fallo | Visto en | Corrección |
|---|---|---|
| No se extraían los perfiles de usuario de Windows XP (`Documents and Settings`), así que no se analizaban NTUSER.DAT, accesos directos ni ShellBags | NIST | Rutas de XP en el perfil de triaje (de 5 a 7 módulos ejecutados) |
| La clave IFEO de ejemplo que trae XP («Your Image File Name Here without a path» → `ntsd -d`) salía como puerta trasera **alta** | NIST | Se reconoce y se ignora |
| Archivos descomprimidos por el Explorador («Temporary Directory N for X.zip») salían como timestomping **alto** | NIST | Gravedad baja: conservan las fechas del ZIP |
| Los `.LOG` del registro salían como «archivo camuflado» | NIST | `.log/.log1/.log2` con cabecera `regf` son normales |
| Cain & Abel, Ethereal, NetStumbler, Look@LAN y 123WASP no se reconocían como herramientas de ataque | NIST | Añadidas, con técnicas ATT&CK (T1003, T1040, T1046, T1555) y alerta nueva de **herramienta ofensiva instalada** |
| `iexplore.exe` (y `tasklist.exe`, `dashost.exe`, `synchost.exe`…) salían como «nombre que imita a un binario del sistema» | NIST + los 660 ejecutables de un Windows 11 | Lista de binarios legítimos vecinos |
| **240 eventos con fecha de 2026** en la línea temporal de un incidente de 2004: las copias extraídas de la imagen aportaban su fecha de extracción como creación | NIST | La extracción guarda las fechas MACB originales (`extraction_times.json`) y el inventario y los accesos directos las usan |
| Las técnicas de reglas Sigma que no estaban en la tabla interna no aparecían en el mapa ATT&CK | EVTX-ATTACK | Se usan las etiquetas de táctica de la propia regla (táctica correcta: del 25 % al 43 %) |
| Cargar SigmaHQ costaba 27 s en cada análisis y evaluar cada evento de creación de procesos, ~18 ms | Hayabusa | Cargador YAML en C, caché de reglas, índice por EventID y prefiltro de cadenas obligatorias, con prueba de que el resultado no cambia |
| Los tests fallaban en un Windows en español | este equipo | El idioma de los tests se fija a inglés |
| No se leía la papelera de Windows XP (`INFO2`) | NIST (2ª ronda) | Analizador de `INFO2` (formatos de 280 y 800 bytes) y extracción de los `D<unidad><n>` |
| No se extraían las tarjetas de red, las concesiones DHCP ni el dominio y usuario de Winlogon | NIST (2ª ronda) | Nuevos registros `network_card` y campos `default_user` / `default_domain` |
| Anonymizer no se marcaba | NIST (2ª ronda) | Herramientas de anonimato con gravedad baja y técnica T1090 |

## Pendiente (siguiente ronda)

- Registros `.evt` de Windows XP: ya se extraen, falta el analizador.
- Configuración de clientes de correo, noticias e IRC (Outlook Express, Forté Agent, mIRC).
- Una imagen moderna (Windows 10/11) con preguntas oficiales para validar SRUM, Amcache, EVTX y navegadores.
- Rendimiento de Sigma: ~150 eventos/s de creación de procesos con SigmaHQ; un índice de cadenas común a todas
  las reglas lo multiplicaría.
