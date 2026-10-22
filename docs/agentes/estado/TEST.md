# estado/TEST.md — 2026-10-23 (fusión de dos sesiones TEST en paralelo)

Nota de coordinación: hubo dos instancias TEST trabajando a la vez (como ya pasó con DIR).
Esta entrada fusiona ambas; se reitera a DIR la regla de una sola instancia por rol.

## Sesión paralela (2026-10-22, ya en main)
- Aportó H-007 (verificar valida las rutas del ORIGINAL en casos copiados con cp/rsync), H-008 (PDF sin navegador, IMP-2) y H-009 (ayuda de exportar en es, IMP-1), todos abiertos.
- Aportó tests/e2e/test_e2e_cli.py (5 tests autocontenidos). Convive con los de esta sesión: 8 e2e en total.
- Su repro de H-001/H-003 «tal cual» fue la misma ilusión de la capa de visualización; la verificación por bytes de esta sesión la resuelve.

## Hecho (esta sesión)
- Cierre de falsos positivos: H-001, H-002 y H-003 verificados a nivel de bytes (conteos con grep/python, sin depender de la vista): las 15 ubicaciones citadas contienen la secuencia corchete+m correcta, 0 formas corruptas en el repo y los commits previos a los agentes ya la tenían. Borrados (close 5b806e3). El daño se reprodujo en vivo en la capa de vista.
- reports-hash-display + firma web verificados de extremo a extremo: columna SHA-256 con insignia contra custodia, casilla de firma genera .sig desacoplada, «Verificar firma» da flash válido, informe manipulado da «could not be verified» e insignia «Changed after generation»; la custodia registra report_signed y report_signature_verified.
- Accesibilidad en HTML servido: skip-link con :focus, aria-current en nav y selector ES/EN, role=alert/status en flashes, role=search y aria-label en buscador/analista, thead+scope en todas las tablas, lang dinámico, tema oscuro y focus-visible.
- MFT de extensión en demo fresca: backup_correo.pst fusiona size 2 GiB y ADS Zone.Identifier del registro 91 (zone_id=3, host_url); carving de la imagen recupera 5 ficheros.
- Correlación entre casos: 5 casos, 9 observables compartidos (hash con IOC, IP, USB, host, cuentas), página web y --json/--tipo correctos.
- tests/e2e/ añadidos: verificar exit 0/2 sobre una copia con --copy manipulada (comprueba que la evidencia copiada es solo lectura) y correlacionar --json entre 2 casos con el mismo evtx. Helpers en tests/e2e/_cli.py; SIN conftest en tests/e2e (rompería el import del conftest raíz, igual conclusión que la sesión paralela).
- Numeración: mi hallazgo de esta sesión pasa de H-007 a H-010 por colisión con la sesión paralela.

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- IMP-1: H-010 (exponer --firmar en informe/--pdf o avisar si la clave no se usa); H-004, H-005, H-006, H-007 y H-009 siguen abiertos.
- PUL: nada que restaurar en README/instaladores/locales; el comando literal del README resuelve (dry-run rc=0).
- DIR: aprobar la propuesta de PUL al PROTOCOLO (evidencias de contenido con órdenes independientes de la vista: grep -c, od -c). TEST la aplica desde ya.

## Flujo y comprobaciones positivas
- verify_file sin claves da ForenseError localizado y claro; cada verificación de firma queda en custodia; la manipulación de informes se detecta por hash de custodia y por firma.

## Sin probar (motivo)
- PDF firmado (sin navegador en el entorno), recolectar (requiere Windows admin), Docker/instaladores completos, memoria real con Volatility, update contra red.
