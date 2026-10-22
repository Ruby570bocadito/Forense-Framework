---
Tipo: bug
Severidad: MEDIO
Persona: Perito veterano
Dirigido a: IMP-1
Estado: resuelto-pendiente-verificación
---

Pasos para reproducir:
1. `forense -L es nuevo /tmp/C1 -n C1 -i T` y `forense -L es -c /tmp/C1 evidencia agregar <dir> --copiar -d x`
2. `cp -r /tmp/C1 /tmp/C1-copia`
3. Manipular un archivo DENTRO de la copia: `echo manipulado >> /tmp/C1-copia/evidence/EV-001/<archivo>`
4. `forense -L es -c /tmp/C1-copia verificar`

Resultado esperado: verificar evalúa la evidencia registrada EN esa copia; al estar manipulada debe marcar
[FAIL] Evidencia EV-001 y salir con código 2 (o avisar que se verifica una ruta distinta a la del caso).

Resultado real: exit 0 y todo [OK] ("Integridad verificada: todo coincide."), sin mencionar qué ruta se verificó.
Causa: `evidence.path` se guarda como ruta absoluta, y en la copia sigue apuntando a la carpeta del caso ORIGINAL
(comprobado leyendo forense.db de la copia en modo ro: `('EV-001', '/.../C1/evidence/EV-001/...')`). Con el original
presente, la copia manipulada verifica OK contra los archivos del original; si el original se mueve o renombra, la
copia íntegra da [FAIL] (verify.missing) y exit 2. Una copia de archivo de un caso (cp/rsync) nunca verifica de
forma independiente. README no documenta cómo mover o archivar un caso.

Sugerencia: guardar relativo a la raíz del caso las rutas dentro del propio caso (re-basar al abrir) o, al verificar,
comparar la ruta usada con la registrada y avisar cuando difieran.

---

Nota de verificación (IMP-1, 2026-10-23): resuelto con las dos Mitades de la sugerencia.
- Almacenamiento: `add_evidence` guarda ahora las rutas DENTRO del caso relativas a su raíz (evidence/EV-001/x,
  analyses/0001_image/extracted); las externas sin --copiar siguen absolutas. Igual convención que analyses.output_dir.
- Resolución: nuevo `Case.disk_path(stored)` usado por verificar, análisis, triaje y delete_analysis: relativo →
  raíz/caso; absoluto bajo la raíz actual → tal cual (casos viejos in situ); absoluto con componente evidence/ o
  analyses/ → primero la copia dentro de ESTA carpeta de caso si existe (copia o caso movido), si no la registrada.
- Custodia: cuando la verificación de una entrada absoluta legada se re-basa a otra ubicación, la entrada
  evidence_verified añade details.path con la ruta usada (auditable).
- Tests (tests/test_core.py): copia manipulada → FAIL contra su propio fichero y el original sigue OK; caso movido →
  OK; entrada legada absoluta re-basada (en sitio y en copia); evidencia externa mantiene ruta absoluta.
  Suite: 310 passed, 1 skipped; ruff limpio.
- PUL: falta documentar en README cómo mover/archivar un caso (ahora ya es portable copiando la carpeta).
