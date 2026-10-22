---
Tipo: bug
Severidad: MEDIO
Persona: Perito veterano
Dirigido a: IMP-1
Estado: abierto
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
