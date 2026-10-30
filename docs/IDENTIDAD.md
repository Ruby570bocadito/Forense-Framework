# Identidad de Sabueso

Una página para que la CLI, la web, los informes y la documentación hablen con la misma voz.

## Quién es

Un **sabueso**: sigue el rastro con paciencia, no se distrae y te trae lo que encuentra. No decide por ti: señala
dónde mirar. El perito es quien firma.

**Lema:** *Sigue el rastro. Las conclusiones, tuyas.* — en inglés: *Follow the trail. The conclusions are yours.*

**Para quién:** peritos y analistas de respuesta a incidentes, sobre todo hispanohablantes, que tienen que
**defender** lo que encuentran ante un cliente o un juzgado.

## Cómo habla

| Es | No es |
|---|---|
| Claro y directo: dice qué ha pasado y qué hacer después | Críptico: códigos, trazas o jerga sin explicar |
| Cercano y tranquilo, de tú en la interfaz | Gracioso a costa del rigor, ni con chistes de perros en cada frase |
| Honesto con sus límites: «indicio», «no se pudo leer», «sin verificar» | Triunfal: nunca «¡amenaza detectada!» ni veredictos |
| Siempre con un **siguiente paso** cuando hay uno | Un callejón sin salida tras un error o un resultado |

Ejemplos:

- ✅ «Rastro seguido: 13 hallazgos (5 altos). Siguiente paso: revísalos con `sabueso -c caso hallazgos`.»
- ❌ «¡¡El sabueso ha olfateado 13 amenazas!! 🐶»
- ✅ «No se pudo leer `SRUDB.dat` (está dañado). El resto del análisis sigue adelante.»
- ❌ «Error: ESEDB_ERROR_UNKNOWN».

## Dónde va la personalidad y dónde no

- **CLI y web:** sí. Portada al ejecutar `sabueso` sin orden, resúmenes al terminar, guía de siguiente paso,
  estados vacíos que explican qué hacer.
- **Informes periciales y exportaciones:** **no**. Lenguaje técnico y sobrio; la marca se limita al logo y al pie.
  Un informe se lee en un juzgado.
- **Hallazgos:** siempre «hallazgo» o «indicio», nunca «rastro» en datos, exportaciones o informes (el término
  técnico manda). «Rastro» queda para la voz de la interfaz.

## Marca

- **Logo:** escudo azul con una huella blanca (`sabueso/web/static/logo.svg`). Escudo = custodia; huella = rastro.
- **Colores:** tinta azul marino para la estructura (`--top #0f1b2d`), azul de acción (`--accent`). La escala de
  gravedad (marrón → naranja) y la de ATT&CK (azules) están validadas para daltonismo y modo oscuro: no se usan para
  decorar.
- **Nombre:** «Sabueso» en la interfaz; «Sabueso-Framework» solo en contextos formales (paquete, informes, About).
- **Emojis:** no en textos de la herramienta (las consolas de Windows no siempre los muestran y restan seriedad).
