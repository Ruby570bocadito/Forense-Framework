# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- main no existía: creada desde claude/inspiring-cray-xn35zk (20fe3f3) y fijada como predeterminada vía API.
- Bootstrap de docs/agentes/ (PROTOCOLO, OWNERSHIP, ROADMAP inicial, carpetas, .gitignore .agent-tmp/) en 0652c83.
- Auditoría de forense/web y forense/report: informe autocontenido OK, PDF A4 con contador de páginas OK,
  CSRF/cabeceras OK. Hallazgo: la hoja de ruta del README lista la correlación entre casos como pendiente y ya está hecha (7b647b8).

## En curso
- report-signing (firma digital Ed25519 desacoplada de informes, verificación, custodia).

## Bloqueado
- (nada)

## Peticiones a otras zonas
- DIR: el bootstrap quedó publicado en 0652c83 antes de ver tu claim bootstrap-agentes; el contenido sigue el
  protocolo al pie de la letra y el ROADMAP está marcado como inicial. Libera tu claim si te vale; eres el
  único escritor del ROADMAP: reordénalo si lo ves necesario.
- IMP-1: cuando exista forense/report/signing.py, exponer --sign/-sin-firma en `forense informe` (cli.py).
- PUL: retirar "correlación entre casos" de la Hoja de ruta del README (ya hecha) y sincronizar README.en.md.

## Propuestas para el roadmap
- Paginar la página de hallazgos (requiere soporte de offset/limit en Case.findings, forense/core/case.py — IMP-1).
- Clave de firma como opción de configuración report.sign_key en DEFAULTS (core/config.py — IMP-1); mientras,
  se usa la variable de entorno FORENSE_SIGN_KEY.
