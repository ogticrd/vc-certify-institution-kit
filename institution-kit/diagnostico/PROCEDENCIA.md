# Procedencia de `diagnostico/`

Copia del diagnóstico de OGTIC (emisor propio, `inji-vc/stack/diagnostico/`), según el diseño D4 de la
spec `kit-firma-y-contexto`. Sin dependencias, Node 22. **No se edita**: se refresca con
`scripts/sync-diagnostico.sh` (que falla si algún fichero tiene cambios locales) y una prueba
(`test/procedencia.test.mjs`) compara las huellas de abajo con los ficheros.

- `cli.mjs`: entrada por línea de comandos (`node cli.mjs <metadata_url https> [--as <servidor>] [--json] [--privadas]`).
- `motor.mjs`: las once comprobaciones sobre la metadata de un emisor y la evaluación de una credencial firmada.
- `red.mjs`: las peticiones hacia fuera con las barreras anti-SSRF (solo https, sin direcciones privadas salvo `--privadas`).
- `jsonld.mjs`: expansión y canonicalización JSON-LD sin dependencias (lo usan el motor y la cobertura de la muestra).

Quien envuelve el motor para el kit es `scripts/lib/verificar-instalacion.mjs` (fichero propio del kit, no
vendorizado) que ejecuta `verify-install.sh`.

<!-- sync-diagnostico:inicio -->
| Fichero | Origen | SHA-256 | Copiado |
|---|---|---|---|
| `cli.mjs` | `inji-vc/stack/diagnostico/cli.mjs` | `095a26c4150ac3bb1d696f13c272f6a869b518b92b508b1185dc2bc65e4d52df` | 2026-10-04 |
| `motor.mjs` | `inji-vc/stack/diagnostico/motor.mjs` | `c09ad2b4173a8b989e64f531c35bbbd815967593e8661bac67f710e740585cbb` | 2026-10-04 |
| `red.mjs` | `inji-vc/stack/diagnostico/red.mjs` | `a766342de997f96a69cd416479823355fdc20896ac64b5d7896bcc830920ff5d` | 2026-10-04 |
| `jsonld.mjs` | `inji-vc/stack/diagnostico/jsonld.mjs` | `b1d8e615bdaa218db928ddea8648461546a700045950abad6370ec48ef0754f7` | 2026-10-04 |

Commit del origen en la última sincronización: sin git (la huella SHA-256 identifica la versión)
<!-- sync-diagnostico:fin -->

El repositorio de origen (`inji-vc/stack`) no está bajo git en el momento de la copia, así que no hay
commit que citar: la huella SHA-256 identifica la versión. Si el origen pasa a git, `sync-diagnostico.sh`
anota el commit en la línea «Commit del origen».

Los contextos W3C que usan las pruebas (`test/fixtures/contextos/`) vienen de
`inji-vc/stack/test/fixtures/contextos/`, copiados sin modificar el 4-oct-2026:

| Fichero | SHA-256 |
|---|---|
| `w3-credentials-v1.json` | `00d7dd6d3ad8b920e3e550dd3a3d9090bffcac84cdbf943da6924b3e0a5c8bb8` |
| `w3-credentials-v2.json` | `5547321d5b3b0456fe63f3b09dc039859cc660770e9f93282bf7f235e9c9d4e7` |
| `w3id-ed25519-2020-v1.json` | `b9e1ab971fd8bf2c7553e0c4a9438e0b9450afde1ea1ca5b2492368b9f549588` |
