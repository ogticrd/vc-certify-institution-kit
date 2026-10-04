# Procedencia de `diagnostico/`

Copia del diagnóstico de OGTIC (emisor propio, `inji-vc/stack/diagnostico/`), según el diseño D4 de la
spec `kit-firma-y-contexto`. Sin dependencias, Node 22.

| Fichero | Origen | SHA-256 | Copiado |
|---|---|---|---|
| `jsonld.mjs` | `inji-vc/stack/diagnostico/jsonld.mjs` | `964e0d5ae6a1c662ee995e90ac65d4bd0e3c22d1af3a5b9b9625367f06fb544e` | 4-oct-2026 (T2) |

El repositorio de origen (`inji-vc/stack`) no está bajo git en el momento de la copia, así que no hay
commit que citar: la huella SHA-256 identifica la versión. T6 añade `cli.mjs`, `motor.mjs` y `red.mjs` con
`scripts/sync-diagnostico.sh` y actualiza esta tabla.

`jsonld.mjs` se trajo en T2 porque la prueba de cobertura de firma (`test/credencial.test.mjs`)
canonicaliza con él una credencial de muestra. No se ha modificado.

Los contextos W3C que usan las pruebas (`test/fixtures/contextos/`) vienen de
`inji-vc/stack/test/fixtures/contextos/`, copiados sin modificar el 4-oct-2026:

| Fichero | SHA-256 |
|---|---|
| `w3-credentials-v1.json` | `00d7dd6d3ad8b920e3e550dd3a3d9090bffcac84cdbf943da6924b3e0a5c8bb8` |
| `w3-credentials-v2.json` | `5547321d5b3b0456fe63f3b09dc039859cc660770e9f93282bf7f235e9c9d4e7` |
| `w3id-ed25519-2020-v1.json` | `b9e1ab971fd8bf2c7553e0c4a9438e0b9450afde1ea1ca5b2492368b9f549588` |
