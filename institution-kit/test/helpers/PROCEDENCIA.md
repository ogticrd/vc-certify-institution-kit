# Procedencia de los ayudantes de prueba copiados

Copiados **sin modificar** el 4-oct-2026 (T6) de `inji-vc/stack/test/` (emisor propio de OGTIC). Importar entre
repositorios no sirve: el repositorio del kit no tiene a `inji-vc` al lado en CI. Las rutas relativas que usan
(`../../diagnostico/red.mjs`, `../fixtures/...`) resuelven igual aquí (`institution-kit/diagnostico/`,
`institution-kit/test/fixtures/`).

| Fichero aquí | Origen | SHA-256 |
|---|---|---|
| `helpers/emisor-simulado.mjs` | `inji-vc/stack/test/helpers/emisor-simulado.mjs` | `acb8e318d9a8dcc887e1c961fb755118dca5585256a2f6c916ccfd84b1705a28` |
| `helpers/aislamiento.mjs` | `inji-vc/stack/test/helpers/aislamiento.mjs` | `5e52fc168f79cbcf2a47e4bf642ddd47e9676206f7a89328a863ce8488faade1` |
| `fixtures/generar.mjs` | `inji-vc/stack/test/fixtures/generar.mjs` | `882441671e9283e435d39399723c182fb77546be3bae79ab5792bfda0f6cc37a` |
| `fixtures/tls/localhost.pem` | `inji-vc/stack/test/fixtures/tls/localhost.pem` | `94ea755fc94ffa97e4af4c8c0d91a986df4185bbadf4c911fc725be6107a8a99` |
| `fixtures/tls/localhost.key` | `inji-vc/stack/test/fixtures/tls/localhost.key` | `d2a51d8dc9380660185ac8e3bab6a16d06409dfc75cbfb5ea82be6a1c800bdb0` |
| `fixtures/tls/desconocido.pem` | `inji-vc/stack/test/fixtures/tls/desconocido.pem` | `5e4f4350efe5e7f3c2ddd88e9ecea8ad9ce659c21c0142ce8e223bf8d187a950` |
| `fixtures/tls/desconocido.key` | `inji-vc/stack/test/fixtures/tls/desconocido.key` | `4ee84858e1f73369ab4798a28b0347c908b7cfc722290273754f054f06504eca` |

Los certificados de `fixtures/tls/` son autofirmados, de mentira y solo para estas pruebas (no protegen nada).
`emisor-simulado.mjs` sirve metadata, `did.json`, JWKS, contextos, logo, endpoint de emisión y descubrimiento
del servidor de autorización en `https://localhost:<puerto libre>` (escucha en 127.0.0.1); las pruebas del kit lo
retocan por sus ganchos (`metadata`, `did`, `rutas`) para que sirva lo que generó el kit.
