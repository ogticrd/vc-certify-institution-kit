# Cambios del kit de instituciones

El formato sigue la idea de [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Las fechas son de 2026.

## Sin publicar

Cambios de la rama `fix/kit-firma-y-contexto` respecto al kit anterior (`dr-implementation-kit`). Es un cambio grande: **si ya instaló el kit anterior, lea primero la sección «Para instituciones ya instaladas»**.

### Seguridad

- **La firma ahora cubre los datos de la credencial.** Antes, toda credencial se emitía con un único contexto (`credentials/v1`) que no define los atributos de la institución; la conversión que precede a la firma los descartaba y **ningún atributo quedaba firmado**: cualquiera podía cambiar un dato sin invalidar la credencial. Ahora el kit genera un contexto propio que define cada atributo de `CREDENTIAL_ATTRIBUTES` (protegido), lo publica en `https://<su dirección>/contextos/<clave>.json` y lo incluye en cada credencial. Medido en las pruebas del kit: **100 % de los atributos firmados con el contexto nuevo, 0 % con el anterior**. `verify-install.sh` lo comprueba al instalar. Qué es el contexto y por qué no se edita: guía, sección 5.
- **El panel interno de Certify (actuator) ya no es público.** El kit anterior dejaba `management.endpoints.web.exposure.include=*` y `management.endpoint.env.show-values=ALWAYS`: con la ruta abierta en el proxy, cualquiera en internet podía leer la configuración del servicio, contraseñas incluidas. Ahora Caddy responde 404 a todo `/v1/certify/actuator/…` salvo el estado de salud desde la red interna, y Certify solo habilita `health` (sin detalles) y nunca muestra valores de configuración.
- **Secretos.** Si `POSTGRES_PASSWORD` y `KEYSTORE_PASSWORD` valen los de siempre (`postgres`, `local`) o están vacías, el kit genera contraseñas aleatorias de 64 caracteres, las guarda solo en `generated/.env.runtime` (permisos 600, ya sin `OAUTH_CLIENT_SECRET`) y no las escribe en ninguna salida. **Solo para instalaciones nuevas** (ver más abajo). Antes, el almacén de llaves usaba la contraseña `local` fija y `.env.runtime` copiaba secretos en claro con los permisos por defecto.
- **Tokens fuera de los registros.** El commit `541f1d9` («add token logs») del proyecto base hace que Certify escriba el **token de acceso completo** y todas sus claims en cada petición de credencial. El kit fija el nivel de registro de ese filtro en `WARN` (en las properties y en `templates/logback-kit.xml`). Qué hace y qué no: [`docs/IUGO-CUSTOMIZATIONS.md`](docs/IUGO-CUSTOMIZATIONS.md).
- **Logo de terceros eliminado.** El logo por defecto ya no se descarga de una dirección ajena: el logo de la credencial es el PNG de la institución, servido por el propio kit.

**Lo que esta versión no resuelve** (para que no se dé por cerrado):

- Las líneas del código Java que escriben el token siguen en el fuente del proyecto base; el kit solo lo evita por configuración. Revertir el commit `541f1d9` es una decisión aparte.
- Las tres validaciones relajadas del token (audiencia, `client_id`, `c_nonce`) siguen como estaban: [`docs/IUGO-CUSTOMIZATIONS.md`](docs/IUGO-CUSTOMIZATIONS.md).
- Los ficheros `generated/config/*.properties` contienen contraseñas y tienen permisos de lectura para todos los usuarios del servidor (el contenedor corre con otro usuario y los lee por montaje). Limite el acceso al servidor.

### Cambiado

- **Autenticación de producción.** El servidor de autorización de las personas por defecto es Cuenta Única de producción (`https://auth.cuentaunica.gob.do`), configurable con `AUTH_ISSUER_URL` (sin barra final). Antes apuntaba al entorno de staging (`cuenta.digital.gob.do`), que no sirve en producción. La dirección del token de la API de datos, `RESTAPI_TOKEN_URL`, **es ahora obligatoria y sin valor por defecto**: la entrega OGTIC (antes apuntaba al servidor de staging). `OAUTH_CLIENT_ID` debe cambiarse: el marcador `CAMBIAR-ME` detiene el kit (la plantilla anterior traía un identificador de aspecto real).
- **Credenciales VC 2.0.** La plantilla usa `validFrom` y `validUntil` (antes `issuanceDate` y `expirationDate`). El `@context` es `[credentials/v2, contexto propio, suite Ed25519-2020]`.
- **Orden de tipos y contextos.** El kit guarda `credential_type` y `context` ordenados como lo hace Certify al buscar la configuración (orden por unidades UTF-16, mayúsculas antes que minúsculas). Con tipos personalizados y sin ese orden, emitir fallaba con «CredentialConfig not found».
- **Idempotencia.** El SQL de la credencial es un `INSERT … ON CONFLICT … DO UPDATE` con identificador determinista (la propia `CREDENTIAL_CONFIG_KEY_ID`; antes un UUID aleatorio) que conserva el estado (`status`). Nuevo `scripts/apply-credential.sh`: cambia el aspecto de la credencial sin recrear la base. Guía, sección 10.
- **Nombres de atributo validados.** Solo letras sin acento, dígitos y `_`, sin empezar por dígito, sin repetidos y sin chocar con términos de `credentials/v2`, de la suite o de la plantilla. Las etiquetas pasan a `CREDENTIAL_LABELS_JSON` (JSON; pueden llevar `:` y acentos). `CREDENTIAL_ATTRIBUTE_LABELS` ya no se admite (truncaba las etiquetas en el primer `:`). `CREDENTIAL_CONTEXT` ya no es una entrada: el kit genera el contexto, y el valor que haya en el `.env` se ignora. `CREDENTIAL_FORMAT` solo admite `ldp_vc`.
- **Logo obligatorio.** `LOGO_PATH` (un PNG) es obligatoria; `CREDENTIAL_LOGO_URL` desaparece y detiene el kit si sigue en el `.env`.
- **`did.json` conforme.** `install.sh` ejecuta `scripts/generate-did.sh` una vez que Certify está en marcha: corrige `assertionMethod` y `authentication` (que Certify deja con el DID a secas, y los verificadores conformes rechazan) y Caddy lo publica con `Cache-Control: no-cache`.
- **Modo proxy.** Nuevo `TLS_MODE=proxy` para instituciones con un proxy inverso propio: Caddy escucha solo HTTP en `CADDY_HTTP_PORT` (8080), sin certificados ni puerto 443; `CERTIFY_PUBLIC_URL` es obligatoria; `TRUSTED_PROXIES` indica de quién se acepta `X-Forwarded-For`. Los modos `domain` e `ip` siguen funcionando igual.
- **Orden de `docker compose` por modo.** El `docker-compose.yml` base ya no publica puertos: los añade un fichero superpuesto según el modo (`docker-compose.tls.yml` o `docker-compose.proxy.yml`). La orden exacta queda en `generated/compose-args`. Un `docker compose` a secas deja Caddy sin puertos y no lee las contraseñas generadas: use `docker compose $(cat generated/compose-args) …`.
- **Verificación al instalar.** `scripts/verify-install.sh` sustituye a `verify-health.sh`: además del estado de salud, ejecuta contra la dirección pública de la propia institución el diagnóstico de OGTIC (once comprobaciones) y dos del kit (`@context` de la metadata completo y cobertura de firma de una credencial de muestra). Una línea por comprobación, en español; **sale con código distinto de cero si algo falla**, y `install.sh` también. No necesita Node en el servidor (usa un contenedor `node:22-alpine`). Guía, sección 7. El estado de salud ya no se consulta desde internet.
- **Requisitos de `install.sh`.** Ahora comprueba también `envsubst` (paquete `gettext-base`) y `openssl`.
- **Documentación.** Nuevos `README.md` del kit y este `CHANGELOG.md`; reescritos `docs/01-PREREQUISITOS.md` y `docs/02-GUIA-DE-INSTALACION.md`; revisado `docs/IUGO-CUSTOMIZATIONS.md`.

### Para instituciones ya instaladas

**No ejecute `./install.sh` de esta versión sobre una instalación hecha con el kit anterior sin leer esto.** La migración detallada (qué hacer con la credencial emitida, cómo comunicarlo a las personas) es una tarea aparte que publicará OGTIC; mientras tanto, lo siguiente es lo que debe saber y lo único que se recomienda hacer.

**Qué pasaría si lo ejecuta tal cual**

1. **Su `.env` actual no pasará la validación.** Faltan `RESTAPI_TOKEN_URL` y `LOGO_PATH` (obligatorias); si `OAUTH_CLIENT_ID` conserva el marcador, también se detiene; `CREDENTIAL_LOGO_URL` y `CREDENTIAL_ATTRIBUTE_LABELS` detienen el kit. El kit se detiene antes de construir o arrancar nada, pero **antes de detenerse puede escribir `generated/.env.runtime` con contraseñas nuevas** (vea el punto siguiente): ponga la variable indicada allí antes de volver a intentarlo.
2. **Podría romper la conexión con su base de datos.** Si su instalación usa `postgres` y `local` (lo normal con el kit anterior), el kit nuevo generaría contraseñas distintas, que no coinciden con las ya grabadas en la base y en el almacén de llaves. **Antes de ejecutar nada, agregue `KIT_CONSERVAR_SECRETOS_POR_DEFECTO=1` al `.env`** (o fije en `POSTGRES_PASSWORD` la contraseña que ya tiene la base). Detalle: guía, sección 11.
3. **La credencial.** Su configuración actual guarda un `@context` que no cubre sus datos y un identificador aleatorio. Con la **misma** `CREDENTIAL_CONFIG_KEY_ID`, el kit la sobrescribiría en su sitio; con una clave **nueva**, crearía otra configuración y dejaría la vieja activa. Cuál conviene (lo recomendable es una clave nueva y que las personas pidan de nuevo su credencial) lo fijará el procedimiento de migración.
4. **Cambian los comandos.** Los `docker compose` del kit llevan ahora la configuración de `generated/compose-args`, y el estado de salud ya no se consulta desde internet.

**Qué puede hacer hoy sin riesgo**

- **Respalde** la base de datos, el almacén de llaves y su carpeta del kit (guía, sección 12). No use `docker compose down` sobre la instalación en uso.
- **Compruebe si su actuator está abierto.** Con el kit anterior lo estaba (todos sus endpoints y los valores de configuración). Desde cualquier equipo de internet:

  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" https://<su dirección>/v1/certify/actuator/env
  ```

  Si responde `200`, los secretos del servicio (contraseñas, secreto OAuth) han estado expuestos: avise a OGTIC y planifique rotarlos.
- **Revise sus registros.** Si construyó Certify desde una versión que contiene el commit `541f1d9`, cuente cuántas veces aparece la línea del token: `docker compose logs certify | grep -c "Raw access token"`. Si no es cero, los registros contienen tokens de acceso: limite el acceso a ellos y purgue lo que corresponda.
- **Avise a OGTIC** antes de cambiar nada y pida el procedimiento de migración. Si su instalación apuntaba al entorno de staging de Cuenta Única, necesitará además el cliente de producción.
