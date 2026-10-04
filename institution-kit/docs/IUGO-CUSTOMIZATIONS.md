# Personalizaciones de IUGO que el kit hereda del fork de Certify

El kit configura Certify con tres validaciones **relajadas** y con un nivel de registro **fijado**. Vienen del fork de IUGO (`docs/IUGO-CUSTOMIZATIONS.md` en la raíz del repositorio, que explica el origen) y están escritas en `templates/certify-default.properties.tpl`. Este documento dice, para cada una, **qué relaja, por qué, qué riesgo deja y cómo endurecerla**. Es la referencia que cita ese fichero.

**No las cambie sin probar la emisión con Cuenta Única de extremo a extremo**: un valor `true` que no case con los tokens reales rechaza a todos los ciudadanos con un error que no se parece a un problema de configuración.

## Resumen

| Propiedad | Valor del kit | Valor por defecto de Certify (Java) | Con `true` |
|---|---|---|---|
| `mosip.certify.authn.validate-audience` | `false` | `false` | El `aud` del token debe estar en `mosip.certify.authn.allowed-audiences` |
| `mosip.certify.authn.require-client-id-claim` | `false` | `false` | El token debe traer la claim `client_id` |
| `mosip.certify.issuance.validate-cnonce` | `false` | `false` | Se valida el `c_nonce` y el nonce del *proof* JWT |

El emisor propio de OGTIC (`inji-vc/stack/config/certify-soyyord.properties`) **no fija ninguna de las tres**: corre en producción con el valor por defecto del código, que es `false`. El kit las escribe de forma explícita para que sea visible, pero el comportamiento es el mismo.

Lo que **sí** se valida siempre, con estas tres en `false`: la firma del token contra el `jwks` de Cuenta Única, el emisor (`iss`, igualdad exacta con `AUTH_ISSUER_URL`), que `sub` exista, y las fechas (`iat` pasado, `exp` futuro). Además, el `scope` del token se compara con el de la configuración de la credencial.

## `validate-audience=false`

**Qué relaja.** `AccessTokenValidationFilter` solo añade el validador de `aud` si esta propiedad es `true`. Con `false`, Certify acepta cualquier token bien firmado por Cuenta Única aunque no vaya dirigido a este emisor.

**Por qué.** El fork documenta que, con CuentaDigital en 0.12.2, el `aud` llegaba a veces como arreglo vacío, y que la lista `allowed-audiences` de la plantilla no es fiable: su segunda entrada (`${authorization.url}/v1/esignet/vci/credential`) apunta a una ruta de eSignet que este despliegue no tiene, y la primera depende de `mosipbox.public.url`. Con la validación activa y una lista equivocada, se rechazaría todo. **No se ha medido** qué `aud` trae un token de producción de Cuenta Única; está pendiente.

**Riesgo.** Confusión de destinatario: un token que Cuenta Única emitió para *otra* aplicación (mismo emisor, firma válida, no caducado) sirve para pedir una credencial aquí. Lo acotan el `scope` (debe coincidir con `CREDENTIAL_SCOPE`) y que los datos salen de la API de la institución para el titular del token, pero no es una defensa de audiencia. Riesgo medio.

**Cómo endurecerla.** Obtener un token real de producción y leer su `aud`; poner ese valor exacto en `mosip.certify.authn.allowed-audiences`; pasar la propiedad a `true`; reiniciar `certify`; probar una emisión real.

## `require-client-id-claim=false`

**Qué relaja.** Con `true`, el filtro rechaza el token si no trae la claim `client_id`. Con `false`, la acepta ausente.

**Por qué.** El fork documenta que `client_id` / `azp` no siempre llegaba en los tokens de CuentaDigital. **No se ha medido** si los de producción de Cuenta Única la traen.

**Riesgo.** Certify no puede atar el token a una aplicación cliente concreta. Cuando `validate-cnonce` está en `true`, `JwtProofValidator` exige que la claim `iss` del *proof* (si la trae) coincida con ese `client_id`; con `validate-cnonce=false` esa comprobación tampoco se hace. Riesgo bajo.

**Cómo endurecerla.** Comprobar que el token de producción lleva `client_id`; entonces pasar a `true` y reiniciar.

## `validate-cnonce=false`

**Qué relaja.** Con `false`, `VCIssuanceServiceImpl` y `CertifyIssuanceServiceImpl` saltan la validación del `c_nonce` y del nonce del *proof* JWT, y escriben en cada petición el aviso `Skipping cNonce and proof nonce validation`. La firma del *proof* (posesión de la clave del titular) **sigue** comprobándose; lo que no se comprueba es que sea reciente y de un solo uso.

**Por qué.** El fork documenta que el `c_nonce` y el nonce del *proof* no cuadraban con OpenID4VCI en el flujo de la cartera, y `getValidClientNonce` rechazaba la petición.

**Riesgo.** Reutilización de pruebas de posesión: quien capture un *proof* y tenga un token válido puede pedir otra credencial atada a la misma clave. Necesita un token del propio ciudadano, así que el riesgo es bajo, pero no hay protección contra repetición.

**Cómo endurecerla.** Es la que más pruebas necesita (depende de la cartera y de Mimoto): activarla en un entorno de prueba y emitir con la cartera real antes de tocar producción.

## Registro (logs) del filtro del token

**Qué pasa.** El commit `541f1d9` («add token logs», 15-sep-2026) añadió en `AccessTokenValidationFilter` tres `log.info` que escriben el **token de acceso completo**, todas sus claims y la claim `ext` en cada petición al endpoint de credencial. Es un dato personal y una credencial al portador. (El documento del fork lo lista como «descartado a propósito»; el commit lo reintrodujo.) Incidente: `inji-vc/docs/incidentes/2026-10-04-tokens-de-acceso-en-logs-de-certify.md`.

**Qué hace el kit** (defensa en profundidad, solo configuración): `logging.level.io.mosip.certify.filter=WARN` en las properties **y** `templates/logback-kit.xml` (montado y referenciado por `LOGGING_CONFIG` en `docker-compose.yml`) con el logger `io.mosip.certify.filter` en `WARN`. El XML existe porque varias dependencias de MOSIP traen su propio `logback.xml` en el jar y el emisor propio comprobó que, con eso, Spring ignora `logging.file.name`; para `logging.level` no se midió, así que se fijó el nivel donde manda en cualquier caso.

**Qué NO hace.** No borra las líneas del fuente de Java: eso es una corrección del código del fork (revertir `541f1d9`), decisión aparte con IUGO. Mientras esas líneas existan, un cambio de nivel o de configuración las vuelve a activar. Los servidores que ya construyeron Certify desde esa rama tienen tokens en sus logs: purgarlos y revisar quién tiene acceso.
