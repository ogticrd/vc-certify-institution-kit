# Personalizaciones de IUGO que el kit hereda del fork de Certify

**Para quién es este documento.** Para el equipo de seguridad y de infraestructura de la institución. **No hace falta hacer nada** con él para instalar: el kit ya viene configurado así. Sirve para saber qué validaciones del token de acceso están relajadas, qué riesgo dejan y cómo endurecerlas, y qué hace el kit para que el token no quede escrito en los registros. Vuelva a la [guía de instalación](./02-GUIA-DE-INSTALACION.md) o a los [prerrequisitos](./01-PREREQUISITOS.md) cuando termine.

**Vocabulario.** Cuando una persona pide su credencial, la billetera presenta a Certify un **token de acceso** que emitió Cuenta Única: un documento firmado que dice quién es la persona y qué permiso tiene. Certify lo valida antes de entregar nada. El token trae campos llamados *claims* (`aud`: a quién va dirigido; `client_id`: qué aplicación lo pidió; `scope`: el permiso). La billetera acompaña su petición con un **proof**: una prueba firmada con la llave de la persona, que incluye un número de un solo uso (`c_nonce`) para que no se pueda repetir. El `jwks` es el conjunto de llaves públicas de Cuenta Única con el que Certify comprueba la firma del token.

El kit configura Certify con tres validaciones **relajadas** y con un nivel de registro **fijado**. Vienen del fork de IUGO (el documento `docs/IUGO-CUSTOMIZATIONS.md` de la raíz del repositorio explica su origen) y están escritas en `templates/certify-default.properties.tpl`. Este documento dice, para cada una, **qué relaja, por qué, qué riesgo deja y cómo endurecerla**. Es la referencia que cita ese fichero.

**No las cambie sin probar la emisión con Cuenta Única de extremo a extremo**: un valor `true` que no case con los tokens reales rechaza a todas las personas con un error que no se parece a un problema de configuración. Antes de endurecer cualquiera, coordine con OGTIC.

## Resumen

| Propiedad | Valor del kit | Valor por defecto de Certify (Java) | Con `true` |
|---|---|---|---|
| `mosip.certify.authn.validate-audience` | `false` | `false` | El `aud` del token debe estar en `mosip.certify.authn.allowed-audiences` |
| `mosip.certify.authn.require-client-id-claim` | `false` | `false` | El token debe traer la claim `client_id` |
| `mosip.certify.issuance.validate-cnonce` | `false` | `false` | Se valida el `c_nonce`, el nonce **y la firma** del *proof* JWT (posesión de la clave del titular) |

El emisor que OGTIC opera en producción **no fija ninguna de las tres**: corre con el valor por defecto del código, que es `false`. El kit las escribe de forma explícita para que sea visible, pero el comportamiento es el mismo.

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

**Qué relaja.** Con `false`, `VCIssuanceServiceImpl` y `CertifyIssuanceServiceImpl` saltan la validación del `c_nonce` y del nonce del *proof* JWT, y escriben en cada petición el aviso `Skipping cNonce and proof nonce validation`. **Con `false` el *proof* no se valida en absoluto, tampoco su firma**: en `CertifyIssuanceServiceImpl` la llamada a `proofValidator.validate(...)` está dentro del `if (validateCNonce)`. Esto se midió en la prueba de integración con Certify real (4-oct-2026): un *proof* con la firma rellena de basura y sin nonce se aceptó y la credencial salió atada al `did:jwk` de ese *proof*. (Una versión anterior de este documento decía que la firma del *proof* seguía comprobándose: era un error.)

**Por qué.** El fork documenta que el `c_nonce` y el nonce del *proof* no cuadraban con OpenID4VCI en el flujo de la cartera, y `getValidClientNonce` rechazaba la petición.

**Riesgo.** Certify no comprueba que quien pide la credencial posea la clave a la que se ata: con un token válido se puede pedir una credencial atada a **cualquier** `did:jwk` (la clave de otra persona, por ejemplo), y tampoco hay protección contra repetición. Necesita un token del propio ciudadano, así que el riesgo de abuso externo es bajo, pero la propiedad «la credencial está atada a la clave de su titular» no se cumple mientras esté en `false`. Riesgo medio.

**Cómo endurecerla.** Es la que más pruebas necesita (depende de la cartera y de Mimoto): activarla en un entorno de prueba y emitir con la cartera real antes de tocar producción.

## Registro (logs) del filtro del token

**Qué pasa.** El commit `541f1d9` («add token logs», 15-sep-2026) añadió en `AccessTokenValidationFilter` tres `log.info` que escriben el **token de acceso completo**, todas sus claims y la claim `ext` en cada petición al endpoint de credencial. Es un dato personal y una credencial al portador. (El documento del fork lo lista como «descartado a propósito»; el commit lo reintrodujo.) OGTIC lo tiene registrado como un incidente de seguridad.

**Qué hace el kit** (defensa en profundidad, solo configuración): `logging.level.io.mosip.certify.filter=WARN` en las properties **y** `templates/logback-kit.xml` (montado y referenciado por `LOGGING_CONFIG` en `docker-compose.yml`) con el logger `io.mosip.certify.filter` en `WARN`. El XML existe porque varias dependencias de MOSIP traen su propio `logback.xml` en el jar y en el emisor de OGTIC se comprobó que, con eso, Spring ignora `logging.file.name`; para `logging.level` no se midió, así que se fijó el nivel donde manda en cualquier caso.

**Cómo comprobar su servidor.** Desde `institution-kit/`, cuente cuántas veces aparece la línea del token en los registros de Certify; con la configuración del kit debería dar `0` (su efecto sobre un Certify real todavía está por medirse, así que no lo dé por supuesto):

```bash
docker compose $(cat generated/compose-args) logs certify | grep -c "Raw access token"
```

Si da un número mayor que cero, los registros ya contienen tokens (de una versión anterior, o de una configuración de registro cambiada).

**Lo que el filtro no cubre: el plugin de la API de datos.** Medido con Certify real y un token JWT válido: con la configuración del kit, el registro no contiene el token (ni «Raw access token» ni las claims decodificadas). Pero el plugin `restapi-dataprovider-plugin-0.3.0.jar` (precompilado; su fuente no está en este repositorio) imprime por la salida estándar, en cada emisión, `identityDetails: {ext={username=<cédula>}, sub=…}`, `DataProviderRepositoryImpl: Attempting to fetch data for ID: <cédula>`, `Target API URL: …/<cédula>` y `Target API Response Body: {…todos los atributos…}`. No usa el sistema de registro, así que ningún nivel ni XML lo apaga. Es el mismo incidente de datos personales por otra vía; su corrección es una decisión sobre el código del plugin (OGTIC/IUGO).

**Qué NO hace.** No borra las líneas del fuente de Java: eso es una corrección del código del fork (revertir `541f1d9`), decisión que toman OGTIC e IUGO. Mientras esas líneas existan, un cambio de nivel o de configuración las vuelve a activar. Los servidores que ya construyeron Certify desde esa rama pueden tener tokens en sus registros: revíselos, purgue los que los contengan y revise quién tiene acceso a ellos.
