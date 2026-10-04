# Kit de instituciones — emisor de credenciales verificables

Este kit instala, en un servidor de su institución, el **emisor** que entrega credenciales verificables (por ejemplo, una licencia, un carné o una constancia) a la persona que las pide desde la app de billetera ciudadana.

Una **credencial verificable** es un documento digital con los datos de la persona, **firmado** por la institución que lo emite. Cualquiera puede comprobar con la llave pública de la institución que el documento es de ella y que nadie lo cambió después. El kit se encarga de la parte técnica de esa firma y de dejar el emisor listo para que OGTIC lo conecte con la billetera.

> Este README es el del kit. El `README.md` de la raíz del repositorio es el del proyecto Inji Certify (upstream) y no habla de instituciones.

## Qué instala

El kit levanta tres contenedores con Docker Compose:

| Contenedor | Para qué sirve |
|---|---|
| **Certify** (Inji Certify) | El emisor: valida a la persona, pide sus datos a la API de su institución y firma la credencial. Se construye desde este repositorio. |
| **PostgreSQL** | Guarda la configuración de la credencial y las llaves de firma del emisor. |
| **Caddy** | La puerta de entrada pública: entrega los documentos públicos del emisor (metadata, `did.json`, contexto y logo) y reenvía a Certify **solo lo que la billetera y los verificadores usan** (lista blanca: el endpoint de emisión, la metadata, la lista de estado); todo lo demás, incluido el panel interno (actuator), la gestión de la credencial y el flujo pre-autorizado, responde 404. En los modos `domain` e `ip` también obtiene el certificado HTTPS. Los tres contenedores se reinician solos. |

Además genera la configuración, corrige el documento público de identidad del emisor (`did.json`) y, al terminar, **verifica la instalación** contra su propia dirección pública (incluido que lo que Certify publica coincida con su `.env`).

## Requisitos (resumen)

1. Un servidor Linux x86_64 con 4 vCPU, 8 GB de RAM y 50 GB de disco, con Docker Engine 24 o superior y Docker Compose v2.
2. Herramientas en el servidor: `git`, `curl`, `jq`, `openssl`, `iconv` (viene con Linux) y `envsubst` (paquete `gettext-base` en Debian y Ubuntu).
3. Salida a internet desde el servidor (imágenes de Docker, dependencias Maven en la primera construcción, Cuenta Única y, al emitir, `www.w3.org` y `w3id.org` para los contextos estándar); Certify también debe poder alcanzar su propia dirección pública.
4. Una forma de ser alcanzable desde internet por HTTPS: un dominio propio, o solo una IP pública, o un proxy inverso de la institución que ya publica el servicio.
5. Lo que entrega OGTIC (cliente de Cuenta Única **de producción**, URL del token de la API de datos, URL de la API) y un **logo PNG** de la institución.

La lista completa está en [`docs/01-PREREQUISITOS.md`](docs/01-PREREQUISITOS.md).

## Los tres modos de acceso público

Se elige uno solo con `TLS_MODE` en el archivo `.env`.

| Modo | Úselo cuando… | Quién pone el HTTPS | Puertos que abre el kit | Variables propias |
|---|---|---|---|---|
| `domain` | La institución tiene un nombre de dominio (por ejemplo `certify.institucion.gob.do`) que apunta al servidor. Es el modo recomendado si no hay proxy. | Caddy, con un certificado de Let's Encrypt | 80 y 443 | `CERTIFY_PUBLIC_HOST`, `CADDY_ACME_EMAIL` |
| `ip` | No hay dominio: solo la IP pública del servidor. El kit deriva un nombre del tipo `203-0-113-10.sslip.io`. | Caddy, con un certificado de Let's Encrypt | 80 y 443 | `SERVER_PUBLIC_IP`, `IP_DNS_PROVIDER`, `CADDY_ACME_EMAIL` |
| `proxy` | Ya hay un proxy inverso de la institución (nginx, F5, un balanceador) que publica el servicio y termina el HTTPS. | El proxy de la institución | Solo `CADDY_HTTP_PORT` (8080 por defecto), en HTTP | `CERTIFY_PUBLIC_URL`, `CADDY_HTTP_PORT`, `TRUSTED_PROXIES` |

## El flujo en seis pasos

1. **Preparar el `.env`.** Copie `.env.example` a `.env` y complételo con los valores de su institución y los que entrega OGTIC. Antes de decidir los atributos de la credencial, lea la sección 5 de la guía: no se pueden cambiar después sin emitir de nuevo.
2. **Ejecutar `./install.sh`.** Valida el `.env`, genera la configuración, construye la imagen de Certify (varios minutos la primera vez), levanta los tres contenedores y corrige el `did.json`.
3. **Leer la verificación.** Al final, `install.sh` ejecuta `verify-install.sh`, que hace una línea por comprobación (`OK`, `FALLA`, `AVISO`, `PENDIENTE`). Debe terminar en «la instalación pasa la verificación». La guía explica cada línea y qué hacer si algo falla.
4. **Enviar los datos a OGTIC.** `install.sh` imprime al final los datos que OGTIC necesita para registrar su emisor (identificador de institución, URL pública, identificador del cliente de Cuenta Única, clave de la credencial y nombre visible).
5. **Alta en la app.** OGTIC registra su emisor en la billetera. Hasta que lo confirme, ninguna persona puede emitir la credencial aunque la verificación haya pasado.
6. **Prueba.** Con el alta confirmada, una persona de la institución pide su credencial desde la app y comprueba que se emite y que se ve con el nombre, el logo y las etiquetas esperados.

## Documentación

| Documento | Para qué |
|---|---|
| [`docs/01-PREREQUISITOS.md`](docs/01-PREREQUISITOS.md) | Qué debe tener listo antes de instalar: servidor, red y puertos por modo, logo, accesos de Cuenta Única y datos para OGTIC. |
| [`docs/02-GUIA-DE-INSTALACION.md`](docs/02-GUIA-DE-INSTALACION.md) | La guía paso a paso: todas las variables del `.env`, el contexto, `install.sh`, cómo leer la verificación, cómo cambiar la credencial, los secretos, el modo proxy y los problemas frecuentes. |
| [`docs/IUGO-CUSTOMIZATIONS.md`](docs/IUGO-CUSTOMIZATIONS.md) | Tres validaciones del token que el kit hereda relajadas del proyecto base, el riesgo de cada una y el registro de tokens. Para el equipo de seguridad. |
| [`CHANGELOG.md`](CHANGELOG.md) | Qué cambió respecto al kit anterior (`dr-implementation-kit`) y qué deben hacer las instituciones que ya instalaron. |

## Si ya instaló una versión anterior del kit

**No ejecute `./install.sh` de esta versión sobre una instalación vieja sin leer antes la sección «Para instituciones ya instaladas» de [`CHANGELOG.md`](CHANGELOG.md).** El kit nuevo exige variables nuevas y cambia la credencial. **No genera contraseñas nuevas sobre una instalación existente**: si siguen siendo `postgres` / `local`, se detiene y le explica cómo rotarlas; y si los datos de PostgreSQL están en el volumen anónimo del kit anterior, se detiene y explica cómo migrarlos al volumen con nombre. OGTIC publicará aparte el procedimiento de migración de la credencial.

## Para quien mantiene el kit

Las pruebas automáticas (sin Docker) usan solo Node 22. Desde la raíz del repositorio:

```bash
node --test "institution-kit/test/*.test.mjs"
```

El glob entre comillas es obligatorio. Con `KIT_VELOCITY_CP` apuntando a Velocity 1.7 y velocity-tools 3.1 la plantilla de la credencial se prueba con Velocity real (el CI de GitHub lo hace: `.github/workflows/kit.yml`, que además valida con `caddy validate` el Caddyfile de los tres modos). El motor de verificación de `institution-kit/diagnostico/` es una copia de OGTIC con su procedencia anotada; no se edita (ver la guía, sección 12).
