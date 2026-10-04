# Lista de prerrequisitos para instituciones emisoras

Este documento lista todo lo que una institución debe tener listo **antes** de ejecutar el kit. Si algún punto no está claro, resuélvalo con OGTIC antes de instalar: varios valores solo los entrega OGTIC y el kit no arranca sin ellos.

El kit levanta tres contenedores en un servidor propio de la institución: **Inji Certify** (el emisor), **PostgreSQL** (su base de datos) y **Caddy** (la puerta de entrada pública). Una descripción general está en el [README del kit](../README.md).

**Siguiente paso:** cuando complete esta lista, continúe con [02-GUIA-DE-INSTALACION.md](./02-GUIA-DE-INSTALACION.md).

---

## 1. Infraestructura

El equipo de infraestructura debe cubrir esta sección completa antes de la instalación.

### 1.1 Herramientas obligatorias en el servidor

- **Git**: para clonar el repositorio con el kit.
- **Docker Engine 24 o superior y Docker Compose v2** (el comando `docker compose`, no `docker-compose`). Los componentes se levantan con Docker Compose.
- **`curl` y `jq`**: `jq` lo usan los scripts para leer las respuestas del servicio.
- **`openssl`**: el kit lo usa para generar contraseñas aleatorias.
- **`iconv`**: viene con Linux (glibc) y macOS. El kit lo usa para escribir los acentos del nombre de la institución en el formato que Certify lee (`install.sh` se detiene si no está).
- **`envsubst`**: viene en el paquete `gettext-base` (Debian y Ubuntu: `sudo apt-get install -y gettext-base`) o `gettext` (RHEL y Fedora). El kit lo usa para generar la configuración y `install.sh` se detiene si no está.

**No hace falta instalar Node.js.** Dos pasos del kit (generar el contexto de la credencial y verificar la instalación) usan Node; si el servidor no lo tiene, los ejecutan dentro de un contenedor `node:22-alpine` que Docker descarga la primera vez.

### 1.2 Hardware requerido

- 4 vCPU
- 8 GB de memoria RAM
- 50 GB de disco
- Linux x86_64 compatible con Docker Engine, por ejemplo Ubuntu 22 o 24

### 1.3 Acceso al repositorio

Solicite a OGTIC el acceso y la dirección del repositorio y de la rama que debe clonar. Debe clonar el repositorio **completo**, no solo la carpeta `institution-kit/`: la imagen de Certify se construye con el código que está fuera de esa carpeta.

### 1.4 Cómo será alcanzable el emisor desde internet

El emisor debe ser alcanzable desde internet por HTTPS: las billeteras y los verificadores leen sus documentos públicos. Elija **uno solo** de los tres modos y configúrelo con `TLS_MODE` en el archivo `.env`.

| Modo | Úselo cuando… |
|---|---|
| `domain` | Tiene un nombre de dominio que apunta al servidor y no hay un proxy inverso delante. |
| `ip` | No tiene dominio: solo la IP pública del servidor. |
| `proxy` | Ya existe un proxy inverso de la institución (nginx, F5, un balanceador) que publica el servicio y termina el HTTPS. |

#### Modo dominio (`TLS_MODE=domain`)

- Registre un subdominio DNS, por ejemplo `certify.institucion.gob.do`.
- Agregue un registro tipo A (o AAAA) hacia la IP pública fija del servidor.
- En el `.env` indique `CERTIFY_PUBLIC_HOST` (el dominio, **en minúsculas**, sin `https://`, sin barra final ni puerto) y `CADDY_ACME_EMAIL` (un solo correo de infraestructura; Let's Encrypt lo usa para avisos).

Caddy obtiene y renueva solo el certificado HTTPS con Let's Encrypt (validación ACME HTTP-01). El servidor necesita una IP pública fija, o un mecanismo equivalente (IP reservada, DNS dinámico estable): sin ella, el registro DNS no apunta de forma confiable al emisor.

#### Modo IP (`TLS_MODE=ip`)

- En el `.env` indique la IP pública del servidor (`SERVER_PUBLIC_IP`; no una IP de red interna como `192.168.x.x`), el proveedor de nombres (`IP_DNS_PROVIDER`, por defecto `sslip.io`; también sirve `nip.io`) y `CADDY_ACME_EMAIL`.
- El kit deriva un nombre usable, por ejemplo `https://203-0-113-10.sslip.io`.
- Caddy pide el certificado a Let's Encrypt igual que en modo dominio, por lo que necesita el puerto 80 abierto desde internet.

#### Modo proxy (`TLS_MODE=proxy`)

El HTTPS lo pone el proxy de la institución, no el kit. Caddy escucha solo HTTP, **no pide certificados y no abre el 443**. Necesita:

- **`CERTIFY_PUBLIC_URL`**, obligatoria: la dirección pública que sirve su proxy, con la forma `https://certify.institucion.gob.do` (sin ruta y sin barra final). En los otros dos modos el kit la calcula solo; en este no puede, porque el nombre público lo decide el proxy.
- Que el proxy **reenvíe a `http://<este servidor>:<CADDY_HTTP_PORT>`** (8080 por defecto).
- Que el proxy **envíe `X-Forwarded-For` con la IP real del cliente**. De eso depende que el estado de salud interno de Certify no quede visible desde internet (detalle en la guía, sección 3C).
- Que el servidor pueda **alcanzar su propia dirección pública**: la verificación final se hace desde el servidor contra esa URL y, además, **Certify (el contenedor) la descarga al firmar una credencial** (su contexto propio, `/contextos/<clave>.json`; véase la tabla de puertos de salida). Sin esa salida y vuelta por su propio proxy, la emisión falla.

### 1.5 Puertos de red

Los puertos de entrada dependen del modo.

| Puerto | Dirección | Modos | Origen o destino | Razón |
|---|---|---|---|---|
| 80/tcp | entrada | `domain`, `ip` | Internet → servidor (Caddy) | Validación ACME HTTP-01 de Let's Encrypt y renovación del certificado. |
| 443/tcp | entrada | `domain`, `ip` | Internet → servidor (Caddy) | HTTPS público del emisor. |
| `CADDY_HTTP_PORT` (8080 por defecto) | entrada | `proxy` | **Solo el proxy** → servidor (Caddy) | El proxy reenvía aquí el tráfico en HTTP. El servidor **no** abre el 80 ni el 443. |
| 443/tcp | salida | todos | servidor → `auth.cuentaunica.gob.do` | Descarga de las llaves públicas de Cuenta Única para validar el token de la persona. |
| 443/tcp | salida | todos | servidor → `RESTAPI_TOKEN_URL` y `RESTAPI_BASE_URL` | Obtener el token de la API de datos y los datos de la persona. |
| 443/tcp | salida | todos | servidor → registros de Docker y Maven | Descarga de imágenes y dependencias en la primera construcción. |
| 443/tcp | salida | todos | contenedor de Certify → `www.w3.org` y `w3id.org` | Certify descarga los contextos JSON-LD estándar (`credentials/v2` y el de la suite Ed25519) al firmar. Si no llegan, emitir falla con `ERROR_SIGNING_QR_DATA` («Error occurred during canonicalization»). Comprobado bloqueando cada uno por separado. |
| 443/tcp | salida | todos | contenedor de Certify → **su propia dirección pública** (`CERTIFY_PUBLIC_URL`) | Al firmar, Certify descarga también el contexto propio de la credencial por esa dirección. Si el contenedor no puede llegar a ella (DNS interno, cortafuegos que no permite salir y volver a entrar), mismo error. |

**Sobre `CADDY_HTTP_PORT` (modo proxy).** Docker publica ese puerto en **todas las interfaces** del servidor, no solo en la que ve el proxy. Proteja el puerto de una de estas dos formas:

- Con el **cortafuegos** del servidor o de la red, de modo que solo la dirección del proxy pueda llegar a `CADDY_HTTP_PORT`. Es la forma recomendada.
- Si el proxy corre **en el mismo servidor**, haciendo que el puerto solo escuche en `127.0.0.1`: edite `docker-compose.proxy.yml` y cambie `"${CADDY_HTTP_PORT:-8080}:80"` por `"127.0.0.1:${CADDY_HTTP_PORT:-8080}:80"`. (El kit no trae esta variante como opción; es un cambio local suyo y hay que repetirlo cuando actualice el kit.)

Nota: Docker escribe sus propias reglas en el cortafuegos del servidor, por lo que reglas hechas con `ufw` o equivalentes pueden no afectar a un puerto publicado por Docker. Compruebe desde otra máquina que el puerto realmente queda cerrado.

El puerto interno de Certify (8090) no se publica nunca: Caddy lo alcanza por la red interna de Docker.

---

## 2. Datos que debe tener definidos

### 2.1 Datos de la institución y de la API

- **Identificador único del emisor** (`INSTITUTION_ID`). Úselo con letras sin acento, dígitos y guion bajo (`INTRANT`, `MIMARENA`; **un guion `-` no vale**): se usa para formar el nombre del tipo de credencial.
- **Nombre de la institución** (`INSTITUTION_DISPLAY_NAME`): lo ve la persona en la billetera.
- **URL base de la API** que entrega los datos de la persona (`RESTAPI_BASE_URL`), que le indica OGTIC.
- **Un ejemplo de la respuesta de esa API.** Los nombres de los campos que quiera incluir en la credencial salen de ahí, con la regla de nombres de la sección 3.

### 2.2 Accesos que entrega OGTIC

Hay **dos cosas distintas** que no deben confundirse. Las dos las entrega OGTIC y la institución no las crea por su cuenta.

1. **El inicio de sesión de la persona: cliente de Cuenta Única de producción.**
   Cuenta Única es el sistema con el que la persona se identifica antes de pedir su credencial. Para que su emisor participe, OGTIC registra un *cliente* de su institución en Cuenta Única **de producción** (`https://auth.cuentaunica.gob.do`). Ese cliente tiene un identificador y una clave:
   - `OAUTH_CLIENT_ID`
   - `OAUTH_CLIENT_SECRET`

   Un cliente de pruebas o del entorno de staging **no sirve** en producción: el kit apunta a producción por defecto y rechaza los tokens de otro servidor.

2. **El token de la API de datos: `RESTAPI_TOKEN_URL`.**
   Para pedir a la API de la institución los datos de la persona, Certify necesita su propio token, que se obtiene en una dirección que entrega OGTIC: `RESTAPI_TOKEN_URL`. **No es** el token de la persona ni tiene que ver con Cuenta Única. No existe valor por defecto: sin ella, el kit no genera nada. Confírmela con OGTIC antes de instalar.

Según la configuración del kit, el par `OAUTH_CLIENT_ID` y `OAUTH_CLIENT_SECRET` es también el que Certify presenta en `RESTAPI_TOKEN_URL` al pedir el token de la API de datos. Si OGTIC le entrega credenciales distintas para cada cosa, consúltelo antes de instalar.

### 2.3 Credencial que va a emitir

El kit carga solo la configuración de la credencial. Necesita:

- **`CREDENTIAL_CONFIG_KEY_ID`**: nombre técnico de la credencial, por ejemplo `DriverLicenseCredential`. Acuérdelo con OGTIC. **Forma parte de la dirección pública de su contexto y de su logo**, por lo que cambiarlo después equivale a crear otra credencial.
- **`CREDENTIAL_ATTRIBUTES`**: la lista de campos, separados por coma. Piénsela con cuidado: **una vez que emita credenciales, cambiar los atributos implica emitir de nuevo** (guía, sección 5).
- **`CREDENTIAL_SCOPE`**: el permiso que debe traer el token de Cuenta Única para emitir esta credencial. Use el valor de la plantilla salvo que OGTIC indique otro.
- **Un logo en formato PNG** (`LOGO_PATH`), **obligatorio**. Es la imagen de su institución en la tarjeta de la billetera.
  - Debe ser un fichero PNG de verdad (el kit comprueba la cabecera del fichero; renombrar un JPG o un SVG a `.png` no sirve). Las billeteras no muestran logos SVG.
  - Póngalo dentro de la carpeta del kit o indique una ruta completa. El kit lo copia y lo sirve en `https://<su dirección>/logos/<CREDENTIAL_CONFIG_KEY_ID>.png`. Ya no existe un logo por defecto ni la variable `CREDENTIAL_LOGO_URL`.
  - No hay límite de tamaño comprobado: use una imagen ligera (unos pocos cientos de píxeles de lado).

De forma opcional puede indicar: el nombre que se muestra en la billetera (`CREDENTIAL_DISPLAY_NAME`), los colores de la tarjeta, las etiquetas en español de cada atributo (`CREDENTIAL_LABELS_JSON`), el DID (`DID_URL`) y los tipos (`CREDENTIAL_TYPE`). Todas están descritas en la guía, sección 4.

---

## 3. Reglas para los nombres de los atributos

Los nombres de `CREDENTIAL_ATTRIBUTES` son nombres técnicos, no lo que ve la persona. Solo admiten **letras sin acento, dígitos y guion bajo**, sin espacios, sin `:` y sin empezar por un dígito: `numero_licencia`, `fullName`. Si la API de su institución devuelve campos con espacios, acentos o dos puntos (por ejemplo `Número de licencia`), hay que darles un nombre técnico válido; lo que verá la persona se define aparte con las etiquetas. La guía, sección 4.5, explica el porqué y los nombres que no se pueden usar.

---

## 4. DID y firma de la credencial

El archivo `did.json` es el documento público de identidad del emisor. Contiene la **llave pública** con la que cualquiera (una billetera, un verificador) comprueba que una credencial la firmó esa institución y que no se modificó. La dirección lógica de ese documento se llama **DID**; en este kit tiene la forma `did:web:<su dirección pública>`.

La llave privada nunca se publica: queda en el servidor y Certify la usa para firmar. El kit crea la llave en el primer arranque, y el `did.json` se publica **después** de que Certify esté en marcha, porque lleva esa llave. Esto lo hace `install.sh` por usted.

Por el mismo motivo, **respalde el volumen del keystore de Certify y la base de datos** (guía, sección 12): si se pierden, el emisor tendría que crear llaves nuevas y las credenciales ya emitidas dejarían de verificarse.

---

## 5. Qué le pedirá OGTIC al final de la instalación

Instalar el emisor no basta: OGTIC debe registrarlo en la plataforma central de billeteras. Al terminar, `install.sh` imprime estos datos para que usted se los envíe:

| Dato | Ejemplo |
|---|---|
| `INSTITUTION_ID` | `INTRANT` |
| `CERTIFY_PUBLIC_URL` | `https://certify.institucion.gob.do` |
| `OAUTH_CLIENT_ID` | el que le entregó OGTIC |
| `CREDENTIAL_CONFIG_KEY_ID` | `DriverLicenseCredential` |
| Nombre visible de la credencial | `INTRANT` |

No envíe nunca el `OAUTH_CLIENT_SECRET` ni las contraseñas. Además, las direcciones `<su dirección>/.well-known/openid-credential-issuer` y `<su dirección>/.well-known/did.json` deben responder desde internet; `install.sh` las imprime junto con los datos de arriba.

---

## 6. Consideraciones de seguridad para su equipo

Hoy Certify y la plataforma central tienen validaciones del token de Cuenta Única que están **relajadas** de fábrica (audiencia, `client_id` y `c_nonce`). Qué relaja cada una, el riesgo y cómo endurecerla está en [`IUGO-CUSTOMIZATIONS.md`](./IUGO-CUSTOMIZATIONS.md). Pruebe siempre una emisión real de principio a fin antes de cambiarlas.

Lo que sí se valida siempre: la firma del token contra las llaves públicas de Cuenta Única, el emisor del token, que exista el sujeto, las fechas y que el permiso (`scope`) coincida con el de la credencial.
