# Guía de instalación — Kit emisor

Esta guía le indica, paso a paso, cómo instalar y poner en marcha el kit en el servidor de su institución, cómo comprobar que quedó bien y cómo cambiar la credencial después.

Al terminar, el servicio de emisión de credenciales estará ejecutándose en su servidor y accesible por internet con una dirección segura (`https://...`).

**Antes de comenzar**, complete la lista de prerrequisitos: [01-PREREQUISITOS.md](./01-PREREQUISITOS.md).

## Contenido

1. Confirmación de prerrequisitos
2. Entrar al servidor y ubicar el kit
3. Elegir el modo de acceso público (3A dominio, 3B IP, 3C proxy)
4. Completar el archivo `.env` (incluye la tabla de **todas** las variables)
5. Qué es el contexto y por qué no se edita una vez publicado
6. Ejecutar la instalación (`install.sh`) y qué hace cada fase
7. Cómo leer la verificación (`verify-install.sh`)
8. Comprobar a mano
9. Qué enviar a OGTIC
10. Cambiar la credencial después de instalar (`apply-credential.sh`)
11. Secretos y superficie expuesta (contraseñas, actuator, registros)
12. Reinstalar, actualizar y respaldar
13. Problemas frecuentes

---

## 1. Confirmación de prerrequisitos

- [ ] Tengo acceso al servidor (terminal o conexión remota / SSH).
- [ ] En el servidor ya están instalados: Git, Docker (24 o superior), Docker Compose v2, `curl`, `jq`, `openssl` y `envsubst` (paquete `gettext-base`).
- [ ] Tengo los valores que entregó OGTIC: identificador de institución, URL de la API de datos, **URL del token de la API de datos** (`RESTAPI_TOKEN_URL`), y el **cliente de Cuenta Única de producción** (`OAUTH_CLIENT_ID` y `OAUTH_CLIENT_SECRET`).
- [ ] Tengo el **logo de la institución en formato PNG**.
- [ ] Tengo definidos la clave y los atributos de la credencial (sección 4.5 y sección 5).
- [ ] Ya tengo un dominio, o voy a usar el modo IP, o hay un proxy inverso; y la red correspondiente está configurada según los prerrequisitos.

---

## 2. Entrar al servidor y ubicar el kit

1. Conéctese al servidor con la herramienta que use su equipo de infraestructura (terminal local o SSH).

2. Si aún no tiene el repositorio en el servidor, clone el que le indicó OGTIC (el repositorio **completo**) y entre a la carpeta del kit:

```bash
git clone <url-proporcionada-por-ogtic>
cd <carpeta-del-repositorio>/institution-kit
```

Si ya lo clonó antes, entre directamente a la carpeta `institution-kit` de su copia.

3. Compruebe que está en la carpeta correcta:

```bash
ls -la
```

Debe ver, entre otros archivos: `install.sh`, `.env.example` y `docker-compose.yml`. Si no los ve, no está en `institution-kit/`: revise la ruta con `pwd`.

**Todos los comandos de esta guía se ejecutan desde la carpeta `institution-kit/`.**

---

## 3. Elegir el modo de acceso público

El kit necesita saber cómo va a ser alcanzable desde internet. Hay tres modos. Elija **uno solo**.

| Si su institución… | Elija |
|---|---|
| Tiene un nombre de dominio que apunta al servidor (ej. `certify.institucion.gob.do`) y no hay proxy delante | Modo dominio → sección **3A** |
| Solo tiene la IP pública del servidor, sin dominio propio | Modo IP → sección **3B** |
| Ya tiene un proxy inverso (nginx, F5, balanceador) que publica el servicio y termina el HTTPS | Modo proxy → sección **3C** |

**Importante:** no mezcle los modos. Configure solo las variables del modo elegido.

### 3A. Modo dominio

En el archivo `.env` (sección 4):

```bash
TLS_MODE=domain
CERTIFY_PUBLIC_HOST=certify.institucion.gob.do
CADDY_ACME_EMAIL=infra@institucion.gob.do
```

- `CERTIFY_PUBLIC_HOST`: el nombre de dominio, **en minúsculas**, sin `https://`, sin barra final, sin puerto (en este modo Caddy usa el 80 y el 443), sin ruta ni `@`, con al menos dos etiquetas (`certify.institucion.gob.do`). Un nombre con acentos va en punycode (`xn--…`). Cualquier otra forma detiene el kit **antes de generar nada**, con un mensaje que nombra la variable.
- `CADDY_ACME_EMAIL`: un correo de su equipo de infraestructura, una sola dirección. Let's Encrypt lo usa para el certificado HTTPS automático.

Con `TLS_MODE=domain`, el kit no usa `SERVER_PUBLIC_IP` ni `IP_DNS_PROVIDER`. La dirección pública será `https://` + `CERTIFY_PUBLIC_HOST`. Puertos: 80 y 443 abiertos desde internet; el DNS debe apuntar ya al servidor al instalar.

### 3B. Modo IP

En el archivo `.env`:

```bash
TLS_MODE=ip
SERVER_PUBLIC_IP=203.0.113.10
IP_DNS_PROVIDER=sslip.io
CADDY_ACME_EMAIL=infra@institucion.gob.do
```

- `SERVER_PUBLIC_IP`: la IP pública del servidor donde corre Docker (no una IP interna tipo `192.168.x.x`), en IPv4 decimal sin ceros a la izquierda (`203.0.113.10`; `999.1.1.1` o `01.2.3.4` se rechazan).
- `IP_DNS_PROVIDER`: deje `sslip.io` salvo que OGTIC le indique otro valor (`nip.io`); es un nombre de dominio en minúsculas.
- `CADDY_ACME_EMAIL`: correo de infraestructura para Let's Encrypt.

El kit convierte la IP en un nombre usable (los puntos se reemplazan por guiones). Con `203.0.113.10`, la dirección pública será `https://203-0-113-10.sslip.io`. Con `TLS_MODE=ip`, el kit no usa `CERTIFY_PUBLIC_HOST`. Puertos: 80 y 443 abiertos desde internet.

### 3C. Modo proxy (detrás de un proxy inverso de la institución)

Use este modo si ya hay un proxy inverso que publica el emisor en internet y termina el HTTPS. Caddy **no** pide certificados ni abre el 443: escucha solo HTTP.

En el archivo `.env`:

```bash
TLS_MODE=proxy
CERTIFY_PUBLIC_URL=https://certify.institucion.gob.do
# CADDY_HTTP_PORT=8080
# TRUSTED_PROXIES=private_ranges
```

- `CERTIFY_PUBLIC_URL` es **obligatoria**: `https://` + el dominio público que sirve su proxy, **en minúsculas**, sin ruta ni barra final (se admite `:puerto`). Con otro valor, el kit se detiene con un mensaje. `http://localhost` o `http://127.0.0.1` solo se admiten para pruebas locales y solo con `KIT_PERMITIR_HTTP=1` (aun así `verify-install.sh` no podrá pasar: el diagnóstico solo habla `https`).
- `CADDY_ACME_EMAIL` no se usa y puede quedar como esté.
- El servidor publica **solo** `CADDY_HTTP_PORT` (8080 por defecto), que apunta al puerto 80 de Caddy. No se publica el 80 ni el 443 del servidor. Ese puerto se publica en **todas las interfaces**: protéjalo con el cortafuegos para que solo el proxy llegue a él (o, si el proxy corre en el mismo servidor, véase el prerrequisito 1.5).
- `TRUSTED_PROXIES` indica de qué direcciones se acepta la cabecera `X-Forwarded-For`. Por defecto `private_ranges` (las redes privadas: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1 y fc00::/7). Si conoce la IP de su proxy, póngala (varias, separadas por espacio; también admite rangos `10.1.2.0/24`); es más estricto. **`0.0.0.0/0` y `::/0` se rechazan**: confían en cualquier origen y cualquiera de internet podría fijar su propio `X-Forwarded-For` y hacerse pasar por una IP interna.

**Qué debe hacer su proxy**

1. **Terminar el HTTPS** con un certificado válido para el dominio de `CERTIFY_PUBLIC_URL`.
2. **Reenviar todas las rutas** a `http://<este servidor>:<CADDY_HTTP_PORT>`. Caddy decide qué publicar y qué no, con una lista blanca (sección 11): solo `/.well-known/…`, `/v1/certify/issuance/credential`, `/v1/certify/.well-known/…`, la lista de estado, `/contextos/…` y `/logos/…`; lo demás es 404, incluida la raíz `/`. **Para sondear que el servicio vive** (balanceador, monitor) use `/.well-known/openid-credential-issuer`, no `/`.
3. **Enviar `X-Forwarded-For` con la IP real del cliente.** Caddy cree en esa cabecera solo si la conexión viene de `TRUSTED_PROXIES`, y la usa para decidir quién puede ver el estado de salud interno. Si el proxy no la envía, Caddy ve la IP del propio proxy (privada), considera «interno» a cualquiera y el estado de salud (`{"status":"UP"}`, sin más detalles) queda visible desde internet. No se filtra nada más, pero no es lo que se busca.
4. **Pasar el `Host` original.** El kit no lo necesita para enrutar (en este modo Caddy atiende cualquier `Host`, y la dirección pública que Certify publica sale de `CERTIFY_PUBLIC_URL`), pero es la práctica habitual y evita sorpresas.
5. **No modificar ni guardar en caché** las respuestas de `/contextos/*`, `/logos/*` y `/.well-known/did.json`. El kit las sirve con `Cache-Control: no-cache` y la verificación lo exige (sección 7).

Ejemplo orientativo para nginx (no se ha probado con el kit; adáptelo a su proxy):

```nginx
location / {
    proxy_pass         http://IP_DEL_SERVIDOR_DEL_KIT:8080;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Forwarded-For   $remote_addr;
    proxy_set_header   X-Forwarded-Proto https;
}
```

Si hay otro proxy o una red de distribución delante del suyo, la IP real del cliente puede no ser `$remote_addr`: ajústelo.

**Orden de trabajo en modo proxy.** `install.sh` termina verificando la instalación contra `CERTIFY_PUBLIC_URL`, que es la dirección de **su** proxy. Si el proxy aún no reenvía a este servidor, esa verificación fallará aunque el kit esté bien (verá `No responde` o un error de certificado en la comprobación 1). Es normal: configure el proxy y repita `./scripts/verify-install.sh`.

---

## 4. Completar el archivo `.env`

1. Desde `institution-kit/`, copie la plantilla y restrinja el acceso (contendrá una clave):

```bash
cp .env.example .env
chmod 600 .env
```

2. Ábralo con el editor que prefiera (por ejemplo `nano .env`) y complete los valores. Guárdelo en **UTF-8**.

El `.env` lo lee `bash`: si un valor tiene espacios, escríbalo entre comillas; si tiene `$`, use comillas simples.

### 4.1 Referencia: todas las variables

Las filas «Siempre» se piden en cualquier modo. Una variable «opcional» se puede dejar comentada (con `#`) o vacía y el kit aplica el valor por defecto.

**Acceso público**

| Variable | ¿Se pide? | Qué es | Por defecto o ejemplo |
|---|---|---|---|
| `TLS_MODE` | Siempre | Cómo se publica el emisor: `domain`, `ip` o `proxy`. Cualquier otro valor detiene el kit. | `domain` |
| `CERTIFY_PUBLIC_HOST` | Solo `domain` | Nombre de dominio del emisor: minúsculas, sin `https://`, sin barra final, sin puerto, sin `@`, al menos dos etiquetas (acentos en punycode). Si no cumple, el kit se detiene antes de generar nada. | `certify.institucion.gob.do` |
| `SERVER_PUBLIC_IP` | Solo `ip` | IP pública del servidor (no la de la red interna), IPv4 decimal válida. | `203.0.113.10` |
| `IP_DNS_PROVIDER` | Opcional, solo `ip` | Servicio que convierte la IP en un nombre (`sslip.io` o `nip.io`), en minúsculas. | `sslip.io` |
| `CADDY_ACME_EMAIL` | `domain` e `ip` (no se usa en `proxy`) | Correo de contacto para Let's Encrypt: una sola dirección, sin espacios ni saltos de línea. No lo entrega OGTIC: es de su institución. | `infra@institucion.gob.do` |
| `CERTIFY_PUBLIC_URL` | Solo `proxy` | Dirección pública que sirve su proxy: `https://<dominio>` en minúsculas, sin ruta ni barra final. En `domain` e `ip` el kit la calcula y se ignora lo que ponga aquí. | `https://certify.institucion.gob.do` |
| `CADDY_HTTP_PORT` | Opcional, solo `proxy` | Puerto del servidor donde Caddy escucha HTTP para su proxy (1 a 65535, sin ceros a la izquierda). Se publica en todas las interfaces. | `8080` |
| `TRUSTED_PROXIES` | Opcional, solo `proxy` | Direcciones o redes (separadas por espacio) cuyo `X-Forwarded-For` se acepta; `private_ranges` o IP/CIDR. `0.0.0.0/0` y `::/0` se rechazan. | `private_ranges` |

**Institución y API de datos**

| Variable | ¿Se pide? | Qué es | Por defecto o ejemplo |
|---|---|---|---|
| `INSTITUTION_ID` | Siempre | Identificador único de su institución ante OGTIC. Solo letras sin acento, dígitos y `_`, sin empezar por dígito (**un guion no vale**: forma el tipo `<ID>Credential`). | `INTRANT` |
| `INSTITUTION_DISPLAY_NAME` | Siempre | Nombre que ve la persona en la billetera. Admite acentos y la comilla simple (el kit los escribe en el formato que Certify lee); no admite `\`, `$`, `{`, `}` ni saltos de línea. Si tiene espacios, entre comillas en el `.env`. | `INTRANT` |
| `RESTAPI_BASE_URL` | Siempre | Dirección base de la API que entrega los datos de la persona. | `https://api.ogtic.gob.do/intrant` |
| `RESTAPI_TOKEN_URL` | Siempre | Dirección donde Certify pide el token de la **API de datos** (no el de la persona ni el de Cuenta Única). La entrega OGTIC; no hay valor por defecto. Debe ser una URL `http(s)` sin espacios. | (la de OGTIC) |
| `RESTAPI_SCOPE_ENDPOINT_MAPPING` | Opcional | Cómo se consulta la API según el permiso del token. Déjelo como viene salvo indicación de OGTIC. | `{'openid offline_access profile email': '/:national_id','openid': '/:national_id'}` |

**Cuenta Única**

| Variable | ¿Se pide? | Qué es | Por defecto o ejemplo |
|---|---|---|---|
| `OAUTH_CLIENT_ID` | Siempre | Identificador del cliente de su institución en Cuenta Única **de producción**. Lo entrega OGTIC. El marcador `CAMBIAR-ME` detiene el kit. | (el de OGTIC) |
| `OAUTH_CLIENT_SECRET` | Siempre | Clave de ese cliente. Lo entrega OGTIC. El marcador `REEMPLAZAR_CON_SECRET_DE_OGTIC` detiene el kit. No admite `$`, `\`, comillas ni espacios (sección 11). **Nunca se envía a OGTIC ni se escribe en pantalla.** | (el de OGTIC) |
| `AUTH_ISSUER_URL` | Opcional | Servidor de autorización de las personas. Solo cámbielo para pruebas. **Sin barra final**: el emisor del token se compara tal cual. | `https://auth.cuentaunica.gob.do` |

**Credencial**

| Variable | ¿Se pide? | Qué es | Por defecto o ejemplo |
|---|---|---|---|
| `CREDENTIAL_CONFIG_KEY_ID` | Siempre | Nombre técnico de la credencial. Letras, dígitos, `_` y `-`. Es parte de la dirección del contexto y del logo: cambiarlo crea otra credencial (sección 5). | `DriverLicenseCredential` |
| `CREDENTIAL_ATTRIBUTES` | Siempre | Campos de la credencial, separados por coma, con los mismos nombres que devuelve la API. Reglas en 4.5. | `national_id,fullName,dateOfBirth,licenseNumber` |
| `CREDENTIAL_SCOPE` | Siempre | Permiso que debe traer el token de Cuenta Única para emitir esta credencial. Confírmelo con OGTIC. | `"openid offline_access profile email"` |
| `LOGO_PATH` | Siempre | Ruta a un fichero **PNG** con el logo. Relativa a la carpeta del kit o absoluta. | `logo-institucion.png` |
| `CREDENTIAL_DISPLAY_NAME` | Opcional | Nombre de la credencial en la billetera. | el valor de `INSTITUTION_DISPLAY_NAME` |
| `CREDENTIAL_TYPE` | Opcional | Tipos de la credencial, separados por coma. Debe incluir al menos un tipo propio; `VerifiableCredential` siempre se incluye. El kit los guarda ordenados. | `VerifiableCredential,<INSTITUTION_ID>Credential` |
| `CREDENTIAL_FORMAT` | Opcional | Formato de la credencial. El kit solo admite `ldp_vc`. | `ldp_vc` |
| `CREDENTIAL_BG_COLOR` | Opcional | Color de fondo de la tarjeta. | `#12107c` |
| `CREDENTIAL_TEXT_COLOR` | Opcional | Color del texto de la tarjeta. | `#FFFFFF` |
| `CREDENTIAL_LABELS_JSON` | Opcional | Etiquetas en español de cada atributo, en JSON entre comillas simples. Sin etiqueta se muestra el nombre del atributo. | `'{"national_id":"Cédula","fullName":"Nombre completo"}'` |
| `DID_URL` | Opcional | Identificador (DID) del emisor. Déjelo vacío salvo que vaya a publicar el `did.json` en otra dirección (sección 4.6). | `did:web:<su dirección pública>` |

**Contraseñas y construcción**

| Variable | ¿Se pide? | Qué es | Por defecto o ejemplo |
|---|---|---|---|
| `POSTGRES_PASSWORD` | Opcional | Contraseña de la base de datos. Si deja `postgres` o la vacía, el kit genera una aleatoria **solo en una instalación nueva**; en una existente con el valor por defecto, el kit se detiene (sección 11). Una contraseña propia no admite `$`, `\`, comillas (simples, dobles o invertidas), espacios ni saltos de línea. | `postgres` |
| `KEYSTORE_PASSWORD` | Opcional | Contraseña del almacén de llaves de Certify. Misma regla que la anterior (`local` por defecto; sección 11). | `local` |
| `POSTGRES_USER` | Opcional | Usuario de la base de datos. | `postgres` |
| `POSTGRES_DB` | Opcional | Nombre de la base de datos. | `inji_certify` |
| `RESTAPI_PLUGIN_JAR` | Opcional | Ruta a un plugin RestAPI distinto del que trae el repositorio (`certify-service/loader_path/certify/restapi-dataprovider-plugin-*.jar`). Solo si OGTIC se lo indica. | (sin definir) |

**Variables de uso avanzado** (no van en el `.env`; se anteponen al comando)

| Variable | Con qué comando | Para qué |
|---|---|---|
| `NO_REGENERAR=1` | `apply-credential.sh` | Aplica el SQL ya generado sin regenerar la configuración. |
| `DRY_RUN=1` | `apply-credential.sh` | Regenera los ficheros (salvo `generated/contextos/`, que no se toca: solo se comprueba) e imprime las órdenes de `psql` y de reinicio de Certify sin ejecutarlas. |
| `KIT_FORZAR_CONTEXTO=1` | scripts de generación | Sobrescribe un contexto ya publicado con otro contenido. **Invalida las credenciales ya emitidas con esa clave**; use una `CREDENTIAL_CONFIG_KEY_ID` nueva en su lugar (sección 5). |
| `KIT_PERMITIR_HTTP=1` | scripts de generación | Admite `http://localhost` / `http://127.0.0.1` en `CERTIFY_PUBLIC_URL` (solo pruebas locales). |
| `NODE_EXTRA_CA_CERTS=<fichero .pem>` | `verify-install.sh` | Autoridad certificadora interna de su institución (por ejemplo, el proxy firma con una CA propia): se monta en el contenedor de Node y se reenvía. |
| `KIT_NODE=auto\|local\|docker` | `verify-install.sh` | Dónde corre Node: `auto` (por defecto) usa el `node` local si es la versión 22 o superior y, si no, un contenedor; `local` y `docker` fuerzan una u otra. |
| `KIT_DRY_RUN=1` | `verify-install.sh` | Imprime la orden de Node en vez de ejecutarla. |
| `VERIFY_PRIVADAS=auto\|1\|0` | `verify-install.sh` | Si la verificación puede conectarse a direcciones privadas. `auto` lo permite solo si la dirección pública resuelve a una IP privada o local (el propio servidor, un proxy interno). |
| `VERIFY_HEALTH_INTENTOS`, `VERIFY_HEALTH_PAUSA` | `verify-install.sh` | Intentos (60) y segundos entre ellos (5) de la espera por Certify. |
| `ESPERA=8000` | `verify-install.sh` | Tiempo máximo de cada petición del diagnóstico, en milisegundos. |
| `KIT_FORCE_DOCKER=1` | scripts que usan Node | Usa siempre el contenedor `node:22-alpine`, aunque haya `node` en el servidor. |

### 4.2 Acceso público

Complete las variables de la sección **3A**, **3B** o **3C**, según el modo. No complete más de un modo.

### 4.3 Identidad de su institución y API de datos

```bash
INSTITUTION_ID=INTRANT
INSTITUTION_DISPLAY_NAME=INTRANT
RESTAPI_BASE_URL=https://api.ogtic.gob.do/intrant
RESTAPI_TOKEN_URL=<la-url-que-entrego-ogtic>
```

`RESTAPI_TOKEN_URL` **no es opcional y no tiene valor por defecto**: es la dirección donde Certify obtiene su propio token para consultar la API de la institución. No es el inicio de sesión de la persona. Si no la tiene, pídala a OGTIC antes de continuar.

La línea `RESTAPI_SCOPE_ENDPOINT_MAPPING` puede quedar como viene en la plantilla.

### 4.4 Cuenta Única

```bash
OAUTH_CLIENT_ID=el-id-que-entrego-ogtic
OAUTH_CLIENT_SECRET='el-secret-real-que-entrego-ogtic'
```

Son las credenciales del cliente de su institución en **Cuenta Única de producción**. La plantilla trae los marcadores `CAMBIAR-ME` y `REEMPLAZAR_CON_SECRET_DE_OGTIC`; el kit no genera nada mientras sigan ahí. Un cliente de pruebas no sirve.

El servidor de autorización de las personas es `https://auth.cuentaunica.gob.do` y no hay que escribirlo. Solo para pruebas contra otro servidor existe `AUTH_ISSUER_URL`, **sin barra final** (el emisor del token se compara tal cual y una barra de más rechaza a todas las personas).

### 4.5 Credencial que va a emitir

```bash
CREDENTIAL_CONFIG_KEY_ID=DriverLicenseCredential
CREDENTIAL_ATTRIBUTES=national_id,fullName,dateOfBirth,licenseNumber
CREDENTIAL_SCOPE="openid offline_access profile email"
LOGO_PATH=logo-institucion.png
CREDENTIAL_LABELS_JSON='{"national_id":"Cédula","fullName":"Nombre completo","dateOfBirth":"Fecha de nacimiento","licenseNumber":"Número de licencia"}'
```

**Nombres de los atributos.** `CREDENTIAL_ATTRIBUTES` es una lista de nombres técnicos separados por coma. Cada nombre debe:

- usar solo **letras sin acento (A-Z, a-z), dígitos y guion bajo**;
- **no empezar por un dígito**;
- **no llevar espacios, `:`, `|`, acentos ni `ñ`**;
- no repetirse en la lista;
- **no coincidir con un término que ya definen otros documentos de la credencial**.

El porqué: cada nombre se convierte en un término del contexto de la credencial (sección 5) y pasa a formar parte de lo que se firma. Los caracteres especiales no son válidos en esos términos, y los que ya están definidos por el estándar o por la suite de firma están **protegidos**: redefinirlos hace fallar la verificación, y falla en el teléfono de la persona, no en su servidor. Por eso el kit se detiene al instalar con un mensaje que dice cuál es el nombre problemático. Los más comunes que **no** puede usar son: `id`, `type`, `name`, `description`, `issuer`, `holder`, `status`, `message`, `created`, `domain`, `expires`, `evidence`, `proof`, `validFrom`, `validUntil`, `credentialSubject`, `credentialStatus`. La lista completa está en `scripts/lib/credencial.mjs` (constante `RESERVADOS`). Use otro nombre, por ejemplo `nombre_titular` en lugar de `name`.

El nombre del atributo debe coincidir con el nombre del campo que devuelve su API. Si la API devuelve campos con espacios, acentos o dos puntos, el kit no traduce nombres: consúltelo con OGTIC.

**Etiquetas (lo que ve la persona).** Se definen con `CREDENTIAL_LABELS_JSON`, un objeto JSON entre comillas simples con la forma `{"atributo":"Etiqueta"}`. Las etiquetas sí pueden llevar acentos, espacios y `:`. Reglas:

- cada clave debe ser un atributo de `CREDENTIAL_ATTRIBUTES` (si hay una errata, el kit se detiene);
- no incluya el apóstrofo `'` dentro de una etiqueta (rompería las comillas simples del `.env`) ni saltos de línea;
- un atributo sin etiqueta se muestra con su nombre técnico.

El formato antiguo `CREDENTIAL_ATTRIBUTE_LABELS` (`atributo:Etiqueta,...`) **ya no se admite**: truncaba las etiquetas con dos puntos, y el kit se detiene si lo encuentra en el `.env`.

**Logo.** `LOGO_PATH` es obligatorio y debe ser un PNG real. Una ruta relativa se cuenta desde la carpeta del kit. El kit lo copia a `generated/logos/<CREDENTIAL_CONFIG_KEY_ID>.png` y Caddy lo sirve en `https://<su dirección>/logos/<CREDENTIAL_CONFIG_KEY_ID>.png`; esa es la dirección que la billetera usa para pintarlo. Si el fichero no existe, no es legible o no es PNG, el kit se detiene. `CREDENTIAL_LOGO_URL`, de versiones anteriores, ya no existe y también detiene el kit si sigue en el `.env`.

**Tipos, formato y colores** son opcionales. `CREDENTIAL_TYPE` solo hace falta si quiere un nombre de tipo distinto de `<INSTITUTION_ID>Credential`; los nombres siguen la misma regla que los atributos. `CREDENTIAL_FORMAT` solo admite `ldp_vc`. Si un valor tiene espacios, escríbalo entre comillas (como `CREDENTIAL_SCOPE`).

### 4.6 Identidad pública del emisor (DID)

Para que una billetera u otro sistema compruebe que una credencial la firmó su institución, necesita la llave pública del emisor. Esa llave vive en un archivo público, `did.json`, y la dirección lógica de ese archivo se llama **DID**.

**Caso normal:** no configure nada. Deje `DID_URL` comentado o vacío. El kit:

1. Crea la llave en el primer arranque de Certify.
2. Publica el archivo en su propio servidor: `https://<su dirección pública>/.well-known/did.json`.
3. Usa un DID automático basado en esa dirección. Por ejemplo, `certify.institucion.gob.do` da `did:web:certify.institucion.gob.do` y `203-0-113-10.sslip.io` da `did:web:203-0-113-10.sslip.io`.

**Por qué `install.sh` corrige el `did.json` después de arrancar.** Certify construye ese archivo con una forma que los verificadores conformes rechazan: en los campos `assertionMethod` y `authentication` (los que dicen «qué llaves están autorizadas para firmar») pone el DID a secas, en lugar de la referencia a la llave que firmó. Con eso, un verificador no encuentra autorizada la llave y declara inválida una credencial cuya firma es correcta. El kit lo arregla en dos pasos: Certify tiene que estar en marcha para entregar su llave pública (no existe antes), y entonces `scripts/generate-did.sh` lee el archivo de Certify por la red interna, sustituye esos dos campos por la lista de identificadores de las llaves y lo guarda en `generated/did/did.json`, que Caddy publica con `Cache-Control: no-cache`. Mientras ese fichero no existe, Caddy sirve el de Certify sin corregir para que el arranque no quede roto. `install.sh` ejecuta este paso solo. Vuelva a ejecutarlo a mano (`./scripts/generate-did.sh`) si cambian las llaves o la dirección pública del emisor, o si la verificación (comprobación 10) lo pide.

**Caso con DID externo.** Si su institución quiere alojar el `did.json` en otra dirección (otro dominio u otro sitio):

1. Descomente `DID_URL` y escriba el DID de esa ubicación, por ejemplo `DID_URL=did:web:claves.institucion.gob.do`.
2. Después de instalar, copie el contenido de `https://<su dirección del kit>/.well-known/did.json` y publique ese mismo contenido en la dirección que administra.

Si pone un `DID_URL` externo y no publica el archivo allí, la verificación de credenciales fallará (quien valide buscará la llave en esa dirección y no la hallará), y la comprobación 10 de `verify-install.sh` también puede fallar hasta que lo publique.

### 4.7 Contraseñas de la base de datos y del almacén de llaves

`POSTGRES_PASSWORD` y `KEYSTORE_PASSWORD` traen los valores de siempre (`postgres`, `local`). **En una instalación nueva, déjelos así**: el kit genera contraseñas aleatorias de 64 caracteres y las guarda solo en `generated/.env.runtime`. **En una instalación que ya existe con esos valores, el kit se detiene** y le explica cómo rotarlas a mano: nunca genera contraseñas nuevas sobre una base o un almacén de llaves ya creados. El detalle está en la sección 11.

### 4.8 Guardar y salir

Guarde el archivo `.env` y cierre el editor.

---

## 5. Qué es el contexto y por qué no se edita una vez publicado

Esta sección explica la pieza que más suele sorprender. Léala antes de decidir los atributos.

**El problema que resuelve.** Una credencial es un documento JSON con los datos de la persona y una firma. Para firmarlo (y para verificarlo), el JSON se convierte primero en una lista normalizada de afirmaciones del tipo «sujeto – propiedad – valor». Esa conversión solo reconoce los campos que algún documento llamado **contexto** define. **Un campo que ningún contexto define se descarta en silencio**: la persona lo ve en pantalla, pero **no entra en la firma**, de modo que cualquiera podría cambiarlo sin invalidar la credencial. En la versión anterior del kit, el único contexto era el genérico del estándar, que no define ningún atributo de su institución: ninguno de sus datos quedaba cubierto por la firma.

**Qué hace el kit ahora.** Genera un contexto propio: un pequeño archivo público que define cada atributo de `CREDENTIAL_ATTRIBUTES` (protegido, para que nadie lo redefina). Lo guarda en `generated/contextos/<CREDENTIAL_CONFIG_KEY_ID>.json` y Caddy lo publica en `https://<su dirección>/contextos/<CREDENTIAL_CONFIG_KEY_ID>.json`. Cada credencial emitida lleva en su `@context` esa dirección junto con el contexto del estándar (W3C, versión 2 de credenciales) y el de la suite de firma. La verificación comprueba, sobre una credencial de muestra, que el 100 % de sus atributos quedan cubiertos por la firma.

**Por qué no se edita una vez publicado.**

1. La credencial lleva la **dirección** del contexto, no una copia. Quien verifica descarga el contexto en ese momento. Si el contenido cambia (otro nombre, otro atributo, otra definición), la lista de afirmaciones que se obtiene ya no es la que se firmó y la verificación de **las credenciales ya emitidas** falla.
2. Los teléfonos y otros verificadores **guardan copias** del contexto durante días (según documenta el diagnóstico de OGTIC, hasta 30 días en iPhone). Aunque el cambio fuera inofensivo en teoría, durante ese tiempo habría dispositivos que usan la versión vieja y otros la nueva, y los mismos documentos verificarían bien en unos y mal en otros.
3. Por eso el kit sirve el contexto con `Cache-Control: no-cache` (el verificador puede guardar su copia pero debe revalidarla) y, aun así, **la regla es no cambiarlo**.

**La regla: contexto nuevo = clave nueva.** Si necesita cambiar los atributos de una credencial que ya emitió (agregar, quitar o renombrar uno, o cambiar los tipos), no cambie el contexto existente: cree una credencial nueva con **otro `CREDENTIAL_CONFIG_KEY_ID`** (por ejemplo `DriverLicenseCredentialV2`). Tendrá su propio contexto en otra dirección y su propio logo, y las personas deberán pedirla de nuevo (**reemisión**). Los pasos están en la sección 10.

**El kit lo hace cumplir.** Cuando el kit genera el contexto (`install.sh`, `scripts/generate-config.sh`, `scripts/apply-credential.sh`) lo guarda junto a una huella: `generated/contextos/<clave>.json` y `generated/contextos/<clave>.sha256`. Si ya hay un contexto publicado para esa clave **con otro contenido** (porque cambió `CREDENTIAL_ATTRIBUTES`, `CREDENTIAL_TYPE`, `INSTITUTION_ID` o la dirección pública), el kit **se niega a sobrescribirlo**: se detiene con el mensaje «contexto nuevo = clave nueva» y no cambia nada de lo publicado. Con la misma lista de atributos no hace nada (reordenar los atributos tampoco cuenta como cambio). `scripts/apply-credential.sh` con `DRY_RUN=1` no escribe nada en `generated/contextos/`: solo comprueba.

Si de verdad necesita sobrescribirlo (por ejemplo, una prueba que nunca emitió credenciales), `KIT_FORZAR_CONTEXTO=1` lo permite con un aviso: **invalida todas las credenciales ya emitidas con esa clave**. Lo correcto es una clave nueva (sección 10.2).

Cambiar la dirección pública del emisor (otro dominio) también cambia la dirección del contexto: es, a efectos prácticos, una credencial nueva.

---

## 6. Ejecutar la instalación

Desde la carpeta `institution-kit/`:

```bash
chmod +x install.sh
./install.sh
```

Si no existe `.env`, el script lo crea desde `.env.example` y se detiene para que lo complete (es normal: complételo y vuelva a ejecutarlo).

**Qué hace cada fase**, en orden:

| Fase | Qué ocurre | Si falla |
|---|---|---|
| 1. Herramientas | Comprueba `docker`, `docker compose` (v2), `curl`, `jq`, `envsubst`, `openssl` e `iconv`. | Se detiene y dice cuál falta. |
| 2. Lectura y validación del `.env` | Calcula la dirección pública y el DID, aplica los valores por defecto y **valida todo antes de generar nada**: formato del `.env`, nombre público, IP y correo, variables obligatorias, marcadores, `RESTAPI_TOKEN_URL`, `AUTH_ISSUER_URL`, logo PNG, nombres de atributos, caracteres de las contraseñas. Solo después resuelve las contraseñas (sección 11): las genera si es una instalación nueva y se detiene si es una existente con las de por defecto. | Se detiene con `ERROR:` y el nombre de la variable. Corrija el `.env` y repita. |
| 3. Generación de la configuración | Escribe en `generated/` (carpeta privada, permisos 700): primero el contexto propio y su huella (si ya hay uno publicado con otro contenido, se detiene: sección 5); después `.env.runtime` (permisos 600: las contraseñas y el secreto OAuth), `compose-args` (la orden de `docker compose` de su modo), el logo, la configuración de Certify (sin secretos), el `Caddyfile`, el SQL de la credencial y la credencial de muestra. | Mensaje de error del generador (por ejemplo un nombre de atributo no válido o «contexto nuevo = clave nueva»). |
| 3b. Base de datos de una instalación anterior | Si hay un contenedor de la base cuyos datos están en un volumen anónimo (kit anterior), se detiene y explica cómo migrarlo (sección 12). | Siga los pasos de la sección 12. |
| 4. Construcción | `docker compose build`: construye la imagen de Certify desde el repositorio. **La primera vez tarda varios minutos; no la cancele.** | Revise el error de la construcción (acceso a internet, memoria). |
| 5. Arranque | `docker compose up -d`: levanta base de datos, Certify y Caddy, que arrancan solos tras un reinicio del servidor (`restart: unless-stopped`). Caddy espera a que Certify esté **sano** (tiene un chequeo de salud interno; el primer arranque tarda un par de minutos). La base crea el esquema y carga la credencial solo en su primer arranque. | Si un servicio no llega a estar sano, el script lo dice: `docker compose … ps` y `… logs certify`. |
| 6. Mensajes del modo | En `domain` e `ip` muestra los registros de Caddy durante 30 segundos (la obtención del certificado). En `proxy` indica el puerto y recuerda configurar el proxy. | — |
| 7. Espera de Certify | Pregunta el estado de salud por la red interna cada 5 segundos, hasta 60 veces (5 minutos). | `ERROR: Certify no respondió UP tras 300s`: revise `docker compose … logs certify`. |
| 8. Corrección del DID | Ejecuta `scripts/generate-did.sh` (sección 4.6). | Mensaje de error: ¿está Certify en pie? |
| 9. Verificación | Ejecuta `scripts/verify-install.sh` contra su dirección pública (sección 7). | Ver sección 7. |
| 10. Resumen | Imprime los datos para OGTIC y termina con el código de la verificación. | — |

Las órdenes `docker compose` del kit llevan siempre la configuración de su modo (`generated/compose-args`). Si ejecuta `docker compose` a mano, hágalo desde `institution-kit/` y con esa configuración:

```bash
docker compose $(cat generated/compose-args) ps
```

Con `docker compose` a secas, Caddy queda sin puertos y las contraseñas generadas no se leen.

### Cómo saber que terminó bien

Al final debe aparecer un bloque como este, y el código de salida del script debe ser 0:

```text
============================================
 Instalación completada
============================================
 CERTIFY_PUBLIC_URL: https://...
 INSTITUTION_ID:     ...
 OAUTH_CLIENT_ID:    ...
 CREDENTIAL:         ...
```

Si aparece «Instalación terminada, pero la verificación FALLÓ», los servicios están en marcha pero hay algo que corregir: vaya a la sección 7. Los datos del bloque se imprimen igual: anótelos (sección 9).

---

## 7. Cómo leer la verificación (`verify-install.sh`)

`install.sh` la ejecuta al final y usted puede repetirla cuando quiera, desde `institution-kit/`:

```bash
./scripts/verify-install.sh
```

**Qué hace.** Consulta su emisor **desde el servidor, por su propia dirección pública**, como lo haría una billetera o un verificador, y comprueba lo que de verdad hace que una credencial se emita y se verifique bien. No necesita Node en el servidor: si no hay Node 22 usa un contenedor `node:22-alpine` y monta solo los ficheros de la verificación, no su `.env`. Termina con **código 0** si no hay ninguna `FALLA` y con **código 1** si hay alguna (o si Certify no llega a `UP`).

### Los cuatro estados

| Estado | Qué significa | ¿Cambia el código de salida? |
|---|---|---|
| `OK` | Comprobación superada. | No |
| `FALLA` | Algo está mal y hay que corregirlo. Una credencial emitida así no se verificaría bien, o no se podría emitir. | **Sí** (código 1) |
| `AVISO` | Funciona, pero hay algo recomendable por revisar. Excepción: en el **logo** y en los **contextos** el kit lo trata como `FALLA` (verá «el kit lo exige» al final del texto). | No (salvo esos dos) |
| `PENDIENTE` | No se pudo evaluar porque depende de otra comprobación que falló. Corrija primero la anterior y repita. | No |

Bajo cada línea que no es `OK` aparece una flecha `->` con **qué hacer** y, a veces, puntos `·` con detalles (por ejemplo, qué atributos no quedaron firmados).

### Cómo se ve

Instalación sana (el servidor de ejemplo es de pruebas):

```text
=== Verificación de la instalación ===
Salud de Certify (red interna) ...
  OK        Certify responde UP.

Verificación de la instalación: https://certify.institucion.gob.do/.well-known/openid-credential-issuer
Servidor de autorización esperado: https://auth.cuentaunica.gob.do
Direcciones privadas: no permitidas
credential_endpoint: https://certify.institucion.gob.do/v1/certify/issuance/credential

  1. OK        La metadata del emisor responde: Responde 200 con JSON y 1 credencial.
  2. OK        El identificador del emisor resuelve y publica su metadata: ...
  ...
 11. OK        Tipos y contextos guardados en el orden que Certify busca: ...
  +. OK        El @context de la metadata está completo (W3C, propio y suite): 1 credencial publica ...
  +. OK        Cobertura de firma sobre la credencial de muestra: 3 de 3 atributos firmados (cobertura 100 %): ...
  +. OK        Los atributos del .env coinciden con los que publica Certify: 3 de 3 atributos publicados (...).

Resumen: 11/11 (+cobertura OK, +@context de la metadata OK, +atributos publicados OK) · FALLA 0 · AVISO 0 · PENDIENTE 0
Resultado: la instalación pasa la verificación.
```

La línea **Direcciones privadas** dice si la verificación puede conectarse a direcciones de red interna. Por seguridad, por defecto no; solo lo permite si su dirección pública resuelve a una IP privada o local (por ejemplo, un proxy interno o el propio servidor). Con `VERIFY_PRIVADAS=1` o `=0` lo fuerza.

El **Resumen** cuenta las 11 comprobaciones del diagnóstico (`11/11`), seguidas de las tres propias del kit (marcadas con `+`) y del total de `FALLA`, `AVISO` y `PENDIENTE`. La última línea es el veredicto: «la instalación pasa la verificación», «sin fallas, pero hay comprobaciones que no se pudieron evaluar» (hay `PENDIENTE` sin `FALLA`) o «la verificación FALLÓ».

### Qué comprueba cada línea y qué hacer si no es `OK`

| Línea | Qué comprueba | Qué suele significar y qué hacer |
|---|---|---|
| **Salud de Certify** | Que Certify responde `UP` por la red interna. | `FALLA`: Certify no arrancó. Mire `docker compose $(cat generated/compose-args) logs certify`. Si dice que no puede conectar con la base, vea «contraseñas» en la sección 11. |
| **1** La metadata del emisor responde | Que `…/.well-known/openid-credential-issuer` responde JSON con las credenciales. Es la puerta de entrada de la billetera. | `No responde`: la dirección pública no llega al servidor (DNS, cortafuegos, certificado aún sin emitir; en modo proxy, el proxy aún no reenvía). `Responde 404`: algo delante de Caddy no reenvía esa ruta. |
| **2** El identificador del emisor resuelve | Que el nombre del emisor resuelve y publica esa misma metadata. | Falla por DNS: el nombre no apunta al servidor. |
| **3** El endpoint de emisión es alcanzable | Un POST vacío al `credential_endpoint`: un emisor sano lo rechaza (400, 401 o 403). | `404` o `405`: la ruta no llega a Certify; revise el proxy. |
| **4** El servidor de autorización es Cuenta Única | Que la metadata declara como servidor de autorización el de `AUTH_ISSUER_URL` y que ese servidor responde. | Revise que `AUTH_ISSUER_URL` no tenga barra final y que su servidor llegue a Cuenta Única (salida 443). |
| **5** Los textos visibles están bien codificados | Que acentos y eñes no salgan rotos («DirecciÃ³n»). | Guarde el `.env` en UTF-8 y aplique de nuevo (sección 10). Si persiste en el nombre de la institución, avise a OGTIC. |
| **6** Cada credencial tiene logo PNG | Que el logo de la tarjeta se descarga y es PNG. | `LOGO_PATH` incorrecto o fichero que no es PNG. Corrija, ejecute `./scripts/apply-credential.sh` y repita. En proxy, compruebe que el proxy deja pasar `/logos/`. |
| **7** Cada `@context` se puede descargar | Que cada contexto baja, es JSON y se sirve con `no-cache`. | Si el contexto propio no baja: ¿existe `generated/contextos/<clave>.json`? Ejecute `./scripts/generate-config.sh`. Si dice que falta `no-cache` o el tipo: en modo proxy, su proxy está cambiando o guardando esas respuestas (sección 3C, punto 5). |
| **8** El `@context` define todos los atributos | Que cada atributo de la credencial está definido en el contexto: es decir, que la firma lo cubre. | `FALLA` con «NO firmados: …»: un atributo quedó fuera. Mire la sección 5: cambiar atributos exige una clave nueva. |
| **9** Los nombres de los atributos coinciden | Que `credentialSubject`, el orden de la tarjeta y el contexto usan los mismos nombres. | Revise mayúsculas y guiones de `CREDENTIAL_ATTRIBUTES` y `CREDENTIAL_LABELS_JSON`; aplique de nuevo. |
| **10** El DID del emisor resuelve y autoriza su clave | Que `did.json` se descarga y sus `assertionMethod` listan la llave. | `FALLA`: ejecute `./scripts/generate-did.sh` y repita. Con `DID_URL` externo, fallará hasta que publique el archivo allí. |
| **11** Tipos y contextos guardados en el orden que Certify busca | Que `credential_type` y `context` en la base están ordenados. Si no, Certify no encuentra la plantilla y emitir falla con «CredentialConfig not found». | El kit los guarda ordenados. Si falla, alguien tocó la base: ejecute `./scripts/apply-credential.sh` y reinicie Certify (sección 10). |
| **+** El `@context` de la metadata está completo | Que la metadata publica el contexto del estándar, el propio y el de la suite, y el tipo `VerifiableCredential`. | `FALLA`: aplique la credencial (sección 10) y **reinicie Certify**, que guarda la configuración en memoria. |
| **+** Los atributos del `.env` coinciden con los que publica Certify | Que la metadata que **Certify publica de verdad** (leída de su base de datos) lista los mismos atributos que su `.env` para su `CREDENTIAL_CONFIG_KEY_ID`. La cobertura de abajo se calcula sobre una muestra que el kit genera desde ese mismo `.env`, así que no detectaba una base desfasada; esta sí. | `FALLA` («faltan …» o «no publica la credencial …»): la base no coincide con el `.env`. Ejecute `./scripts/apply-credential.sh` (que reinicia Certify), o use una clave nueva si cambió los atributos (sección 10.2). `AVISO`: la base trae atributos que el `.env` ya no tiene. |
| **+** Cobertura de firma sobre la credencial de muestra | Que, sobre una credencial de ejemplo construida con **su** plantilla, el 100 % de los atributos entra en la firma. El kit nunca muestra valores, solo nombres de campo. | `FALLA`: «No firmados: …». Es el defecto que el kit existe para evitar; ver sección 5. |

### Casos frecuentes

- **Modo proxy, recién instalado: casi todo en `FALLA`, empezando por la 1.** Su proxy no reenvía aún. Configure el proxy (sección 3C) y repita `./scripts/verify-install.sh`.
- **Si la salud de Certify falla**, el informe lo cuenta como una línea `FALLA` más (`Certify responde UP por la red interna`) y el veredicto final dice «la verificación FALLÓ»; ya no aparece «pasa la verificación» con código 1.
- **Autoridad certificadora propia (proxy con CA interna).** Si la comprobación 1 falla con un error de certificado en una instalación que sí responde, apunte `NODE_EXTRA_CA_CERTS` al `.pem` de su CA (`NODE_EXTRA_CA_CERTS=/ruta/ca.pem ./scripts/verify-install.sh`): se monta en el contenedor de Node.
- **Modo dominio o IP, recién instalado: `No responde` o error de certificado.** Let's Encrypt aún no emitió el certificado. Espere unos minutos, mire `docker compose $(cat generated/compose-args) logs caddy` y confirme que el DNS apunta al servidor y que el 80 está abierto. Repita.
- **Todo en `OK`, pero con `PENDIENTE` o `AVISO`.** El código de salida es 0, pero lea cada línea: suele indicar algo que quedó sin evaluar.
- **El servidor no puede alcanzar su propia dirección pública** (algunas redes no lo permiten desde dentro): las comprobaciones 1 a 11 fallarán aunque desde internet todo funcione. Verifique desde otra red con los `curl` de la sección 8.

---

## 8. Comprobar a mano

Además de la verificación automática puede comprobar desde cualquier equipo (reemplace la dirección por la suya):

```bash
curl https://certify.institucion.gob.do/.well-known/openid-credential-issuer
curl https://certify.institucion.gob.do/.well-known/did.json
curl -I https://certify.institucion.gob.do/contextos/DriverLicenseCredential.json
curl -I https://certify.institucion.gob.do/logos/DriverLicenseCredential.png
```

| Prueba | Resultado esperado |
|---|---|
| `openid-credential-issuer` | JSON con los datos del emisor (incluye la dirección para emitir y la lista de credenciales). |
| `did.json` | JSON con la llave pública; el campo `assertionMethod` debe ser una lista con la referencia a la llave (no el DID a secas). |
| Contexto | Código 200, `content-type: application/ld+json` y `cache-control: no-cache`. |
| Logo | Código 200, `content-type: image/png` y `cache-control: no-cache`. |

En modo IP, si Let's Encrypt emitió el certificado, **no** hace falta `curl -k`.

**El estado de salud solo es interno.** Antes la guía pedía consultar `/v1/certify/actuator/health` desde internet. **Ya no**: el kit publica solo lo imprescindible. Para el estado de salud use la red interna, desde el servidor:

```bash
docker compose $(cat generated/compose-args) exec -T caddy wget -qO- http://certify:8090/v1/certify/actuator/health
```

Debe responder `{"status":"UP"}`. Desde internet, cualquier dirección bajo `/v1/certify/actuator/` debe responder **404**. (Puede responder 200 desde el propio servidor, que cuenta como red interna.)

**Lo que NO debe llegar a Certify desde internet.** Compruebe que la fábrica de credenciales y la gestión de la credencial están cerradas (deben responder **404**, no 200, 401 ni 403):

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://certify.institucion.gob.do/v1/certify/pre-authorized-data
curl -s -o /dev/null -w "%{http_code}\n" https://certify.institucion.gob.do/v1/certify/credential-configurations/DriverLicenseCredential
curl -s -o /dev/null -w "%{http_code}\n" https://certify.institucion.gob.do/
```

**Prueba desde otra red:** abra la dirección de `openid-credential-issuer` desde un celular o computadora fuera de su red. Si responde solo desde el servidor pero no desde fuera, el servicio está bien pero la red pública aún no llega (revise puertos y cortafuegos en los prerrequisitos).

---

## 9. Qué enviar a OGTIC

La instalación no basta para que una persona emita desde la billetera: OGTIC debe registrar su institución en la plataforma central. Envíe a OGTIC (son los datos que imprimió `install.sh`):

| Dato | Ejemplo |
|---|---|
| `INSTITUTION_ID` | `INTRANT` |
| `CERTIFY_PUBLIC_URL` | `https://certify.institucion.gob.do` |
| `OAUTH_CLIENT_ID` | (el que le entregaron) |
| `CREDENTIAL_CONFIG_KEY_ID` | `DriverLicenseCredential` |
| Nombre visible de la credencial | `INTRANT` |

**Nunca** envíe `OAUTH_CLIENT_SECRET` ni contraseñas. Hasta que OGTIC confirme el registro, una persona no podrá emitir la credencial desde la billetera, aunque la verificación haya salido perfecta. Cuando lo confirme, haga una prueba de emisión con una persona de su institución.

---

## 10. Cambiar la credencial después de instalar

El `.env` se lee al generar la configuración, pero **la credencial se carga en la base de datos solo en el primer arranque de PostgreSQL**. Si cambia algo de la credencial en el `.env` y ejecuta de nuevo `install.sh`, la base **no** se actualiza. Para eso existe `apply-credential.sh`.

### 10.1 Re-aplicar la credencial

Úselo cuando cambie el **aspecto** de la credencial: el nombre que se muestra (`CREDENTIAL_DISPLAY_NAME`), los colores, las etiquetas (`CREDENTIAL_LABELS_JSON`), el logo (`LOGO_PATH`) o el permiso (`CREDENTIAL_SCOPE`, que conviene coordinar con OGTIC).

1. Edite el `.env`.
2. Ejecute, desde `institution-kit/` (con los contenedores en marcha):

```bash
./scripts/apply-credential.sh
```

El script valida el `.env`, regenera la configuración (incluidos logo, contexto y SQL), aplica el SQL a la base **sin recrearla** y muestra al final la fila resultante (sin la plantilla). Es **idempotente**: puede ejecutarlo cuantas veces quiera. **Conserva el estado (`status`)** de la credencial.

Variantes: `NO_REGENERAR=1 ./scripts/apply-credential.sh` aplica el SQL que ya está generado sin regenerar nada; `DRY_RUN=1 ./scripts/apply-credential.sh` regenera los ficheros (sin tocar `generated/contextos/`) y solo imprime las órdenes de `psql` y de reinicio.

3. **Certify se reinicia solo**: al terminar de aplicar el SQL, el script ejecuta `docker compose … restart certify` (solo Certify; ni la base ni Caddy). Certify guarda en memoria la configuración de la credencial (hasta una hora, según su configuración) y, sin reiniciar, seguiría emitiendo con la anterior. Si el SQL falla, **no** reinicia. Espere a que vuelva a estar `UP` (un par de minutos).

4. Repita la verificación: `./scripts/verify-install.sh`.

El logo cambia de inmediato porque Caddy lo sirve desde el disco; el resto necesita el reinicio.

### 10.2 Cuándo NO basta: cambio de atributos

Si cambia los **atributos** (`CREDENTIAL_ATTRIBUTES`), los **tipos** (`CREDENTIAL_TYPE` o `INSTITUTION_ID`) o la **dirección pública** del emisor con la misma clave, el kit **se detiene** («contexto nuevo = clave nueva», sección 5): reescribiría el contexto ya publicado y las credenciales emitidas dejarían de verificarse.

Cámbielo así:

1. Elija un **`CREDENTIAL_CONFIG_KEY_ID` nuevo** (por ejemplo `DriverLicenseCredentialV2`) y los atributos nuevos en el `.env`.
2. Ponga la configuración **vieja** en `inactive` en la base, para que deje de ofrecerse:

   ```bash
   printf "UPDATE certify.credential_config SET status = 'inactive' WHERE credential_config_key_id = 'DriverLicenseCredential';\n" \
     | docker compose $(cat generated/compose-args) exec -T database psql -U postgres -d inji_certify
   ```

   (Con su `POSTGRES_USER` y `POSTGRES_DB` si los cambió.) `apply-credential.sh` conserva ese estado: no la reactiva.
3. Ejecute `./scripts/apply-credential.sh`: crea una configuración nueva, con su contexto en `…/contextos/<clave nueva>.json` y su logo propio, y reinicia Certify.
4. **No borre** `generated/contextos/<clave vieja>.json` ni la carpeta `generated/contextos/`: las credenciales ya emitidas siguen apuntando a ese contexto y necesitan poder descargarlo. Incluya esa carpeta en sus respaldos.
5. Avise a OGTIC: la clave nueva es una credencial nueva que debe registrarse, y coordine con ellos cómo se retira la vieja. Las personas deben pedir de nuevo su credencial (reemisión).

---

## 11. Secretos y superficie expuesta

### Qué genera el kit y dónde queda

- **Contraseñas.** Si `POSTGRES_PASSWORD` vale `postgres` (o está vacía), o `KEYSTORE_PASSWORD` vale `local` (o está vacía), **en una instalación nueva** el kit genera una contraseña aleatoria de 64 caracteres (`openssl rand -hex 32`) y la guarda **solo** en `generated/.env.runtime` (permisos 600). **No se escribe en ninguna pantalla ni registro** y se **reutiliza** en cada ejecución (regenerar la configuración o aplicar la credencial no la cambia). Al generarla, el kit avisa con un `AVISO` en pantalla, sin mostrarla.
- **Dónde está cada secreto.** Las contraseñas y el `OAUTH_CLIENT_SECRET` viven en dos sitios: su `.env` y `generated/.env.runtime` (600). **Los ficheros `generated/config/*.properties` ya no los llevan**: Certify los recibe como variables de entorno del contenedor, que `docker compose` lee de `generated/.env.runtime`, y las properties solo tienen marcadores (`${KIT_DB_PASSWORD}`…). Esos ficheros son legibles por todos porque Certify corre dentro del contenedor con otro usuario (uid 1001) y los lee tal cual; no hay nada secreto en ellos. La carpeta `generated/` es privada (permisos 700).
- **`generated/` no se sube a ningún repositorio** (está ignorado) y contiene secretos: respáldelo en un lugar protegido.
- **`.env` contiene `OAUTH_CLIENT_SECRET`**: `install.sh` lo crea con permisos 600 y los scripts avisan si es legible por otros usuarios (`AVISO: …/.env es legible por otros usuarios (modo 644)`); corríjalo con `chmod 600 .env`.
- **Caracteres admitidos.** Una contraseña o secreto que usted escriba no puede contener `$`, `\`, comillas (simples, dobles o invertidas), espacios ni saltos de línea: `docker compose`, Spring y la base de datos los leen de formas distintas y la contraseña dejaría de ser la misma en cada sitio (Postgres se crearía con una y Certify se conectaría con otra). Use letras, dígitos y `. _ @ % + = -`, por ejemplo `openssl rand -hex 32`. El kit lo comprueba y se detiene sin imprimir la contraseña.

### Solo para instalaciones nuevas (y qué hace el kit si ya existe una)

La contraseña de PostgreSQL queda grabada en el volumen de datos al crear la base, y la del almacén de llaves queda dentro del almacén de Certify desde el primer arranque. **Cambiarlas después rompe el arranque**: la base rechaza la conexión y Certify no puede abrir sus llaves. Por eso el kit **nunca genera ni regenera contraseñas sobre una instalación existente**. Hay instalación existente si existe `generated/.env.runtime` o, con Docker, un contenedor de la base o un volumen de datos o del almacén de llaves de este kit.

- Si ya hay contraseñas **generadas por el kit** en `generated/.env.runtime`, se reutilizan.
- Si escribió contraseñas **propias** en el `.env`, se respetan.
- Si hay instalación existente y las contraseñas siguen siendo `postgres` / `local` (o están vacías), **`install.sh` se detiene** con un mensaje, sin tocar nada. Debe **rotarlas a mano**, una sola vez:

  1. Genere dos contraseñas: `openssl rand -hex 32` (dos veces).
  2. **PostgreSQL:** cámbiela en la base, con la instalación en marcha:

     ```bash
     printf "ALTER USER postgres PASSWORD '<la nueva>';\n" \
       | docker compose $(cat generated/compose-args) exec -T database psql -U postgres -d inji_certify
     ```
  3. **Almacén de llaves:** haga primero una copia del volumen `…_certify-pkcs12` y cambie la contraseña de `local.p12`:

     ```bash
     docker compose $(cat generated/compose-args) run --rm --no-deps --entrypoint keytool certify \
       -storepasswd -storetype PKCS12 -keystore /home/mosip/CERTIFY_PKCS12/local.p12
     ```

     (El kit no ha probado este paso con un Certify real: no lo haga sin la copia, y confírmelo con OGTIC.)
  4. Escriba las dos nuevas en `POSTGRES_PASSWORD` y `KEYSTORE_PASSWORD` del `.env` y vuelva a ejecutar `./install.sh`.

La variable `KIT_CONSERVAR_SECRETOS_POR_DEFECTO` de versiones anteriores **ya no existe**: si la tiene en su `.env`, el kit la ignora y avisa. Dejar `postgres` y `local` sin rotar no es una opción.

Si ya ejecutó una versión anterior de `install.sh` que generó contraseñas nuevas sobre una instalación existente y Certify no conecta con la base, las contraseñas que están en `generated/.env.runtime` no son las de la base: ponga en el `.env` (`POSTGRES_PASSWORD`, `KEYSTORE_PASSWORD`) las que la base y el almacén de llaves realmente tienen y repita `./install.sh`.

### Qué publica Caddy: una lista blanca

El kit **no** publica `/v1/certify/` entero. Certify trae, además de lo que usa la billetera, rutas que no deben ser alcanzables desde internet: el flujo de código pre-autorizado (emite una credencial completa **sin persona**), la gestión de la configuración de la credencial (escribir o borrar su plantilla), la revocación, los certificados del servicio y la documentación de la API. En Certify estaban abiertas sin autenticación; ahora Caddy responde **404** a todas, y Certify mismo solo deja sin autenticar lo que el kit usa (el resto exige un token de Cuenta Única).

| Ruta | Qué hace Caddy |
|---|---|
| `/.well-known/openid-credential-issuer` (y la misma bajo `/v1/certify/.well-known/…`), `did.json` y `jwks.json` de Certify | Pasan a Certify. |
| `POST /v1/certify/issuance/credential` | Pasa a Certify: es el endpoint de emisión, que valida el token de la persona. Con otro método, 404. |
| `GET /v1/certify/credentials/status-list/*` | Pasa: la lista de estado pública (solo lectura). |
| `GET /v1/certify/rendering-template/*` | Pasa: la plantilla de presentación (solo lectura). |
| `/.well-known/did.json` (el corregido), `/contextos/*`, `/logos/*` | Los sirve Caddy desde disco. |
| `/v1/certify/actuator/health` | Solo desde redes internas; el resto del actuator, 404. |
| `pre-authorized-data`, `credential-offer-data`, `oauth`, `credential-configurations`, `credentials/status` (revocar), `system-info`, `ledger-search`, `swagger-ui`, `v3/api-docs`, el resto de `issuance/…` y cualquier otra ruta | **404 explícito.** |
| Todo lo que no está en la lista (incluida la raíz `/`) | **404** (antes, un 200 vacío: un balanceador lo leía como «sano»). |

Si su balanceador sondea la salud, use `/.well-known/openid-credential-issuer`. Esta lista se prueba con una simulación del enrutado y se valida con el Caddy real en el CI del kit.

### El panel interno de Certify (actuator) ya no es público

Certify trae un panel de administración (*actuator*) que, mal configurado, expone la configuración y el entorno del servicio, incluidas contraseñas. Ya no es público:

- Caddy responde **404** a todo lo que cuelga de `/v1/certify/actuator/`, con una sola excepción: el estado de salud (`/health`), solo para redes internas.
- Certify mismo solo habilita `health` (sin detalles) y no muestra valores de configuración.

Por eso la guía anterior que pedía `curl https://<su dirección>/v1/certify/actuator/health` desde internet **ya no aplica**: dará 404. Use la red interna (sección 8). Si usted tenía abierto el actuator en una instalación anterior, ya no lo estará con este kit, pero las contraseñas que estuvieron visibles hay que darlas por conocidas: rótelas.

### Registros (logs)

El kit configura Certify para que **no escriba en los registros el token de acceso de la persona ni sus datos** (hay una versión del proyecto base que sí lo hacía). Qué hace y qué no, y qué debe hacer si construyó Certify desde una versión anterior, está en [IUGO-CUSTOMIZATIONS.md](./IUGO-CUSTOMIZATIONS.md).

---

## 12. Reinstalar, actualizar y respaldar

### Respaldar (hágalo antes de tocar nada importante)

- La base de datos (credencial y llaves de firma):

  ```bash
  docker compose $(cat generated/compose-args) exec -T database pg_dump -U postgres inji_certify > respaldo-$(date +%F).sql
  ```

  (Si cambió `POSTGRES_USER` o `POSTGRES_DB`, use esos valores.)
- El almacén de llaves de Certify: es un volumen de Docker con nombre `…_certify-pkcs12` (véalo con `docker volume ls`). Respáldelo con el procedimiento de su institución para volúmenes.
- Las carpetas del kit: `.env` y `generated/` (en particular `generated/contextos/`).
- Guarde estos respaldos cifrados y con acceso restringido: contienen secretos y llaves.

Si se pierden la base o el almacén de llaves, el emisor tendría que crear llaves nuevas y las credenciales ya emitidas dejarían de verificarse.

### `docker compose down` y los datos de PostgreSQL

Los datos de PostgreSQL viven en un **volumen con nombre** (`…_pgdata`), así que `docker compose down` **conserva la base**: solo `down -v` o `docker volume rm` la borran. Aun así, para el uso diario es más suave parar y arrancar:

```bash
docker compose $(cat generated/compose-args) stop        # parar
docker compose $(cat generated/compose-args) start       # arrancar de nuevo
docker compose $(cat generated/compose-args) restart certify
```

Los tres servicios se reinician solos si el servidor se reinicia o un servicio cae (`restart: unless-stopped`); un `stop` manual se respeta.

**Instalaciones hechas con una versión anterior del kit.** Antes, los datos estaban en un volumen **anónimo**. Al actualizar sin migrar, Docker crearía el volumen `pgdata` **vacío**: la base nueva solo traería el esquema y la credencial, y se perdería lo ya emitido (libro de emisiones, estados). Por eso `install.sh` **se detiene** si encuentra un contenedor de la base con datos en un volumen anónimo y le explica la migración, que son cinco pasos: copia de seguridad (`pg_dumpall`), parar la base, crear el contenedor con el volumen nuevo (`up --no-start database`), copiar los datos del volumen anónimo al nuevo con un contenedor `alpine`, y volver a ejecutar `./install.sh`. El kit no ha ejecutado esos pasos con un Docker real: **haga la copia del paso 1** y avise a OGTIC si algo no cuadra.

Un caso concreto: si en modo `ip` o `domain` Caddy se quedó con un certificado interno y hay que limpiar su volumen, haga solo esto (la base no se toca):

```bash
docker compose $(cat generated/compose-args) rm -sf caddy
docker volume ls                      # busque el que termina en _caddy_data
docker volume rm <nombre-del-volumen>
docker compose $(cat generated/compose-args) up -d caddy
```

### Si cambia el `.env` (sin tocar la credencial)

Para cambios de acceso público, API de datos o Cuenta Única, vuelva a ejecutar:

```bash
./install.sh
```

Regenera la configuración, reconstruye lo que haga falta, reinicia lo que cambió y vuelve a verificar. Las contraseñas generadas se reutilizan. Si cambió atributos, tipos o la dirección pública con la misma clave, el kit se detiene («contexto nuevo = clave nueva»: sección 5). Para cambios en la credencial, vea la sección 10.

### Actualizar el kit

1. Lea el [`CHANGELOG.md`](../CHANGELOG.md) de la versión nueva.
2. Respalde (arriba).
3. Traiga la versión nueva (`git pull` de la rama que le indique OGTIC). Si modificó algún fichero del kit (por ejemplo `docker-compose.proxy.yml` para escuchar solo en `127.0.0.1`), `git` le avisará de conflictos: repita su cambio.
4. Si su instalación es de una versión **anterior al volumen con nombre de PostgreSQL**, `install.sh` se detendrá pidiendo la migración (arriba). Si usa las contraseñas por defecto, también se detendrá pidiendo rotarlas (sección 11). Compare su `.env` con el `.env.example` nuevo para ver si hay variables nuevas (`diff .env.example .env` muestra las diferencias; los valores propios de su institución aparecerán como diferentes, es lo esperado). Una variable nueva obligatoria hace que el kit se detenga con un mensaje que la nombra.
5. Ejecute `./install.sh`.

### Reinstalar desde cero (solo en una instalación de pruebas)

Para empezar de nuevo una instalación **sin uso** (que no haya emitido credenciales), este comando **borra la base de datos (el volumen `pgdata`) y las llaves** y es irreversible:

```bash
docker compose $(cat generated/compose-args) down -v
rm -rf generated
./install.sh
```

No lo haga en una instalación con credenciales emitidas: el emisor tendría llaves nuevas y las anteriores dejarían de verificarse.

### `sync-diagnostico.sh` no es para instituciones

El motor que usa `verify-install.sh` está en `institution-kit/diagnostico/` y **viene incluido en el kit**, ya actualizado en cada versión. El script `scripts/sync-diagnostico.sh` existe para que **OGTIC** refresque esa copia desde su propio repositorio (`inji-vc/stack/diagnostico`, que las instituciones no tienen). **No lo ejecute**, y no edite los ficheros de `diagnostico/`: una prueba automática vigila que coincidan con la copia de OGTIC.

---

## 13. Problemas frecuentes

| Qué ve | Qué hacer |
|---|---|
| `ERROR: Variables obligatorias vacías en .env` | Abra `.env`, complete las variables que lista el mensaje y vuelva a ejecutar `./install.sh`. |
| `OAUTH_CLIENT_SECRET` o `OAUTH_CLIENT_ID` siguen con el marcador (`REEMPLAZAR_CON_SECRET_DE_OGTIC`, `CAMBIAR-ME`) | Escriba los valores que entregó OGTIC. Son del cliente de Cuenta Única **de producción**. |
| `RESTAPI_TOKEN_URL es obligatorio` | Pídala a OGTIC. No tiene valor por defecto. Es el token de la API de datos, no el de Cuenta Única. |
| `LOGO_PATH es obligatorio` / `LOGO_PATH no apunta a un fichero legible` / `no es un PNG` | Indique la ruta de un PNG real (relativa a `institution-kit/` o absoluta). |
| `CREDENTIAL_LOGO_URL ya no existe` | Quite esa línea del `.env` y use `LOGO_PATH`. |
| `CREDENTIAL_ATTRIBUTE_LABELS … ya no se admite` | Quite esa línea y use `CREDENTIAL_LABELS_JSON` (sección 4.5). |
| `El atributo «…» no es válido` o `choca con un término que ya definen…` | Renombre el atributo según las reglas de la sección 4.5. |
| `INSTITUTION_ID «…» no es válido` | `INSTITUTION_ID` forma el tipo por defecto (`<ID>Credential`) y solo admite letras sin acento, dígitos y `_` (un guion no vale). Cambie `INSTITUTION_ID` o fije un `CREDENTIAL_TYPE` válido. |
| `ERROR: ya hay una instalación previa de este kit … estas contraseñas siguen siendo las de defecto` | El kit no regenera contraseñas sobre una instalación existente. Rótelas a mano (sección 11). |
| `ERROR: la base de datos de esta instalación vive en un volumen ANÓNIMO` | Instalación de una versión anterior: siga los pasos de migración que imprime (sección 12) antes de actualizar. |
| `contexto nuevo = clave nueva` | Cambió atributos, tipo, `INSTITUTION_ID` o la dirección pública con la misma `CREDENTIAL_CONFIG_KEY_ID`. Use una clave nueva (sección 10.2). |
| `CERTIFY_PUBLIC_HOST no es un nombre de dominio válido` / `SERVER_PUBLIC_IP no es una dirección IPv4 válida` / `CADDY_ACME_EMAIL no es una dirección de correo válida` | Corrija el valor según la sección 3: minúsculas, sin `https://`, sin barra, sin puerto, una sola dirección. |
| `POSTGRES_PASSWORD contiene un carácter no admitido` (o `KEYSTORE_PASSWORD`, `OAUTH_CLIENT_SECRET`) | Quite `$`, `\`, comillas, espacios y saltos de línea (sección 11). |
| `INSTITUTION_DISPLAY_NAME no puede llevar …` | Quite `\`, `$`, `{`, `}` o los saltos de línea. Acentos y la comilla simple sí valen. |
| `.env tiene finales de línea de Windows (CRLF)` / `no se pudo leer .env` | Conviértalo (`sed -i 's/\r$//' .env`) o ponga entre comillas los valores con espacios. |
| `TRUSTED_PROXIES=… confía en cualquier origen` | Ponga la IP o red de su proxy (sección 3C). |
| `AVISO: …/.env es legible por otros usuarios` | `chmod 600 .env`. |
| `AUTH_ISSUER_URL debe ser una URL https … SIN barra final` | Quite la barra final de la dirección. |
| `CERTIFY_PUBLIC_URL es obligatorio con TLS_MODE=proxy` | Escriba la dirección pública de su proxy (sección 3C). |
| `Comando requerido no encontrado: envsubst` | Instale `gettext-base` (Debian/Ubuntu: `sudo apt-get install -y gettext-base`). |
| `AVISO: se generaron contraseñas aleatorias…` | Es normal en una instalación nueva. En una existente el kit ya no las genera: se detiene (sección 11). |
| Certify no responde `UP` o hay tiempo de espera | Espere unos minutos (el primer arranque es lento). Luego mire `docker compose $(cat generated/compose-args) logs certify`. |
| Certify no conecta con la base de datos | Probablemente las contraseñas no coinciden con las de la base ya creada. Sección 11. |
| El estado de salud responde JSON con `Full authentication is required` | Regenere la configuración y recree Certify: `./scripts/generate-config.sh` y `docker compose $(cat generated/compose-args) up -d --force-recreate certify`. Debe devolver `{"status":"UP"}`. |
| Modo dominio o IP: no obtiene el certificado HTTPS | Confirme el puerto 80 abierto desde internet. En modo dominio, que el DNS apunte al servidor; en modo IP, que `sslip.io` resuelva a la IP pública. Si Caddy quedó con un certificado interno, limpie solo su volumen como se indica en la sección 12. Justo tras instalar, la comprobación 1 puede fallar un minuto mientras se emite el certificado: repita `./scripts/verify-install.sh`. |
| Un servicio no llega a estar sano al hacer `up -d` | `docker compose $(cat generated/compose-args) ps` y `… logs certify`. Certify tarda un par de minutos en su primer arranque. |
| Modo IP: la URL no responde desde internet | Confirme que los puertos 80 y 443 de la IP pública llegan al servidor. |
| Modo proxy: `Bind for 0.0.0.0:8080 failed: port is already allocated` | Otro programa usa ese puerto: cambie `CADDY_HTTP_PORT` en el `.env` y repita `./install.sh`; actualice el proxy al puerto nuevo. |
| Modo proxy: el estado de salud se ve desde internet | Su proxy no envía `X-Forwarded-For` con la IP real. Configúrelo (sección 3C). |
| `did.json` con el DID a secas en `assertionMethod` | Ejecute `./scripts/generate-did.sh` (Certify debe estar en marcha) y repita la verificación. |
| Al emitir: `CredentialConfig not found` | Los tipos o contextos de la base no están en el orden que Certify busca. Ejecute `./scripts/apply-credential.sh` y reinicie Certify. |
| No encuentra el complemento RestAPI (archivo `.jar`) | Verifique que clonó el repositorio completo y que existe la carpeta `certify-service/loader_path/certify/` con ese fichero. |
| `docker compose ... no configuration file provided` | Ejecute los comandos desde la carpeta `institution-kit/`. |

### Acceso a los registros por servicio

Desde `institution-kit/`:

```bash
docker compose $(cat generated/compose-args) logs -f caddy
docker compose $(cat generated/compose-args) logs -f certify
docker compose $(cat generated/compose-args) logs -f database
```
