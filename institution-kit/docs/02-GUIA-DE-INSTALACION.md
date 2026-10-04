# Guía de instalación — Kit emisor

Esta guía le indica paso a paso cómo instalar y poner en marcha el kit en el servidor de su institución.

Al terminar, el servicio de emisión de credenciales estará siendo ejecutado en su servidor y accesible por internet con una dirección segura (`https://...`).

**Antes de comenzar**, complete el checklist de prerrequisitos que se envió en un documento aparte: [01-PREREQUISITOS.md](./01-PREREQUISITOS.md).

---

## 1. Confirmación de pre requisitos

- [ ] Tengo acceso al servidor (terminal o conexión remota / SSH).
- [ ] En el servidor ya están instalados: Git, Docker, Docker Compose, `curl` y `jq`.
- [ ] Tengo a mano los valores que entregó OGTIC (identificador de institución, URL de la API para obtener los datos del usuario, Client ID, Client Secret, y datos de la credencial).
- [ ] Ya tengo un dominio o voy a utilizar el modo IP, y la red correspondiente está configurada según los pre-requisitos.

---

## 2. Entrar al servidor y ubicar el kit

1. Conéctese al servidor con la herramienta que use su equipo de infraestructura (terminal local o SSH).

2. Si aún no tiene el repositorio en el servidor, clone el que le indicó OGTIC:

```bash
git clone <url-proporcionada-por-ogtic>
cd inji-rd-certify/institution-kit
```

Si ya lo clonó antes:

```bash
cd inji-rd-certify/institution-kit
```

3. Compruebe que está en la carpeta correcta. Ejecute el comando:

```bash
ls -la
```

Debe ver, entre otros archivos: `install.sh`, `.env.example` y `docker-compose.yml`.

Si no los ve, no está en `institution-kit/`. Revise la ruta con `pwd` y vuelva al paso 2.

---

## 3. Elegir el modo de acceso público

El kit necesita saber cómo va a ser alcanzable desde internet. Hay dos modos, al mismo nivel. Elija **uno solo** (el que ya decidió en los pre-requisitos).

| Si su institución… | Elija |
|--------------------|--------|
| Tiene un nombre de dominio que apunta al servidor (ej. `certify.institucion.gob.do`) | Modo dominio → siga la sección **3A** |
| Solo tiene la IP pública del servidor, sin dominio propio | Modo IP → siga la sección **3B** |

**Importante:** no mezcle ambos modos. Configure solo las variables del modo elegido.

### 3A. Modo dominio

En el archivo `.env` (sección 4) deje así el bloque de acceso público:

```bash
TLS_MODE=domain
CERTIFY_PUBLIC_HOST=certify.institucion.gob.do
CADDY_ACME_EMAIL=infra@institucion.gob.do
```

Donde:

- `CERTIFY_PUBLIC_HOST`: es el nombre de dominio sin `https://` (ej. `certify.intrant.gob.do`).
- `CADDY_ACME_EMAIL`: un correo de su equipo de infraestructura. El kit lo usa para el certificado HTTPS automático.

Deje sin usar las líneas de modo IP (`SERVER_PUBLIC_IP`, `IP_DNS_PROVIDER`): aunque aparezcan en la plantilla, con `TLS_MODE=domain` el kit no las utiliza.

La dirección pública quedará: `https://` + el valor de `CERTIFY_PUBLIC_HOST`.

### 3B. Modo IP

En el archivo `.env` (sección 4) deje así el bloque de acceso público:

```bash
TLS_MODE=ip
SERVER_PUBLIC_IP=203.0.113.10
IP_DNS_PROVIDER=sslip.io
CADDY_ACME_EMAIL=infra@institucion.gob.do
```

- `SERVER_PUBLIC_IP`: la IP pública del servidor donde corre Docker (no una IP interna tipo `192.168.x.x`).
- `IP_DNS_PROVIDER`: deje `sslip.io` salvo que OGTIC le indique otro valor.
- `CADDY_ACME_EMAIL`: correo de infraestructura para Let's Encrypt (igual que en modo dominio).

Deje sin usar la línea de modo dominio (`CERTIFY_PUBLIC_HOST`): aunque aparezca en la plantilla, con `TLS_MODE=ip` el kit no la utiliza.

El kit convertirá la IP en un nombre usable. Ejemplo: si la IP es `203.0.113.10`, la dirección pública será:

```text
https://203-0-113-10.sslip.io
```

(Los puntos de la IP se reemplazan por guiones.) Caddy pedirá un certificado público a Let's Encrypt para ese hostname; el puerto 80 debe estar abierto.

---

## 4. Completar el archivo `.env`

1. Desde `institution-kit/`, copie la plantilla:

```bash
cp .env.example .env
```

2. Ábralo con el editor que prefiera, por ejemplo:

```bash
nano .env
```

3. Complete los campos obligatorios siguientes. Use los valores que ya obtuvo en los pre-requisitos.

### 4.1 Acceso público (según el modo elegido)

Complete las variables de la sección **3A** o **3B**. No complete ambos.

### 4.2 Identidad de su institución

| Variable | Qué es | Como lo obtengo | Ejemplo |
|----------|--------|-----------------|---------|
| `INSTITUTION_ID` | Identificador único de su institución ante OGTIC | Acordado con OGTIC | `INTRANT` |
| `INSTITUTION_DISPLAY_NAME` | Nombre que verá el ciudadano en la billetera | Su institución / OGTIC | `INTRANT` |

```bash
INSTITUTION_ID=INTRANT
INSTITUTION_DISPLAY_NAME=INTRANT
```

### 4.3 API de datos (OGTIC)

| Variable | Qué es | Como lo obtengo | Ejemplo |
|----------|--------|-----------------|---------|
| `RESTAPI_BASE_URL` | Dirección base de la API que entrega los datos del ciudadano | OGTIC | `https://api.ogtic.gob.do/intrant` |

```bash
RESTAPI_BASE_URL=https://api.ogtic.gob.do/intrant
```

La línea `RESTAPI_SCOPE_ENDPOINT_MAPPING` puede quedar como viene en la plantilla, salvo que OGTIC le indique otro valor.

### 4.4 Acceso a Cuenta Única (CuentaDigital)

| Variable | Qué es | Como lo obtengo |
|----------|--------|-----------------|
| `OAUTH_CLIENT_ID` | Identificador de su institución ante Cuenta Única | OGTIC |
| `OAUTH_CLIENT_SECRET` | Contraseña asociada a ese identificador | OGTIC |

```bash
OAUTH_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
OAUTH_CLIENT_SECRET=el-secret-real-que-entrego-ogtic
```

### 4.5 Credencial que va a emitir

| Variable | Qué es | De dónde sale | Ejemplo |
|----------|--------|---------------|---------|
| `CREDENTIAL_CONFIG_KEY_ID` | Nombre técnico de la configuración de la credencial | Acordado con OGTIC | `DriverLicenseCredential` |
| `CREDENTIAL_ATTRIBUTES` | Campos de la credencial, separados por coma; mismos nombres que en la respuesta de ejemplo de la API OGTIC | OGTIC + su definición de credencial | `national_id,fullName,dateOfBirth,licenseNumber` |
| `CREDENTIAL_SCOPE` | Permisos del token de Cuenta Única que autoriza emitir esta credencial | Confirmado con OGTIC | `"openid offline_access profile email"` |

```bash
CREDENTIAL_CONFIG_KEY_ID=DriverLicenseCredential
CREDENTIAL_ATTRIBUTES=national_id,fullName,dateOfBirth,licenseNumber
CREDENTIAL_SCOPE="openid offline_access profile email"
```

**Nota:** si un valor tiene espacios, escríbalo entre comillas dobles, como en `CREDENTIAL_SCOPE`.

### 4.6 Identidad pública del emisor (DID)

Para que una billetera u otro sistema pueda verificar que una credencial la firmó su institución, necesita consultar la llave pública de su emisor.

Esa información vive en un archivo público (en la práctica, `did.json`). La dirección lógica de ese archivo se llama DID.

**Caso normal:** no configure nada. El kit:

1. Genera la llave y el archivo con la información pública.
2. Lo publica en el mismo servidor del kit, en:
   `https://{su-url-pública}/.well-known/did.json`
3. Usa un DID automático basado en ese host, por ejemplo:
   - dominio `certify.institucion.gob.do` → `did:web:certify.institucion.gob.do`
   - IP / sslip.io `203-0-113-10.sslip.io` → `did:web:203-0-113-10.sslip.io`

En ese caso, deje `DID_URL` comentado o vacío en el `.env`.

En el caso de que su institución quiera alojar y gestionar ese archivo en otra URL (otro dominio, otro sitio web, etc.), no en el servidor del kit. Entonces:

1. Descomente y complete `DID_URL` en el `.env` con el DID que corresponda a esa ubicación, por ejemplo:
   `DID_URL=did:web:claves.institucion.gob.do`
2. Después de instalar, copie el contenido de
   `https://{su-url-pública-del-kit}/.well-known/did.json`
   y publique ese mismo contenido en la URL pública que usted va a administrar (la asociada a ese DID).

Si pone un `DID_URL` externo pero no publica ahí el archivo, la verificación de credenciales fallará: quien valide buscará la llave en esa dirección y no la encontrará.

### 4.7 Campos opcionales

Las líneas que empiezan con `#` (logo, colores, etiquetas en español, etc.) pueden quedar comentadas. El kit aplica valores por defecto. Solo descoméntelas si OGTIC o su equipo quieren personalizar la apariencia de la credencial.

### 4.8 Guardar y salir

Guarde el archivo `.env` y cierre el editor.

---

## 5. Ejecutar la instalación

Desde la carpeta `institution-kit/`:

```bash
chmod +x install.sh
./install.sh
```

El script va a:

1. Realizar una comprobación de que existen Docker, Docker Compose, `curl` y `jq`.
2. Lectura y validación de su archivo `.env`.
3. Generación automática de la configuración.
4. Construcción de la imagen del servicio (la primera vez puede tardar varios minutos; es normal, no cancele).
5. Ejecución de tres componentes: base de datos, Certify (el emisor) y Caddy (HTTPS).
6. Si eligió modo dominio, mensajes breves sobre la obtención del certificado HTTPS.
7. Verificación automática de que el servicio responde.

### Cómo saber qué terminó bien

Al final debe aparecer un bloque similar a:

```text
============================================
Instalación completada
============================================
CERTIFY_PUBLIC_URL: https://...
INSTITUTION_ID:     ...
OAUTH_CLIENT_ID:    ...
CREDENTIAL:         ...
============================================
```

Anote esos cuatro valores: los necesitará para que OGTIC registre su emisor (sección 7).

Si el script termina con `ERROR`, ver sección 8.

---

## 6. Comprobar que quedó bien

Puede repetir la verificación automática:

```bash
./scripts/verify-health.sh
```

O realizar una validación manual.

### 6A. Modo dominio

Reemplace el dominio por el suyo:

```bash
curl https://certify.institucion.gob.do/v1/certify/actuator/health
curl https://certify.institucion.gob.do/.well-known/openid-credential-issuer
curl https://certify.institucion.gob.do/.well-known/did.json
```

### 6B. Modo IP

Reemplace el hostname por el que derivó el kit (IP con guiones + `.sslip.io`). Si Let's Encrypt emitió el certificado, **no** hace falta `-k`:

```bash
curl https://203-0-113-10.sslip.io/v1/certify/actuator/health
curl https://203-0-113-10.sslip.io/.well-known/openid-credential-issuer
curl https://203-0-113-10.sslip.io/.well-known/did.json
```

Si `curl` marca error de certificado, revise logs de Caddy (`docker compose logs caddy`) y confirme puerto 80 abierto.

### Qué debe obtener

| Prueba | Resultado esperado |
|--------|--------------------|
| Health | Una respuesta de texto que incluya `"status":"UP"` |
| openid-credential-issuer | Una respuesta de texto con datos de su servicio emisor (incluye la dirección para emitir credenciales) |
| did.json | Un archivo público de identidad: sirve para que terceros verifiquen que las credenciales las firmó su institución |

**Prueba desde otra red:** abra la URL de health desde un celular o computadora con otra red. Si solo responde “desde el propio servidor” pero no desde afuera, el servicio está ejecutando correctamente pero la red pública aún no llega (vuelva a los pre-requisitos de puertos / firewall).

---

## 7. Qué enviar a OGTIC

La instalación en su servidor no alcanza para que un ciudadano emita desde la billetera. OGTIC debe registrar su institución en la plataforma central de billeteras.

Envíe a OGTIC (los mismos datos que imprimió `install.sh`):

| Dato | Ejemplo |
|------|---------|
| `INSTITUTION_ID` | `INTRANT` |
| `CERTIFY_PUBLIC_URL` | `https://certify.intrant.gob.do` |
| `OAUTH_CLIENT_ID` | (el que le entregaron) |
| `CREDENTIAL_CONFIG_KEY_ID` | `DriverLicenseCredential` |
| Nombre visible de la credencial | `INTRANT` |

Hasta que OGTIC confirme el registro, un ciudadano aún no podrá emitir la credencial desde la billetera, aunque las pruebas de la sección 6 hayan salido bien.

---

## 8. Troubleshooting

| Qué ve | Qué hacer |
|--------|-----------|
| Error porque falta un valor en `.env`, o el secret sigue siendo `REEMPLAZAR_CON_SECRET_DE_OGTIC` | Abra `.env`, complete o corrija el valor, guarde y vuelva a ejecutar `./install.sh` |
| El health no responde o hay timeout | Espere unos minutos (el primer arranque es lento). Luego revise logs: `docker compose logs certify` |
| Health responde JSON con `Full authentication is required` | Regenere config y reinicie Certify (`./scripts/generate-properties.sh` y `docker compose up -d --force-recreate certify`). Debe devolver `{"status":"UP"}` |
| Modo dominio o IP: no obtiene el certificado HTTPS | Confirme puerto 80 abierto desde internet. En modo dominio, que el DNS apunte al servidor. En modo IP, que `sslip.io` resuelva a la IP pública. Si antes usó certificado interno, borre el volumen de Caddy (`docker volume rm …_caddy_data`) y reinicie. |
| Modo IP: la URL no responde desde internet | Confirme que los puertos 80 y 443 de la IP pública llegan al servidor |
| Mensaje de que no encuentra el complemento RestAPI (archivo `.jar`) | Verifique que clonó el repositorio completo (`inji-rd-certify`) y que existe la carpeta `certify-service/loader_path/certify/` con ese archivo |
| `docker compose ... no configuration file provided` | Ejecute los comandos desde la carpeta `institution-kit/` (donde está `docker-compose.yml`) |

### Acceso a logs por servicio

Desde `institution-kit/`:

```bash
docker compose logs -f caddy
docker compose logs -f certify
docker compose logs -f database
```

### Si cambió el `.env` después de instalar

Vuelva a ejecutar:

```bash
./install.sh
```

**Nota:** si ya tuvo una instalación exitosa y más adelante cambia los atributos de la credencial (`CREDENTIAL_ATTRIBUTES` u otros campos de credencial), avise a OGTIC/IUGO antes de asumir que el cambio quedó aplicado. La configuración inicial de la credencial en la base de datos se carga en el primer arranque; un cambio posterior en el `.env` puede requerir acompañamiento técnico.
