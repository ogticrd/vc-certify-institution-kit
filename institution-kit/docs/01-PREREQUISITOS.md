# Lista de pre-requisitos para instituciones emisoras — Inji Certify

Este documento lista todo lo que una institución debe tener listo antes de ejecutar el kit de implementación.

El despliegue levanta Inji Certify, una base de datos PostgreSQL y Caddy (proxy HTTPS) en un servidor propio de la institución.

**Siguiente paso:** cuando complete este checklist, continúe con [02-GUIA-DE-INSTALACION.md](./02-GUIA-DE-INSTALACION.md).

---

## Infraestructura

Toda la información de servidor, software, red, DNS y puertos está en esta sección. El equipo de infraestructura debe cubrirla completa antes de la instalación.

Para desplegar Inji Certify la institución debe disponer de un servidor con las características de hardware indicadas más abajo. En ese servidor se instalan las herramientas, se registra el DNS (si aplica) y se abren los puertos.

### Herramientas obligatorias

- **Git:** es necesario tener instalado git para poder clonar el repositorio de Inji Certify.
- **Docker Engine & Docker Compose:** los componentes necesarios para la emisión de la credencial se levantan utilizando Docker Compose. Para Docker Engine utilizar como mínimo la versión 24, e instalar la versión 2 de Docker Compose.
- **Curl y jq:** para poder verificar desde el servidor los endpoints de health check y hacer verificaciones básicas. `jq` se utiliza para la verificación automática de healthcheck.

### Hardware requerido

Ese servidor debe cumplir al menos con las siguientes características:

- 4 vCPU
- 8 GB de memoria RAM
- 50 GB de disco duro
- SO Linux x86_64 compatible con Docker Engine, por ejemplo Ubuntu 22/24

### Acceso al repositorio

Solicitar a OGTIC acceso e información necesaria para clonar el repositorio y el branch indicados por OGTIC.

### DNS y TLS

El emisor debe ser alcanzable desde internet. El servidor debe poder iniciar las conexiones HTTPS de salida indicadas en la tabla de puertos más abajo.

El servidor debe tener una IP pública fija (o un mecanismo análogo: IP elástica/reservada, o DNS dinámico estable) para poder registrar el DNS o derivar un hostname en modo IP. Sin una IP estable, el registro A/AAAA no apunta de forma confiable al emisor.

El kit soporta dos modos de acceso público (variable `TLS_MODE` en el archivo `.env`). Elija **uno solo**.

#### Modo dominio (`TLS_MODE=domain`)

Usar cuando la institución tiene un nombre de dominio propio que apunta al servidor.

- Registrar un subdominio DNS, por ejemplo: `certify.institucion.gob.do`
- Agregar un registro tipo A (o AAAA) a la IP pública fija del servidor
- En el `.env` indicar `CERTIFY_PUBLIC_HOST` (el dominio, sin `https://`) y `CADDY_ACME_EMAIL` (correo de infraestructura)

Caddy obtiene y renueva automáticamente el certificado HTTPS con Let's Encrypt (ACME HTTP-01).

#### Modo IP (`TLS_MODE=ip`)

Usar cuando la institución no provee un nombre de dominio propio.

- Indicar en el `.env` la IP pública del servidor (`SERVER_PUBLIC_IP`), el proveedor DNS dinámico (por defecto `sslip.io`; también puede usarse `nip.io`) y `CADDY_ACME_EMAIL`
- El kit deriva un hostname usable, por ejemplo: `https://203-0-113-10.sslip.io`
- Caddy solicita un certificado HTTPS a Let's Encrypt (ACME HTTP-01), igual que en modo dominio. Requiere puerto 80 abierto desde internet.

### Puertos de red (entrada y salida)

El equipo de infraestructura debe asegurar que los siguientes puertos estén disponibles:

| Puerto | Dirección | Destino | Razón |
|--------|-----------|---------|-------|
| 80/tcp | in | Internet → servidor (Caddy) | Validación ACME HTTP-01 (Let's Encrypt) y renovación automática del certificado. Obligatorio en ambos modos (`domain` e `ip`). |
| 443/tcp | in | Internet → servidor (Caddy) | HTTPS público del emisor (OID4VCI, health, DID). Obligatorio en ambos modos. |
| 443/tcp | out | `cuenta.digital.gob.do` | OAuth / validación de tokens JWT (Cuenta Única / Cuenta Digital). |
| 443/tcp | out | URL de la API de datos de la institución | Obtener los datos del ciudadano para armar la credencial. |
| 443/tcp | out | Registries Docker / Maven | Descarga de imágenes y dependencias en el build (primera instalación). |

**Nota:** el puerto interno de Certify (8090) no se publica en internet. Caddy recibe el tráfico HTTPS en el 443, lo desencripta y lo reenvía a Certify por la red interna de Docker. El puerto 80 debe estar abierto desde internet para que Caddy pueda obtener y renovar el certificado con Let’s Encrypt.

---

## Datos generales

Antes del deploy, se debe tener definida la siguiente información:

- Identificador único del emisor
- Nombre de la institución
- URL base de la API
- Ejemplo de respuesta del servicio; los nombres de los campos deben coincidir con los atributos definidos en la configuración de la credencial (`credential_attributes`)
- Scope de la credencial (`credential_scope`): usar el default del kit salvo que se necesite o quiera indicar otro
- Client Id OAuth
- Client Secret OAuth

---

## OAuth con Cuenta Única

El Client ID OAuth es el identificador de la institución ante Cuenta Única: es cómo el sistema reconoce al emisor (el “usuario” de la aplicación). El Client Secret OAuth es la contraseña asociada a ese identificador. Certify los usa para autenticarse contra Cuenta Única (validar al ciudadano y pedir tokens).

Los entrega OGTIC al registrar el cliente; la institución no los genera ni los registra por cuenta propia.

---

## Configuración de la credencial a emitir

El deploy inserta automáticamente la configuración de la credencial. Para ello es necesario definir:

- id de la credencial — `credential_config_key_id`
- lista de atributos de la credencial — `credential_attributes`
- scope de la credencial — `credential_config.scope` (puede utilizarse el que viene por defecto en el `.env`)

De forma opcional se deben indicar:

- Nombre que se va a mostrar en la wallet — `credential_display_name` (valor default: nombre de la institución)
- `credential_format` (valor default: `ldp_vc`)
- logo — `credential_logo_url` (default: logo genérico del kit)
- color de background (default: color genérico del kit)
- nombre de los atributos que se van a mostrar en la wallet (default: nombre técnico del campo)
- URL DID (default: `did:web:host` derivado del `certify_public_url`)

---

## DID y firma de la credencial

El archivo `did.json` es el documento público del emisor. Ahí está la llave pública. Quien verifica una credencial (por ejemplo una wallet o Inji Verify) consulta ese archivo para comprobar que la credencial la firmó esa institución y que no fue modificada.

La llave privada nunca se publica: queda en el servidor y Certify la usa para firmar cada credencial. En el primer arranque el kit genera un certificado (autofirmado) junto con esa llave. Más adelante la institución puede cargar un certificado propio (por ejemplo uno emitido por su autoridad certificadora) para que las credenciales se firmen con ese certificado en lugar del dummy.

---

## Consideraciones OGTIC

Hoy Certify y Mimoto tienen configuraciones que prenden/apagan algunas validaciones del token que se obtiene de Cuenta Única.

### Access Token del ciudadano

- claim `aud`: si se valida, tiene que incluir el audience del emisor.
- claim `client_id`: si se valida, tiene que venir en el token.
- `scope`: el valor exacto que emite debe ser el que está registrado en el scope de la credencial.
- `c_nonce` / nonce: si se valida, Cuenta Única tiene que retornar el claim `c_nonce`, `c_nonce_expires_in` dentro del access token.
