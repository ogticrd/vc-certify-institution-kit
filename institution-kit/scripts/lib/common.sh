#!/usr/bin/env bash
# Shared helpers for institution-kit scripts.

set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "${KIT_DIR}/.." && pwd)"
ENV_FILE="${KIT_DIR}/.env"
GENERATED_DIR="${KIT_DIR}/generated"
RUNTIME_ENV="${GENERATED_DIR}/.env.runtime"

load_env() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    echo "ERROR: No existe ${ENV_FILE}. Copie .env.example a .env y complete los valores." >&2
    exit 1
  fi
  aviso_permisos_env
  # shellcheck disable=SC1090
  set -a
  source "${ENV_FILE}"
  set +a
}

# Modo (octal, p. ej. 644) de un fichero, en Linux (GNU stat) y en macOS (BSD stat).
file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || true
}

# K1/K12: el .env lleva OAUTH_CLIENT_SECRET y, a veces, las contraseñas. Si lo puede leer otro usuario del
# servidor, avisa (una sola vez por ejecución: los scripts hijos heredan la marca) y dice cómo corregirlo.
# Solo avisa: no cambia el modo de un fichero que la institución ya tenía.
aviso_permisos_env() {
  [[ -z "${KIT_AVISO_ENV_MOSTRADO:-}" ]] || return 0
  local m
  m="$(file_mode "${ENV_FILE}")"
  [[ "${m}" =~ ^[0-7]{3,4}$ ]] || return 0
  if (( (8#${m}) & 8#077 )); then
    echo "AVISO: ${ENV_FILE} es legible por otros usuarios (modo ${m}) y contiene el secreto de OAuth. Ejecute: chmod 600 ${ENV_FILE}" >&2
    KIT_AVISO_ENV_MOSTRADO=1
    export KIT_AVISO_ENV_MOSTRADO
  fi
}

# generated/ guarda .env.runtime (contraseñas) y la configuración: solo para quien instala (700). Docker
# monta SUBcarpetas y ficheros concretos (el daemon los lee como root), no generated/ entera.
ensure_generated_dir() {
  mkdir -p "${GENERATED_DIR}"
  chmod 700 "${GENERATED_DIR}"
}

derive_public_url() {
  case "${TLS_MODE:-}" in
    domain)
      [[ -n "${CERTIFY_PUBLIC_HOST:-}" ]] || { echo "ERROR: CERTIFY_PUBLIC_HOST es obligatorio con TLS_MODE=domain" >&2; exit 1; }
      CERTIFY_PUBLIC_URL="https://${CERTIFY_PUBLIC_HOST}"
      ;;
    ip)
      [[ -n "${SERVER_PUBLIC_IP:-}" ]] || { echo "ERROR: SERVER_PUBLIC_IP es obligatorio con TLS_MODE=ip" >&2; exit 1; }
      local provider="${IP_DNS_PROVIDER:-sslip.io}"
      local ip_dashes="${SERVER_PUBLIC_IP//./-}"
      IP_HOSTNAME="${ip_dashes}.${provider}"
      CERTIFY_PUBLIC_URL="https://${IP_HOSTNAME}"
      ;;
    proxy)
      # Detrás de un proxy inverso ajeno (R6): el kit no conoce el nombre público, lo da la
      # institución. Sin ACME ni certificados: el TLS lo termina el proxy.
      if [[ -z "${CERTIFY_PUBLIC_URL:-}" ]]; then
        echo "ERROR: CERTIFY_PUBLIC_URL es obligatorio con TLS_MODE=proxy: la URL pública que sirve su proxy, p. ej. https://certify.suinstitucion.gob.do (sin barra final)." >&2
        exit 1
      fi
      validate_proxy_public_url
      ;;
    *)
      echo "ERROR: TLS_MODE debe ser 'domain', 'ip' o 'proxy' (actual: ${TLS_MODE:-})" >&2
      exit 1
      ;;
  esac
  export CERTIFY_PUBLIC_URL IP_HOSTNAME
}

# CERTIFY_PUBLIC_URL en modo proxy: https://<host>[:puerto], sin ruta ni barra final. (http solo para
# localhost / 127.0.0.1, pruebas locales: es lo mismo que admite scripts/lib/credencial.mjs.)
validate_proxy_public_url() {
  local u="${CERTIFY_PUBLIC_URL}"
  local https_re='^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$'
  local local_re='^http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$'
  if [[ "${u}" == */ ]]; then
    echo "ERROR: CERTIFY_PUBLIC_URL no debe terminar en «/» (valor: ${u})." >&2
    exit 1
  fi
  if ! [[ "${u}" =~ ${https_re} || "${u}" =~ ${local_re} ]]; then
    echo "ERROR: CERTIFY_PUBLIC_URL debe ser https://<dominio público> sin ruta ni espacios (valor: ${u})." >&2
    exit 1
  fi
}

derive_did_url() {
  if [[ -z "${DID_URL:-}" ]]; then
    local host
    host="${CERTIFY_PUBLIC_URL#https://}"
    host="${host#http://}"
    host="${host%%/*}"
    # did:web codifica el puerto como %3A (did:web:host%3A8443).
    DID_URL="did:web:${host//:/%3A}"
  fi
  export DID_URL
}

apply_defaults() {
  CREDENTIAL_DISPLAY_NAME="${CREDENTIAL_DISPLAY_NAME:-${INSTITUTION_DISPLAY_NAME}}"
  # El orden en que se escriben tipos y contextos en la base de datos lo fija
  # scripts/lib/credencial.mjs (como Collections.sort de Java); aquí solo el valor por defecto.
  # El contexto ya no es una entrada: lo genera el kit (scripts/generate-context.mjs).
  CREDENTIAL_TYPE="${CREDENTIAL_TYPE:-VerifiableCredential,${INSTITUTION_ID}Credential}"
  CREDENTIAL_FORMAT="${CREDENTIAL_FORMAT:-ldp_vc}"
  CREDENTIAL_BG_COLOR="${CREDENTIAL_BG_COLOR:-#12107c}"
  CREDENTIAL_TEXT_COLOR="${CREDENTIAL_TEXT_COLOR:-#FFFFFF}"
  if [[ -z "${RESTAPI_SCOPE_ENDPOINT_MAPPING:-}" ]]; then
    RESTAPI_SCOPE_ENDPOINT_MAPPING="{'openid offline_access profile email': '/:national_id','openid': '/:national_id'}"
  fi
  POSTGRES_USER="${POSTGRES_USER:-postgres}"
  POSTGRES_DB="${POSTGRES_DB:-inji_certify}"
  # Servidor de autorización de los ciudadanos (R4): Cuenta Única de producción por defecto. SIN barra
  # final: el emisor (`iss`) del token se compara por igualdad exacta.
  AUTH_ISSUER_URL="${AUTH_ISSUER_URL:-https://auth.cuentaunica.gob.do}"
  # Modo proxy (R6, D5)
  CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-8080}"
  TRUSTED_PROXIES="${TRUSTED_PROXIES:-private_ranges}"
  export CREDENTIAL_DISPLAY_NAME CREDENTIAL_TYPE CREDENTIAL_FORMAT
  export CREDENTIAL_BG_COLOR CREDENTIAL_TEXT_COLOR
  export RESTAPI_SCOPE_ENDPOINT_MAPPING POSTGRES_USER POSTGRES_DB
  export AUTH_ISSUER_URL CADDY_HTTP_PORT TRUSTED_PROXIES
  # Los secretos se resuelven en validate_env, DESPUÉS de validar (T7-3).
}

# --- Secretos (R9, D7; T8: K2, K3) -----------------------------------------------------------------
# POSTGRES_PASSWORD y KEYSTORE_PASSWORD (contraseña del keystore PKCS12 de Certify): si la institución
# deja el valor por defecto (postgres / local) o lo vacía, el kit genera 32 bytes aleatorios
# (`openssl rand -hex 32`, 64 caracteres hex) y los guarda SOLO en generated/.env.runtime (modo 600).
# Nunca se escriben en la salida estándar ni en ningún log.
#
# REGLA (K2): las contraseñas SOLO se generan en una instalación NUEVA. La de Postgres queda grabada en el
# volumen de datos al crear la base, y la del keystore en local.p12 (volumen certify-pkcs12) al primer
# arranque de Certify; cambiarlas después rompe el arranque (Postgres rechaza la conexión; Certify no abre el
# keystore y no puede descifrar sus claves de firma). Por eso:
#   1. Valor propio en el .env (distinto del defecto): se respeta. Es la forma de rotar a mano.
#   2. Hay una generada antes en .env.runtime (distinta del defecto): se REUTILIZA, no se regenera.
#   3. Valor por defecto/vacío y NO hay generada, pero hay instalación previa (generated/.env.runtime, o un
#      contenedor de la base o un volumen de datos/keystore de ESTE kit en Docker): el kit se DETIENE con el
#      procedimiento para rotarlas a mano. No genera contraseñas nuevas (K2) y ya no existe la salida
#      KIT_CONSERVAR_SECRETOS_POR_DEFECTO (K3): dejar postgres/local en silencio no es una opción.
#   4. Instalación nueva (nada de lo anterior): se generan.
# Se resuelven DESPUÉS de validar el .env (validate_env, T7-3): un .env inválido no deja contraseñas nuevas.
SECRETO_DEFECTO_POSTGRES="postgres"
SECRETO_DEFECTO_KEYSTORE="local"

# Valor de CLAVE en generated/.env.runtime (sin ejecutar el fichero; sin comillas si las tuviera).
_valor_runtime() {
  [[ -f "${RUNTIME_ENV}" ]] || return 0
  local v
  v="$({ grep -m1 "^$1=" "${RUNTIME_ENV}" || true; } | cut -d= -f2-)"
  if [[ "${v}" =~ ^\"(.*)\"$ || "${v}" =~ ^\'(.*)\'$ ]]; then v="${BASH_REMATCH[1]}"; fi
  printf '%s' "${v}"
}

# Ejecuta una orden con límite de tiempo, en Linux y en macOS (que no trae `timeout`):
#   kit_timeout <segundos> <orden> [argumentos…]   (devuelve 124 si se agotó, como `timeout`)
kit_timeout() {
  local seg="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "${seg}" "$@"; return; fi
  if command -v gtimeout >/dev/null 2>&1; then gtimeout "${seg}" "$@"; return; fi
  local rc=0 pid vigia marca
  marca="$(mktemp "${TMPDIR:-/tmp}/kit-timeout.XXXXXX")"
  "$@" &
  pid=$!
  ( sleep "${seg}"; echo 1 > "${marca}"; kill -TERM "${pid}" 2>/dev/null ) >/dev/null 2>&1 &
  vigia=$!
  wait "${pid}" 2>/dev/null || rc=$?
  kill "${vigia}" 2>/dev/null || true
  wait "${vigia}" 2>/dev/null || true
  if [[ -s "${marca}" ]]; then rc=124; fi
  rm -f "${marca}"
  return "${rc}"
}

# ¿Hay una instalación previa de ESTE kit? Basta con generated/.env.runtime; además, si hay Docker, un
# contenedor de la base (aunque esté parado) o un volumen de datos/keystore de este kit. Sin Docker, o con
# el daemon parado, solo cuenta el fichero. Deja en INSTALACION_PREVIA_MOTIVO por qué.
instalacion_previa() {
  INSTALACION_PREVIA_MOTIVO=""
  if [[ -f "${RUNTIME_ENV}" ]]; then
    INSTALACION_PREVIA_MOTIVO="existe ${RUNTIME_ENV}"
    return 0
  fi
  command -v docker >/dev/null 2>&1 || return 1
  local salida proyecto
  salida="$(kit_timeout 10 docker ps -a -q --filter "label=com.docker.compose.service=database" \
    --filter "label=com.docker.compose.project.working_dir=${KIT_DIR}" 2>/dev/null || true)"
  if [[ -n "${salida//[[:space:]]/}" ]]; then
    INSTALACION_PREVIA_MOTIVO="hay un contenedor de la base de datos de este kit en Docker (docker ps -a)"
    return 0
  fi
  proyecto="${COMPOSE_PROJECT_NAME:-$(basename "${KIT_DIR}" | tr '[:upper:]' '[:lower:]')}"
  for vol in pgdata certify-pkcs12; do
    salida="$(kit_timeout 10 docker volume ls -q --filter "label=com.docker.compose.project=${proyecto}" \
      --filter "label=com.docker.compose.volume=${vol}" 2>/dev/null || true)"
    if [[ -n "${salida//[[:space:]]/}" ]]; then
      INSTALACION_PREVIA_MOTIVO="hay un volumen de Docker de este kit (${vol}: docker volume ls)"
      return 0
    fi
  done
  return 1
}

# Deja en $1 (nombre de variable) la contraseña a usar para $2 (clave en .env.runtime) cuyo valor por
# defecto es $3. Marca SECRETOS_GENERADOS=1 si tuvo que generar una; si hace falta generar pero hay una
# instalación previa, anota la clave en SECRETOS_BLOQUEADOS (resolve_secrets se detiene).
_resolver_secreto() {
  local var="$1" clave="$2" defecto="$3"
  local actual="${!var:-}"
  if [[ -n "${actual}" && "${actual}" != "${defecto}" ]]; then
    return 0  # la institución fijó un valor propio: se respeta
  fi
  local previo
  previo="$(_valor_runtime "${clave}")"
  if [[ -n "${previo}" && "${previo}" != "${defecto}" ]]; then
    printf -v "${var}" '%s' "${previo}"
    return 0
  fi
  if instalacion_previa; then
    SECRETOS_BLOQUEADOS+=("${clave}")
    return 0
  fi
  command -v openssl >/dev/null 2>&1 || { echo "ERROR: hace falta openssl para generar las contraseñas." >&2; exit 1; }
  printf -v "${var}" '%s' "$(openssl rand -hex 32)"
  SECRETOS_GENERADOS=1
}

resolve_secrets() {
  SECRETOS_GENERADOS=""
  SECRETOS_BLOQUEADOS=()
  if [[ -n "${KIT_CONSERVAR_SECRETOS_POR_DEFECTO:-}" ]]; then
    echo "AVISO: KIT_CONSERVAR_SECRETOS_POR_DEFECTO ya no existe y se ignora: el kit no deja las contraseñas por defecto (postgres/local). En una instalación existente, rótelas a mano y póngalas en el .env (guía, sección «Secretos»)." >&2
  fi
  _resolver_secreto POSTGRES_PASSWORD POSTGRES_PASSWORD "${SECRETO_DEFECTO_POSTGRES}"
  _resolver_secreto KEYSTORE_PASSWORD KEYSTORE_PASSWORD "${SECRETO_DEFECTO_KEYSTORE}"
  if [[ ${#SECRETOS_BLOQUEADOS[@]} -gt 0 ]]; then
    local c
    {
      echo "ERROR: ya hay una instalación previa de este kit (${INSTALACION_PREVIA_MOTIVO}) y estas contraseñas siguen siendo las de defecto o están vacías:"
      for c in "${SECRETOS_BLOQUEADOS[@]}"; do echo "  - ${c}"; done
      cat <<'MENSAJE'
El kit NO genera ni regenera contraseñas sobre una instalación existente: la base de datos y el keystore de
Certify conservan las antiguas y, con otras nuevas, Certify dejaría de arrancar (o perdería el acceso a sus
claves de firma). Tampoco existe ya KIT_CONSERVAR_SECRETOS_POR_DEFECTO. Rótelas a mano, una vez:
  1. Genere una por cada una: openssl rand -hex 32   (sin $ \ ` " ' ni espacios).
  2. Postgres: cambie la contraseña EN la base, con la instalación en marcha:
       printf "ALTER USER <POSTGRES_USER> PASSWORD '<nueva>';\n" | docker compose $(cat generated/compose-args) exec -T database psql -U <POSTGRES_USER> -d <POSTGRES_DB>
  3. Keystore: haga copia del volumen certify-pkcs12 y cambie la contraseña de local.p12:
       docker compose $(cat generated/compose-args) run --rm --no-deps --entrypoint keytool certify \
         -storepasswd -storetype PKCS12 -keystore /home/mosip/CERTIFY_PKCS12/local.p12
     (el kit no ha probado este paso con un Certify real: no lo haga sin la copia).
  4. Escriba las nuevas en POSTGRES_PASSWORD y KEYSTORE_PASSWORD del .env y vuelva a ejecutar.
Detalle en institution-kit/docs/02-GUIA-DE-INSTALACION.md, sección «Secretos».
MENSAJE
    } >&2
    exit 1
  fi
  export POSTGRES_PASSWORD KEYSTORE_PASSWORD
  if [[ -n "${SECRETOS_GENERADOS}" ]]; then
    # Se persisten YA: otro script del kit (generate-properties.sh, compose…) tiene que ver los mismos.
    write_runtime_env
    echo "AVISO: se generaron contraseñas aleatorias para la base de datos y/o el keystore (guardadas en generated/.env.runtime, modo 600). Solo valen para una instalación NUEVA; no se regeneran nunca más." >&2
  fi
}

# Default: restapi-dataprovider-plugin-*.jar shipped in certify-service/loader_path/certify/
PLUGIN_DIR="${REPO_ROOT}/certify-service/loader_path/certify"

resolve_plugin_jar() {
  local explicit="${RESTAPI_PLUGIN_JAR:-}"
  local resolved=""

  if [[ -n "${explicit}" ]]; then
    local candidate="${explicit}"
    if [[ "${candidate}" != /* ]]; then
      if [[ -f "${KIT_DIR}/${candidate}" ]]; then
        candidate="${KIT_DIR}/${candidate}"
      elif [[ -f "${REPO_ROOT}/${candidate}" ]]; then
        candidate="${REPO_ROOT}/${candidate}"
      else
        candidate="${KIT_DIR}/${candidate}"
      fi
    fi
    if [[ ! -f "${candidate}" ]]; then
      echo "ERROR: RESTAPI_PLUGIN_JAR no encontrado: ${explicit}" >&2
      exit 1
    fi
    resolved="${candidate}"
  else
    shopt -s nullglob
    local jars=("${PLUGIN_DIR}"/restapi-dataprovider-plugin*.jar)
    shopt -u nullglob
    if [[ ${#jars[@]} -eq 0 && -f "${PLUGIN_DIR}/restapi-dataprovider-plugin.jar" ]]; then
      jars=("${PLUGIN_DIR}/restapi-dataprovider-plugin.jar")
    fi
    if [[ ${#jars[@]} -eq 0 ]]; then
      echo "ERROR: No se encontró restapi-dataprovider-plugin*.jar en ${PLUGIN_DIR}" >&2
      exit 1
    fi
    if [[ ${#jars[@]} -gt 1 ]]; then
      echo "AVISO: Varios plugins en ${PLUGIN_DIR}; usando $(basename "${jars[0]}")" >&2
    fi
    resolved="${jars[0]}"
  fi

  RESTAPI_PLUGIN_JAR_RESOLVED="${resolved}"
  export RESTAPI_PLUGIN_JAR_RESOLVED
}

validate_env() {
  local missing=()
  for var in INSTITUTION_ID INSTITUTION_DISPLAY_NAME RESTAPI_BASE_URL OAUTH_CLIENT_ID OAUTH_CLIENT_SECRET \
    CREDENTIAL_CONFIG_KEY_ID CREDENTIAL_ATTRIBUTES CREDENTIAL_SCOPE; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("$var")
    fi
  done
  # El correo de ACME (Let's Encrypt) solo lo usa Caddy en domain e ip; en proxy no hay ACME.
  if [[ "${TLS_MODE:-}" != "proxy" && -z "${CADDY_ACME_EMAIL:-}" ]]; then
    missing+=("CADDY_ACME_EMAIL")
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: Variables obligatorias vacías en .env:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 1
  fi
  if [[ "${OAUTH_CLIENT_SECRET}" == "REEMPLAZAR_CON_SECRET_DE_OGTIC" ]]; then
    echo "ERROR: Configure OAUTH_CLIENT_SECRET con el valor provisto por OGTIC." >&2
    exit 1
  fi
  if [[ "${OAUTH_CLIENT_ID}" == "CAMBIAR-ME" ]]; then
    echo "ERROR: Configure OAUTH_CLIENT_ID con el valor provisto por OGTIC (sigue el marcador CAMBIAR-ME del .env.example)." >&2
    exit 1
  fi
  # R4: el token de la API de datos NO tiene defecto. Antes apuntaba a Cuenta Única de staging; un
  # defecto equivocado se descubre en producción.
  if [[ -z "${RESTAPI_TOKEN_URL:-}" || "${RESTAPI_TOKEN_URL}" == "CAMBIAR-ME" ]]; then
    echo "ERROR: RESTAPI_TOKEN_URL es obligatorio: es la URL donde Certify pide el token de la API de datos de su institución (RESTAPI_BASE_URL), NO el del ciudadano ni el de Cuenta Única. OGTIC entrega el valor: confírmelo con OGTIC antes de instalar." >&2
    exit 1
  fi
  if ! [[ "${RESTAPI_TOKEN_URL}" =~ ^https?://[^[:space:]]+$ ]]; then
    echo "ERROR: RESTAPI_TOKEN_URL debe ser una URL http(s) sin espacios." >&2
    exit 1
  fi
  # El emisor (`iss`) del token se compara por igualdad exacta: una barra final lo rompe todo.
  if ! [[ "${AUTH_ISSUER_URL}" =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[^[:space:]]*[^[:space:]/])?$ ]]; then
    echo "ERROR: AUTH_ISSUER_URL debe ser una URL https sin espacios y SIN barra final (valor: ${AUTH_ISSUER_URL}). Es el emisor del token de Cuenta Única y se compara tal cual." >&2
    exit 1
  fi
  if [[ "${TLS_MODE:-}" == "proxy" ]]; then
    if ! [[ "${CADDY_HTTP_PORT}" =~ ^[0-9]{1,5}$ ]] || (( 10#${CADDY_HTTP_PORT} < 1 || 10#${CADDY_HTTP_PORT} > 65535 )); then
      echo "ERROR: CADDY_HTTP_PORT debe ser un puerto entre 1 y 65535 (valor: ${CADDY_HTTP_PORT})." >&2
      exit 1
    fi
    # TRUSTED_PROXIES va al Caddyfile: solo `private_ranges` o direcciones/CIDR separadas por espacio.
    local tp
    for tp in ${TRUSTED_PROXIES}; do
      if ! [[ "${tp}" == "private_ranges" || "${tp}" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]]; then
        echo "ERROR: TRUSTED_PROXIES solo admite «private_ranges» o IP/CIDR separadas por espacios (valor no válido: ${tp})." >&2
        exit 1
      fi
    done
  fi
  validate_logo_path
  # T7-3: los secretos se resuelven solo cuando todo lo demás es válido; un .env incorrecto no deja
  # contraseñas nuevas en generated/.env.runtime.
  resolve_secrets
}

# El logo de la credencial (R10): LOGO_PATH es obligatorio y tiene que ser un PNG. Una ruta relativa
# se resuelve desde el directorio del kit. Deja la ruta absoluta en LOGO_PATH_RESOLVED.
# La firma PNG son los 8 bytes 89 50 4E 47 0D 0A 1A 0A.
validate_logo_path() {
  if [[ -n "${CREDENTIAL_LOGO_URL:-}" ]]; then
    echo "ERROR: CREDENTIAL_LOGO_URL ya no existe: el logo lo sirve el propio kit. Quítela del .env y use LOGO_PATH=<ruta a un PNG>." >&2
    exit 1
  fi
  if [[ -z "${LOGO_PATH:-}" ]]; then
    echo "ERROR: LOGO_PATH es obligatorio: ruta a un fichero PNG con el logo de su institución (se muestra en la cartera del ciudadano)." >&2
    exit 1
  fi
  local candidato="${LOGO_PATH}"
  [[ "${candidato}" == /* ]] || candidato="${KIT_DIR}/${candidato}"
  if [[ ! -f "${candidato}" || ! -r "${candidato}" ]]; then
    echo "ERROR: LOGO_PATH no apunta a un fichero legible: ${LOGO_PATH}" >&2
    exit 1
  fi
  local firma
  firma="$(head -c 8 "${candidato}" | od -An -tx1 | tr -d ' \n')"
  if [[ "${firma}" != "89504e470d0a1a0a" ]]; then
    echo "ERROR: LOGO_PATH no es un PNG (la cabecera del fichero no es la de un PNG): ${LOGO_PATH}" >&2
    exit 1
  fi
  LOGO_PATH_RESOLVED="${candidato}"
  export LOGO_PATH_RESOLVED
}

# generated/.env.runtime (modo 600): lo que necesita la ejecución —contraseñas y secreto OAuth— y nada
# más. Lo lee `docker compose` (--env-file, ver generated/compose-args) y las propias funciones del
# kit; NO se carga con `source`. No copia el .env entero. K1: es el ÚNICO fichero que lleva los secretos;
# las properties de Certify (generated/config/*.properties, 644 porque el contenedor las lee como uid 1001)
# solo llevan marcadores ${KIT_DB_PASSWORD}, ${KIT_KEYSTORE_PASSWORD} y ${KIT_OAUTH_CLIENT_SECRET} que Spring
# resuelve desde el entorno del contenedor (docker-compose.yml las toma de este fichero).
# Se escribe de forma atómica con permisos restrictivos desde el primer byte.
write_runtime_env() {
  ensure_generated_dir
  local tmp
  tmp="$(umask 077 && mktemp "${GENERATED_DIR}/.env.runtime.XXXXXX")"
  cat > "${tmp}" <<EOF
TLS_MODE=${TLS_MODE:-}
CERTIFY_PUBLIC_URL=${CERTIFY_PUBLIC_URL:-}
DID_URL=${DID_URL:-}
POSTGRES_USER=${POSTGRES_USER:-postgres}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-}
POSTGRES_DB=${POSTGRES_DB:-inji_certify}
KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD:-}
OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET:-}
CADDY_HTTP_PORT=${CADDY_HTTP_PORT:-8080}
EOF
  chmod 600 "${tmp}"
  mv "${tmp}" "${RUNTIME_ENV}"
}

# generated/compose-args: la orden exacta de `docker compose` para este modo (D5). Compose no tiene
# condicionales, así que el modo se elige con ficheros superpuestos:
#   domain, ip -> docker-compose.yml + docker-compose.tls.yml    (Caddy publica 80 y 443)
#   proxy      -> docker-compose.yml + docker-compose.proxy.yml  (Caddy publica solo CADDY_HTTP_PORT -> 80)
# y las variables (contraseñas) se leen de generated/.env.runtime. El docker-compose.yml base NO
# publica ningún puerto: ejecutar `docker compose` a secas deja Caddy sin puertos, no con los
# equivocados. Las rutas son relativas al directorio del kit.
write_compose_args() {
  ensure_generated_dir
  local overlay
  case "${TLS_MODE}" in
    proxy) overlay="docker-compose.proxy.yml" ;;
    domain | ip) overlay="docker-compose.tls.yml" ;;
    *) echo "ERROR: TLS_MODE inválido: ${TLS_MODE}" >&2; exit 1 ;;
  esac
  printf '%s\n' "-f docker-compose.yml -f ${overlay} --env-file generated/.env.runtime" > "${GENERATED_DIR}/compose-args"
}

# Deja en KIT_COMPOSE la orden `docker compose …` de este modo (lee generated/compose-args). Úsese
# como: "${KIT_COMPOSE[@]}" exec -T caddy …   (desde el directorio del kit).
load_compose_args() {
  local f="${GENERATED_DIR}/compose-args"
  if [[ ! -f "${f}" ]]; then
    echo "ERROR: no existe ${f}; ejecute scripts/generate-config.sh (o ./install.sh) primero." >&2
    exit 1
  fi
  local args
  read -r -a args < "${f}"
  KIT_COMPOSE=(docker compose "${args[@]}")
}

# Espera a que Certify responda UP, por la red interna (R9: el actuator no se publica). Desde el
# contenedor de Caddy a Certify; necesita load_compose_args. Devuelve 0 si llega a UP y 1 si se agotan
# los intentos (la última respuesta queda en HEALTH_ULTIMA_RESPUESTA).
#   wait_for_health [intentos=60] [segundos entre intentos=5]
wait_for_health() {
  local max="${1:-60}" pausa="${2:-5}" i status response=""
  HEALTH_ULTIMA_RESPUESTA=""
  for ((i = 1; i <= max; i++)); do
    if response=$(cd "${KIT_DIR}" && "${KIT_COMPOSE[@]}" exec -T caddy wget -qO- http://certify:8090/v1/certify/actuator/health 2>/dev/null); then
      status=$(echo "${response}" | jq -r '.status // empty' 2>/dev/null || true)
      if [[ "${status}" == "UP" ]]; then return 0; fi
    fi
    if ((i < max)); then
      echo "  Intento ${i}/${max} — esperando ${pausa}s ..." >&2
      sleep "${pausa}"
    fi
  done
  HEALTH_ULTIMA_RESPUESTA="${response:-sin respuesta}"
  return 1
}

export_env_for_templates() {
  export CERTIFY_PUBLIC_URL CERTIFY_PUBLIC_HOST IP_HOSTNAME TLS_MODE DID_URL
  export INSTITUTION_ID INSTITUTION_DISPLAY_NAME RESTAPI_BASE_URL
  export OAUTH_CLIENT_ID OAUTH_CLIENT_SECRET
  export CREDENTIAL_CONFIG_KEY_ID CREDENTIAL_ATTRIBUTES CREDENTIAL_SCOPE
  export CREDENTIAL_DISPLAY_NAME CREDENTIAL_TYPE CREDENTIAL_FORMAT
  export LOGO_PATH CREDENTIAL_BG_COLOR CREDENTIAL_TEXT_COLOR CREDENTIAL_LABELS_JSON CREDENTIAL_ATTRIBUTE_LABELS
  export RESTAPI_SCOPE_ENDPOINT_MAPPING POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB
  export CADDY_ACME_EMAIL RESTAPI_TOKEN_URL AUTH_ISSUER_URL KEYSTORE_PASSWORD
  export CADDY_HTTP_PORT TRUSTED_PROXIES
}

# Variables que leen los programas Node (scripts/lib/credencial.mjs) y que `run_node` reenvía al
# contenedor cuando no hay Node local.
NODE_ENV_VARS=(
  CREDENTIAL_CONFIG_KEY_ID CREDENTIAL_ATTRIBUTES CREDENTIAL_TYPE CREDENTIAL_LABELS_JSON
  CREDENTIAL_ATTRIBUTE_LABELS CREDENTIAL_DISPLAY_NAME CREDENTIAL_BG_COLOR
  CREDENTIAL_TEXT_COLOR CREDENTIAL_SCOPE CREDENTIAL_FORMAT CERTIFY_PUBLIC_URL DID_URL
  INSTITUTION_ID INSTITUTION_DISPLAY_NAME
)
NODE_IMAGE="${NODE_IMAGE:-node:22-alpine}"

# Ejecuta un programa de scripts/ con Node, sin exigir Node en el servidor: usa `node` si existe
# y, si no, `docker run` con la imagen ${NODE_IMAGE} y el kit montado en /kit. Con
# KIT_FORCE_DOCKER=1 usa siempre el contenedor; con KIT_DRY_RUN=1 imprime el comando en vez de
# ejecutarlo. Los ficheros salen con el usuario de quien lo corre (no root).
#   run_node generate-context.mjs [argumentos…]
run_node() {
  local programa="$1"; shift
  local cmd
  if [[ -z "${KIT_FORCE_DOCKER:-}" ]] && command -v node >/dev/null 2>&1; then
    cmd=(node "scripts/${programa}" "$@")
    ( cd "${KIT_DIR}" && _ejecutar_o_mostrar "${cmd[@]}" )
  else
    command -v docker >/dev/null 2>&1 || {
      echo "ERROR: hace falta Node 18+ o Docker para generar la credencial (no se encontró ninguno)." >&2
      return 1
    }
    cmd=(docker run --rm --user "$(id -u):$(id -g)" -v "${KIT_DIR}:/kit" -w /kit)
    local v
    for v in "${NODE_ENV_VARS[@]}"; do cmd+=(-e "${v}"); done
    cmd+=("${NODE_IMAGE}" node "/kit/scripts/${programa}" "$@")
    _ejecutar_o_mostrar "${cmd[@]}"
  fi
}

_ejecutar_o_mostrar() {
  if [[ -n "${KIT_DRY_RUN:-}" ]]; then
    local primero=1 x
    for x in "$@"; do
      if [[ -n "${primero}" ]]; then primero=""; else printf ' '; fi
      printf '%q' "${x}"
    done
    printf '\n'
  else
    "$@"
  fi
}
