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
  # shellcheck disable=SC1090
  set -a
  source "${ENV_FILE}"
  set +a
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
    *)
      echo "ERROR: TLS_MODE debe ser 'domain' o 'ip' (actual: ${TLS_MODE:-})" >&2
      exit 1
      ;;
  esac
  export CERTIFY_PUBLIC_URL IP_HOSTNAME
}

derive_did_url() {
  if [[ -z "${DID_URL:-}" ]]; then
    local host
    host="${CERTIFY_PUBLIC_URL#https://}"
    host="${host#http://}"
    host="${host%%/*}"
    DID_URL="did:web:${host}"
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
  export CREDENTIAL_DISPLAY_NAME CREDENTIAL_TYPE CREDENTIAL_FORMAT
  export CREDENTIAL_BG_COLOR CREDENTIAL_TEXT_COLOR
  export RESTAPI_SCOPE_ENDPOINT_MAPPING POSTGRES_USER POSTGRES_DB
  export AUTH_ISSUER_URL
  resolve_secrets
}

# --- Secretos (R9, D7) -----------------------------------------------------------------------------
# POSTGRES_PASSWORD y KEYSTORE_PASSWORD (contraseña del keystore PKCS12 de Certify): si la institución
# deja el valor por defecto (postgres / local) o lo vacía, el kit genera 32 bytes aleatorios
# (`openssl rand -hex 32`, 64 caracteres hex) y los guarda SOLO en generated/.env.runtime (modo 600).
# Nunca se escriben en la salida estándar ni en ningún log.
#
# SOLO PARA INSTALACIONES NUEVAS. La contraseña de Postgres queda grabada en el volumen de datos al
# crear la base, y la del keystore en generated/…/local.p12 (volumen certify-pkcs12) al primer
# arranque de Certify; cambiarlas en .env.runtime después rompe el arranque (Postgres rechaza la
# conexión; Certify no abre el keystore y no puede descifrar sus claves). Una instalación existente:
#   - Postgres: cambie la contraseña EN la base (ALTER USER … PASSWORD '…') y póngala en
#     POSTGRES_PASSWORD, explícita y distinta de «postgres».
#   - Keystore: si ya arrancó con «local», no hay forma segura de cambiarla desde aquí; ponga
#     KIT_CONSERVAR_SECRETOS_POR_DEFECTO=1 en el .env para que el kit NO genere contraseñas nuevas y
#     deje los valores por defecto tal cual (la institución decide cómo rotarlos con keytool).
# Las ya generadas se REUTILIZAN en cada ejecución (se leen de .env.runtime): regenerar la
# configuración, o aplicar la credencial, no cambia las contraseñas.
SECRETO_DEFECTO_POSTGRES="postgres"
SECRETO_DEFECTO_KEYSTORE="local"

# Valor de CLAVE en generated/.env.runtime (sin ejecutar el fichero).
_valor_runtime() {
  [[ -f "${RUNTIME_ENV}" ]] || return 0
  { grep -m1 "^$1=" "${RUNTIME_ENV}" || true; } | cut -d= -f2-
}

# Deja en $1 (nombre de variable) la contraseña a usar para $2 (clave en .env.runtime) cuyo valor por
# defecto es $3. Marca SECRETOS_GENERADOS=1 si tuvo que generar una.
_resolver_secreto() {
  local var="$1" clave="$2" defecto="$3"
  local actual="${!var:-}"
  if [[ -n "${actual}" && "${actual}" != "${defecto}" ]]; then
    return 0  # la institución fijó un valor propio: se respeta
  fi
  if [[ -n "${KIT_CONSERVAR_SECRETOS_POR_DEFECTO:-}" ]]; then
    printf -v "${var}" '%s' "${defecto}"
    return 0
  fi
  local previo
  previo="$(_valor_runtime "${clave}")"
  if [[ -n "${previo}" && "${previo}" != "${defecto}" ]]; then
    printf -v "${var}" '%s' "${previo}"
    return 0
  fi
  command -v openssl >/dev/null 2>&1 || { echo "ERROR: hace falta openssl para generar las contraseñas." >&2; exit 1; }
  printf -v "${var}" '%s' "$(openssl rand -hex 32)"
  SECRETOS_GENERADOS=1
}

resolve_secrets() {
  SECRETOS_GENERADOS=""
  _resolver_secreto POSTGRES_PASSWORD POSTGRES_PASSWORD "${SECRETO_DEFECTO_POSTGRES}"
  _resolver_secreto KEYSTORE_PASSWORD KEYSTORE_PASSWORD "${SECRETO_DEFECTO_KEYSTORE}"
  export POSTGRES_PASSWORD KEYSTORE_PASSWORD
  if [[ -n "${SECRETOS_GENERADOS}" ]]; then
    # Se persisten YA: otro script del kit (generate-properties.sh, compose…) tiene que ver los mismos.
    write_runtime_env
    echo "AVISO: se generaron contraseñas aleatorias para la base de datos y/o el keystore (guardadas en generated/.env.runtime, modo 600). Solo valen para una instalación NUEVA; si ya tiene una base de datos o un keystore creados con otras contraseñas, lea la guía (instalación existente) antes de continuar." >&2
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
  if [[ -z "${CADDY_ACME_EMAIL:-}" ]]; then
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
  validate_logo_path
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

# generated/.env.runtime (modo 600): lo que necesita la ejecución —las contraseñas incluidas— y nada
# más. Lo lee `docker compose` (--env-file, ver generated/compose-args) y las propias funciones del
# kit; NO se carga con `source`. Ya no copia el .env entero ni OAUTH_CLIENT_SECRET (nada lo leía).
# Se escribe de forma atómica con permisos restrictivos desde el primer byte.
write_runtime_env() {
  mkdir -p "${GENERATED_DIR}"
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
  mkdir -p "${GENERATED_DIR}"
  local overlay="docker-compose.tls.yml"
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

export_env_for_templates() {
  export CERTIFY_PUBLIC_URL CERTIFY_PUBLIC_HOST IP_HOSTNAME TLS_MODE DID_URL
  export INSTITUTION_ID INSTITUTION_DISPLAY_NAME RESTAPI_BASE_URL
  export OAUTH_CLIENT_ID OAUTH_CLIENT_SECRET
  export CREDENTIAL_CONFIG_KEY_ID CREDENTIAL_ATTRIBUTES CREDENTIAL_SCOPE
  export CREDENTIAL_DISPLAY_NAME CREDENTIAL_TYPE CREDENTIAL_FORMAT
  export LOGO_PATH CREDENTIAL_BG_COLOR CREDENTIAL_TEXT_COLOR CREDENTIAL_LABELS_JSON CREDENTIAL_ATTRIBUTE_LABELS
  export RESTAPI_SCOPE_ENDPOINT_MAPPING POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB
  export CADDY_ACME_EMAIL RESTAPI_TOKEN_URL AUTH_ISSUER_URL KEYSTORE_PASSWORD
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
