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
  case "${TLS_MODE}" in
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
      echo "ERROR: TLS_MODE debe ser 'domain' o 'ip' (actual: ${TLS_MODE})" >&2
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
  CREDENTIAL_LOGO_URL="${CREDENTIAL_LOGO_URL:-https://mosip.github.io/inji-config/logos/agro-vertias-logo.png}"
  CREDENTIAL_BG_COLOR="${CREDENTIAL_BG_COLOR:-#12107c}"
  CREDENTIAL_TEXT_COLOR="${CREDENTIAL_TEXT_COLOR:-#FFFFFF}"
  if [[ -z "${RESTAPI_SCOPE_ENDPOINT_MAPPING:-}" ]]; then
    RESTAPI_SCOPE_ENDPOINT_MAPPING="{'openid offline_access profile email': '/:national_id','openid': '/:national_id'}"
  fi
  POSTGRES_USER="${POSTGRES_USER:-postgres}"
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}"
  POSTGRES_DB="${POSTGRES_DB:-inji_certify}"
  export CREDENTIAL_DISPLAY_NAME CREDENTIAL_TYPE CREDENTIAL_FORMAT
  export CREDENTIAL_LOGO_URL CREDENTIAL_BG_COLOR CREDENTIAL_TEXT_COLOR
  export RESTAPI_SCOPE_ENDPOINT_MAPPING POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB
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
}

write_runtime_env() {
  mkdir -p "${GENERATED_DIR}"
  cat > "${RUNTIME_ENV}" <<EOF
CERTIFY_PUBLIC_URL=${CERTIFY_PUBLIC_URL}
CERTIFY_PUBLIC_HOST=${CERTIFY_PUBLIC_HOST:-}
IP_HOSTNAME=${IP_HOSTNAME:-}
TLS_MODE=${TLS_MODE}
DID_URL=${DID_URL}
INSTITUTION_ID=${INSTITUTION_ID}
INSTITUTION_DISPLAY_NAME=${INSTITUTION_DISPLAY_NAME}
RESTAPI_BASE_URL=${RESTAPI_BASE_URL}
OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID}
OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
CREDENTIAL_CONFIG_KEY_ID=${CREDENTIAL_CONFIG_KEY_ID}
CREDENTIAL_ATTRIBUTES=${CREDENTIAL_ATTRIBUTES}
CREDENTIAL_SCOPE=${CREDENTIAL_SCOPE}
CREDENTIAL_DISPLAY_NAME=${CREDENTIAL_DISPLAY_NAME}
CREDENTIAL_TYPE=${CREDENTIAL_TYPE}
CREDENTIAL_FORMAT=${CREDENTIAL_FORMAT}
CREDENTIAL_LOGO_URL=${CREDENTIAL_LOGO_URL}
CREDENTIAL_BG_COLOR=${CREDENTIAL_BG_COLOR}
CREDENTIAL_TEXT_COLOR=${CREDENTIAL_TEXT_COLOR}
RESTAPI_SCOPE_ENDPOINT_MAPPING=${RESTAPI_SCOPE_ENDPOINT_MAPPING}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB}
CADDY_ACME_EMAIL=${CADDY_ACME_EMAIL:-}
EOF
}

export_env_for_templates() {
  export CERTIFY_PUBLIC_URL CERTIFY_PUBLIC_HOST IP_HOSTNAME TLS_MODE DID_URL
  export INSTITUTION_ID INSTITUTION_DISPLAY_NAME RESTAPI_BASE_URL
  export OAUTH_CLIENT_ID OAUTH_CLIENT_SECRET
  export CREDENTIAL_CONFIG_KEY_ID CREDENTIAL_ATTRIBUTES CREDENTIAL_SCOPE
  export CREDENTIAL_DISPLAY_NAME CREDENTIAL_TYPE CREDENTIAL_FORMAT
  export CREDENTIAL_LOGO_URL CREDENTIAL_BG_COLOR CREDENTIAL_TEXT_COLOR CREDENTIAL_LABELS_JSON CREDENTIAL_ATTRIBUTE_LABELS
  export RESTAPI_SCOPE_ENDPOINT_MAPPING POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB
  export CADDY_ACME_EMAIL
}

# Variables que leen los programas Node (scripts/lib/credencial.mjs) y que `run_node` reenvía al
# contenedor cuando no hay Node local.
NODE_ENV_VARS=(
  CREDENTIAL_CONFIG_KEY_ID CREDENTIAL_ATTRIBUTES CREDENTIAL_TYPE CREDENTIAL_LABELS_JSON
  CREDENTIAL_ATTRIBUTE_LABELS CREDENTIAL_DISPLAY_NAME CREDENTIAL_LOGO_URL CREDENTIAL_BG_COLOR
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
