#!/usr/bin/env bash
# Institution kit entry point — configure, build and start Inji Certify stack.

set -euo pipefail

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "ERROR: Ejecute con bash: ./install.sh  (no use 'sh install.sh')" >&2
  exit 1
fi

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${KIT_DIR}"

# shellcheck source=scripts/lib/common.sh
source "${KIT_DIR}/scripts/lib/common.sh"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: Comando requerido no encontrado: $1" >&2
    exit 1
  fi
}

echo "=== Kit de implantación Inji Certify ==="

require_cmd docker
require_cmd curl
require_cmd jq
docker compose version >/dev/null 2>&1 || { echo "ERROR: Docker Compose v2 requerido (docker compose)" >&2; exit 1; }

if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ -f "${KIT_DIR}/.env.example" ]]; then
    cp "${KIT_DIR}/.env.example" "${ENV_FILE}"
    echo "Se creó ${ENV_FILE} desde .env.example."
    echo "Complete los valores y vuelva a ejecutar ./install.sh"
    exit 1
  fi
  echo "ERROR: No existe .env ni .env.example" >&2
  exit 1
fi

load_env
apply_defaults
derive_public_url
derive_did_url
validate_env
resolve_plugin_jar
write_runtime_env
export_env_for_templates

echo "Modo TLS: ${TLS_MODE}"
echo "URL pública: ${CERTIFY_PUBLIC_URL}"
echo "DID: ${DID_URL}"
echo "Plugin RestAPI: ${RESTAPI_PLUGIN_JAR_RESOLVED}"

echo ""
echo "=== Generando configuración ==="
"${KIT_DIR}/scripts/generate-config.sh"

echo ""
echo "=== Construyendo imagen Certify (puede tardar varios minutos la primera vez) ==="
docker compose build

echo ""
echo "=== Levantando stack ==="
docker compose up -d

echo ""
echo "Caddy solicitará certificado Let's Encrypt (ACME HTTP-01)."
if [[ "${TLS_MODE}" == "domain" ]]; then
  echo "Asegúrese de que DNS apunta a este servidor y el puerto 80 está abierto."
else
  echo "Modo IP: hostname ${IP_HOSTNAME:-} debe resolver a este servidor y el puerto 80 debe estar abierto."
  echo "Si Caddy ya usó certificado interno antes, limpie el volumen: docker compose down && docker volume rm institution-kit_caddy_data"
fi
echo "Monitoreando logs de Caddy (30s) ..."
timeout 30 docker compose logs -f caddy 2>/dev/null || true

echo ""
echo "=== Verificando endpoints ==="
export CERTIFY_PUBLIC_URL TLS_MODE
"${KIT_DIR}/scripts/verify-health.sh"

echo ""
echo "============================================"
echo " Instalación completada"
echo "============================================"
echo " CERTIFY_PUBLIC_URL: ${CERTIFY_PUBLIC_URL}"
echo " INSTITUTION_ID:     ${INSTITUTION_ID}"
echo " OAUTH_CLIENT_ID:    ${OAUTH_CLIENT_ID}"
echo " CREDENTIAL:         ${CREDENTIAL_CONFIG_KEY_ID}"
echo ""
echo " Envíe estos datos a OGTIC para registro en Mimoto central."
echo " Health: ${CERTIFY_PUBLIC_URL}/v1/certify/actuator/health"
echo " Issuer: ${CERTIFY_PUBLIC_URL}/.well-known/openid-credential-issuer"
echo "============================================"
