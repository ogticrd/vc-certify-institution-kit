#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

load_env
apply_defaults
derive_public_url
export_env_for_templates

# Ambos modos usan Let's Encrypt; sin -k para detectar cert inválido/autofirmado.
CURL_OPTS=()

BASE_URL="${CERTIFY_PUBLIC_URL}"
MAX_ATTEMPTS=60
SLEEP_SECS=5

echo "Verificando health en ${BASE_URL}/v1/certify/actuator/health ..."

for ((i = 1; i <= MAX_ATTEMPTS; i++)); do
  if response=$(curl -sf "${CURL_OPTS[@]}" "${BASE_URL}/v1/certify/actuator/health" 2>/dev/null); then
    status=$(echo "${response}" | jq -r '.status // empty')
    if [[ "${status}" == "UP" ]]; then
      echo "  Health: UP"
      break
    fi
  fi
  if [[ "${i}" -eq "${MAX_ATTEMPTS}" ]]; then
    echo "ERROR: Certify no respondió UP tras $((MAX_ATTEMPTS * SLEEP_SECS))s" >&2
    echo "Última respuesta: ${response:-sin respuesta}" >&2
    exit 1
  fi
  echo "  Intento ${i}/${MAX_ATTEMPTS} — esperando ${SLEEP_SECS}s ..."
  sleep "${SLEEP_SECS}"
done

echo "Verificando openid-credential-issuer ..."
if issuer=$(curl -sf "${CURL_OPTS[@]}" "${BASE_URL}/.well-known/openid-credential-issuer" 2>/dev/null); then
  credential_endpoint=$(echo "${issuer}" | jq -r '.credential_endpoint // empty')
  if [[ -n "${credential_endpoint}" ]]; then
    echo "  credential_endpoint: ${credential_endpoint}"
  else
    echo "WARN: Respuesta sin credential_endpoint" >&2
  fi
else
  echo "ERROR: No se pudo obtener /.well-known/openid-credential-issuer" >&2
  exit 1
fi

echo "Verificación completada."
