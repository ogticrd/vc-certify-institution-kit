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
# envsubst (paquete gettext-base en Debian/Ubuntu, gettext en otros) lo usan los generadores de
# properties y de Caddyfile; openssl genera las contraseñas aleatorias.
if ! command -v envsubst >/dev/null 2>&1; then
  echo "ERROR: Comando requerido no encontrado: envsubst. Instale el paquete gettext-base (Debian/Ubuntu: sudo apt-get install -y gettext-base; RHEL/Fedora: gettext)." >&2
  exit 1
fi
require_cmd openssl
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
export_env_for_templates

echo "Modo TLS: ${TLS_MODE}"
echo "URL pública: ${CERTIFY_PUBLIC_URL}"
echo "DID: ${DID_URL}"
echo "Plugin RestAPI: ${RESTAPI_PLUGIN_JAR_RESOLVED}"

echo ""
echo "=== Generando configuración ==="
"${KIT_DIR}/scripts/generate-config.sh"

echo ""
# generate-config.sh dejó en generated/compose-args la orden de docker compose de este modo (ficheros
# superpuestos y contraseñas de generated/.env.runtime). Todo `docker compose` del kit la usa.
load_compose_args

echo ""
echo "=== Construyendo imagen Certify (puede tardar varios minutos la primera vez) ==="
"${KIT_COMPOSE[@]}" build

echo ""
echo "=== Levantando stack ==="
"${KIT_COMPOSE[@]}" up -d

echo ""
case "${TLS_MODE}" in
  proxy)
    echo "Modo proxy: Caddy escucha solo HTTP en el puerto ${CADDY_HTTP_PORT} de este servidor (no pide certificados ni abre el 443)."
    echo "Configure su proxy inverso para que ${CERTIFY_PUBLIC_URL} reenvíe a este servidor, puerto ${CADDY_HTTP_PORT}, con X-Forwarded-For (la IP real del cliente)."
    ;;
  domain)
    echo "Caddy solicitará certificado Let's Encrypt (ACME HTTP-01)."
    echo "Asegúrese de que DNS apunta a este servidor y el puerto 80 está abierto."
    ;;
  *)
    echo "Caddy solicitará certificado Let's Encrypt (ACME HTTP-01)."
    echo "Modo IP: hostname ${IP_HOSTNAME:-} debe resolver a este servidor y el puerto 80 debe estar abierto."
    echo "Si Caddy ya usó certificado interno antes, limpie el volumen: docker compose down && docker volume rm institution-kit_caddy_data"
    ;;
esac
if [[ "${TLS_MODE}" != "proxy" ]]; then
  echo "Monitoreando logs de Caddy (30s) ..."
  timeout 30 "${KIT_COMPOSE[@]}" logs -f caddy 2>/dev/null || true
fi

echo ""
echo "=== Esperando a Certify (health por la red interna) ==="
export CERTIFY_PUBLIC_URL TLS_MODE
if ! wait_for_health 60 5; then
  echo "ERROR: Certify no respondió UP tras 300s" >&2
  echo "Última respuesta: ${HEALTH_ULTIMA_RESPUESTA}" >&2
  exit 1
fi
echo "  Health: UP"

# El DID corregido (R5) necesita a Certify en marcha: lleva su clave pública. Hasta ahora Caddy servía
# el DID de Certify sin corregir (assertionMethod con el DID pelado); desde aquí, el corregido.
echo ""
echo "=== Corrigiendo el DID (assertionMethod) ==="
"${KIT_DIR}/scripts/generate-did.sh"

# Verificación (R8): salud, el diagnóstico de OGTIC contra la URL pública y la cobertura de firma de la
# credencial de muestra. Va después de corregir el DID (la comprobación 10 lo lee). Si algo FALLA, el
# resumen se imprime igual (los datos para OGTIC siguen valiendo) y install.sh sale con ese código.
echo ""
codigo=0
"${KIT_DIR}/scripts/verify-install.sh" || codigo=$?

echo ""
echo "============================================"
if [[ "${codigo}" -eq 0 ]]; then
  echo " Instalación completada"
else
  echo " Instalación terminada, pero la verificación FALLÓ (código ${codigo})"
fi
echo "============================================"
echo " CERTIFY_PUBLIC_URL: ${CERTIFY_PUBLIC_URL}"
echo " INSTITUTION_ID:     ${INSTITUTION_ID}"
echo " OAUTH_CLIENT_ID:    ${OAUTH_CLIENT_ID}"
echo " CREDENTIAL:         ${CREDENTIAL_CONFIG_KEY_ID}"
echo ""
echo " Envíe estos datos a OGTIC para registro en Mimoto central."
echo " Health: solo por la red interna (el actuator no se publica en internet)"
echo " DID:    ${CERTIFY_PUBLIC_URL}/.well-known/did.json"
echo " Issuer: ${CERTIFY_PUBLIC_URL}/.well-known/openid-credential-issuer"
echo "============================================"
exit "${codigo}"
