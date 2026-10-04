#!/usr/bin/env bash
# Verificación de la instalación (R8, D4). Sustituye a verify-health.sh: hace lo que hacía (salud de
# Certify por la red interna y credential_endpoint) y añade el diagnóstico de OGTIC contra la URL
# PÚBLICA de la propia institución. Sale con código 1 si alguna comprobación FALLA.
#
#   ./scripts/verify-install.sh
#
# Qué comprueba y de dónde sale cada cosa:
#   - Salud: `docker compose exec caddy wget …/actuator/health` (red interna; el actuator no es público).
#   - Las 11 comprobaciones del diagnóstico de OGTIC (diagnostico/cli.mjs, motor vendorizado sin tocar):
#     metadata, identificador, endpoint de emisión, servidor de autorización, codificación, logo,
#     contextos (con no-cache), cobertura (del motor, desde la metadata), nombres, DID (assertionMethod
#     conforme) y orden de tipos/contextos.
#   - Del kit (scripts/lib/verificar-instalacion.mjs): @context completo en la metadata y cobertura de
#     firma 100 % sobre generated/credencial-muestra.json (la muestra va sin firma, el motor no la admite).
#
# Node no se instala en el servidor: si no hay `node` 22 se usa `docker run node:22-alpine`.
# Variables (todas opcionales):
#   KIT_NODE=auto|local|docker   auto (por defecto): `node` local si es 22 o más; si no, el contenedor.
#   KIT_DRY_RUN=1                imprime la orden de Node en vez de ejecutarla.
#   VERIFY_PRIVADAS=auto|1|0     direcciones privadas en el diagnóstico (auto: solo si la URL pública resuelve
#                                a una dirección privada o de bucle: el propio servidor, un proxy interno).
#   VERIFY_HEALTH_INTENTOS=60 y VERIFY_HEALTH_PAUSA=5   espera a Certify (segundos entre intentos).
#   NODE_EXTRA_CA_CERTS=<fichero .pem>   CA interna de la institución (proxy con CA propia): con `node` local lo
#                                hereda el proceso; con `docker run` se monta de solo lectura y se reenvía.
#   ESPERA=8000                  tiempo de espera de cada petición del diagnóstico, en ms.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

load_env
apply_defaults
derive_public_url
export_env_for_templates
load_compose_args

METADATA_URL="${CERTIFY_PUBLIC_URL}/.well-known/openid-credential-issuer"
MUESTRA="${GENERATED_DIR}/credencial-muestra.json"
FALLO_SALUD=0

echo "=== Verificación de la instalación ==="
echo "Salud de Certify (red interna) ..."
if wait_for_health "${VERIFY_HEALTH_INTENTOS:-60}" "${VERIFY_HEALTH_PAUSA:-5}"; then
  echo "  OK        Certify responde UP."
else
  FALLO_SALUD=1
  echo "  FALLA     Certify no respondió UP tras ${VERIFY_HEALTH_INTENTOS:-60} intentos." >&2
  echo "            Última respuesta: ${HEALTH_ULTIMA_RESPUESTA}" >&2
  echo "            -> Revise: ${KIT_COMPOSE[*]} logs certify" >&2
fi
echo ""

# --- Qué Node ---------------------------------------------------------------------------------
KIT_NODE="${KIT_NODE:-auto}"
node_local_sirve() {
  command -v node >/dev/null 2>&1 || return 1
  local mayor
  mayor="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [[ "${mayor}" -ge 22 ]]
}
case "${KIT_NODE}" in
  local)
    command -v node >/dev/null 2>&1 || { echo "ERROR: KIT_NODE=local pero no hay node en el PATH." >&2; exit 1; }
    usar_docker=0 ;;
  docker) usar_docker=1 ;;
  auto)
    if [[ -z "${KIT_FORCE_DOCKER:-}" ]] && node_local_sirve; then usar_docker=0; else usar_docker=1; fi ;;
  *) echo "ERROR: KIT_NODE debe ser auto, local o docker (actual: ${KIT_NODE})." >&2; exit 1 ;;
esac

case "${VERIFY_PRIVADAS:-auto}" in
  auto) privadas=auto ;;
  1 | si | true) privadas=si ;;
  0 | no | false) privadas=no ;;
  *) echo "ERROR: VERIFY_PRIVADAS debe ser auto, 1 o 0 (actual: ${VERIFY_PRIVADAS})." >&2; exit 1 ;;
esac

if [[ "${usar_docker}" -eq 1 ]]; then
  command -v docker >/dev/null 2>&1 || { echo "ERROR: hace falta Node 22 o Docker para la verificación (no se encontró ninguno)." >&2; exit 1; }
  # Solo se montan, de solo lectura, el diagnóstico, el programa del kit y la muestra: ni .env ni
  # generated/.env.runtime (ahí están los secretos). --network host: el diagnóstico debe ver la URL
  # pública igual que este servidor.
  cmd=(docker run --rm --network host --user "$(id -u):$(id -g)"
    -v "${KIT_DIR}/diagnostico:/kit/diagnostico:ro"
    -v "${KIT_DIR}/scripts/lib/verificar-instalacion.mjs:/kit/scripts/lib/verificar-instalacion.mjs:ro")
  muestra_en_nodo="/kit/generated/credencial-muestra.json"
  [[ -f "${MUESTRA}" ]] && cmd+=(-v "${MUESTRA}:${muestra_en_nodo}:ro")
  [[ -n "${ESPERA:-}" ]] && cmd+=(-e ESPERA)
  # K10: una CA interna de la institución (proxy con CA propia) hace falla la comprobación 1 en una instalación
  # sana si el contenedor no la conoce: se monta el fichero de solo lectura y se reenvía la variable.
  if [[ -n "${NODE_EXTRA_CA_CERTS:-}" ]]; then
    [[ -r "${NODE_EXTRA_CA_CERTS}" ]] || { echo "ERROR: NODE_EXTRA_CA_CERTS apunta a un fichero que no existe o no se puede leer: ${NODE_EXTRA_CA_CERTS}" >&2; exit 1; }
    cmd+=(-v "${NODE_EXTRA_CA_CERTS}:/kit/ca-extra.pem:ro" -e NODE_EXTRA_CA_CERTS=/kit/ca-extra.pem)
  fi
  cmd+=(-w /kit "${NODE_IMAGE}" node /kit/scripts/lib/verificar-instalacion.mjs)
else
  cmd=(node "${KIT_DIR}/scripts/lib/verificar-instalacion.mjs")
  muestra_en_nodo="${MUESTRA}"
fi
# K10: se le pasan la clave y los atributos DEL .env para compararlos con lo que Certify publica (no con la muestra,
# que sale del mismo .env). Con node local, NODE_EXTRA_CA_CERTS lo hereda el proceso.
cmd+=(--url "${METADATA_URL}" --as "${AUTH_ISSUER_URL}" --muestra "${muestra_en_nodo}" --privadas "${privadas}"
  --clave "${CREDENTIAL_CONFIG_KEY_ID}" --atributos "${CREDENTIAL_ATTRIBUTES//[[:space:]]/}")
[[ "${FALLO_SALUD}" -eq 1 ]] && cmd+=(--salud falla)

if [[ -n "${KIT_DRY_RUN:-}" ]]; then
  _ejecutar_o_mostrar "${cmd[@]}"
  exit 0
fi

codigo=0
"${cmd[@]}" || codigo=$?

if [[ "${FALLO_SALUD}" -eq 1 ]]; then
  echo ""
  echo "Resultado global: la verificación FALLÓ (Certify no respondió UP)." >&2
  exit 1
fi
exit "${codigo}"
