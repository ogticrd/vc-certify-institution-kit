#!/usr/bin/env bash
# Corrige el documento DID que genera Certify y lo deja en generated/did/did.json, que Caddy
# sirve en /.well-known/did.json (R5).
#
# PROCEDENCIA: copia adaptada de `inji-vc/stack/bin/generar-did.sh` del emisor propio de OGTIC
# (repositorio de infraestructura; copiado el 4-oct-2026; en producción con 11/11 en el
# diagnóstico). Cambios respecto del original: sin `sudo` ni `python3` (aquí `jq`); se lee de Caddy
# y no de `certify-nginx`; escribe en generated/did/; acepta DID_ORIGEN para probar sin Docker;
# escritura atómica; avisa si el `id` no coincide con DID_URL.
#
# POR QUE HACE FALTA
# Certify construye el DID con el proofPurpose apuntando al DID pelado en vez de a los métodos de
# verificación (DIDDocumentUtil.java:62-63, cableado, no configurable):
#
#     didDocument.put("authentication",  Collections.singletonList(didUrl));
#     didDocument.put("assertionMethod", Collections.singletonList(didUrl));
#
# Un verificador conforme resuelve el DID, mira qué claves están autorizadas para
# `assertionMethod`, no encuentra la que firmó —porque ahí está el DID, no el id del método— y
# rechaza la credencial. La firma es correcta; lo que falla es la autorización. Demostrado el
# 17-sep-2026 en el emisor propio: con el DID tal cual sale de Certify, «CREDENCIAL INVÁLIDA»; con
# este corregido, «CREDENCIAL VÁLIDA».
#
# QUÉ PRODUCE (igual que el original): `authentication` y `assertionMethod` pasan a ser la lista de
# los `id` de los `verificationMethod` (referencias a los métodos de verificación, forma válida de
# DID Core §5.3), en lugar del DID pelado. Lo demás del documento no se toca.
#
# CUÁNDO SE EJECUTA
# Necesita a Certify EN MARCHA (el DID lleva su clave pública, que no existe hasta que arranca), así
# que NO forma parte de generate-config.sh: install.sh lo ejecuta después de que Certify responda
# UP. Mientras generated/did/did.json no exista, Caddy reescribe /.well-known/did.json al DID de
# Certify (sin corregir), de modo que el arranque no queda roto.
# HAY QUE VOLVER A CORRERLO cuando cambien las claves o el host: el id del método de verificación
# deriva de la clave, y el DID del dominio (install.sh lo hace en cada ejecución).
#
#   ./scripts/generate-did.sh                      pide el DID a Certify por la red interna
#   DID_ORIGEN=ruta/did.json ./scripts/generate-did.sh   lee ese fichero (pruebas, sin Docker)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

load_env
apply_defaults
derive_public_url
derive_did_url

command -v jq >/dev/null 2>&1 || { echo "ERROR: hace falta jq para corregir el DID." >&2; exit 1; }

DESTINO="${GENERATED_DIR}/did"
mkdir -p "${DESTINO}"

if [[ -n "${DID_ORIGEN:-}" ]]; then
  [[ -f "${DID_ORIGEN}" ]] || { echo "ERROR: DID_ORIGEN no es un fichero: ${DID_ORIGEN}" >&2; exit 1; }
  CRUDO="$(cat "${DID_ORIGEN}")"
else
  # Se pide a Certify DIRECTAMENTE, por la red interna (el contenedor de Caddy llega a `certify`),
  # sin pasar por el nombre público.
  #
  # NO usar ${CERTIFY_PUBLIC_URL}/.well-known/did.json como respaldo: esa ruta la sirve Caddy desde
  # el fichero que ESTE script escribe, así que el respaldo se leería a sí mismo y el DID nunca
  # incorporaría una clave nueva (le pasó al emisor propio el 17-sep-2026: el script «funcionaba»
  # y no cambiaba nada). Si Certify no responde, se falla en voz alta en vez de escribir algo viejo.
  load_compose_args
  CRUDO="$(cd "${KIT_DIR}" && "${KIT_COMPOSE[@]}" exec -T caddy \
            wget -qO- http://certify:8090/v1/certify/.well-known/did.json 2>/dev/null)" \
    || { echo "ERROR: no se pudo leer el DID de Certify. ¿Está en pie? Pruebe: docker compose ps certify" >&2; exit 1; }
fi
[[ -n "${CRUDO}" ]] || { echo "ERROR: Certify devolvió un DID vacío; no se sobreescribe el actual." >&2; exit 1; }

# Debe ser un documento con al menos un método de verificación con id.
if ! printf '%s' "${CRUDO}" | jq -e '
      type == "object"
      and (.id | type == "string" and length > 0)
      and (.verificationMethod | type == "array" and length > 0)
      and all(.verificationMethod[]; (.id | type == "string" and length > 0))' >/dev/null 2>&1; then
  echo "ERROR: el DID de Certify no es un documento válido o no trae ningún verificationMethod con id; no se corrige nada." >&2
  exit 1
fi

TMP="$(mktemp "${DESTINO}/.did.json.XXXXXX")"
trap 'rm -f "${TMP}"' EXIT
printf '%s' "${CRUDO}" | jq '
  [.verificationMethod[].id] as $ids
  | .assertionMethod = $ids
  | .authentication = $ids' > "${TMP}"
chmod 644 "${TMP}"
mv "${TMP}" "${DESTINO}/did.json"   # atómico: Caddy nunca ve un fichero a medias
trap - EXIT

ID_DID="$(jq -r '.id' "${DESTINO}/did.json")"
echo "DID corregido en ${DESTINO}/did.json"
echo "  id              : ${ID_DID}"
echo "  assertionMethod : $(jq -c '.assertionMethod' "${DESTINO}/did.json")"
if [[ "${ID_DID}" != "${DID_URL}" ]]; then
  echo "AVISO: el id del DID (${ID_DID}) no coincide con DID_URL (${DID_URL}); las credenciales se firman con DID_URL como emisor y no se resolverán contra este documento." >&2
fi
