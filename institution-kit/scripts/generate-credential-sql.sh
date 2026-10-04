#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

load_env
apply_defaults
derive_public_url
derive_did_url
export_env_for_templates

OUT_FILE="${GENERATED_DIR}/credential_config.sql"
mkdir -p "${GENERATED_DIR}"

IFS=',' read -ra ATTRS <<< "${CREDENTIAL_ATTRIBUTES}"
LABELS_JSON="{}"
if [[ -n "${CREDENTIAL_ATTRIBUTE_LABELS:-}" ]]; then
  LABELS_JSON=$(echo "${CREDENTIAL_ATTRIBUTE_LABELS}" | tr ',' '\n' | jq -R 'split(":") | {(.[0]): .[1]}' | jq -s 'add')
fi
ATTRS_JSON=$(printf '%s\n' "${ATTRS[@]}" | jq -R . | jq -s .)
CREDENTIAL_SUBJECT_JSON=$(jq -n --argjson attrs "${ATTRS_JSON}" --argjson labels "${LABELS_JSON}" '
  [ $attrs[] | . as $a | {key: $a, label: ($labels[$a] // $a)} ] |
  map({(.key): {"display": [{"name": .label, "locale": "es"}]}}) |
  add
')

# --- VC types for template ---
IFS=',' read -ra TYPE_PARTS <<< "${CREDENTIAL_TYPE}"
TYPES_JSON=$(printf '%s\n' "${TYPE_PARTS[@]}" | jq -R . | jq -s .)

# --- Build Velocity VC template JSON ---
SUBJECT_FIELDS=$(jq -n --argjson attrs "${ATTRS_JSON}" '
  reduce $attrs[] as $a ({}; . + {($a): ("${" + $a + "}")}) | . + {"id": "${_holderId}"}
')

VC_TEMPLATE_JSON=$(jq -n \
  --arg ctx "${CREDENTIAL_CONTEXT}" \
  --argjson types "${TYPES_JSON}" \
  --argjson subject "${SUBJECT_FIELDS}" \
  '{
    "@context": [$ctx],
    "issuer": "${_issuer}",
    "type": $types,
    "issuanceDate": "${validFrom}",
    "expirationDate": "${validUntil}",
    "credentialSubject": $subject
  }')

VC_TEMPLATE_B64=$(echo "${VC_TEMPLATE_JSON}" | jq -c . | base64 | tr -d '\n')

DISPLAY_JSON=$(jq -n \
  --arg name "${CREDENTIAL_DISPLAY_NAME}" \
  --arg logo "${CREDENTIAL_LOGO_URL}" \
  --arg bg "${CREDENTIAL_BG_COLOR}" \
  --arg fg "${CREDENTIAL_TEXT_COLOR}" \
  '[{
    "name": $name,
    "locale": "es",
    "logo": {"url": $logo, "alt_text": $name},
    "background_color": $bg,
    "text_color": $fg
  }]')

# Escape single quotes for SQL
sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

VC_B64_SQL=$(sql_escape "${VC_TEMPLATE_B64}")
DISPLAY_SQL=$(sql_escape "$(echo "${DISPLAY_JSON}" | jq -c .)")
SUBJECT_SQL=$(sql_escape "$(echo "${CREDENTIAL_SUBJECT_JSON}" | jq -c .)")
SCOPE_SQL=$(sql_escape "${CREDENTIAL_SCOPE}")
KEY_ID_SQL=$(sql_escape "${CREDENTIAL_CONFIG_KEY_ID}")
CTX_SQL=$(sql_escape "${CREDENTIAL_CONTEXT}")
TYPE_SQL=$(sql_escape "${CREDENTIAL_TYPE}")
FORMAT_SQL=$(sql_escape "${CREDENTIAL_FORMAT}")
DID_SQL=$(sql_escape "${DID_URL}")

# display_order as PostgreSQL text array
DISPLAY_ORDER_SQL="ARRAY[$(printf "'%s'," "${ATTRS[@]}" | sed 's/,$//')]"

cat > "${OUT_FILE}" <<EOF
-- Generated credential_config for ${INSTITUTION_ID} — do not edit by hand
INSERT INTO certify.credential_config (
    credential_config_key_id,
    config_id,
    status,
    vc_template,
    doctype,
    sd_jwt_vct,
    context,
    credential_type,
    credential_format,
    did_url,
    key_manager_app_id,
    key_manager_ref_id,
    signature_algo,
    signature_crypto_suite,
    sd_claim,
    display,
    display_order,
    scope,
    cryptographic_binding_methods_supported,
    credential_signing_alg_values_supported,
    proof_types_supported,
    credential_subject,
    sd_jwt_claims,
    mso_mdoc_claims,
    plugin_configurations,
    credential_status_purpose,
    qr_settings,
    qr_signature_algo,
    cr_dtimes,
    upd_dtimes
) VALUES (
    '${KEY_ID_SQL}',
    gen_random_uuid()::VARCHAR(255),
    'active',
    '${VC_B64_SQL}',
    NULL,
    NULL,
    '${CTX_SQL}',
    '${TYPE_SQL}',
    '${FORMAT_SQL}',
    '${DID_SQL}',
    'CERTIFY_VC_SIGN_ED25519',
    'ED25519_SIGN',
    'EdDSA',
    'Ed25519Signature2020',
    NULL,
    '${DISPLAY_SQL}'::JSONB,
    ${DISPLAY_ORDER_SQL},
    '${SCOPE_SQL}',
    ARRAY['did:jwk'],
    ARRAY['Ed25519Signature2020'],
    '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256"]}}'::JSONB,
    '${SUBJECT_SQL}'::JSONB,
    NULL,
    NULL,
    NULL,
    ARRAY['revocation'],
    NULL,
    NULL,
    NOW(),
    NULL
);
EOF

echo "SQL de credencial generado en ${OUT_FILE}"
