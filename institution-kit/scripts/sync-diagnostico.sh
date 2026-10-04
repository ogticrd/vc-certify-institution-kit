#!/usr/bin/env bash
# Trae a institution-kit/diagnostico/ la copia vigente del diagnóstico de OGTIC (D4 de la spec
# kit-firma-y-contexto) y regenera las huellas SHA-256 de diagnostico/PROCEDENCIA.md.
#
#   scripts/sync-diagnostico.sh
#   DIAGNOSTICO_ORIGEN=/ruta/a/inji-vc/stack/diagnostico scripts/sync-diagnostico.sh
#
# DIAGNOSTICO_ORIGEN (por defecto ../../inji-vc/stack/diagnostico, relativa al directorio del kit)
# es la carpeta del emisor propio de OGTIC donde viven cli.mjs, motor.mjs, red.mjs y jsonld.mjs.
#
# Los ficheros vendorizados NO se editan aquí: si algo del motor no encaja, se adapta desde fuera
# (scripts/lib/verificar-instalacion.mjs) y se corrige en el origen. Por eso el script FALLA, sin
# tocar nada, si alguno de los ficheros locales no coincide con la huella registrada en
# PROCEDENCIA.md (cambios locales) y tampoco con el del origen. SYNC_FORZAR=1 los sobrescribe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DESTINO="${KIT_DIR}/diagnostico"
PROCEDENCIA="${DESTINO}/PROCEDENCIA.md"
ORIGEN_RELATIVO="../../inji-vc/stack/diagnostico"
ORIGEN="${DIAGNOSTICO_ORIGEN:-${KIT_DIR}/${ORIGEN_RELATIVO}}"
FICHEROS=(cli.mjs motor.mjs red.mjs jsonld.mjs)
INICIO="<!-- sync-diagnostico:inicio -->"
FIN="<!-- sync-diagnostico:fin -->"

sha256_de() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

fallar() { echo "ERROR: $*" >&2; exit 1; }

[[ -d "${ORIGEN}" ]] || fallar "no existe el origen del diagnóstico: ${ORIGEN} (indique DIAGNOSTICO_ORIGEN=<carpeta>)."
ORIGEN="$(cd "${ORIGEN}" && pwd)"
[[ -f "${PROCEDENCIA}" ]] || fallar "falta ${PROCEDENCIA}."
grep -qF "${INICIO}" "${PROCEDENCIA}" && grep -qF "${FIN}" "${PROCEDENCIA}" \
  || fallar "PROCEDENCIA.md no tiene los marcadores ${INICIO} y ${FIN}."

# Huella registrada de un fichero en PROCEDENCIA.md (fila «| `fichero` | origen | sha | fecha |»).
huella_registrada() {
  awk -F'|' -v f="\`$1\`" '{ gsub(/^ +| +$/, "", $2) } $2 == f { gsub(/[` ]/, "", $4); print $4; exit }' "${PROCEDENCIA}"
}
fecha_registrada() {
  awk -F'|' -v f="\`$1\`" '{ gsub(/^ +| +$/, "", $2) } $2 == f { gsub(/^ +| +$/, "", $5); print $5; exit }' "${PROCEDENCIA}"
}

# 1. Todo el origen existe y el destino no tiene cambios locales (antes de tocar nada).
for f in "${FICHEROS[@]}"; do
  [[ -f "${ORIGEN}/${f}" ]] || fallar "el origen no tiene ${f} (${ORIGEN})."
  if [[ -f "${DESTINO}/${f}" && -z "${SYNC_FORZAR:-}" ]]; then
    local_sha="$(sha256_de "${DESTINO}/${f}")"
    registrada="$(huella_registrada "${f}")"
    origen_sha="$(sha256_de "${ORIGEN}/${f}")"
    if [[ "${local_sha}" != "${registrada}" && "${local_sha}" != "${origen_sha}" ]]; then
      fallar "diagnostico/${f} tiene cambios locales (su SHA-256 no es el de PROCEDENCIA.md ni el del origen). Los ficheros vendorizados no se editan: devuelva el cambio al origen (inji-vc/stack/diagnostico) o use SYNC_FORZAR=1 para descartarlo."
    fi
  fi
done

# 2. Copia y tabla nueva.
fecha_hoy="$(date +%Y-%m-%d)"
tabla="$(mktemp)"
trap 'rm -f "${tabla}" "${tabla}.nuevo"' EXIT
{
  echo "| Fichero | Origen | SHA-256 | Copiado |"
  echo "|---|---|---|---|"
} > "${tabla}"
for f in "${FICHEROS[@]}"; do
  anterior="$(huella_registrada "${f}")"
  nueva="$(sha256_de "${ORIGEN}/${f}")"
  cp "${ORIGEN}/${f}" "${DESTINO}/${f}"
  # La fecha solo cambia si el contenido cambió.
  if [[ "${anterior}" == "${nueva}" && -n "$(fecha_registrada "${f}")" ]]; then fecha="$(fecha_registrada "${f}")"; else fecha="${fecha_hoy}"; fi
  printf '| `%s` | `inji-vc/stack/diagnostico/%s` | `%s` | %s |\n' "${f}" "${f}" "${nueva}" "${fecha}" >> "${tabla}"
done

# Commit del origen, si está bajo git (no lo estaba al vendorizar por primera vez).
commit="sin git (la huella SHA-256 identifica la versión)"
if command -v git >/dev/null 2>&1 && git -C "${ORIGEN}" rev-parse --git-dir >/dev/null 2>&1; then
  commit="$(git -C "${ORIGEN}" log -1 --format=%H -- . 2>/dev/null || true)"
  [[ -n "${commit}" ]] || commit="sin git (la huella SHA-256 identifica la versión)"
  if [[ "${commit}" != sin* && -n "$(git -C "${ORIGEN}" status --porcelain -- . 2>/dev/null)" ]]; then
    commit="${commit} (con cambios sin confirmar en el origen)"
  fi
fi

# 3. Reescribe solo lo que hay entre los marcadores.
{
  awk -v ini="${INICIO}" '{ print } $0 == ini { exit }' "${PROCEDENCIA}"
  cat "${tabla}"
  echo ""
  echo "Commit del origen en la última sincronización: ${commit}"
  awk -v fin="${FIN}" '$0 == fin { f = 1 } f { print }' "${PROCEDENCIA}"
} > "${tabla}.nuevo"
mv "${tabla}.nuevo" "${PROCEDENCIA}"

echo "Diagnóstico sincronizado desde ${ORIGEN}:"
for f in "${FICHEROS[@]}"; do printf '  %s  %s\n' "$(sha256_de "${DESTINO}/${f}" | cut -c1-12)" "${f}"; done
