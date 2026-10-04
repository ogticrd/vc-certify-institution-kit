// T9 · I9 (integración real, 4-oct-2026): con CERTIFY_PUBLIC_URL=http://localhost y KIT_PERMITIR_HTTP=1, el AVISO de
// «usa http … verify-install.sh fallará» salía 9 veces en una sola ejecución de install.sh (lo imprimía cada script
// que revalida la URL: generate-config.sh y cada generador). Una vez basta.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { prepararEntorno } from "./helpers/entorno.mjs";

const veces = (texto, re) => (texto.match(re) ?? []).length;

describe("I9 · el aviso de http se imprime una sola vez por ejecución", () => {
  test("generate-config.sh con http://localhost y KIT_PERMITIR_HTTP=1: exactamente un AVISO", () => {
    const e = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: "http://localhost:8080", CADDY_ACME_EMAIL: undefined, KIT_PERMITIR_HTTP: "1" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.equal(veces(e.salida.stderr, /AVISO: CERTIFY_PUBLIC_URL usa http/g), 1, e.salida.stderr);
    } finally { e.limpiar(); }
  });
  test("una segunda ejecución independiente vuelve a avisar (la marca no se arrastra entre ejecuciones)", () => {
    const e = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: "http://localhost:8080", CADDY_ACME_EMAIL: undefined, KIT_PERMITIR_HTTP: "1" } });
    try {
      const otra = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
      assert.equal(otra.status, 0, otra.stderr);
      assert.equal(veces(otra.stderr, /AVISO: CERTIFY_PUBLIC_URL usa http/g), 1);
    } finally { e.limpiar(); }
  });
});
