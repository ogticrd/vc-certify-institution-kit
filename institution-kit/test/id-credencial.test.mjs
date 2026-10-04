// T9 · I12 (integración real, 4-oct-2026): el `id` de cada credencial emitida salía bajo `https://mosip.io/credential/<uuid>`,
// un dominio que no es de la institución ni del Estado, porque certify-institution.properties.tpl fijaba
// `id-field-prefix-uri=https://mosip.io/credential/`. El emisor propio de OGTIC usa su propio host (`https://${HOST}/credential/`).
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { prepararEntorno } from "./helpers/entorno.mjs";

const valor = (texto, clave) => texto.match(new RegExp(`^${clave}=(.*)$`, "m"))?.[1];

describe("I12 · el id de la credencial cuelga de la dirección pública de la institución", () => {
  const casos = {
    domain: { esperado: "https://certify.prueba.invalid/credential/", extra: { CERTIFY_PUBLIC_HOST: "certify.prueba.invalid" } },
    proxy: { esperado: "https://certify.prueba.invalid/credential/", extra: { CERTIFY_PUBLIC_URL: "https://certify.prueba.invalid", CADDY_ACME_EMAIL: undefined } },
  };
  for (const [modo, { esperado, extra }] of Object.entries(casos)) {
    test(`${modo}: id-field-prefix-uri = ${esperado} y ningún mosip.io fuera de comentarios`, () => {
      const e = prepararEntorno({ modo, extra });
      try {
        assert.equal(e.salida.status, 0, e.salida.stderr);
        const p = e.leer("propiedadesInstitucion");
        assert.equal(valor(p, "mosip\\.certify\\.data-provider-plugin\\.id-field-prefix-uri"), esperado);
        const sinComentarios = p.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
        assert.doesNotMatch(sinComentarios, /mosip\.io/);
      } finally { e.limpiar(); }
    });
  }
});
