// T8 · K8 (alta): el Caddyfile publica en lista blanca, no `/v1/certify/*` entero. Y las properties dejan sin
// autenticación solo lo que el kit usa. Sin Docker ni Caddy: se simula el enrutado (helpers/caddy-rutas.mjs) y se
// comprueban las properties. Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { prepararEntorno } from "./helpers/entorno.mjs";
import { enrutar } from "./helpers/caddy-rutas.mjs";

const MODOS = {
  domain: {},
  ip: {},
  proxy: { CERTIFY_PUBLIC_URL: "https://certify.prueba.invalid", CADDY_ACME_EMAIL: undefined },
};

// [método, ruta] -> a Certify.
const PERMITIDAS = [
  ["GET", "/.well-known/openid-credential-issuer"],
  ["GET", "/v1/certify/.well-known/openid-credential-issuer"],
  ["GET", "/v1/certify/.well-known/did.json"],
  ["GET", "/v1/certify/.well-known/jwks.json"],
  ["POST", "/v1/certify/issuance/credential"],
  ["GET", "/v1/certify/credentials/status-list/abc-123"],
  ["GET", "/v1/certify/rendering-template/plantilla"],
];

// Lo que NO debe llegar a Certify desde internet (todas, con su método real).
const CERRADAS = [
  ["POST", "/v1/certify/pre-authorized-data"],
  ["GET", "/v1/certify/credential-offer-data/abc"],
  ["POST", "/v1/certify/oauth/token"],
  ["POST", "/v1/certify/oauth/iar"],
  ["GET", "/v1/certify/.well-known/oauth-authorization-server"],
  ["POST", "/v1/certify/credential-configurations"],
  ["GET", "/v1/certify/credential-configurations/DriverLicenseCredential"],
  ["PUT", "/v1/certify/credential-configurations/DriverLicenseCredential"],
  ["DELETE", "/v1/certify/credential-configurations/DriverLicenseCredential"],
  ["POST", "/v1/certify/credentials/status"],
  ["POST", "/v1/certify/credentials/v2/status"],
  ["GET", "/v1/certify/system-info/certificate"],
  ["POST", "/v1/certify/system-info/uploadCertificate"],
  ["POST", "/v1/certify/system-info/generate-csr"],
  ["POST", "/v1/certify/system-info/upload-ca-certificate"],
  ["POST", "/v1/certify/ledger-search"],
  ["POST", "/v1/certify/v2/ledger-search"],
  ["GET", "/v1/certify/swagger-ui/index.html"],
  ["GET", "/v1/certify/v3/api-docs"],
  ["GET", "/v1/certify/v3/api-docs/swagger-config"],
  ["GET", "/v1/certify/actuator/env"],
  ["GET", "/v1/certify/actuator/heapdump"],
  ["POST", "/v1/certify/issuance/vd11/credential"],
  ["POST", "/v1/certify/issuance/vd12/credential"],
  ["GET", "/v1/certify/issuance/.well-known/openid-credential-issuer"],
  // el método importa: el endpoint de emisión solo admite POST; la lista de estado solo GET
  ["GET", "/v1/certify/issuance/credential"],
  ["DELETE", "/v1/certify/issuance/credential"],
  ["POST", "/v1/certify/credentials/status-list/abc"],
  // Caddy casa las rutas sin distinguir mayúsculas: las variantes no cuelan nada
  ["POST", "/V1/CERTIFY/PRE-AUTHORIZED-DATA"],
  ["POST", "/v1/Certify/OAuth/Token"],
  // rutas inventadas y raíz: 404 explícito, no 200 vacío
  ["GET", "/v1/certify/ruta-inventada"],
  ["POST", "/v1/certify/otra/cosa/mas"],
  ["GET", "/v1/certify"],
  ["GET", "/v1/certify/"],
  ["GET", "/"],
  ["GET", "/cualquier-cosa"],
  ["GET", "/.well-known/jwks.json"],
  ["GET", "/v1/otra-api/x"],
];

for (const [modo, extra] of Object.entries(MODOS)) {
  describe(`K8 · lista blanca de /v1/certify/* · TLS_MODE=${modo}`, () => {
    let e, c, p;
    before(() => { e = prepararEntorno({ modo, extra }); c = e.leer("caddyfile"); p = e.leer("propiedadesDefault").replaceAll("\\\n", ""); });
    after(() => e.limpiar());

    test("la generación termina bien", () => assert.equal(e.salida.status, 0, e.salida.stderr));

    for (const [m, ruta] of PERMITIDAS) {
      test(`pasa a Certify: ${m} ${ruta}`, () => assert.equal(enrutar(c, m, ruta), "certify"));
    }
    for (const [m, ruta] of CERRADAS) {
      test(`404: ${m} ${ruta}`, () => assert.equal(enrutar(c, m, ruta), "404"));
    }

    test("el health sigue siendo solo para la red privada; el resto del actuator, 404", () => {
      assert.equal(enrutar(c, "GET", "/v1/certify/actuator/health", { interno: true }), "certify");
      assert.equal(enrutar(c, "GET", "/v1/certify/actuator/health", { interno: false }), "404");
      assert.equal(enrutar(c, "GET", "/v1/certify/actuator/metrics"), "404");
    });

    test("did.json, contextos y logos no se rompen con el 404 final (siguen yendo a su regla)", () => {
      assert.equal(enrutar(c, "GET", "/contextos/PruebaLicencia.json"), "fichero");
      assert.equal(enrutar(c, "GET", "/logos/PruebaLicencia.png"), "fichero");
      assert.notEqual(enrutar(c, "GET", "/.well-known/did.json", { interno: false }), "404");
    });

    test("cada ruta cerrada tiene su `respond 404` EXPLÍCITO en el Caddyfile (no solo el comodín final)", () => {
      for (const ruta of [
        "/v1/certify/pre-authorized-data*", "/v1/certify/credential-offer-data*", "/v1/certify/oauth*",
        "/v1/certify/credential-configurations*", "/v1/certify/credentials/status", "/v1/certify/credentials/v2/*",
        "/v1/certify/system-info*", "/v1/certify/ledger-search*", "/v1/certify/v2/*", "/v1/certify/swagger-ui*",
        "/v1/certify/v3/api-docs*", "/v1/certify/actuator*", "/v1/certify/issuance/*",
      ]) {
        const re = new RegExp(`handle ${ruta.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\{\\n\\t\\trespond 404\\n\\t\\}`);
        assert.match(c, re, ruta);
      }
    });

    test("cada ruta permitida está escrita en el Caddyfile", () => {
      for (const ruta of [
        "/.well-known/openid-credential-issuer", "/v1/certify/.well-known/openid-credential-issuer",
        "/v1/certify/.well-known/did.json", "/v1/certify/.well-known/jwks.json", "/v1/certify/issuance/credential",
        "/v1/certify/credentials/status-list/*", "/v1/certify/rendering-template/*",
      ]) assert.ok(c.includes(`handle ${ruta} {`), ruta);
    });

    test("ya no hay `handle /v1/certify/* { reverse_proxy … }`: el comodín de /v1/certify/ es 404", () => {
      assert.doesNotMatch(c, /handle \/v1\/certify\/\* \{\n\t\treverse_proxy/);
      assert.match(c, /handle \/v1\/certify\/\* \{\n\t\trespond 404\n\t\}/);
    });

    test("hay un `handle` final sin matcher con 404 para lo que no está listado", () => {
      assert.match(c, /\n\thandle \{\n\t\trespond 404\n\t\}\n\}/);
    });

    test("ninguna ruta usa `route` ni `handle_path` junto al 404 final (el orden de directivas de Caddy los pondría detrás)", () => {
      const fragmento = c.slice(c.indexOf("(certify_comun) {"), c.indexOf("\n}\n", c.indexOf("(certify_comun) {")));
      assert.doesNotMatch(fragmento.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n"), /^\t(route|handle_path) /m);
    });

    test("properties: ignore-auth-urls y ignore-csrf-urls solo llevan lo que el kit usa", () => {
      for (const clave of ["ignore-auth-urls", "ignore-csrf-urls"]) {
        const v = p.match(new RegExp(`^mosip\\.certify\\.security\\.${clave}=(.*)$`, "m"))[1].split(",").map((s) => s.trim()).filter(Boolean);
        for (const fuera of ["/oauth/**", "/pre-authorized-data", "/pre-authorized-data/**", "/credential-offer-data/**", "/credential-configurations/**",
          "/system-info/**", "/ledger-search/**", "/swagger-ui/**", "/v3/api-docs/**", "/credentials/**", "/issuance/**"]) {
          assert.ok(!v.includes(fuera), `${clave} no debe llevar ${fuera}: ${v}`);
        }
        for (const dentro of ["/actuator/**", "/error", "/issuance/credential", "/.well-known/**"]) {
          assert.ok(v.includes(dentro), `${clave} debe llevar ${dentro}: ${v}`);
        }
      }
      const auth = p.match(/^mosip\.certify\.security\.ignore-auth-urls=(.*)$/m)[1];
      assert.match(auth, /\/credentials\/status-list\/\*\*/);
      assert.match(auth, /\/rendering-template\/\*\*/);
    });

    test("properties: el filtro de token sigue protegiendo el endpoint de emisión (authn.filter-urls)", () => {
      assert.match(p, /^mosip\.certify\.authn\.filter-urls=.*\/issuance\/credential/m);
    });
  });
}
