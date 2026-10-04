// LÍNEA BASE (T1): comportamiento ACTUAL de los generadores del kit, antes de corregirlos.
//
// Estas aserciones documentan el estado de partida, defectos incluidos. Las tareas T2-T5
// las cambiarán a propósito; al hacerlo, cada cambio debe quedar explicado en su commit.
// Un test marcado «DEFECTO» describe algo que la spec manda corregir (R1-R10).
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  prepararEntorno, valoresSql, literal, plantillaDesdeSql, KIT_ORIGEN,
} from "./helpers/entorno.mjs";

const CTX_V2 = "https://www.w3.org/ns/credentials/v2";
const CTX_ED = "https://w3id.org/security/suites/ed25519-2020/v1";

for (const modo of ["domain", "ip"]) {
  describe(`línea base · TLS_MODE=${modo}`, () => {
    let e;
    const host = modo === "domain" ? "emisor.prueba.invalid" : "203-0-113-10.sslip.io";
    before(() => { e = prepararEntorno({ modo }); });
    after(() => e.limpiar());

    // T2: de cinco a siete ficheros (se suman el contexto propio y la credencial de muestra); T3: el logo.
    test("la generación termina bien y produce los ocho ficheros", () => {
      assert.equal(e.pasos.runtime.status, 0, e.pasos.runtime.stderr);
      assert.equal(e.pasos.generar.status, 0, e.pasos.generar.stderr);
      for (const clave of ["runtime", "propiedadesDefault", "propiedadesInstitucion", "caddyfile", "sql", "muestra", "contexto", "logo"]) {
        assert.ok(e.existe(clave), `falta ${clave}: ${e.rutas[clave]}`);
      }
    });

    test(".env.runtime lleva la URL pública y el DID derivados", () => {
      const r = e.leer("runtime");
      assert.match(r, new RegExp(`^CERTIFY_PUBLIC_URL=https://${host}$`, "m"));
      assert.match(r, new RegExp(`^DID_URL=did:web:${host}$`, "m"));
      assert.match(r, new RegExp(`^TLS_MODE=${modo}$`, "m"));
    });

    test("DEFECTO (T4): .env.runtime guarda en claro el secreto OAuth y la contraseña de Postgres", () => {
      const r = e.leer("runtime");
      assert.match(r, /^OAUTH_CLIENT_SECRET=secreto-de-mentira$/m);
      assert.match(r, /^POSTGRES_PASSWORD=clave-bd-de-mentira$/m);
    });

    // T2 (R7): antes «un INSERT sin ON CONFLICT y con config_id aleatorio (gen_random_uuid)».
    test("SQL: UPSERT con config_id = clave y ON CONFLICT que conserva status (R7)", () => {
      const sql = e.leer("sql");
      const v = valoresSql(sql);
      assert.equal(literal(v.credential_config_key_id), "PruebaLicencia");
      assert.equal(literal(v.config_id), "PruebaLicencia");
      assert.match(sql, /ON CONFLICT \(credential_config_key_id\) DO UPDATE SET/);
      assert.match(sql, /status = certify\.credential_config\.status/);
      assert.equal(literal(v.status), "active");
    });

    // T2 (R1): antes «DEFECTO R1: el único @context es credentials/v1».
    test("R1: @context con credentials/v2, el contexto propio y la suite (en la columna, ordenados)", () => {
      const sql = e.leer("sql");
      const propio = `https://${host}/contextos/PruebaLicencia.json`;
      assert.equal(literal(valoresSql(sql).context), [CTX_ED, CTX_V2, propio].sort().join(","));
      assert.deepEqual(plantillaDesdeSql(sql)["@context"], [CTX_V2, propio, CTX_ED]);
      assert.doesNotMatch(sql, /2018\/credentials\/v1/);
    });

    // T2 (R2): antes «DEFECTO R2: los tipos se guardan sin ordenar (pruebaCredential,VerifiableCredential)».
    test("R2: los tipos se guardan ordenados como Java (V… antes que p…)", () => {
      const sql = e.leer("sql");
      assert.equal(literal(valoresSql(sql).credential_type), "VerifiableCredential,pruebaCredential");
      assert.deepEqual(plantillaDesdeSql(sql).type, ["VerifiableCredential", "pruebaCredential"]);
    });

    // T2 (R3): antes «DEFECTO R3: la plantilla es VC 1.1 (issuanceDate/expirationDate)»; el id pasa
    // al principio del credentialSubject (como el emisor propio).
    test("R3: la plantilla es VC 2.0 (validFrom/validUntil)", () => {
      const t = plantillaDesdeSql(e.leer("sql"));
      assert.equal(t.validFrom, "${validFrom}");
      assert.equal(t.validUntil, "${validUntil}");
      assert.equal(t.issuanceDate, undefined);
      assert.equal(t.expirationDate, undefined);
      assert.deepEqual(Object.keys(t.credentialSubject), ["id", "nombre", "apellido", "numeroLicencia"]);
    });

    test("SQL: atributos en credential_subject y display_order en el orden del .env", () => {
      const v = valoresSql(e.leer("sql"));
      assert.equal(v.display_order, "ARRAY['nombre','apellido','numeroLicencia']");
      const sujeto = JSON.parse(literal(v.credential_subject));
      assert.deepEqual(Object.keys(sujeto), ["nombre", "apellido", "numeroLicencia"]);
      assert.equal(sujeto.nombre.display[0].locale, "es");
    });

    // T3 (R10): antes la URL externa configurada (y por defecto, el logo de un tercero).
    test("R10: el logo es el propio, servido por el kit en /logos/<clave>.png", () => {
      const v = valoresSql(e.leer("sql"));
      const display = JSON.parse(literal(v.display));
      assert.equal(display[0].logo.url, `https://${host}/logos/PruebaLicencia.png`);
    });

    test("Caddyfile: sitio con el host, email ACME global y proxy a certify:8090", () => {
      const c = e.leer("caddyfile");
      assert.match(c, /^\{\n\temail infra@prueba\.invalid\n\}/);
      assert.match(c, new RegExp(`^${host.replaceAll(".", "\\.")} \\{$`, "m"));
      assert.match(c, /import certify_comun/);
      // Sin bloque `tls` explícito: Caddy usa ACME (Let's Encrypt) por defecto con el email global.
      assert.doesNotMatch(c, /^\s*tls\b/m);
      assert.doesNotMatch(c, /^\s*(http:\/\/|:80\b)/m);
    });

    // T3: antes did.json se reescribía a Certify tal cual y no había /contextos, /logos ni bloqueo del
    // actuator. El detalle de las rutas nuevas está en caddy-did-logos.test.mjs.
    test("el Caddyfile conserva la metadata del emisor y el proxy a Certify, y añade did.json/contextos/logos/actuator (T3)", () => {
      const c = e.leer("caddyfile");
      assert.match(c, /route \/\.well-known\/openid-credential-issuer \{\n\t\trewrite \* \/v1\/certify\/\.well-known\/openid-credential-issuer\n\t\treverse_proxy certify:8090/);
      assert.match(c, /handle \/v1\/certify\/\* \{\n\t\treverse_proxy certify:8090/);
      assert.match(c, /\/contextos\/\*/);
      assert.match(c, /\/logos\/\*/);
      assert.match(c, /\/v1\/certify\/actuator\*/);
    });

    test("DEFECTO R4: las properties apuntan a cuenta.digital.gob.do (staging)", () => {
      const p = e.leer("propiedadesDefault");
      assert.match(p, /^mosip\.certify\.authorization\.url=https:\/\/cuenta\.digital\.gob\.do$/m);
      assert.match(p, /^mosip\.certify\.authn\.issuer-uri=https:\/\/cuenta\.digital\.gob\.do$/m);
      assert.match(p, /^mosip\.certify\.authn\.jwk-set-uri=https:\/\/cuenta\.digital\.gob\.do\/\.well-known\/jwks\.json$/m);
      assert.doesNotMatch(p, /auth\.cuentaunica\.gob\.do/);
      const i = e.leer("propiedadesInstitucion");
      assert.match(i, /^mosip\.certify\.data-provider-plugin\.restapi\.auth\.token-url=https:\/\/cuenta\.digital\.gob\.do\/oauth2\/token$/m);
    });

    test("properties: URL pública, DID y base de datos sustituidos; ninguna variable sin sustituir", () => {
      const p = e.leer("propiedadesDefault");
      assert.match(p, new RegExp(`^mosip\\.certify\\.domain\\.url=https://${host.replaceAll(".", "\\.")}$`, "m"));
      assert.match(p, new RegExp(`^mosip\\.certify\\.data-provider-plugin\\.did-url=did:web:${host.replaceAll(".", "\\.")}$`, "m"));
      assert.match(p, /^spring\.datasource\.url=jdbc:postgresql:\/\/database:5432\/inji_certify\?currentSchema=certify$/m);
      const i = e.leer("propiedadesInstitucion");
      assert.match(i, /^mosip\.certify\.data-provider-plugin\.restapi\.auth\.client-id=cliente-de-mentira$/m);
      assert.match(i, /^mosip\.certify\.data-provider-plugin\.restapi\.base-url=https:\/\/api\.prueba\.invalid\/datos$/m);
      // envsubst solo toca la lista blanca: quedan ${mosip...} propios de Spring, nunca de las variables del kit.
      for (const f of [p, i]) assert.doesNotMatch(f, /\$\{(CERTIFY_|DID_URL|POSTGRES_|OAUTH_|RESTAPI_|INSTITUTION_)/);
    });

    test("DEFECTO R9: actuator completo, env.show-values=ALWAYS, contraseñas en claro", () => {
      const p = e.leer("propiedadesDefault");
      assert.match(p, /^management\.endpoints\.web\.exposure\.include=\*$/m);
      assert.match(p, /^management\.endpoint\.env\.show-values=ALWAYS$/m);
      assert.match(p, /^mosip\.kernel\.keymanager\.hsm\.keystore-pass=local$/m);
      assert.match(p, /^spring\.datasource\.password=clave-bd-de-mentira$/m);
      assert.match(e.leer("propiedadesInstitucion"), /^mosip\.certify\.data-provider-plugin\.restapi\.auth\.client-secret=secreto-de-mentira$/m);
    });

    test("DEFECTO: no hay configuración de logging; Certify arranca con el nivel INFO por defecto (R12)", () => {
      assert.doesNotMatch(e.leer("propiedadesDefault"), /^logging\./m);
      assert.doesNotMatch(e.leer("propiedadesInstitucion"), /^logging\./m);
    });
  });
}

describe("línea base · casos límite del comportamiento actual", () => {
  // T2 (R2): antes «CREDENTIAL_TYPE explícito se guarda tal cual, sin ordenar» (Zeta…,Verifiable…).
  test("CREDENTIAL_TYPE explícito se guarda ordenado (R2)", () => {
    const e = prepararEntorno({ extra: { CREDENTIAL_TYPE: "ZetaCredential,VerifiableCredential" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.equal(literal(valoresSql(e.leer("sql")).credential_type), "VerifiableCredential,ZetaCredential");
    } finally { e.limpiar(); }
  });

  // T2: antes «DEFECTO: una etiqueta con ':' se trunca (split(":"))». Ahora el formato «attr:Etiqueta»
  // se rechaza con un mensaje y las etiquetas van en CREDENTIAL_LABELS_JSON, donde «:» es un carácter más.
  test("una etiqueta con ':' se conserva entera (CREDENTIAL_LABELS_JSON)", () => {
    const e = prepararEntorno({
      extra: { CREDENTIAL_LABELS_JSON: '{"nombre":"Nombre","numeroLicencia":"Licencia: nº"}' },
    });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const sujeto = JSON.parse(literal(valoresSql(e.leer("sql")).credential_subject));
      assert.equal(sujeto.nombre.display[0].name, "Nombre");
      assert.equal(sujeto.numeroLicencia.display[0].name, "Licencia: nº");
      assert.equal(sujeto.apellido.display[0].name, "apellido"); // sin etiqueta: el nombre del atributo
    } finally { e.limpiar(); }
  });

  test("DEFECTO (T4): generate-config.sh por sí solo NO escribe .env.runtime (lo hace install.sh)", () => {
    const e = prepararEntorno({ runtime: false });
    try {
      assert.equal(e.pasos.generar.status, 0, e.pasos.generar.stderr);
      assert.equal(e.existe("runtime"), false);
      assert.ok(e.existe("sql"));
    } finally { e.limpiar(); }
  });

  test("TLS_MODE=proxy se rechaza hoy (T5 lo admitirá)", () => {
    const e = prepararEntorno({ modo: "proxy", runtime: false });
    try {
      assert.notEqual(e.pasos.generar.status, 0);
      assert.match(e.pasos.generar.stderr, /TLS_MODE debe ser 'domain' o 'ip' \(actual: proxy\)/);
      assert.equal(e.existe("caddyfile"), false);
    } finally { e.limpiar(); }
  });

  test("falta OAUTH_CLIENT_SECRET: falla con mensaje y sin generar SQL", () => {
    const e = prepararEntorno({ extra: { OAUTH_CLIENT_SECRET: undefined }, runtime: false });
    try {
      assert.notEqual(e.pasos.generar.status, 0);
      assert.match(e.pasos.generar.stderr, /Variables obligatorias vacías/);
      assert.match(e.pasos.generar.stderr, /OAUTH_CLIENT_SECRET/);
    } finally { e.limpiar(); }
  });

  test("el .env.example del kit, con el secreto sustituido, genera sin error", () => {
    const ejemplo = readFileSync(join(KIT_ORIGEN, ".env.example"), "utf8")
      .replace("REEMPLAZAR_CON_SECRET_DE_OGTIC", "secreto-de-mentira")
      .replace(/^LOGO_PATH=$/m, "LOGO_PATH=__LOGO_PATH__");
    const e = prepararEntorno({ envTexto: ejemplo });
    try {
      assert.equal(e.pasos.runtime.status, 0, e.pasos.runtime.stderr);
      assert.equal(e.pasos.generar.status, 0, e.pasos.generar.stderr);
      assert.equal(literal(valoresSql(e.leer("sql")).credential_config_key_id), "DriverLicenseCredential");
    } finally { e.limpiar(); }
  });

  test("el arnés escribe su propio .env de prueba y parte sin generated/", () => {
    const e = prepararEntorno({ generar: false, runtime: false });
    try {
      const env = readFileSync(join(e.kit, ".env"), "utf8");
      assert.match(env, /^INSTITUTION_ID="prueba"$/m);
      assert.equal(e.existe("sql"), false);
    } finally { e.limpiar(); }
  });
});
