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

const CTX_V1 = "https://www.w3.org/2018/credentials/v1";

for (const modo of ["domain", "ip"]) {
  describe(`línea base · TLS_MODE=${modo}`, () => {
    let e;
    const host = modo === "domain" ? "emisor.prueba.invalid" : "203-0-113-10.sslip.io";
    before(() => { e = prepararEntorno({ modo }); });
    after(() => e.limpiar());

    test("la generación termina bien y produce los cinco ficheros", () => {
      assert.equal(e.pasos.runtime.status, 0, e.pasos.runtime.stderr);
      assert.equal(e.pasos.generar.status, 0, e.pasos.generar.stderr);
      for (const clave of ["runtime", "propiedadesDefault", "propiedadesInstitucion", "caddyfile", "sql"]) {
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

    test("SQL: un INSERT sin ON CONFLICT y con config_id aleatorio (T2: R7)", () => {
      const sql = e.leer("sql");
      const v = valoresSql(sql);
      assert.equal(literal(v.credential_config_key_id), "PruebaLicencia");
      assert.equal(v.config_id, "gen_random_uuid()::VARCHAR(255)");
      assert.doesNotMatch(sql, /ON CONFLICT/i);
      assert.equal(literal(v.status), "active");
    });

    test("DEFECTO R1: el único @context es credentials/v1 (la firma no cubrirá los atributos)", () => {
      const sql = e.leer("sql");
      const v = valoresSql(sql);
      assert.equal(literal(v.context), CTX_V1);
      assert.deepEqual(plantillaDesdeSql(sql)["@context"], [CTX_V1]);
      assert.doesNotMatch(sql, /ed25519-2020|credentials\/v2|\/contextos\//);
    });

    test("DEFECTO R2: los tipos se guardan sin ordenar (<ID>Credential,VerifiableCredential)", () => {
      const sql = e.leer("sql");
      assert.equal(literal(valoresSql(sql).credential_type), "pruebaCredential,VerifiableCredential");
      // Certify busca con Collections.sort (orden por unidades UTF-16): sería V... antes que p...
      assert.deepEqual(plantillaDesdeSql(sql).type, ["pruebaCredential", "VerifiableCredential"]);
    });

    test("DEFECTO R3: la plantilla es VC 1.1 (issuanceDate/expirationDate)", () => {
      const t = plantillaDesdeSql(e.leer("sql"));
      assert.equal(t.issuanceDate, "${validFrom}");
      assert.equal(t.expirationDate, "${validUntil}");
      assert.equal(t.validFrom, undefined);
      assert.equal(t.validUntil, undefined);
      assert.deepEqual(Object.keys(t.credentialSubject), ["nombre", "apellido", "numeroLicencia", "id"]);
    });

    test("SQL: atributos en credential_subject y display_order en el orden del .env", () => {
      const v = valoresSql(e.leer("sql"));
      assert.equal(v.display_order, "ARRAY['nombre','apellido','numeroLicencia']");
      const sujeto = JSON.parse(literal(v.credential_subject));
      assert.deepEqual(Object.keys(sujeto), ["nombre", "apellido", "numeroLicencia"]);
      assert.equal(sujeto.nombre.display[0].locale, "es");
    });

    test("DEFECTO R10: el logo es la URL externa configurada (y por defecto, el de un tercero)", () => {
      const v = valoresSql(e.leer("sql"));
      const display = JSON.parse(literal(v.display));
      assert.equal(display[0].logo.url, "https://emisor.prueba.invalid/logo-de-prueba.png");
    });

    test("Caddyfile: sitio con el host, email ACME global y proxy a certify:8090", () => {
      const c = e.leer("caddyfile");
      assert.match(c, /^\{\n\temail infra@prueba\.invalid\n\}/);
      assert.match(c, new RegExp(`^${host.replaceAll(".", "\\.")} \\{$`, "m"));
      assert.match(c, /reverse_proxy \/v1\/certify\/\* certify:8090/);
      // Sin bloque `tls` explícito: Caddy usa ACME (Let's Encrypt) por defecto con el email global.
      assert.doesNotMatch(c, /^\s*tls\b/m);
      assert.doesNotMatch(c, /^\s*(http:\/\/|:80\b)/m);
    });

    test("DEFECTO R5: did.json se reescribe a Certify tal cual; no hay /contextos, /logos ni bloqueo del actuator", () => {
      const c = e.leer("caddyfile");
      assert.match(c, /route \/\.well-known\/did\.json \{\n\t\trewrite \* \/v1\/certify\/\.well-known\/did\.json/);
      assert.match(c, /route \/\.well-known\/openid-credential-issuer/);
      assert.doesNotMatch(c, /contextos|logos|file_server|no-cache|respond .*404|actuator/);
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
  test("CREDENTIAL_TYPE explícito se guarda tal cual, sin ordenar (R2)", () => {
    const e = prepararEntorno({ extra: { CREDENTIAL_TYPE: "ZetaCredential,VerifiableCredential" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.equal(literal(valoresSql(e.leer("sql")).credential_type), "ZetaCredential,VerifiableCredential");
    } finally { e.limpiar(); }
  });

  test("DEFECTO: una etiqueta con ':' se trunca (split(\":\") en generate-credential-sql.sh)", () => {
    const e = prepararEntorno({
      extra: { CREDENTIAL_ATTRIBUTE_LABELS: "nombre:Nombre,apellido:Apellido,numeroLicencia:Licencia: nº" },
    });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const sujeto = JSON.parse(literal(valoresSql(e.leer("sql")).credential_subject));
      assert.equal(sujeto.nombre.display[0].name, "Nombre");
      assert.equal(sujeto.numeroLicencia.display[0].name, "Licencia"); // debería ser «Licencia: nº»
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
      .replace("REEMPLAZAR_CON_SECRET_DE_OGTIC", "secreto-de-mentira");
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
