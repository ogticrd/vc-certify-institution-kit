// T4 · Autenticación de producción, secretos, actuator y logs (R4, R9, R12; D7, D8).
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"  (desde la raíz del repo)
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  readFileSync, writeFileSync, mkdirSync, chmodSync, symlinkSync, existsSync, readdirSync, statSync,
} from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { prepararEntorno, KIT_ORIGEN } from "./helpers/entorno.mjs";

const SIN_CONTRASENAS = { POSTGRES_PASSWORD: undefined, KEYSTORE_PASSWORD: undefined };
const HEX64 = /^[0-9a-f]{64}$/;
const sinComentarios = (t) => t.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
const valor = (texto, clave) => texto.match(new RegExp(`^${clave}=(.*)$`, "m"))?.[1];

// Genera con `extra` y devuelve el entorno ya preparado; el llamador limpia.
const generar = (extra = {}, opciones = {}) => prepararEntorno({ extra, ...opciones });

describe("R4 · autenticación de producción", () => {
  test("por defecto: los tres valores apuntan a https://auth.cuentaunica.gob.do y el jwks sale de ahí", () => {
    const e = generar();
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const p = e.leer("propiedadesDefault");
      assert.match(p, /^mosip\.certify\.authorization\.url=https:\/\/auth\.cuentaunica\.gob\.do$/m);
      assert.match(p, /^mosip\.certify\.authn\.issuer-uri=https:\/\/auth\.cuentaunica\.gob\.do$/m);
      assert.match(p, /^mosip\.certify\.authn\.jwk-set-uri=https:\/\/auth\.cuentaunica\.gob\.do\/\.well-known\/jwks\.json$/m);
      // Ni el staging anterior ni el `mi.` que rechaza todo token (H-2 del emisor propio), fuera de comentarios.
      assert.doesNotMatch(sinComentarios(p), /cuenta\.digital\.gob\.do|mi\.cuentaunica\.gob\.do/);
      assert.doesNotMatch(p, /\$\{AUTH_ISSUER_URL\}/, "variable sin sustituir");
      // Las URL derivadas del servidor de autorización (metadata OAuth) siguen a la propiedad.
      assert.match(p, /^mosip\.certify\.oauth\.issuer=\$\{mosip\.certify\.authorization\.url\}$/m);
    } finally { e.limpiar(); }
  });

  test("con AUTH_ISSUER_URL propio: los tres valores y el jwks lo siguen", () => {
    const e = generar({ AUTH_ISSUER_URL: "https://auth.prueba.invalid" });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const p = e.leer("propiedadesDefault");
      assert.match(p, /^mosip\.certify\.authorization\.url=https:\/\/auth\.prueba\.invalid$/m);
      assert.match(p, /^mosip\.certify\.authn\.issuer-uri=https:\/\/auth\.prueba\.invalid$/m);
      assert.match(p, /^mosip\.certify\.authn\.jwk-set-uri=https:\/\/auth\.prueba\.invalid\/\.well-known\/jwks\.json$/m);
      assert.doesNotMatch(sinComentarios(p), /auth\.cuentaunica\.gob\.do/);
    } finally { e.limpiar(); }
  });

  for (const [nombre, valorMalo] of [
    ["con barra final (el iss se compara por igualdad exacta)", "https://auth.prueba.invalid/"],
    ["con http", "http://auth.prueba.invalid"],
    ["con espacios", "https://auth.prueba.invalid x"],
    ["con salto de línea (inyección de propiedades)", "https://auth.prueba.invalid\nspring.x=1"],
  ]) {
    test(`AUTH_ISSUER_URL ${nombre} se rechaza y no genera nada`, () => {
      const e = generar({ AUTH_ISSUER_URL: valorMalo });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /AUTH_ISSUER_URL debe ser una URL https/);
        assert.equal(e.existe("propiedadesDefault"), false);
      } finally { e.limpiar(); }
    });
  }

  test("sin RESTAPI_TOKEN_URL: falla diciendo que es el token de la API de datos y que OGTIC entrega el valor", () => {
    const e = generar({ RESTAPI_TOKEN_URL: undefined });
    try {
      assert.notEqual(e.salida.status, 0);
      assert.match(e.salida.stderr, /RESTAPI_TOKEN_URL es obligatorio/);
      assert.match(e.salida.stderr, /token de la API de datos/);
      assert.match(e.salida.stderr, /NO el del ciudadano ni el de Cuenta Única/);
      assert.match(e.salida.stderr, /OGTIC entrega el valor/);
      for (const f of ["propiedadesInstitucion", "propiedadesDefault", "caddyfile", "sql"]) assert.equal(e.existe(f), false, f);
    } finally { e.limpiar(); }
  });

  for (const v of ["", "CAMBIAR-ME", "no es una url"]) {
    test(`RESTAPI_TOKEN_URL=${JSON.stringify(v)} no vale`, () => {
      const e = generar({ RESTAPI_TOKEN_URL: v });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /RESTAPI_TOKEN_URL/);
        assert.equal(e.existe("propiedadesInstitucion"), false);
      } finally { e.limpiar(); }
    });
  }

  test("RESTAPI_TOKEN_URL llega a las properties de la institución; no queda ningún token-url de staging", () => {
    const e = generar({ RESTAPI_TOKEN_URL: "https://datos.prueba.invalid/oauth2/token" });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const i = e.leer("propiedadesInstitucion");
      assert.match(i, /^mosip\.certify\.data-provider-plugin\.restapi\.auth\.token-url=https:\/\/datos\.prueba\.invalid\/oauth2\/token$/m);
      assert.doesNotMatch(sinComentarios(i), /cuenta\.digital\.gob\.do/);
    } finally { e.limpiar(); }
  });

  test("OAUTH_CLIENT_ID=CAMBIAR-ME (el marcador de .env.example) se rechaza", () => {
    const e = generar({ OAUTH_CLIENT_ID: "CAMBIAR-ME" });
    try {
      assert.notEqual(e.salida.status, 0);
      assert.match(e.salida.stderr, /OAUTH_CLIENT_ID/);
      assert.match(e.salida.stderr, /CAMBIAR-ME/);
    } finally { e.limpiar(); }
  });

  test(".env.example: sin ID de cliente con aspecto real, con marcador y con RESTAPI_TOKEN_URL documentada y vacía", () => {
    const ej = readFileSync(join(KIT_ORIGEN, ".env.example"), "utf8");
    assert.match(ej, /^OAUTH_CLIENT_ID=CAMBIAR-ME$/m);
    assert.doesNotMatch(ej, /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, "un UUID parece un ID de cliente real");
    assert.match(ej, /^RESTAPI_TOKEN_URL=$/m);
    assert.match(ej, /token de la API de datos[\s\S]*?OGTIC entrega el valor|OGTIC entrega el valor[\s\S]*?RESTAPI_TOKEN_URL/);
    assert.match(ej, /^# AUTH_ISSUER_URL=https:\/\/auth\.cuentaunica\.gob\.do$/m);
    assert.doesNotMatch(sinComentarios(ej), /cuenta\.digital\.gob\.do/);
  });
});

describe("R9 · actuator (D8)", () => {
  test("solo health, sin detalles, env nunca muestra valores", () => {
    const e = generar();
    try {
      const p = e.leer("propiedadesDefault");
      assert.match(p, /^management\.endpoints\.web\.exposure\.include=health$/m);
      assert.match(p, /^management\.endpoint\.health\.show-details=never$/m);
      assert.match(p, /^management\.endpoint\.env\.show-values=NEVER$/m);
      assert.doesNotMatch(p, /^management\.endpoints\.web\.exposure\.include=.*\*/m);
      assert.doesNotMatch(p, /show-values=ALWAYS/);
    } finally { e.limpiar(); }
  });

  test("/actuator/** sigue en ignore-auth-urls: el health interno se pide sin token (Caddy → certify:8090)", () => {
    const e = generar();
    try {
      const p = e.leer("propiedadesDefault").replaceAll("\\\n", "");
      assert.match(p, /^mosip\.certify\.security\.ignore-auth-urls=\/actuator\/\*\*,/m);
      // …y la comprobación de install.sh/verify-install.sh (wait_for_health, en common.sh) es justo esa petición interna.
      const v = readFileSync(join(KIT_ORIGEN, "scripts", "lib", "common.sh"), "utf8");
      assert.match(v, /certify:8090\/v1\/certify\/actuator\/health/);
    } finally { e.limpiar(); }
  });
});

describe("R12 · el filtro del token no registra a INFO", () => {
  test("properties: logging.level.io.mosip.certify.filter=WARN", () => {
    const e = generar();
    try {
      assert.match(e.leer("propiedadesDefault"), /^logging\.level\.io\.mosip\.certify\.filter=WARN$/m);
    } finally { e.limpiar(); }
  });

  const xml = readFileSync(join(KIT_ORIGEN, "templates", "logback-kit.xml"), "utf8");

  test("templates/logback-kit.xml: logger del filtro en WARN, raíz en INFO, bien formado", () => {
    const vivo = xml.replace(/<!--[\s\S]*?-->/g, "");
    assert.match(vivo, /<logger name="io\.mosip\.certify\.filter" level="WARN"\s*\/>/);
    assert.match(vivo, /<root level="INFO">/);
    assert.match(vivo, /<appender-ref ref="CONSOLE"\/>/);
    // Etiquetas equilibradas (no hay analizador XML sin dependencias: se cuentan aperturas y cierres).
    assert.equal((vivo.match(/<configuration>/g) ?? []).length, 1);
    assert.equal((vivo.match(/<\/configuration>/g) ?? []).length, 1);
    assert.equal((vivo.match(/<root /g) ?? []).length, (vivo.match(/<\/root>/g) ?? []).length);
    // Nunca el logger del filtro por debajo de WARN.
    assert.doesNotMatch(vivo, /io\.mosip\.certify\.filter" level="(TRACE|DEBUG|INFO)"/);
  });

  test("templates/logback-kit.xml: cabecera con procedencia y con el porqué", () => {
    assert.match(xml, /PROCEDENCIA:.*logback-soyyord\.xml/s);
    assert.match(xml, /541f1d9/);
    assert.match(xml, /POR QU[ÉE] UN XML/);
  });

  test("docker-compose.yml: LOGGING_CONFIG apunta al XML y el XML está montado en esa ruta", () => {
    const e = generar();
    try {
      const y = readFileSync(e.rutas.compose, "utf8");
      const ruta = y.match(/^\s*- LOGGING_CONFIG=(\S+)$/m)?.[1];
      assert.equal(ruta, "/home/mosip/config/logback-kit.xml");
      assert.match(y, new RegExp(`^\\s*- \\./templates/logback-kit\\.xml:${ruta.replaceAll(".", "\\.")}:ro$`, "m"));
      assert.ok(existsSync(join(e.kit, "templates", "logback-kit.xml")), "el XML montado existe en el kit");
    } finally { e.limpiar(); }
  });
});

describe("validaciones relajadas: documentadas, no cambiadas (R11)", () => {
  test("las tres siguen en false (cambiarlas podría romper la emisión con Cuenta Única)", () => {
    const e = generar();
    try {
      const p = e.leer("propiedadesDefault");
      assert.match(p, /^mosip\.certify\.authn\.validate-audience=false$/m);
      assert.match(p, /^mosip\.certify\.authn\.require-client-id-claim=false$/m);
      assert.match(p, /^mosip\.certify\.issuance\.validate-cnonce=false$/m);
    } finally { e.limpiar(); }
  });

  test("institution-kit/docs/IUGO-CUSTOMIZATIONS.md existe y explica cada una (qué relaja, por qué, riesgo)", () => {
    const d = readFileSync(join(KIT_ORIGEN, "docs", "IUGO-CUSTOMIZATIONS.md"), "utf8");
    for (const flag of ["mosip.certify.authn.validate-audience", "mosip.certify.authn.require-client-id-claim", "mosip.certify.issuance.validate-cnonce"]) {
      const i = d.indexOf(flag);
      assert.ok(i !== -1, `falta ${flag}`);
      const seccion = d.slice(i, i + 2500);
      assert.match(seccion, /Qué relaja/i, flag);
      assert.match(seccion, /Por qué/i, flag);
      assert.match(seccion, /Riesgo/i, flag);
    }
  });

  test("la plantilla cita el documento que existe", () => {
    const t = readFileSync(join(KIT_ORIGEN, "templates", "certify-default.properties.tpl"), "utf8");
    const m = t.match(/(institution-kit\/docs\/IUGO-CUSTOMIZATIONS\.md)/);
    assert.ok(m, "la plantilla cita la ruta del documento");
    assert.ok(existsSync(join(KIT_ORIGEN, "docs", "IUGO-CUSTOMIZATIONS.md")));
  });
});

describe("D7 · secretos", () => {
  test("con las contraseñas por defecto: .env.runtime en modo 600 con 64 hex distintas, y las properties las usan", () => {
    const e = generar(SIN_CONTRASENAS);
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.equal(e.modo("runtime"), 0o600);
      const r = e.leer("runtime");
      const pg = valor(r, "POSTGRES_PASSWORD");
      const ks = valor(r, "KEYSTORE_PASSWORD");
      assert.match(pg, HEX64);
      assert.match(ks, HEX64);
      assert.notEqual(pg, ks);
      assert.notEqual(pg, "postgres");
      assert.notEqual(ks, "local");
      // T8 (K1): las properties llevan marcadores y el contenedor recibe las contraseñas de .env.runtime.
      const p = e.leer("propiedadesDefault");
      assert.match(p, /^spring\.datasource\.password=\$\{KIT_DB_PASSWORD\}$/m);
      assert.match(p, /^mosip\.kernel\.keymanager\.hsm\.keystore-pass=\$\{KIT_KEYSTORE_PASSWORD\}$/m);
      assert.ok(!p.includes(pg) && !p.includes(ks), "ni la contraseña de Postgres ni la del keystore van en las properties");
      assert.doesNotMatch(sinComentarios(p), /keystore-pass=local$/m);
    } finally { e.limpiar(); }
  });

  test("las contraseñas por defecto explícitas (postgres, local) o vacías también se sustituyen", () => {
    for (const extra of [
      { POSTGRES_PASSWORD: "postgres", KEYSTORE_PASSWORD: "local" },
      { POSTGRES_PASSWORD: "", KEYSTORE_PASSWORD: "" },
    ]) {
      const e = generar(extra);
      try {
        assert.equal(e.salida.status, 0, e.salida.stderr);
        const r = e.leer("runtime");
        assert.match(valor(r, "POSTGRES_PASSWORD"), HEX64);
        assert.match(valor(r, "KEYSTORE_PASSWORD"), HEX64);
      } finally { e.limpiar(); }
    }
  });

  test("se cambian por separado: solo se genera la que vale el defecto", () => {
    const e = generar({ POSTGRES_PASSWORD: "mi-clave-de-bd", KEYSTORE_PASSWORD: "local" });
    try {
      const r = e.leer("runtime");
      assert.equal(valor(r, "POSTGRES_PASSWORD"), "mi-clave-de-bd");
      assert.match(valor(r, "KEYSTORE_PASSWORD"), HEX64);
    } finally { e.limpiar(); }
  });

  test("con contraseñas explícitas se respetan: en .env.runtime y en las properties", () => {
    const e = generar({ POSTGRES_PASSWORD: "bd-explicita-123", KEYSTORE_PASSWORD: "keystore-explicito-456" });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const r = e.leer("runtime");
      assert.equal(valor(r, "POSTGRES_PASSWORD"), "bd-explicita-123");
      assert.equal(valor(r, "KEYSTORE_PASSWORD"), "keystore-explicito-456");
      const p = e.leer("propiedadesDefault");
      assert.ok(!p.includes("bd-explicita-123") && !p.includes("keystore-explicito-456"), "K1: no van en las properties");
      assert.match(p, /^spring\.datasource\.password=\$\{KIT_DB_PASSWORD\}$/m);
      assert.equal(e.modo("runtime"), 0o600);
    } finally { e.limpiar(); }
  });

  test("las ya generadas se reutilizan al volver a generar (si no, se rompería una instalación en marcha)", () => {
    const e = generar(SIN_CONTRASENAS);
    try {
      const antes = e.leer("runtime");
      for (let i = 0; i < 2; i++) {
        const r = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
        assert.equal(r.status, 0, r.stderr);
        assert.doesNotMatch(r.stderr, /se generaron contraseñas/, "no vuelve a avisar: no generó nada");
      }
      assert.equal(e.leer("runtime"), antes);
      assert.equal(e.modo("runtime"), 0o600);
      const apply = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1" });
      assert.equal(apply.status, 0, apply.stderr);
      assert.equal(e.leer("runtime"), antes, "apply-credential.sh regenera y no cambia las contraseñas");
    } finally { e.limpiar(); }
  });

  test("KIT_CONSERVAR_SECRETOS_POR_DEFECTO=1 (instalación existente): no genera, deja postgres/local", () => {
    const e = generar({ ...SIN_CONTRASENAS, KIT_CONSERVAR_SECRETOS_POR_DEFECTO: "1" });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const r = e.leer("runtime");
      assert.equal(valor(r, "POSTGRES_PASSWORD"), "postgres");
      assert.equal(valor(r, "KEYSTORE_PASSWORD"), "local");
      assert.doesNotMatch(e.salida.stderr, /se generaron contraseñas/);
    } finally { e.limpiar(); }
  });

  test(".env.runtime no copia el .env entero (solo contraseñas y secreto OAuth) y no deja temporales", () => {
    const e = generar(SIN_CONTRASENAS);
    try {
      const r = e.leer("runtime");
      assert.doesNotMatch(r, /CREDENTIAL_|INSTITUTION_|RESTAPI_/);
      const restos = readdirSync(e.generated).filter((f) => f.startsWith(".env.runtime."));
      assert.deepEqual(restos, []);
    } finally { e.limpiar(); }
  });

  // La prueba negativa que importa (regla del 3-oct): ningún secreto, generado o del .env, en la
  // salida estándar ni en la de error de generate-config.sh.
  for (const [nombre, extra] of [
    ["generadas", SIN_CONTRASENAS],
    ["explícitas", { POSTGRES_PASSWORD: "bd-explicita-123", KEYSTORE_PASSWORD: "keystore-explicito-456" }],
  ]) {
    test(`la salida (stdout+stderr) de generate-config.sh no contiene ninguna contraseña ni el secreto OAuth (${nombre})`, () => {
      const e = generar(extra);
      try {
        const salida = e.salida.stdout + e.salida.stderr;
        assert.equal(e.salida.status, 0, salida);
        assert.ok(salida.length > 0);
        const secretos = ["secreto-de-mentira", "bd-explicita-123", "keystore-explicito-456"];
        const r = e.leer("runtime");
        secretos.push(valor(r, "POSTGRES_PASSWORD"), valor(r, "KEYSTORE_PASSWORD"));
        for (const s of secretos) assert.ok(!salida.includes(s), `la salida contiene un secreto (${s.slice(0, 6)}…)`);
        assert.doesNotMatch(salida, /[0-9a-f]{64}/, "ninguna cadena de 64 hex en la salida");
        // Una segunda ejecución (reutiliza) tampoco lo imprime.
        const dos = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
        for (const s of secretos) assert.ok(!(dos.stdout + dos.stderr).includes(s));
        // Ni los demás scripts que cargan el entorno.
        const did = e.ejecutar('DID_ORIGEN=test/x bash "$PWD/scripts/generate-did.sh"');
        for (const s of secretos) assert.ok(!(did.stdout + did.stderr).includes(s));
      } finally { e.limpiar(); }
    });
  }

  test("los errores de validación tampoco imprimen secretos", () => {
    const e = generar({ POSTGRES_PASSWORD: "bd-explicita-123", RESTAPI_TOKEN_URL: undefined });
    try {
      const salida = e.salida.stdout + e.salida.stderr;
      assert.notEqual(e.salida.status, 0);
      for (const s of ["secreto-de-mentira", "bd-explicita-123", "clave-keystore-de-mentira"]) assert.ok(!salida.includes(s));
    } finally { e.limpiar(); }
  });

  test("ningún script del kit activa `set -x` ni vuelca el entorno (env, printenv, declare -p)", () => {
    const recorre = (dir, acc = []) => {
      for (const n of readdirSync(dir)) {
        const r = join(dir, n);
        if (["test", "generated", "diagnostico", "docs"].includes(n)) continue;
        if (statSync(r).isDirectory()) recorre(r, acc);
        else if (/\.sh$/.test(n)) acc.push(r);
      }
      return acc;
    };
    for (const f of [join(KIT_ORIGEN, "install.sh"), ...recorre(join(KIT_ORIGEN, "scripts"))]) {
      const t = sinComentarios(readFileSync(f, "utf8"));
      assert.doesNotMatch(t, /\bset\s+-[a-z]*x|\bset\s+-o\s+xtrace|\bprintenv\b|declare\s+-p|^\s*env\s*$/m, f);
    }
  });

  test("compose-args hace que docker compose lea las contraseñas de .env.runtime (no del .env)", () => {
    const e = generar(SIN_CONTRASENAS);
    try {
      assert.equal(e.leer("composeArgs").trim(), "-f docker-compose.yml -f docker-compose.tls.yml --env-file generated/.env.runtime");
    } finally { e.limpiar(); }
  });
});

const hayCompose = (() => {
  try { execFileSync("docker", ["compose", "version"], { stdio: "ignore" }); return true; } catch { return false; }
})();

describe("D7 · compose interpola de verdad la contraseña generada (docker compose config, sin daemon)", () => {
  test("POSTGRES_PASSWORD de .env.runtime llega a la base y a Certify; el defecto `postgres` desaparece", { skip: !hayCompose && "docker compose no está instalado" }, () => {
    const e = generar(SIN_CONTRASENAS);
    try {
      const r = e.ejecutar("docker compose $(cat generated/compose-args) config --format json", { HOME: process.env.HOME });
      assert.equal(r.status, 0, r.stderr);
      const cfg = JSON.parse(r.stdout);
      const pg = valor(e.leer("runtime"), "POSTGRES_PASSWORD");
      assert.equal(cfg.services.database.environment.POSTGRES_PASSWORD, pg);
      assert.equal(cfg.services.certify.environment.DATABASE_PASSWORD, pg);
      assert.equal(cfg.services.certify.environment.LOGGING_CONFIG, "/home/mosip/config/logback-kit.xml");
    } finally { e.limpiar(); }
  });
});

describe("install.sh · comprobación de envsubst (hallazgo 3 de T1)", () => {
  test("sin envsubst en el PATH falla antes de generar nada, nombrando el paquete", () => {
    const e = generar({}, { generar: false });
    try {
      // PATH mínimo: bash, dirname y env (que install.sh necesita) y un docker/curl/jq falsos; sin envsubst.
      const bin = join(e.raiz, "bin"); mkdirSync(bin);
      for (const c of ["bash", "dirname", "env", "cat", "cp"]) {
        const ruta = execFileSync("sh", ["-c", `command -v ${c}`], { encoding: "utf8" }).trim();
        symlinkSync(ruta, join(bin, c));
      }
      for (const c of ["docker", "curl", "jq", "openssl"]) {
        writeFileSync(join(bin, c), "#!/bin/sh\nexit 0\n"); chmodSync(join(bin, c), 0o755);
      }
      const r = e.ejecutar('bash "$PWD/install.sh"', { PATH: bin });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /envsubst/);
      assert.match(r.stderr, /gettext/);
      assert.equal(existsSync(join(e.generated, "config")), false, "no generó nada");
    } finally { e.limpiar(); }
  });

  test("install.sh ya no escribe .env.runtime (lo hace generate-config.sh)", () => {
    const t = sinComentarios(readFileSync(join(KIT_ORIGEN, "install.sh"), "utf8"));
    assert.doesNotMatch(t, /write_runtime_env/);
    assert.match(t, /require_cmd openssl/);
  });
});
