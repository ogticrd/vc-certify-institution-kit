// T8 · K1 (alta) y K12 (.env): los secretos no quedan en ficheros legibles por otros usuarios.
// Medido por la evaluación adversarial: `generated/config/*.properties` (modo 644, en un `generated/` 755) llevaba
// la contraseña de Postgres, la del keystore y el OAUTH_CLIENT_SECRET.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, chmodSync, symlinkSync, writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { prepararEntorno, KIT_ORIGEN } from "./helpers/entorno.mjs";

const SECRETOS = { POSTGRES_PASSWORD: "bd-explicita-123", KEYSTORE_PASSWORD: "keystore-explicito-456", OAUTH_CLIENT_SECRET: "oauth-secreto-789" };
const VALORES = Object.values(SECRETOS);

function recorre(dir, acc = []) {
  for (const n of readdirSync(dir)) {
    const r = join(dir, n);
    acc.push(r);
    if (statSync(r).isDirectory()) recorre(r, acc);
  }
  return acc;
}
const modo = (r) => statSync(r).mode & 0o777;

describe("K1 · permisos de lo generado", () => {
  test("generated/ en 700 y .env.runtime en 600, aunque el umask sea 000", () => {
    const e = prepararEntorno({ extra: SECRETOS, generar: false });
    try {
      const r = e.ejecutar('umask 000; bash "$PWD/scripts/generate-config.sh"');
      assert.equal(r.status, 0, r.stderr);
      assert.equal(modo(e.generated), 0o700, "generated/");
      assert.equal(modo(e.rutas.runtime), 0o600, ".env.runtime");
      assert.equal(modo(join(e.generated, "config")), 0o700, "generated/config/");
    } finally { e.limpiar(); }
  });

  test("regenerar sobre un generated/ ya creado en 755 lo deja en 700", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      chmodSync(e.generated, 0o755);
      const r = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
      assert.equal(r.status, 0, r.stderr);
      assert.equal(modo(e.generated), 0o700);
    } finally { e.limpiar(); }
  });

  test("ningún fichero con un secreto (contraseñas, secreto OAuth) es legible por «otros» ni «grupo»; solo .env.runtime los lleva", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const conSecreto = [];
      for (const f of recorre(e.generated)) {
        if (!statSync(f).isFile()) continue;
        const t = readFileSync(f);
        if (VALORES.some((v) => t.includes(v))) conSecreto.push(f);
      }
      assert.ok(conSecreto.length >= 1, "al menos .env.runtime lleva las contraseñas");
      for (const f of conSecreto) assert.equal(modo(f) & 0o077, 0, `${f} (modo ${modo(f).toString(8)}) lleva un secreto y no es privado`);
      assert.deepEqual(conSecreto.map((f) => f.slice(e.generated.length + 1)), [".env.runtime"],
        "los secretos solo van en .env.runtime: las properties los reciben por variables de entorno del contenedor");
    } finally { e.limpiar(); }
  });

  test("las properties no llevan ninguna contraseña ni el secreto: usan marcadores que Spring resuelve desde el entorno", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      const d = e.leer("propiedadesDefault");
      const i = e.leer("propiedadesInstitucion");
      for (const v of VALORES) { assert.ok(!d.includes(v), "default"); assert.ok(!i.includes(v), "institution"); }
      assert.match(d, /^spring\.datasource\.password=\$\{KIT_DB_PASSWORD\}$/m);
      assert.match(d, /^mosip\.kernel\.keymanager\.hsm\.keystore-pass=\$\{KIT_KEYSTORE_PASSWORD\}$/m);
      assert.match(i, /^mosip\.certify\.data-provider-plugin\.restapi\.auth\.client-secret=\$\{KIT_OAUTH_CLIENT_SECRET\}$/m);
    } finally { e.limpiar(); }
  });

  test("las properties son legibles por el contenedor (uid 1001 las lee por bind mount: 644, sin secretos) y están documentadas así", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      assert.equal(modo(e.rutas.propiedadesDefault), 0o644);
      assert.equal(modo(e.rutas.propiedadesInstitucion), 0o644);
      const g = readFileSync(join(KIT_ORIGEN, "scripts", "generate-properties.sh"), "utf8");
      assert.match(g, /uid 1001/);
    } finally { e.limpiar(); }
  });

  test(".env.runtime lleva lo que el contenedor necesita: las contraseñas y el secreto OAuth (y nada más del .env)", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      const r = e.leer("runtime");
      assert.match(r, /^OAUTH_CLIENT_SECRET=oauth-secreto-789$/m);
      assert.match(r, /^POSTGRES_PASSWORD=bd-explicita-123$/m);
      assert.doesNotMatch(r, /CREDENTIAL_|INSTITUTION_|RESTAPI_/);
      assert.equal(modo(e.rutas.runtime), 0o600);
    } finally { e.limpiar(); }
  });

  test("compose-args no lleva secretos", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      const t = e.leer("composeArgs");
      for (const v of VALORES) assert.ok(!t.includes(v));
      assert.doesNotMatch(t, /PASSWORD|SECRET/i);
    } finally { e.limpiar(); }
  });

  test("docker-compose.yml pasa a Certify los tres secretos desde .env.runtime (las properties los leen del entorno)", () => {
    const y = readFileSync(join(KIT_ORIGEN, "docker-compose.yml"), "utf8");
    assert.match(y, /- KIT_DB_PASSWORD=\$\{POSTGRES_PASSWORD[^}]*\}/);
    assert.match(y, /- KIT_KEYSTORE_PASSWORD=\$\{KEYSTORE_PASSWORD[^}]*\}/);
    assert.match(y, /- KIT_OAUTH_CLIENT_SECRET=\$\{OAUTH_CLIENT_SECRET[^}]*\}/);
  });

  test("la salida del propio script no revela los secretos (sigue igual)", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      const s = e.salida.stdout + e.salida.stderr;
      for (const v of VALORES) assert.ok(!s.includes(v));
    } finally { e.limpiar(); }
  });
});

describe("K1/K12 · el .env (OAUTH_CLIENT_SECRET, contraseñas)", () => {
  test("install.sh crea el .env desde .env.example con modo 600", () => {
    const e = prepararEntorno({ generar: false });
    try {
      rmSync(join(e.kit, ".env"));
      const bin = join(e.raiz, "bin"); mkdirSync(bin);
      for (const c of ["bash", "dirname", "env", "cat", "cp", "chmod", "stat", "grep", "tr", "cut", "head", "mkdir", "mktemp", "mv", "rm", "id", "uname", "ls", "sed"]) {
        try { symlinkSync(execFileSync("sh", ["-c", `command -v ${c}`], { encoding: "utf8" }).trim(), join(bin, c)); } catch { /* opcional */ }
      }
      for (const c of ["docker", "curl", "jq", "openssl", "envsubst", "iconv"]) { writeFileSync(join(bin, c), "#!/bin/sh\nexit 0\n"); chmodSync(join(bin, c), 0o755); }
      const r = e.ejecutar('umask 022; bash "$PWD/install.sh"', { PATH: bin });
      assert.notEqual(r.status, 0, "sale con 1 pidiendo completar el .env");
      assert.ok(existsSync(join(e.kit, ".env")), r.stderr + r.stdout);
      assert.equal(modo(join(e.kit, ".env")), 0o600);
      assert.match(r.stdout, /chmod 600|600/);
    } finally { e.limpiar(); }
  });

  test("un .env legible por otros (644) da un AVISO que dice cómo corregirlo; en 600 no hay aviso", () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      chmodSync(join(e.kit, ".env"), 0o644);
      const a = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
      assert.equal(a.status, 0, a.stderr);
      assert.match(a.stderr, /AVISO: .*\.env.*644.*chmod 600/s);
      assert.equal((a.stderr.match(/AVISO: .*\.env.*644/g) ?? []).length, 1, "una sola vez por ejecución, no por script");
      chmodSync(join(e.kit, ".env"), 0o600);
      const b = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
      assert.equal(b.status, 0, b.stderr);
      assert.doesNotMatch(b.stderr, /\.env.*chmod 600/);
    } finally { e.limpiar(); }
  });
});

const hayCompose = (() => { try { execFileSync("docker", ["compose", "version"], { stdio: "ignore" }); return true; } catch { return false; } })();

describe("K1 · compose interpola de verdad los tres secretos desde .env.runtime (docker compose config, sin daemon)", () => {
  test("Certify recibe KIT_DB_PASSWORD, KIT_KEYSTORE_PASSWORD y KIT_OAUTH_CLIENT_SECRET", { skip: !hayCompose && "docker compose no está instalado" }, () => {
    const e = prepararEntorno({ extra: SECRETOS });
    try {
      const r = e.ejecutar("docker compose $(cat generated/compose-args) config --format json", { HOME: process.env.HOME });
      assert.equal(r.status, 0, r.stderr);
      const env = JSON.parse(r.stdout).services.certify.environment;
      assert.equal(env.KIT_DB_PASSWORD, SECRETOS.POSTGRES_PASSWORD);
      assert.equal(env.KIT_KEYSTORE_PASSWORD, SECRETOS.KEYSTORE_PASSWORD);
      assert.equal(env.KIT_OAUTH_CLIENT_SECRET, SECRETOS.OAUTH_CLIENT_SECRET);
    } finally { e.limpiar(); }
  });
});
